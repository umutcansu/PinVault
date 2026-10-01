package com.example.pinvault.server.route

import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.store.ClientIdentityStore
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Duration
import java.util.Base64

/** The JSON a CSR enrollment or renewal answers with (`X-PinVault-Cert-Format: pem-chain`). */
suspend fun respondIssuedClientCert(
    call: ApplicationCall,
    clientId: String,
    issued: CertificateService.IssuedClientCert,
    extra: Map<String, JsonElement> = emptyMap()
) {
    val body = buildJsonObject {
        put("clientId", JsonPrimitive(clientId))
        put("commonName", JsonPrimitive(issued.commonName))
        put("chain", JsonArray(issued.chainPem.map { JsonPrimitive(it) }))
        put("serial", JsonPrimitive(issued.serialHex))
        put("notBefore", JsonPrimitive(issued.notBefore.toString()))
        put("notAfter", JsonPrimitive(issued.notAfter.toString()))
        put("spkiSha256", JsonPrimitive(issued.spkiSha256))
        extra.forEach { (k, v) -> put(k, v) }
    }
    call.response.header("X-PinVault-Cert-Format", "pem-chain")
    call.response.header(HttpHeaders.CacheControl, "no-store")
    call.respondText(body.toString(), ContentType.Application.Json)
}

/**
 * `POST /api/v1/client-certs/renew` — renewal of a CSR-enrolled certificate.
 *
 * Mounted on every Config API listener and, alone, on the recovery listener.
 * Two doors, one check:
 *  - client certificate presented (mTLS listener): it must be valid, it names
 *    the client, and it must carry the same key as the CSR;
 *  - none presented (TLS or recovery listener): the body names the client, and
 *    the CSR's self-signature must verify with the key registered at enrollment.
 *
 * Either way the identity must exist and not be revoked. Every refusal is the
 * same 403 `reenroll_required`, so a caller cannot probe which client ids
 * exist or which keys they hold.
 */
fun Route.clientCertRenewalRoute(
    configApiId: String,
    certService: CertificateService,
    clientIdentityStore: ClientIdentityStore,
    ttlFor: (clientId: String) -> Duration,
    renewLimiter: RateLimiter? = null,
    renewFailures: AuthFailureRecorder? = null,
    audit: AuditLog? = null
) {
    post("/api/v1/client-certs/renew") {
        val remote = call.request.origin.remoteAddress
        val json = try { Json.parseToJsonElement(call.receiveText()).jsonObject } catch (_: Exception) { null }
        val csrB64 = json?.get("csr")?.jsonPrimitive?.content
            ?: return@post call.respondText("""{"error":"invalid_csr","message":"csr is required"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)

        val presented = call.clientCertificate()
        val clientId = if (presented != null) {
            presented.subjectX500Principal.name.let { dn -> Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1) }
                ?.removePrefix(CLIENT_CN_PREFIX)?.trim()
        } else {
            json["clientId"]?.jsonPrimitive?.content?.trim()?.takeIf { it.isNotEmpty() }
        } ?: return@post call.respondText("""{"error":"invalid_request","message":"clientId is required"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
        val via = if (presented != null) "mtls" else "recovery"

        if (renewLimiter?.allow("$remote|$clientId") == false) {
            return@post call.respondText("""{"error":"rate_limited"}""", ContentType.Application.Json, HttpStatusCode.TooManyRequests)
        }

        suspend fun refuse(reason: String) {
            renewFailures?.report(remote, "POST", "/api/v1/client-certs/renew", actor = clientId, reason = reason)
            call.respondText(
                """{"error":"reenroll_required","message":"This identity cannot be renewed. Enroll again."}""",
                ContentType.Application.Json, HttpStatusCode.Forbidden
            )
        }

        val csr = try {
            certService.parseCsr(Base64.getDecoder().decode(csrB64))
        } catch (e: IllegalArgumentException) {
            return@post call.respondText("""{"error":"invalid_csr","message":"${e.message}"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
        }

        val identity = clientIdentityStore.get(clientId) ?: return@post refuse("unknown client id")
        if (identity.revoked) return@post refuse("revoked")
        if (identity.spkiSha256 != csr.spkiSha256) return@post refuse("CSR key differs from the registered key")
        if (presented != null) {
            if (runCatching { presented.checkValidity() }.isFailure) return@post refuse("presented certificate expired")
            if (certService.spkiSha256(presented.publicKey) != csr.spkiSha256) return@post refuse("presented certificate key differs from CSR key")
        }

        val issued = certService.issueClientCertificate(clientId, csr, ttlFor(clientId))
        val now = java.time.Instant.now().toString()
        if (!clientIdentityStore.recordRenewal(clientId, issued.serialHex, issued.notBefore.toString(), issued.notAfter.toString(), now)) {
            return@post refuse("revoked")
        }
        val renewCount = clientIdentityStore.get(clientId)?.renewCount ?: 0
        audit?.record("client_cert_renewed", "Certificate of $clientId renewed via $via (valid until ${issued.notAfter})",
            configApiId, clientId, actor = clientId, ip = remote,
            detail = buildJsonObject {
                put("via", JsonPrimitive(via))
                put("serial", JsonPrimitive(issued.serialHex))
                put("notAfter", JsonPrimitive(issued.notAfter.toString()))
                put("renewCount", JsonPrimitive(renewCount))
            })
        respondIssuedClientCert(call, clientId, issued, mapOf(
            "renewCount" to JsonPrimitive(renewCount),
            "via" to JsonPrimitive(via)
        ))
    }
}
