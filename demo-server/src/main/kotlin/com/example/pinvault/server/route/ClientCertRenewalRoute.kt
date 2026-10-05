package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.receiveLimitedText
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
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Duration

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
 *
 * Anyone can reach this, so the order is what keeps it cheap:
 *  1. a source address that keeps being refused is cut off (429) before the
 *     body is read — counted per address ([RateLimiter.sourceKey]), not per
 *     client id, which the caller picks and could change with every request;
 *  2. the identity is looked up, and the CSR only inspected (size, shape, key
 *     type — no signature work; a malformed one is a 400 for any client id);
 *  3. the CSR's signature is verified only when it carries the registered key
 *     of an identity that may renew.
 * A renewal that authenticated is then counted per identity, so one device
 * cannot renew in a loop.
 */
fun Route.clientCertRenewalRoute(
    configApiId: String,
    certService: CertificateService,
    clientIdentityStore: ClientIdentityStore,
    ttlFor: (clientId: String) -> Duration,
    renewLimiter: RateLimiter? = null,
    renewFailures: AuthFailureRecorder? = null,
    audit: AuditLog? = null,
    /**
     * Renewals per identity (`id|<clientId>`), apart from the source addresses
     * of [renewLimiter]: one table for both let a flood of new addresses fill
     * it and shut out every identity's renewal. Null = [renewLimiter] (as before).
     */
    identityLimiter: RateLimiter? = null
) {
    val perIdentity = identityLimiter ?: renewLimiter
    post("/api/v1/client-certs/renew") {
        val remote = call.request.origin.remoteAddress
        val source = RateLimiter.sourceKey(remote)
        if (renewLimiter?.exceeded(source) == true) {
            return@post call.respondText("""{"error":"rate_limited"}""", ContentType.Application.Json, HttpStatusCode.TooManyRequests)
        }

        /** A request that is not one: 400, counted against the source. */
        suspend fun invalid(error: String, message: String) {
            renewLimiter?.allow(source)
            call.respondText(buildJsonObject { put("error", JsonPrimitive(error)); put("message", JsonPrimitive(message)) }.toString(),
                ContentType.Application.Json, HttpStatusCode.BadRequest)
        }

        val body = call.receiveLimitedText() ?: return@post
        val json = try { Json.parseToJsonElement(body) as? JsonObject } catch (_: Exception) { null }
        val csrB64 = json.string("csr") ?: return@post invalid("invalid_csr", "csr is required")

        val presented = call.clientCertificate()
        val clientId = if (presented != null) {
            presented.subjectX500Principal.name.let { dn -> Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1) }
                ?.removePrefix(CLIENT_CN_PREFIX)?.trim()
        } else {
            json.string("clientId")?.trim()?.takeIf { it.isNotEmpty() }
        } ?: return@post invalid("invalid_request", "clientId is required")
        val via = if (presented != null) "mtls" else "recovery"

        suspend fun refuse(reason: String, actor: String = clientId) {
            renewLimiter?.allow(source)
            renewFailures?.report(remote, "POST", "/api/v1/client-certs/renew", actor = actor, reason = reason)
            call.respondText(
                """{"error":"reenroll_required","message":"This identity cannot be renewed. Enroll again."}""",
                ContentType.Application.Json, HttpStatusCode.Forbidden
            )
        }

        // The body's client id is the caller's text: one that could never have
        // been enrolled is not looked up, and not written into the audit log.
        if (presented == null && !isValidIdentifier(clientId)) return@post refuse("malformed client id", actor = "unknown")
        val identity = clientIdentityStore.get(clientId)

        val candidate = try {
            certService.inspectCsr(csrB64)
        } catch (e: IllegalArgumentException) {
            return@post invalid("invalid_csr", e.message ?: "The CSR is not a valid PKCS#10 request.")
        }
        if (identity == null) return@post refuse("unknown client id")
        if (identity.revoked) return@post refuse("revoked")
        if (identity.spkiSha256 != candidate.spkiSha256) return@post refuse("CSR key differs from the registered key")
        if (presented != null) {
            if (runCatching { presented.checkValidity() }.isFailure) return@post refuse("presented certificate expired")
            if (certService.spkiSha256(presented.publicKey) != candidate.spkiSha256) return@post refuse("presented certificate key differs from CSR key")
        }
        // The very CSR the last renewal accepted, sent again: a copy of an earlier
        // request (the recovery door takes no client certificate, the signed CSR
        // is the proof) — not the device asking for a new certificate.
        val csrSha256 = java.util.Base64.getEncoder().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(candidate.der))
        if (clientIdentityStore.isReplayedRenewal(clientId, csrSha256)) return@post refuse("CSR replayed (the same request the last renewal accepted)")
        // Signature work only now: for the registered key of an identity that may renew.
        val csr = try {
            certService.verifyCsr(candidate)
        } catch (e: IllegalArgumentException) {
            return@post invalid("invalid_csr", e.message ?: "CSR signature is invalid")
        }
        // The key here is an identity that just proved itself, never the caller's text.
        if (perIdentity?.allow("id|$clientId") == false) {
            return@post call.respondText("""{"error":"rate_limited"}""", ContentType.Application.Json, HttpStatusCode.TooManyRequests)
        }

        val issued = certService.issueClientCertificate(clientId, csr, ttlFor(clientId))
        val now = java.time.Instant.now().toString()
        // In the same statement as the replay check: two copies racing, one renews.
        if (!clientIdentityStore.recordRenewal(clientId, issued.serialHex, issued.notBefore.toString(), issued.notAfter.toString(), now,
                csrSha256 = csrSha256, certPem = issued.chainPem.first())) {
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
