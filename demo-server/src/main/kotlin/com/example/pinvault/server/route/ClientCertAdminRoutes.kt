package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.DEFAULT_ADMIN_BODY_MAX_BYTES
import com.example.pinvault.server.plugin.receiveLimitedText
import com.example.pinvault.server.plugin.receiveMultipartForm
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.P12Transfer
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.ClientIdentityStore
import com.example.pinvault.server.store.EnrollmentTokenStore
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant

private const val INVALID_ID = """{"error":"invalid_client_id","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}"""
private const val REVOKED_ID =
    """{"error":"revoked","message":"This client id was revoked. Forget it first (POST /api/v1/client-certs/{id}/forget) or use another id."}"""

/**
 * Management endpoints that put a client into mTLS trust by an
 * administrator's hand: a server-made P12, an uploaded certificate, and the
 * one-time tokens devices enroll with. (Moved out of Main.kt so the tests can
 * mount them.)
 *
 * All three are under two-person approval when it is on. Whatever the mode:
 * the client id must have the shape of an identifier, a revoked id is never
 * brought back (the row is written with the unless-revoked upsert, as
 * enrollment does), an uploaded certificate must be ONE end-entity client
 * certificate — never a CA — and each is audited under its own action.
 */
fun Route.clientCertAdminRoutes(
    certService: CertificateService,
    clientCertStore: ClientCertStore,
    clientIdentityStore: ClientIdentityStore?,
    enrollmentTokenStore: EnrollmentTokenStore,
    audit: AuditLog?,
    /** The truststore changed: running mTLS listeners must be restarted against it. */
    refreshMtlsTrust: (reason: String) -> Unit,
    /** The largest JSON body or certificate file read (`ADMIN_UPLOAD_MAX_BYTES`). */
    maxUploadBytes: Long = DEFAULT_ADMIN_BODY_MAX_BYTES,
    /**
     * Whether a server-made key (P12) may be generated here (`ENROLLMENT_P12`,
     * and not `ENROLLMENT_ATTESTATION=enforce`). False → 403 `csr_required`.
     */
    serverMadeKeys: Boolean = true
) {
    fun revoked(id: String) = clientCertStore.get(id)?.revoked == true || clientIdentityStore?.get(id)?.revoked == true

    /** Why an upload under [id] would replace something that exists, or null. */
    fun uploadConflict(id: String): String? = when {
        clientCertStore.get(id)?.revoked == false || clientIdentityStore?.get(id)?.revoked == false ->
            """{"error":"client_id_in_use","message":"This client id is an active identity. Revoke and forget it first, or use another id."}"""
        certService.getTrustStore()?.containsAlias(id.lowercase()) == true ->
            """{"error":"client_id_in_use","message":"The mTLS truststore already has an entry under this id. Use another id."}"""
        else -> null
    }

    post("/api/v1/client-certs/generate") {
        // A private key made here and handed out: off with ENROLLMENT_P12=off.
        if (!serverMadeKeys) return@post call.respondJson(CSR_REQUIRED_NO_P12, HttpStatusCode.Forbidden)
        val body = call.receiveLimitedText(maxUploadBytes) ?: return@post
        val clientId = jsonString(body, "clientId") ?: "client-${System.currentTimeMillis()}"
        // It becomes the certificate's CN and a row the dashboard prints.
        if (!isValidIdentifier(clientId)) return@post call.respondJson(INVALID_ID, HttpStatusCode.BadRequest)
        if (isReservedClientId(clientId)) return@post call.respondJson(RESERVED_CLIENT_ID, HttpStatusCode.BadRequest)
        // Before anything is generated: a revoked id stays revoked.
        if (revoked(clientId)) return@post call.respondJson(REVOKED_ID, HttpStatusCode.Conflict)

        // The dashboard negotiates and shows the one-off password once; an API client without the feature needs CLIENT_P12_PASSWORD.
        val wrapping = P12Transfer.wrappingFor(call)
            ?: return@post call.respondJson(P12Transfer.NEGOTIATION_REQUIRED, HttpStatusCode.BadRequest)
        // Issued by the client CA: nothing is added to the truststore.
        val result = certService.generateClientCertificate(clientId, wrapping.password)
        // Never over a revoked row: a revocation that landed after the check above stays.
        if (!clientCertStore.addUnlessRevoked(clientId, result.commonName, result.fingerprint, Instant.now().toString())) {
            return@post call.respondJson(REVOKED_ID, HttpStatusCode.Conflict)
        }
        val now = Instant.now().toString()
        // Replacing an identity enrolled over a device-held key: that key is retired, as on enrollment.
        val retired = clientIdentityStore?.supersede(clientId, now) ?: 0
        clientIdentityStore?.recordServerMadeKey(clientId, result.spkiSha256, now)
        audit?.record(
            "client_cert_generated",
            "Client certificate (server-made P12) generated for $clientId" + if (retired > 0) "; its $retired previous key(s) retired" else "",
            target = clientId,
            detail = buildJsonObject { put("format", "p12"); put("fingerprint", result.fingerprint); put("validUntil", result.validUntil) }
        )

        // The client CA is trusted already. Only an older self-signed P12 of
        // this id (its own trust anchor) leaving the truststore needs the
        // running mTLS listeners restarted.
        if (retireLegacyAnchor(certService, clientIdentityStore, clientId, keep = result.spkiSha256, now = now)) {
            refreshMtlsTrust("client cert generated: $clientId (old anchor removed)")
        }

        call.response.header(HttpHeaders.ContentDisposition, "attachment; filename=\"$clientId.p12\"")
        call.response.header(HttpHeaders.CacheControl, "no-store")
        P12Transfer.respond(call, result.p12Bytes, wrapping)
    }

    post("/api/v1/client-certs/upload") {
        val form = call.receiveMultipartForm(maxUploadBytes) ?: return@post
        val bytes = form.file
            ?: return@post call.respondJson("""{"error":"Dosya gerekli"}""", HttpStatusCode.BadRequest)
        val id = form.fields["clientId"]?.trim()?.takeIf { it.isNotEmpty() } ?: "uploaded-${System.currentTimeMillis()}"
        if (!isValidIdentifier(id)) return@post call.respondJson(INVALID_ID, HttpStatusCode.BadRequest)
        // `client-ca` used to overwrite the client CA in the truststore for good.
        if (isReservedClientId(id)) return@post call.respondJson(RESERVED_CLIENT_ID, HttpStatusCode.BadRequest)
        if (revoked(id)) return@post call.respondJson(REVOKED_ID, HttpStatusCode.Conflict)
        // An upload never replaces what an id already is: an active identity
        // (its certificate, its key) or another truststore entry under the same
        // alias — JKS aliases ignore case, so `Dev-1` is `dev-1`'s entry.
        uploadConflict(id)?.let { return@post call.respondJson(it, HttpStatusCode.Conflict) }

        // One end-entity client certificate, never a CA (see parseUploadedClientCertificate).
        val certificate = try {
            certService.parseUploadedClientCertificate(bytes)
        } catch (e: IllegalArgumentException) {
            return@post call.respondText(
                buildJsonObject { put("error", "invalid_client_certificate"); put("message", e.message ?: "The certificate was refused.") }.toString(),
                ContentType.Application.Json, HttpStatusCode.BadRequest
            )
        }
        try {
            val fingerprint = certService.importClientCertificate(id, bytes)
            if (!clientCertStore.addUnlessRevoked(id, "Uploaded: $id", fingerprint, Instant.now().toString())) {
                certService.removeFromTrustStore(id)
                return@post call.respondJson(REVOKED_ID, HttpStatusCode.Conflict)
            }
            audit?.record(
                "client_cert_uploaded",
                "Client certificate ${certificate.subjectX500Principal.name} trusted as $id on the mTLS listeners",
                target = id,
                detail = buildJsonObject {
                    put("subject", certificate.subjectX500Principal.name)
                    put("fingerprint", fingerprint)
                    put("notAfter", certificate.notAfter.toInstant().toString())
                }
            )
            // Same reason as /generate: the truststore file changed, the
            // running listeners have not.
            refreshMtlsTrust("client cert uploaded: $id")
            call.respondJson("""{"id":"$id","fingerprint":"$fingerprint","uploaded":true}""", HttpStatusCode.OK)
        } catch (e: Exception) {
            call.respondText(buildJsonObject { put("error", "Import hatası: ${e.message}") }.toString(), ContentType.Application.Json, HttpStatusCode.BadRequest)
        }
    }

    // ── Enrollment Token Management ─────────────────

    post("/api/v1/enrollment-tokens/generate") {
        val body = call.receiveLimitedText(maxUploadBytes) ?: return@post
        val clientId = jsonString(body, "clientId") ?: "device-${System.currentTimeMillis()}"
        // It becomes the certificate's CN and is printed in the dashboard.
        if (!isValidIdentifier(clientId)) return@post call.respondJson(INVALID_ID, HttpStatusCode.BadRequest)
        if (isReservedClientId(clientId)) return@post call.respondJson(RESERVED_CLIENT_ID, HttpStatusCode.BadRequest)

        // Optional: the device id (ANDROID_ID) the token is for. The enrollment
        // must then name it, and the identity's device id counts as proven —
        // what lets its certificate replace the device's E2E key and open its
        // token_mtls files (a device id sent at enrollment is only a claim).
        val deviceUid = jsonString(body, "deviceUid")
        if (deviceUid != null && !isValidIdentifier(deviceUid)) {
            return@post call.respondJson("""{"error":"invalid_device_uid","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}""", HttpStatusCode.BadRequest)
        }

        val token = enrollmentTokenStore.create(clientId, deviceUid)
        audit?.record("enrollment_token_created", "One-time enrollment token created for client id $clientId" +
            (deviceUid?.let { " (device $it)" } ?: ""), target = clientId)
        // The token exists in plain text only in this answer.
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respondText(buildJsonObject {
            put("token", token); put("clientId", clientId); deviceUid?.let { put("deviceUid", it) }
        }.toString(), ContentType.Application.Json)
    }

    get("/api/v1/enrollment-tokens") {
        call.respond(enrollmentTokenStore.getAll())
    }
}

/**
 * The answer to an enrollment (or a P12 generation) that would make the key
 * on the server while server-made keys are off (`ENROLLMENT_P12=off`, or
 * `ENROLLMENT_ATTESTATION=enforce`). The library maps `csr_required` to
 * `EnrollmentRefusal.CSR_REQUIRED`.
 */
internal const val CSR_REQUIRED_NO_P12 =
    """{"error":"csr_required","message":"This server issues certificates only over a key the device keeps (a CSR, X-PinVault-Features: csr); server-made keys (P12) are turned off."}"""

/**
 * [clientId] was issued a new identity (a CSR certificate or a P12 from the
 * client CA): the per-certificate trust anchor it held — a self-signed P12
 * from before P12s came from the client CA, or an uploaded certificate —
 * leaves the truststore (D1) and its key is retired, so the old certificate
 * is refused even on a listener that still has the old truststore loaded.
 * [keep] is the new key, never retired here.
 *
 * @return true when the truststore changed (the mTLS listeners need a restart).
 */
internal fun retireLegacyAnchor(
    certService: CertificateService,
    identities: ClientIdentityStore?,
    clientId: String,
    keep: String?,
    now: String
): Boolean {
    val anchor = certService.removeLegacyAnchor(clientId) ?: return false
    val spki = certService.spkiSha256(anchor.publicKey)
    if (spki != keep) identities?.retireKey(clientId, spki, now)
    return true
}

/** How an enrollment's attestation reads in the audit log. */
internal fun attestationNote(record: com.example.pinvault.server.store.KeyAttestation?): String = when {
    record == null -> "attestation not checked"
    // Apple vouched for the app and the hardware, not for where the key lives.
    com.example.pinvault.server.service.attestation.AppAttestAdmission.admitted(record) -> "admitted by App Attest"
    record.attested -> "hardware-attested key (${record.securityLevel})"
    else -> "key not attested: ${record.reason}"
}

private fun jsonString(body: String, name: String): String? = try {
    (Json.parseToJsonElement(body) as? JsonObject).string(name)
} catch (_: Exception) {
    null
}

private suspend fun ApplicationCall.respondJson(json: String, status: HttpStatusCode) =
    respondText(json, ContentType.Application.Json, status)
