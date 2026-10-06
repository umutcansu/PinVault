package com.example.pinvault.server.route

import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.PinConfigHistoryEntry
import com.example.pinvault.server.model.SigningKeyInfo
import com.example.pinvault.server.plugin.receiveLimitedJson
import com.example.pinvault.server.plugin.receiveLimitedText
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.SigningKeySetService
import com.example.pinvault.server.store.ClientDeviceStore
import com.example.pinvault.server.store.ConnectionHistoryStore
import com.example.pinvault.server.store.DeviceHostAclStore
import com.example.pinvault.server.store.HostClientCertStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.http.*
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.Base64

private val aclLog = LoggerFactory.getLogger("CertificateConfigACL")

/** Bound of the per-client-id refusal windows; past it they start over (tokens are operator-issued, so few ids). */
private const val MAX_INDIVIDUAL_REFUSAL_IDS = 10_000

/**
 * Where refused enrollments go (`client_cert_enroll_refused`); one for each
 * copy of the enrollment endpoint (every Config API, and the management port's).
 */
internal class EnrollRefusalLog(
    private val audit: AuditLog?,
    /** Summarises refusals; null = each refusal is written as it is (tests). */
    private val recorder: com.example.pinvault.server.service.AuthFailureRecorder?,
    private val configApiId: String
) {
    /** Client id → start of the minute its last individually written refusal opened. */
    private val individualRefusals = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /**
     * [authenticated]: the request carried a valid, unspent enrollment token —
     * an operator-issued credential. Its refusals say something (a token used
     * for a device that is already someone else), so the first refusal of a
     * minute per client id is written on its own; the holder can still repeat
     * the request at will, so further ones are only counted into the summary.
     * Refusals of unauthenticated requests (open mode, code-less, no token)
     * are summarised: anyone can send those.
     */
    fun refused(remote: String, clientId: String, summary: String, authenticated: Boolean = false) {
        val recorder = recorder
        if (recorder == null) {
            audit?.record("client_cert_enroll_refused", summary, configApiId, clientId, actor = clientId, ip = remote)
            return
        }
        if (!authenticated) {
            recorder.report(remote, "POST", "/api/v1/client-certs/enroll", actor = clientId, reason = summary)
            return
        }
        val now = System.currentTimeMillis()
        if (individualRefusals.size > MAX_INDIVIDUAL_REFUSAL_IDS) individualRefusals.clear()
        var fresh = false
        individualRefusals.compute(clientId) { _, start ->
            if (start == null || now - start >= 60_000) { fresh = true; now } else start
        }
        if (fresh) {
            audit?.record("client_cert_enroll_refused", summary, configApiId, clientId, actor = clientId, ip = remote)
        } else {
            recorder.count(remote)
        }
    }
}

/**
 * Allowed shape for client-report identifier fields (hostname, model,
 * manufacturer). Permissive enough to accept real Android device strings
 * ("Google Pixel 7a", "Mi 9T", "api.example.com:8443") but rejects HTML
 * metacharacters that would otherwise reach the admin web UI's innerHTML
 * interpolations.
 */
private val CLIENT_REPORT_IDENT_REGEX = Regex("^[A-Za-z0-9._:\\- ]{1,128}$")

fun Route.certificateConfigRoutes(
    configApiId: String,
    store: PinConfigStore,
    historyStore: PinConfigHistoryStore,
    connectionStore: ConnectionHistoryStore,
    signingService: ConfigSigningService,
    clientDeviceStore: ClientDeviceStore,
    certService: com.example.pinvault.server.service.CertificateService? = null,
    enrollmentTokenStore: com.example.pinvault.server.store.EnrollmentTokenStore? = null,
    clientCertStore: com.example.pinvault.server.store.ClientCertStore? = null,
    mockServerManager: com.example.pinvault.server.service.MockServerManager? = null,
    hostClientCertStore: HostClientCertStore? = null,
    onClientCertEnrolled: (() -> Unit)? = null,
    enrollmentMode: String = "token",
    configApiMode: String = "tls",
    /**
     * V2: per-device pin scoping. When a device sends `?hosts=a,b,c` (or
     * identifies itself via `X-Device-Id`), the returned PinConfig is filtered
     * to the intersection of requested hosts and the device's ACL.
     *
     * If [deviceHostAclStore] is null, the legacy "return everything" behavior
     * is preserved. This keeps existing tests and demo flows working until
     * the library starts sending `?hosts=…`.
     */
    deviceHostAclStore: DeviceHostAclStore? = null,
    /**
     * `HOST_CLIENT_CERT_REQUIRE_GRANT`: a host's client certificate (a private
     * key the whole fleet shares) goes only to devices the host ACL names.
     * With it on, a scope without any ACL serves the certificate to nobody;
     * off (default) keeps the open behaviour: every enrolled device gets it.
     */
    requireHostCertGrant: Boolean = false,
    /**
     * Builds the signed envelopes (per request, or cached per content with
     * `CONFIG_SIGNATURE_CACHE`) and attaches the signing-key set. Null = a
     * per-request signer over [signingService] without key sets.
     */
    signedConfigService: SignedConfigService? = null,
    /** Signing-key set status for `GET /api/v1/signing-key`; null = not configured. */
    keySetService: SigningKeySetService? = null,
    /** Checks new pins against the certificates hosts serve now; null = off. */
    liveGate: LiveCertificateGate? = null,
    /** Where pin writes, gate decisions and overrides are recorded; null = nowhere. */
    audit: AuditLog? = null,
    /** CSR enrollment and renewal registry; null = P12 enrollment only. */
    clientIdentityStore: com.example.pinvault.server.store.ClientIdentityStore? = null,
    /** Lifetime of CSR-issued certificates (`CLIENT_CERT_TTL_DAYS`). */
    clientCertTtl: () -> java.time.Duration = { java.time.Duration.ofDays(90) },
    /** Test hook: a one-shot lifetime for the next certificate of a client id (`ALLOW_TEST_HOOKS`). */
    testTtlOverride: ((clientId: String) -> java.time.Duration?)? = null,
    /** Cuts off a source address whose renewals keep being refused, and an identity that renews in a loop; null = unlimited. */
    renewLimiter: com.example.pinvault.server.service.RateLimiter? = null,
    /** Records refused renewals without letting them flood the audit log. */
    renewFailures: com.example.pinvault.server.service.AuthFailureRecorder? = null,
    /** Enrollment codes many devices share, with optional approval; null = one-time tokens only. */
    policyEnrollment: PolicyEnrollment? = null,
    /** How many connection and config-update reports an address or a device may file; null = unlimited. */
    reportLimits: ReportLimits? = null,
    /**
     * Summarises refused enrollments (`client_cert_enroll_refused`): the first
     * of a minute is recorded at once, the rest are counted into one entry.
     * A caller holding a token — or nothing at all in open mode — can cause a
     * refusal per request; written one by one they flooded the audit log and
     * the webhook. Null = each refusal is written as it is (tests).
     */
    enrollRefusals: com.example.pinvault.server.service.AuthFailureRecorder? = null,
    /** Android Key Attestation of CSR enrollment keys (`ENROLLMENT_ATTESTATION`); null = not checked. */
    enrollmentAttestation: com.example.pinvault.server.service.EnrollmentAttestation? = null,
    /** Integrity verdict of the enrolling device (`INTEGRITY_VERIFICATION`); null = not checked. */
    enrollmentIntegrity: com.example.pinvault.server.service.EnrollmentIntegrity? = null,
    /**
     * `ENROLLMENT_P12`: whether an enrollment without a CSR gets a server-made
     * key (P12). False → 403 `csr_required` before anything is spent.
     */
    p12Enrollment: Boolean = true,
    /** Certificates per client id, pickups, device-initiated key replacements (see [com.example.pinvault.server.service.EnrollmentLimits]). */
    enrollmentLimits: com.example.pinvault.server.service.EnrollmentLimits = com.example.pinvault.server.service.EnrollmentLimits(),
    /** Renewals per identity ("id|" keys), apart from [renewLimiter]'s source addresses; null = [renewLimiter]. */
    renewIdentityLimiter: com.example.pinvault.server.service.RateLimiter? = null
) {
    val envelopes = signedConfigService ?: SignedConfigService(signingService)

    val refusalLog = EnrollRefusalLog(audit, enrollRefusals, configApiId)

    /** See [EnrollRefusalLog.refused]. */
    fun enrollRefused(remote: String, clientId: String, summary: String, authenticated: Boolean = false) =
        refusalLog.refused(remote, clientId, summary, authenticated)

    fun ttlFor(clientId: String): java.time.Duration = testTtlOverride?.invoke(clientId) ?: clientCertTtl()

    // Enrollment endpoint — Config API üzerinden client cert dağıtımı
    //
    // Güvenlik modları (ENROLLMENT_MODE):
    //   "token"  → Sadece enrollment token ile kayıt (varsayılan, üretim için önerilir)
    //   "open"   → Token veya deviceId ile kayıt (sadece demo/test için)
    //
    // Üretimde her zaman token modu kullanılmalıdır. Token'lar management API'den
    // oluşturulur ve tek kullanımlıktır.
    if (certService != null) {
        post("/api/v1/client-certs/enroll") {
            // Read up to the body cap, whatever the headers declared (ClientBodyLimit).
            val body = call.receiveLimitedText() ?: return@post
            val json = try { Json.parseToJsonElement(body) as? JsonObject } catch (_: Exception) { null }
            val token = json.string("token")
            val deviceId = json.string("deviceId")

            val deviceAlias = json.string("deviceAlias")
            // In open mode it is the device id, whatever the body says (below).
            var deviceUid = json.string("deviceUid")

            // A device that enrolled with a policy code and was told to wait
            // asks again by its request id (see PolicyEnrollment).
            val requestId = json.string("requestId")
            if (requestId != null && policyEnrollment != null) {
                return@post policyEnrollment.pickup(call, requestId, json)
            }

            val clientId: String
            var openMode = false
            var tokenValid = false
            // The device id an administrator bound the token to (V20), if any.
            var boundUid: String? = null
            if (token != null && (enrollmentTokenStore != null || policyEnrollment != null)) {
                clientId = enrollmentTokenStore?.validate(token)?.also { tokenValid = true; boundUid = enrollmentTokenStore.boundDeviceUid(token) } ?: run {
                    // Not a one-time token: maybe a code many devices share.
                    policyEnrollment?.let { policies ->
                        policies.policyFor(token)?.let { return@post policies.submit(call, it, json) }
                    }
                    return@post call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
                }
            } else if (deviceId != null && policyEnrollment?.acceptsApplications() == true) {
                // Code-less applications are on (the dashboard's switch): the device asks
                // without a token and waits until an administrator lets it in. Ahead of
                // ENROLLMENT_MODE=open: an administrator who wants to approve devices does.
                return@post policyEnrollment!!.submitWithoutCode(call, json)
            } else if (deviceId != null && enrollmentMode == "open") {
                // deviceId-only enrollment — sadece ENROLLMENT_MODE=open iken aktif
                // Üretimde kullanılmamalıdır: deviceId tahmin edilebilir, kimlik doğrulama yok
                clientId = deviceId
                openMode = true
                // The device id is the client id here; a body naming another one is
                // not this device's request. It used to be overwritten silently,
                // while the attestation was checked against the body's value.
                if (deviceUid != null && deviceUid != deviceId) {
                    return@post call.respondText("""{"error":"device_uid_mismatch","message":"In open enrollment deviceUid must be the deviceId."}""",
                        ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
                // The client id IS the device id: bind it as the device too, so the
                // one-identity-per-device check below always runs (it used to be
                // skipped when the body carried no deviceUid).
                deviceUid = deviceId
            } else if (deviceId != null) {
                return@post call.respondText(
                    """{"error":"Token required for enrollment. Generate a token via management API (POST /api/v1/enrollment-tokens/generate). To allow deviceId-only enrollment (not recommended for production), set ENROLLMENT_MODE=open"}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            } else {
                return@post call.respondText("""{"error":"token gerekli — management API'den token oluşturun"}""", ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            // The client id is printed in the dashboard and goes into the
            // certificate subject; the device id is stored and matched against
            // X-Device-Id. Neither may carry markup or extra name parts.
            if (!isValidIdentifier(clientId)) {
                return@post call.respondText("""{"error":"invalid_client_id","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            // Open mode takes the client id from the device: `client-ca` would name
            // the client CA's truststore entry, which revoke and forget act on.
            if (isReservedClientId(clientId)) {
                return@post call.respondText(RESERVED_CLIENT_ID, ContentType.Application.Json, HttpStatusCode.BadRequest)
            }
            if (deviceUid != null && !isValidIdentifier(deviceUid)) {
                return@post call.respondText("""{"error":"invalid_device_uid","message":"Letters, digits, '.', '_', ':' and '-' only, at most 64."}""",
                    ContentType.Application.Json, HttpStatusCode.BadRequest)
            }

            // A token minted for one device enrolls that device only: another
            // device id is refused before the token is spent; none means that one.
            boundUid?.let { bound ->
                if (deviceUid == null) deviceUid = bound
                if (deviceUid != bound) {
                    enrollRefused(call.request.origin.remoteAddress, clientId, "Enrollment of $clientId refused: the token is bound to another device", tokenValid)
                    return@post call.respondText("""{"error":"device_uid_mismatch","message":"This token was issued for another device."}""",
                        ContentType.Application.Json, HttpStatusCode.Forbidden)
                }
            }

            val remote = call.request.origin.remoteAddress

            // A revoked client id stays revoked: re-enrolling it would otherwise
            // put the identity straight back into trust (INSERT OR REPLACE in
            // client_certs used to do exactly that). Checked before the token
            // is spent so an operator's token is not wasted on a refusal.
            if (clientCertStore?.get(clientId)?.revoked == true || clientIdentityStore?.get(clientId)?.revoked == true) {
                enrollRefused(remote, clientId, "Enrollment of revoked client id $clientId refused", tokenValid)
                return@post call.respondText(
                    """{"error":"revoked","message":"This client id was revoked. Ask an administrator for a new one."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }

            // One active identity per device. The device id is whatever the
            // enrolling party sends, and token_mtls and E2E key registration
            // trust it to tie a certificate to a device: a second identity
            // claiming a device id that is already enrolled could act for that
            // device. Re-enrolling under the same client id replaces it; a new
            // client id needs the old one revoked first. Before the token is
            // spent, so the device can retry with it once that is done.
            if (deviceUid != null) {
                val holder = clientCertStore?.activeHolderOf(deviceUid, exceptId = clientId)
                if (holder != null) {
                    enrollRefused(remote, clientId, "Enrollment of $clientId refused: device $deviceUid is enrolled as $holder", tokenValid)
                    return@post call.respondText(
                        """{"error":"device_already_enrolled","message":"This device is enrolled under another client id. Ask an administrator to revoke it, then retry with the same token."}""",
                        ContentType.Application.Json, HttpStatusCode.Conflict
                    )
                }
            }
            // CSR enrollment: the device keeps its key, we only sign a
            // certificate over it. Asked for with the `csr` feature and a
            // `csr` field; anything else is the P12 flow below. Parsed before
            // the token is spent, so a malformed CSR does not burn it.
            val features = call.request.header("X-PinVault-Features").orEmpty().split(',').map { it.trim() }
            val csrB64 = json.string("csr")
            val csr = if ("csr" in features && csrB64 != null && clientIdentityStore != null) {
                try {
                    // Size, shape and key type first; the signature only for a key this server issues for.
                    certService.parseCsr(csrB64)
                } catch (e: IllegalArgumentException) {
                    return@post call.respondText(kotlinx.serialization.json.buildJsonObject {
                        put("error", kotlinx.serialization.json.JsonPrimitive("invalid_csr"))
                        put("message", kotlinx.serialization.json.JsonPrimitive(e.message ?: "The CSR is not a valid PKCS#10 request."))
                    }.toString(), ContentType.Application.Json, HttpStatusCode.BadRequest)
                }
            } else null
            // A key retired with a forgotten identity never gets a certificate
            // again, under any client id. Before the token is spent.
            if (csr != null && clientIdentityStore?.isRetired(csr.spkiSha256) == true) {
                enrollRefused(remote, clientId, "Enrollment of $clientId refused: its key was retired with a forgotten identity", tokenValid)
                return@post call.respondText(
                    """{"error":"revoked","message":"This key was revoked. Enroll again with a new key."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }

            if (openMode) {
                // Nothing authenticates an open-mode request but the device id it
                // names, so it may never replace what that id already holds.
                //
                // A server-made P12 would be handed to whoever asks, and every
                // one rewrote the truststore and restarted every mTLS listener:
                // only a CSR over a key the device keeps.
                if (csr == null) {
                    enrollRefused(remote, clientId, "Open enrollment of $clientId refused: no CSR (P12 is not issued in open mode)")
                    return@post call.respondText(
                        """{"error":"csr_required","message":"Open enrollment issues certificates only over a CSR (X-PinVault-Features: csr)."}""",
                        ContentType.Application.Json, HttpStatusCode.Forbidden
                    )
                }
                // An active identity stays with its key: the request's own key
                // asking again (an answer that got lost) is served, any other
                // key is refused. The way back for a device that lost its key is
                // an administrator revoking (and forgetting) the old identity.
                val activeIdentity = clientIdentityStore?.get(clientId)?.takeUnless { it.revoked }
                val activeCert = clientCertStore?.get(clientId)?.takeUnless { it.revoked }
                if ((activeIdentity != null || activeCert != null) && activeIdentity?.spkiSha256 != csr.spkiSha256) {
                    enrollRefused(remote, clientId, "Open enrollment of $clientId refused: the id is enrolled over another key")
                    return@post call.respondText(
                        """{"error":"identity_already_enrolled","message":"This device id is already enrolled. Ask an administrator to revoke it (and forget it), then enroll again."}""",
                        ContentType.Application.Json, HttpStatusCode.Conflict
                    )
                }
            }

            // No CSR: the server would make the key. Refused, before the token is
            // spent, when server-made keys are off (ENROLLMENT_P12=off) or every
            // key must be hardware-attested (ENROLLMENT_ATTESTATION=enforce: a
            // key made here cannot be). The library reports CSR_REQUIRED.
            if (csr == null && (!p12Enrollment || enrollmentAttestation?.refusesServerMadeKeys == true ||
                    enrollmentIntegrity?.refusesServerMadeKeys == true)) {
                enrollRefused(remote, clientId, "Enrollment of $clientId refused: no CSR, and this server issues no server-made keys", tokenValid)
                return@post call.respondText(CSR_REQUIRED_NO_P12, ContentType.Application.Json, HttpStatusCode.Forbidden)
            }

            // The device key's Android Key Attestation (ENROLLMENT_ATTESTATION):
            // checked after the cheap refusals above and before the token is spent.
            // Against the device id that is stored for the identity: a passing chain proves exactly it.
            val attestationOutcome = if (csr != null) enrollmentAttestation?.check(json, csr.publicKey, deviceUid) else null
            if (attestationOutcome is com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Refuse) {
                enrollRefused(remote, clientId, authenticated = tokenValid, summary = "Enrollment of $clientId refused under ENROLLMENT_ATTESTATION=enforce: " +
                    (attestationOutcome.reason ?: attestationOutcome.error))
                return@post call.respondText(attestationOutcome.body(), ContentType.Application.Json, HttpStatusCode.Forbidden)
            }
            val attestationRecord = (attestationOutcome as? com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Proceed)?.record
            // The device's integrity verdict (INTEGRITY_VERIFICATION), bound to this
            // CSR and device id: also before the token is spent.
            val integrityOutcome = if (csr != null) enrollmentIntegrity?.check(json) else null
            if (integrityOutcome is com.example.pinvault.server.service.EnrollmentIntegrity.Outcome.Refuse) {
                enrollRefused(remote, clientId, authenticated = tokenValid, summary = "Enrollment of $clientId refused under INTEGRITY_VERIFICATION=enforce: " +
                    (integrityOutcome.reason ?: integrityOutcome.error))
                return@post call.respondText(integrityOutcome.body(), ContentType.Application.Json, HttpStatusCode.Forbidden)
            }
            val integrityVerdict = (integrityOutcome as? com.example.pinvault.server.service.EnrollmentIntegrity.Outcome.Proceed)
            // Whether the device id is more than this request's word (V20): the
            // client id itself, a token an administrator bound to it, or a passing
            // attestation (with the app binding) over it. Only a proven device id
            // opens the device's keys, token_mtls files and host certificates.
            val deviceUidProven = deviceUid != null &&
                (deviceUid == clientId || (boundUid != null && boundUid == deviceUid) || attestationRecord?.attested == true)

            // Open mode, the same key asking again for the identity it already
            // has: the certificate it was given (while half its lifetime is
            // left), never a new signature, audit entry and webhook per request.
            if (openMode && csr != null && clientIdentityStore != null) {
                val current = clientIdentityStore.get(clientId)?.takeUnless { it.revoked }
                if (current?.spkiSha256 == csr.spkiSha256) {
                    certService.reusableClientCertificate(clientId, csr.spkiSha256, clientIdentityStore.certPem(clientId))?.let { existing ->
                        return@post respondIssuedClientCert(call, clientId, existing)
                    }
                }
                if (enrollmentLimits.issuance?.allow("issue|$clientId") == false) {
                    call.response.header(HttpHeaders.RetryAfter, "600")
                    return@post call.respondText("""{"error":"rate_limited","message":"Too many certificates for this device id. Try again later."}""",
                        ContentType.Application.Json, HttpStatusCode.TooManyRequests)
                }
            }

            // Spend the token in one statement: of two requests racing with
            // the same token, the second loses here instead of also getting a
            // certificate (validate() above is only a read).
            if (token != null && enrollmentTokenStore?.consume(token) == false) {
                return@post call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
            }

            if (csr != null && clientIdentityStore != null) {
                val issued = certService.issueClientCertificate(clientId, csr, ttlFor(clientId))
                val now = java.time.Instant.now().toString()
                // A token minted again for the same id over a new key: register()
                // retires the replaced key, the audit entry names it.
                val replacedKey = clientIdentityStore.get(clientId)?.takeUnless { it.revoked }?.spkiSha256?.takeIf { it != issued.spkiSha256 }
                val registered = clientIdentityStore.register(
                    clientId, configApiId, issued.spkiSha256, issued.serialHex,
                    issued.notBefore.toString(), issued.notAfter.toString(), deviceAlias, deviceUid, now,
                    // Open mode: checked above, and again here in the same statement
                    // as the write, so two requests racing for one id cannot both win.
                    replaceKey = !openMode,
                    // client_certs in the same transaction, never over a revoked row:
                    // a revocation landing mid-enrollment is not undone.
                    certRecord = if (clientCertStore != null) com.example.pinvault.server.store.ClientIdentityStore.CertRecord(issued.commonName, issued.fingerprint, deviceUidProven) else null,
                    attestation = attestationRecord
                )
                if (!registered) {
                    // Another enrollment won the device id meanwhile (decided in the write itself).
                    deviceUid?.let { clientCertStore?.activeHolderOf(it, exceptId = clientId) }?.let { holder ->
                        enrollRefused(remote, clientId, "Enrollment of $clientId refused: device $deviceUid is enrolled as $holder", tokenValid)
                        return@post call.respondText(
                            """{"error":"device_already_enrolled","message":"This device is enrolled under another client id. Ask an administrator to revoke it, then retry with the same token."}""",
                            ContentType.Application.Json, HttpStatusCode.Conflict
                        )
                    }
                    if (openMode && clientIdentityStore.get(clientId)?.revoked == false) {
                        return@post call.respondText(
                            """{"error":"identity_already_enrolled","message":"This device id is already enrolled. Ask an administrator to revoke it (and forget it), then enroll again."}""",
                            ContentType.Application.Json, HttpStatusCode.Conflict
                        )
                    }
                    return@post call.respondText("""{"error":"revoked"}""", ContentType.Application.Json, HttpStatusCode.Forbidden)
                }
                // An id that held a per-certificate anchor (a self-signed P12 from
                // before P12s came from the client CA) and now enrolls over its own
                // key: the anchor leaves the truststore and its key is retired (D1).
                clientIdentityStore.setCertPem(clientId, issued.chainPem.first())
                val anchorRemoved = retireLegacyAnchor(certService, clientIdentityStore, clientId, keep = issued.spkiSha256, now = now)
                audit?.record("client_cert_issued", "Certificate issued to $clientId over its own key (valid until ${issued.notAfter}; " +
                        "${attestationNote(attestationRecord)}" + (integrityVerdict?.takeIf { it.verdict != null }?.let { "; ${it.note}" } ?: "") + ")",
                    configApiId, clientId, actor = clientId, ip = remote,
                    detail = kotlinx.serialization.json.buildJsonObject {
                        put("format", kotlinx.serialization.json.JsonPrimitive("csr"))
                        put("serial", kotlinx.serialization.json.JsonPrimitive(issued.serialHex))
                        put("notAfter", kotlinx.serialization.json.JsonPrimitive(issued.notAfter.toString()))
                        put("spkiSha256", kotlinx.serialization.json.JsonPrimitive(issued.spkiSha256))
                        replacedKey?.let { put("replacedKeyRetired", kotlinx.serialization.json.JsonPrimitive(it)) }
                        attestationRecord?.let { a ->
                            put("attested", kotlinx.serialization.json.JsonPrimitive(a.attested))
                            a.reason?.let { put("attestationReason", kotlinx.serialization.json.JsonPrimitive(it)) }
                            a.securityLevel?.let { put("securityLevel", kotlinx.serialization.json.JsonPrimitive(it)) }
                        }
                        integrityVerdict?.verdict?.let { v ->
                            put("integrityPassed", kotlinx.serialization.json.JsonPrimitive(v.passed))
                            v.reason?.let { put("integrityReason", kotlinx.serialization.json.JsonPrimitive(it)) }
                        }
                        if (anchorRemoved) put("legacyAnchorRemoved", kotlinx.serialization.json.JsonPrimitive(true))
                    })
                // The client CA is already trusted: no truststore change, no listener
                // restart — unless an old anchor just left the truststore.
                if (anchorRemoved) {
                    if (onClientCertEnrolled != null) onClientCertEnrolled() else mockServerManager?.restartMtlsServers(certService)
                }
                return@post respondIssuedClientCert(call, clientId, issued)
            }

            val wrapping = com.example.pinvault.server.service.P12Transfer.wrappingFor(call)
            // Issued by the client CA: nothing is added to the truststore.
            val result = certService.generateClientCertificate(clientId, wrapping.password)
            // Never over a revoked row: a revocation that landed after the checks above stays.
            if (clientCertStore?.addUnlessRevoked(clientId, result.commonName, result.fingerprint, java.time.Instant.now().toString(),
                    deviceAlias = deviceAlias, deviceUid = deviceUid, deviceUidProven = deviceUidProven) == false) {
                deviceUid?.let { clientCertStore.activeHolderOf(it, exceptId = clientId) }?.let { holder ->
                    enrollRefused(remote, clientId, "Enrollment of $clientId refused: device $deviceUid is enrolled as $holder", tokenValid)
                    return@post call.respondText(
                        """{"error":"device_already_enrolled","message":"This device is enrolled under another client id. Ask an administrator to revoke it, then retry with the same token."}""",
                        ContentType.Application.Json, HttpStatusCode.Conflict
                    )
                }
                enrollRefused(remote, clientId, "Enrollment of $clientId refused: revoked while it was being issued", tokenValid)
                return@post call.respondText(
                    """{"error":"revoked","message":"This client id was revoked. Ask an administrator for a new one."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }
            val p12Now = java.time.Instant.now().toString()
            // A token minted again for an id enrolled over a CSR, used without
            // one: the P12 replaces that identity, whose key is retired.
            clientIdentityStore?.supersede(clientId, p12Now)?.takeIf { it > 0 }?.let { retired ->
                audit?.record("client_cert_key_replaced", "$clientId re-enrolled with a server-made P12: its $retired previous key(s) retired",
                    configApiId, clientId, actor = clientId, ip = remote)
            }
            // The new key on record, every older one of the id retired.
            clientIdentityStore?.recordServerMadeKey(clientId, result.spkiSha256, p12Now)
            // An older self-signed P12 of the same id was its own trust anchor: it goes.
            // Only then do the mTLS listeners (Config APIs and mock hosts, which read
            // the truststore when they start) need a restart — Main folds repeated
            // requests into one per interval (CoalescedRestart).
            if (retireLegacyAnchor(certService, clientIdentityStore, clientId, keep = result.spkiSha256, now = p12Now)) {
                if (onClientCertEnrolled != null) onClientCertEnrolled() else mockServerManager?.restartMtlsServers(certService)
            }

            // A private key was made here and is leaving the server: recorded like a CSR issuance.
            audit?.record("client_cert_issued", "Certificate issued to $clientId as a server-made P12 (valid until ${result.validUntil})",
                configApiId, clientId, actor = clientId, ip = remote,
                detail = kotlinx.serialization.json.buildJsonObject {
                    put("format", kotlinx.serialization.json.JsonPrimitive("p12"))
                    put("fingerprint", kotlinx.serialization.json.JsonPrimitive(result.fingerprint))
                    put("notAfter", kotlinx.serialization.json.JsonPrimitive(result.validUntil))
                })
            com.example.pinvault.server.service.P12Transfer.respond(call, result.p12Bytes, wrapping)
        }

        // Renewal of a CSR-enrolled certificate (see ClientCertRenewalRoute).
        if (clientIdentityStore != null) {
            clientCertRenewalRoute(configApiId, certService, clientIdentityStore, ::ttlFor, renewLimiter, renewFailures, audit,
                identityLimiter = renewIdentityLimiter)
        }
    }

    // Host client cert download — Android PinVault syncHostClientCerts() bunu çağırır
    //
    // Güvenlik: Host-specific client cert'ler sadece mTLS Config API üzerinden sunulmalıdır.
    // TLS Config API'den erişim reddedilir — önce default enrollment yapıp mTLS API kullanın.
    if (hostClientCertStore != null) {
        get("/api/v1/client-certs/{hostname}/download") {
            if (configApiMode == "tls") {
                return@get call.respondText(
                    """{"error":"Host client certs are only available via mTLS Config API. Enroll first to get a default client cert, then use the mTLS endpoint to download host-specific certs."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }
            val hostname = call.pathParameters["hostname"] ?: ""
            // The device host ACL decides which hosts a device gets pins for; it
            // was not asked here, so any enrolled device could download the
            // client private key of every host in the scope. Where the scope has
            // an ACL, the host must be allowed for the device the certificate
            // stands for: its client id, or the device id recorded at enrollment
            // (the id per-device grants are stored under). Before the lookup, so
            // the answer does not say which hosts have a certificate. A scope
            // with no ACL at all keeps serving every enrolled device, as the
            // config fetch does for a device that asks for no scoping — unless
            // HOST_CLIENT_CERT_REQUIRE_GRANT is on: the certificate is one
            // private key for the whole fleet, and a device enrolled with a
            // shared enrollment code (or a phone compromised before its
            // revocation) would otherwise walk off with every host's key.
            if (requireHostCertGrant && (deviceHostAclStore == null || !deviceHostAclStore.isConfigured(configApiId))) {
                aclLog.warn("Host client certificate refused: configApi={} has no device host ACL and HOST_CLIENT_CERT_REQUIRE_GRANT is on", configApiId)
                return@get call.respondText(
                    """{"error":"host_not_allowed","message":"This device is not allowed the client certificate of this host."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }
            if (deviceHostAclStore != null && deviceHostAclStore.isConfigured(configApiId)) {
                val certClientId = call.clientCertId()
                // The device id only when it is proven (V20): one an enrolling party
                // merely named would inherit that device's host grants.
                val devices = listOfNotNull(certClientId, certClientId?.let { clientCertStore?.get(it)?.takeIf { r -> r.deviceUidProven }?.deviceUid })
                    .distinct().ifEmpty { listOf("anonymous") }
                if (devices.none { hostname in deviceHostAclStore.resolve(configApiId, it, listOf(hostname)).granted }) {
                    aclLog.warn("Unauthorized host client certificate request: configApi={} device={} host={}",
                        configApiId, devices.first(), if (CLIENT_REPORT_IDENT_REGEX.matches(hostname)) hostname else "(malformed)")
                    return@get call.respondText(
                        """{"error":"host_not_allowed","message":"This device is not allowed the client certificate of this host."}""",
                        ContentType.Application.Json, HttpStatusCode.Forbidden
                    )
                }
            }
            val p12 = hostClientCertStore.getP12(hostname, configApiId)
                ?: return@get call.respondText("""{"error":"Client cert bulunamadi"}""", ContentType.Application.Json, HttpStatusCode.NotFound)
            com.example.pinvault.server.service.P12Transfer.respondStored(call, certService, p12)
        }
    }

    route("/api/v1/certificate-config") {

        get {
            // The view this device may see: loaded fresh on every call (see
            // signEnvelope for why it may be loaded twice). `?hosts=` and
            // X-Device-Id scope it; the attestation endpoint embeds the very
            // same view (servedPinConfig), from the body's hosts and deviceId.
            val requested = call.request.queryParameters["hosts"]
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
            val headerDeviceId = call.request.header("X-Device-Id")
            fun servedView(): PinConfig = servedPinConfig(call, configApiId, store, deviceHostAclStore, requested, headerDeviceId)

            val signed = call.request.queryParameters["signed"] != "false"
            if (!signed) return@get call.respond(servedView())

            val features = call.request.header("X-PinVault-Features").orEmpty()
                .split(',').map { it.trim() }
            val redelivery = "redelivery" in features
            try {
                call.respond(signEnvelope(envelopes, configApiId, redelivery, ::servedView))
            } catch (e: Exception) {
                // Never hand signer internals (KMS ids, command stderr) to an
                // unauthenticated caller.
                System.err.println("Config signing failed for $configApiId: ${e.message}")
                call.respond(HttpStatusCode.ServiceUnavailable, mapOf("error" to "Config signing is temporarily unavailable"))
            }
        }

        // `?configApiId=` selects the scope to write, exactly as the global
        // force-update/clear-force endpoints below already allow. The
        // management server mounts these routes under the fixed "default-tls"
        // scope, so without it the admin UI could only ever write to
        // default-tls while appearing to edit whichever Config API the
        // operator had open.
        //
        // Deliberately NOT mirrored on the GET above: that one is in the
        // unauthenticated client allowlist (`ApiKeyAuth.isPublicEndpoint`), so
        // a scope parameter there would let any device on one Config API port
        // read another scope's pins. PUT is admin-only (X-API-Key required on
        // both the management and the Config API ports), and an admin can
        // already write any scope via POST /api/v1/config/{id}/update.
        put {
            val scope = call.request.queryParameters["configApiId"] ?: configApiId
            call.applyPinConfigUpdate(scope, store, historyStore, liveGate, audit)
        }

        // Host bazlı geçmiş
        get("history/{hostname}") {
            val hostname = call.pathParameters["hostname"] ?: ""
            call.respond(historyStore.getByHostname(hostname))
        }

        // Per-host force update. `?configApiId=` as on the PUT and the global
        // variants below — the admin UI drives these from a host detail page
        // that may belong to any Config API scope.
        post("force-update/{hostname}") {
            val scope = call.request.queryParameters["configApiId"] ?: configApiId
            val hostname = call.pathParameters["hostname"] ?: ""
            val current = store.load(scope)
            val updated = current.copy(
                pins = current.pins.map { if (it.hostname == hostname) it.copy(forceUpdate = true) else it }
            )
            store.save(scope, updated)
            val pin = updated.pins.find { it.hostname == hostname }
            if (pin != null) {
                historyStore.add(scope, PinConfigHistoryEntry(
                    hostname = hostname, version = pin.version, timestamp = Instant.now().toString(),
                    event = "force_update", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
                ))
            }
            call.respond(HttpStatusCode.OK, updated)
        }

        post("clear-force/{hostname}") {
            val scope = call.request.queryParameters["configApiId"] ?: configApiId
            val hostname = call.pathParameters["hostname"] ?: ""
            val current = store.load(scope)
            val updated = current.copy(
                pins = current.pins.map { if (it.hostname == hostname) it.copy(forceUpdate = false) else it }
            )
            store.save(scope, updated)
            call.respond(HttpStatusCode.OK, updated)
        }

        // Global force — sets/clears the flag on every pin of a scope at once.
        //
        // `?configApiId=` lets the management server (which mounts these routes
        // under the fixed "default-tls" scope) drive any Config API, the same
        // way /api/v1/config/{configApiId}/update does. Without it the admin UI
        // could only ever force-update default-tls while appearing to act on
        // the Config API the operator had open. Admin-only: these paths are not
        // in the ApiKeyAuth allowlist, so X-API-Key is required.
        post("force-update") {
            val scope = call.request.queryParameters["configApiId"] ?: configApiId
            val current = store.load(scope)
            val updated = current.copy(
                pins = current.pins.map { it.copy(forceUpdate = true) }
            )
            store.save(scope, updated)
            current.pins.forEach { pin ->
                historyStore.add(scope, PinConfigHistoryEntry(
                    hostname = pin.hostname, version = pin.version, timestamp = Instant.now().toString(),
                    event = "force_update", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
                ))
            }
            call.respond(HttpStatusCode.OK, updated)
        }

        post("clear-force") {
            val scope = call.request.queryParameters["configApiId"] ?: configApiId
            val current = store.load(scope)
            val updated = current.copy(
                forceUpdate = false,
                pins = current.pins.map { it.copy(forceUpdate = false) }
            )
            store.save(scope, updated)
            call.respond(HttpStatusCode.OK, updated)
        }
    }

    // Public: devices and build tooling read the keys to embed or compare.
    // `publicKey` stays the primary key, as before; `signers` lists every key
    // that signs (m-of-n). Nothing here is secret.
    get("/api/v1/signing-key") {
        call.respond(
            SigningKeyInfo(
                publicKey = signingService.publicKeyBase64,
                keyId = signingService.primary.keyId,
                signers = signingService.signers.map { SigningKeyInfo.Signer(it.keyId, it.publicKeyBase64) },
                keySetVersion = keySetService?.status()?.version ?: 0
            )
        )
    }

    get("/api/v1/connection-history") {
        call.respond(connectionStore.getAll())
    }

    post("/api/v1/connection-history/web") {
        val body = call.receive<JsonObject>()
        connectionStore.addWebCheck(
            hostname = body["hostname"]?.jsonPrimitive?.content ?: "",
            timestamp = Instant.now().toString(),
            status = body["status"]?.jsonPrimitive?.content ?: "unknown",
            responseTimeMs = body["responseTimeMs"]?.jsonPrimitive?.longOrNull ?: 0,
            errorMessage = body["errorMessage"]?.jsonPrimitive?.content
        )
        call.respond(mapOf("saved" to true))
    }

    // Device reports (see DeviceReports.kt): no credential on a TLS listener,
    // so every field is the sender's claim. They used to be stored as sent —
    // any status, any text of any length, a time of the sender's choosing —
    // into a table trimmed to its newest 200 rows across all Config APIs:
    // 200 made-up "healthy" reports erased every real `pin_mismatch`.
    post("/api/v1/connection-history/client-report") {
        // Counted per source address before the body is read; on an mTLS
        // listener also per certificate.
        if (!call.reportAllowedFromAddress(reportLimits)) return@post
        call.clientCertId()?.let { if (!call.reportAllowedForDevice(reportLimits, configApiId, it)) return@post }
        val body = call.receiveLimitedJson() ?: return@post
        val hostname = body.string("hostname").orEmpty()
        val status = body.string("status")
        val manufacturer = body.string("deviceManufacturer")
        val model = body.string("deviceModel")
        val pinVersion = body.int("pinVersion") ?: 0
        val serverCertPin = body.string("serverCertPin")
        val storedPin = body.string("storedPin")
        // The server's clock: a reported time could be anything, and the dashboard sorts by it.
        val timestamp = Instant.now().toString()

        // M-04: this endpoint is public, so an attacker can post arbitrary
        // values that the admin web UI later renders. Hostname / model /
        // manufacturer must look like hostnames / identifiers, not HTML.
        // We reject the report rather than silently sanitizing so logs flag
        // the abuse instead of swallowing it.
        if (hostname.isNotBlank() && !CLIENT_REPORT_IDENT_REGEX.matches(hostname)) {
            return@post call.respondInvalidReport("hostname", "A host name of at most 128 characters.")
        }
        if (manufacturer != null && !CLIENT_REPORT_IDENT_REGEX.matches(manufacturer)) {
            return@post call.respondInvalidReport("deviceManufacturer", "Letters, digits, spaces and . _ : - only, at most 128.")
        }
        if (model != null && !CLIENT_REPORT_IDENT_REGEX.matches(model)) {
            return@post call.respondInvalidReport("deviceModel", "Letters, digits, spaces and . _ : - only, at most 128.")
        }
        // The dashboard counts and colours by status: only what the library reports.
        if (status == null || status !in ConnectionHistoryStore.CLIENT_REPORT_STATUSES) {
            return@post call.respondInvalidReport("status", "One of ${ConnectionHistoryStore.CLIENT_REPORT_STATUSES.joinToString()}.")
        }
        if (pinVersion < 0) return@post call.respondInvalidReport("pinVersion", "Not negative.")
        if (serverCertPin != null && !REPORT_PIN_REGEX.matches(serverCertPin)) {
            return@post call.respondInvalidReport("serverCertPin", "A Base64 pin.")
        }
        if (storedPin != null && !REPORT_PIN_REGEX.matches(storedPin)) {
            return@post call.respondInvalidReport("storedPin", "A Base64 pin.")
        }

        connectionStore.addClientReport(
            configApiId = configApiId,
            hostname = hostname,
            timestamp = timestamp,
            status = status,
            responseTimeMs = (body.long("responseTimeMs") ?: 0).coerceIn(0, REPORT_MAX_RESPONSE_MS),
            serverCertPin = serverCertPin,
            storedPin = storedPin,
            pinMatched = body.bool("pinMatched"),
            pinVersion = pinVersion,
            deviceManufacturer = manufacturer,
            deviceModel = model,
            errorMessage = reportText(body.string("errorMessage"))
        )

        // client_devices tablosunu güncelle
        if (hostname.isNotBlank() && manufacturer != null && model != null) {
            val deviceId = "${manufacturer}_${model}".lowercase().replace(" ", "_")
            clientDeviceStore.upsert(hostname, deviceId, manufacturer, model, pinVersion, status, timestamp)
        }

        call.respond(mapOf("saved" to true))
    }

    post("/api/v1/connection-history/config-update-report") {
        if (!call.reportAllowedFromAddress(reportLimits)) return@post
        call.clientCertId()?.let { if (!call.reportAllowedForDevice(reportLimits, configApiId, it)) return@post }
        val body = call.receiveLimitedJson() ?: return@post
        val status = body.string("status")
        val manufacturer = body.string("deviceManufacturer")
        val model = body.string("deviceModel")
        val pinVersion = body.int("pinVersion")
        val timestamp = Instant.now().toString()

        // Same M-04 hardening as /client-report: device identifiers must look
        // like identifiers, not HTML — the admin UI renders them later.
        if (manufacturer != null && !CLIENT_REPORT_IDENT_REGEX.matches(manufacturer)) {
            return@post call.respondInvalidReport("deviceManufacturer", "Letters, digits, spaces and . _ : - only, at most 128.")
        }
        if (model != null && !CLIENT_REPORT_IDENT_REGEX.matches(model)) {
            return@post call.respondInvalidReport("deviceModel", "Letters, digits, spaces and . _ : - only, at most 128.")
        }
        if (status == null || status !in ConnectionHistoryStore.CONFIG_UPDATE_STATUSES) {
            return@post call.respondInvalidReport("status", "One of ${ConnectionHistoryStore.CONFIG_UPDATE_STATUSES.joinToString()}.")
        }
        if (pinVersion != null && pinVersion < 0) return@post call.respondInvalidReport("pinVersion", "Not negative.")

        connectionStore.addConfigUpdateReport(
            timestamp = timestamp,
            status = status,
            pinVersion = pinVersion,
            deviceManufacturer = manufacturer,
            deviceModel = model,
            failureReason = reportText(body.string("failureReason")),
            configApiId = configApiId
        )

        call.respond(mapOf("saved" to true))
    }

    get("/api/v1/connection-history/{hostname}") {
        val hostname = call.pathParameters["hostname"] ?: ""
        call.respond(connectionStore.getByHostname(hostname))
    }

    get("/api/v1/hosts/{hostname}/clients") {
        val hostname = call.pathParameters["hostname"] ?: ""
        call.respond(clientDeviceStore.getByHostname(hostname))
    }
}

/** Decodes a pin-config write body the way the ContentNegotiation plugin would (unknown keys ignored). */
private val PIN_CONFIG_JSON = Json { ignoreUnknownKeys = true }

/** The library's intake rules (see [com.example.pinvault.server.service.PinConfigRules]); empty when [config] may be published. */
private fun validatePinConfig(config: PinConfig): List<String> =
    com.example.pinvault.server.service.PinConfigRules.errors(config.pins) +
        com.example.pinvault.server.service.PinConfigRules.trustRootErrors(config.trustRoots)

/**
 * The pin config a device may see in [configApiId]: the stored config
 * filtered to the intersection of [requestedHosts] (`?hosts=`, or the
 * attestation body's `hosts`) and the device's host ACL.
 *
 * Legacy behaviour is kept when both [requestedHosts] and [claimedDeviceId]
 * are absent, or when no ACL store is wired: the full config.
 *
 * [claimedDeviceId] is `X-Device-Id` (or the attested `deviceId`). On an
 * mTLS listener DeviceIdBinding has already refused a header naming another
 * device than the certificate's. On a TLS listener it is the device's own
 * claim: there the ACL shapes what an honest device gets, it keeps nothing
 * from anyone (pins are public keys).
 *
 * The mTLS client certificate identifies the device when no id is claimed.
 * It is deliberately NOT part of the gate: a cert alone must not switch
 * filtering on for clients that send neither `?hosts=` nor `X-Device-Id`, or
 * every existing mTLS device would suddenly be cut down to the (usually
 * empty) default ACL. It only sharpens the identity once scoping was already
 * requested, where a per-device ACL can add grants on top of the default.
 */
internal fun servedPinConfig(
    call: ApplicationCall,
    configApiId: String,
    store: PinConfigStore,
    deviceHostAclStore: DeviceHostAclStore?,
    requestedHosts: List<String>?,
    claimedDeviceId: String?
): PinConfig {
    val config = store.load(configApiId)
    val deviceId = claimedDeviceId ?: extractCertCn(call)
    val filtered = if (deviceHostAclStore != null && (requestedHosts != null || claimedDeviceId != null)) {
        val decision = deviceHostAclStore.resolve(configApiId, deviceId ?: "anonymous", requestedHosts)
        if (decision.hasUnauthorized) {
            aclLog.warn("Unauthorized host request: configApi={} deviceId={} denied={}",
                configApiId, deviceId ?: "anonymous", decision.denied)
        }
        // With `?hosts=`: only the granted ones of those; without: the ACL's.
        config.copy(pins = config.pins.filter { it.hostname in decision.granted })
    } else {
        config
    }
    // The library's "force update or refuse to start" gate reads the
    // config-level flag, while the dashboard only ever sets per-host flags.
    // Without this the admin-visible switch never reached that gate, so a
    // device with a stale forced config kept starting up happily while the
    // backend was unreachable.
    return filtered.copy(forceUpdate = filtered.hasAnyForceUpdate())
}

/**
 * The signed envelope of the view [load] returns now.
 *
 * issuedAt/expiresAt are stamped by the envelope service right before
 * signing (or reused from a cached signature of the very same content — see
 * SignedConfigService). The generation is taken BEFORE loading: if a change
 * lands in between, the envelope service refuses (StaleLoad) and the view is
 * loaded again, so a device never gets pre-change content with a post-change
 * issuedAt. Throws what the signer throws; the caller answers 503 (or, for
 * an embedded config, leaves it out).
 */
internal suspend fun signEnvelope(
    envelopes: SignedConfigService,
    configApiId: String,
    redelivery: Boolean,
    load: () -> PinConfig
): com.example.pinvault.server.model.SignedConfig {
    repeat(3) {
        val loadedAt = envelopes.generation()
        val view = load()
        try {
            // An external signer may take seconds, or make the request wait
            // its turn: never on the event loop.
            return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                envelopes.envelope(configApiId, view, redelivery, loadedAt)
            }
        } catch (_: SignedConfigService.StaleLoad) {
            // A change landed while serving; load again.
        }
    }
    // Changes keep landing: sign the latest view uncached, which always
    // carries the newest issuedAt.
    val latest = load()
    return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        envelopes.envelope(configApiId, latest, redeliveryOk = false)
    }
}

/**
 * Extract CN from the mTLS client cert's SubjectDN, if one is present on the
 * call. Used for deriving deviceId when X-Device-Id header is not sent.
 */
private fun extractCertCn(call: io.ktor.server.application.ApplicationCall): String? =
    // Shared with the vault routes — see ClientCertIdentity.kt. Returns the
    // client id (CN minus the "PinVault Client: " prefix), which under
    // auto-enrollment IS the device's ANDROID_ID and therefore the key the
    // per-device host ACL is stored under. Devices that send X-Device-Id
    // explicitly never reach this fallback.
    call.clientCertId()

/** 422 body when the live certificate gate refuses a pin set. */
@kotlinx.serialization.Serializable
data class LiveCheckRejection(
    val error: String,
    val liveCheck: LiveCertificateGate.Result,
    /** True when `?liveCheckOverride=<reason>` would be accepted. */
    val overridable: Boolean
)

/**
 * What the live certificate gate decides about publishing [updated] over
 * [current] in a scope, before anything is stored. One decision for every
 * route that publishes pins — the pin editor, a host's certificate change, a
 * new host — and for the description an approver is shown.
 */
internal class LiveGateDecision(
    /** The probe results; null when the gate is off or no pin set changed. */
    val result: LiveCertificateGate.Result?,
    /** `pass`, `warn`, `overridden` or `blocked`. */
    val outcome: String,
    val overrideReason: String? = null
) {
    val blocked: Boolean get() = outcome == "blocked"
}

/** [override] is the request's `?liveCheckOverride=<reason>`. Probes the hosts: call it off the event loop. */
internal fun liveGateDecision(
    liveGate: LiveCertificateGate?, current: PinConfig?, updated: PinConfig, override: String?
): LiveGateDecision {
    if (liveGate == null || !liveGate.enabled) return LiveGateDecision(null, "pass")
    val result = liveGate.check(current, updated)
    val reason = override?.trim()?.takeIf { it.isNotEmpty() }
    return when {
        result.passed -> LiveGateDecision(result, "pass")
        liveGate.mode == LiveCertificateGate.Mode.WARN -> LiveGateDecision(result, "warn")
        reason != null && liveGate.allowOverride -> LiveGateDecision(result, "overridden", reason)
        else -> LiveGateDecision(result, "blocked")
    }
}

/**
 * Runs the live gate for a pin write of this call and does what it decided:
 * a warning is flagged (`X-PinVault-Live-Check: warn`) and audited, an
 * override audited with its reason, a refusal audited and answered with 422
 * ([LiveCheckRejection]). False = refused and answered; the caller stops.
 */
internal suspend fun ApplicationCall.passesLiveGate(
    scope: String, current: PinConfig?, updated: PinConfig, liveGate: LiveCertificateGate?, audit: AuditLog?
): Boolean {
    if (liveGate == null || !liveGate.enabled) return true
    // Network I/O: off the event loop.
    val decision = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        liveGateDecision(liveGate, current, updated, request.queryParameters["liveCheckOverride"])
    }
    val result = decision.result ?: return true
    if (result.passed) return true
    val detail = Json.encodeToJsonElement(LiveCertificateGate.Result.serializer(), result)
    val hosts = result.failures().joinToString(",") { it.hostname }
    when (decision.outcome) {
        "warn" -> {
            response.header("X-PinVault-Live-Check", "warn")
            audit?.record("live_check_warning", result.describe(), scope, hosts, detail)
        }
        "overridden" -> audit?.record(
            "live_check_overridden", "Override \"${decision.overrideReason!!.take(200)}\": ${result.describe()}", scope, hosts, detail
        )
        else -> {
            audit?.record("live_check_blocked", result.describe(), scope, hosts, detail)
            respond(
                HttpStatusCode.UnprocessableEntity,
                LiveCheckRejection("Live certificate check failed: ${result.describe()}", result, liveGate.allowOverride)
            )
            return false
        }
    }
    return true
}

/**
 * The pin write behind `PUT /api/v1/certificate-config` and
 * `POST /api/v1/config/{id}/update`: duplicate and format validation,
 * per-host versioning, the live certificate gate, the save and the history.
 * One implementation, so neither route can skip a check the other makes.
 */
internal suspend fun ApplicationCall.applyPinConfigUpdate(
    scope: String,
    store: PinConfigStore,
    historyStore: PinConfigHistoryStore,
    liveGate: LiveCertificateGate?,
    audit: AuditLog?
) {
    // Read as JSON first: whether `trustRoots` was SENT decides below whether
    // the scope's list is replaced or kept (a data class default cannot tell
    // an omitted field from an empty list).
    val bodyJson = receive<JsonObject>()
    val incoming = try {
        PIN_CONFIG_JSON.decodeFromJsonElement(PinConfig.serializer(), bodyJson)
    } catch (e: kotlinx.serialization.SerializationException) {
        respond(HttpStatusCode.BadRequest, mapOf("errors" to listOf("Invalid pin config: ${e.message?.lineSequence()?.firstOrNull() ?: "cannot parse"}")))
        return
    }
    val current = store.load(scope)

    // Aynı hostname birden fazla kez eklenemez — büyük/küçük harf farkı da
    // aynı host: the library compares names ignoring case and refuses the
    // whole config otherwise.
    val duplicates = com.example.pinvault.server.service.PinConfigRules.duplicateHosts(incoming.pins.map { it.hostname })
    if (duplicates.isNotEmpty()) {
        respond(HttpStatusCode.Conflict, mapOf("errors" to duplicates.map { "$it: zaten mevcut" }))
        return
    }

    // Per-host versioning: sadece değişen host'ların versiyonunu artır
    val currentPinMap = current.pins.associateBy { it.hostname }
    val updatedPins = incoming.pins.map { newPin ->
        val oldPin = currentPinMap[newPin.hostname]
        when {
            oldPin == null -> newPin.copy(version = 1) // yeni host
            oldPin.sha256 != newPin.sha256 -> newPin.copy(version = oldPin.version + 1) // pin değişti
            else -> newPin.copy(version = oldPin.version) // değişmedi
        }
    }
    // Managed trust roots (ATTESTATION.md §10) travel with the pins. A body
    // that carries `trustRoots` replaces the scope's list (`[]` clears it); a
    // body without the field — an older script or dashboard — keeps the list
    // the scope has, so a pin edit cannot drop the roots by accident.
    val trustRoots = if (bodyJson.containsKey("trustRoots")) incoming.trustRoots.map { it.trim() } else current.trustRoots
    val updated = incoming.copy(pins = updatedPins, trustRoots = trustRoots)

    val errors = validatePinConfig(updated)
    if (errors.isNotEmpty()) {
        respond(HttpStatusCode.BadRequest, mapOf("errors" to errors))
        return
    }

    // Live certificate gate: new or changed pin sets must include the leaf the
    // host serves right now. See LiveCertificateGate.
    if (!passesLiveGate(scope, current, updated, liveGate, audit)) return

    // Hangi host'lar değişti, eklendi, silindi?
    val oldHostnames = current.pins.map { it.hostname }.toSet()
    val newHostnames = updated.pins.map { it.hostname }.toSet()

    val added = newHostnames - oldHostnames
    val removed = oldHostnames - newHostnames
    val kept = newHostnames.intersect(oldHostnames)

    // Re-added hosts continue their version sequence (see PinConfigStore.save);
    // history and the response must report the stored versions.
    val saved = store.save(scope, updated)
    val now = Instant.now().toString()

    added.forEach { hostname ->
        val pin = saved.pins.first { it.hostname == hostname }
        historyStore.add(scope, PinConfigHistoryEntry(
            hostname = hostname, version = pin.version, timestamp = now,
            event = "host_added", pinPrefix = pin.sha256.firstOrNull()?.take(12) ?: ""
        ))
    }

    removed.forEach { hostname ->
        val oldPin = currentPinMap[hostname]
        historyStore.add(scope, PinConfigHistoryEntry(
            hostname = hostname, version = oldPin?.version ?: 0, timestamp = now,
            event = "host_removed", pinPrefix = ""
        ))
    }

    kept.forEach { hostname ->
        val oldPin = current.pins.first { it.hostname == hostname }
        val newPin = saved.pins.first { it.hostname == hostname }
        if (oldPin.sha256 != newPin.sha256) {
            historyStore.add(scope, PinConfigHistoryEntry(
                hostname = hostname, version = newPin.version, timestamp = now,
                event = "pins_updated", pinPrefix = newPin.sha256.firstOrNull()?.take(12) ?: ""
            ))
        }
    }

    // A changed root list is a trust change like a pin change; it rides the
    // next signed envelope (the cache is dropped on every admin write).
    if (current.trustRoots.toSet() != saved.trustRoots.toSet()) {
        historyStore.add(scope, PinConfigHistoryEntry(
            hostname = "*", version = saved.computedVersion(), timestamp = now,
            event = "trust_roots_updated", pinPrefix = saved.trustRoots.firstOrNull()?.take(12) ?: ""
        ))
        audit?.record(
            "trust_roots_updated",
            "Managed trust roots of $scope set to ${saved.trustRoots.size} root(s)",
            configApiId = scope,
            detail = kotlinx.serialization.json.buildJsonObject {
                put("count", kotlinx.serialization.json.JsonPrimitive(saved.trustRoots.size))
            }
        )
    }

    respond(HttpStatusCode.OK, saved)
}
