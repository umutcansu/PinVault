package com.example.pinvault.server.route

import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.ClientIdentityStore
import com.example.pinvault.server.store.EnrollmentPolicy
import com.example.pinvault.server.store.EnrollmentPolicyStore
import com.example.pinvault.server.store.EnrollmentRequest
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant

private val policyLog = LoggerFactory.getLogger("PolicyEnrollment")

/**
 * The device side of enrollment policies, on `POST /api/v1/client-certs/enroll`:
 * a device enrolls with a code many devices share ([submit]) and, when the
 * policy wants an administrator's approval, comes back for its certificate
 * once it was let in ([pickup]).
 *
 * The device is recognised by its key. Every call carries a CSR, and its
 * signature proves the caller holds the key the request was made with — the
 * request id the device is given is no secret, it picks up nothing on its own.
 * Only CSR enrollment takes a policy code: a server-made P12 would leave
 * nothing to recognise the device by.
 */
class PolicyEnrollment(
    private val configApiId: String,
    private val policies: EnrollmentPolicyStore,
    private val certService: CertificateService,
    private val identities: ClientIdentityStore,
    private val clientCerts: ClientCertStore,
    private val audit: AuditLog?,
    /** Refusals anyone holding the code can cause, recorded without flooding the log. */
    private val refusals: AuthFailureRecorder?,
    private val ttlFor: (clientId: String) -> Duration,
    /** How long a request waits for a decision before it lapses (ENROLLMENT_REQUEST_TTL_HOURS). */
    private val pendingTtl: Duration = Duration.ofHours(24),
    /** Code-less applications: the most that may wait at once (OPEN_ENROLLMENT_MAX_PENDING). */
    private val openMaxPending: Int = 50,
    /** Code-less applications: new ones per source address (OPEN_ENROLLMENT_RATE_LIMIT); null = no limit. */
    private val openLimiter: com.example.pinvault.server.service.RateLimiter? = null,
    /**
     * Android Key Attestation of the device key (`ENROLLMENT_ATTESTATION`);
     * null = not checked. Checked before a request is recorded or a slot is
     * taken; the verdict is stored with the request (the approver sees it) and
     * then with the identity.
     */
    private val attestation: com.example.pinvault.server.service.EnrollmentAttestation? = null,
    /** Issuance per client id and pickups per request and source (see [com.example.pinvault.server.service.EnrollmentLimits]). */
    private val limits: com.example.pinvault.server.service.EnrollmentLimits = com.example.pinvault.server.service.EnrollmentLimits(),
    /**
     * The device's integrity verdict (`INTEGRITY_VERIFICATION`); null = not
     * checked. Checked once, when a request is made (before it is recorded or
     * a slot is taken), and noted in the audit log; a waiting device's
     * pickups are tied to its key and are not verified again.
     */
    private val integrity: com.example.pinvault.server.service.EnrollmentIntegrity? = null
) {
    /** When lapsed requests were last expired; see [expireLapsed]. */
    @Volatile private var lastExpiry = 0L

    /**
     * Requests nobody decided on lapse after [pendingTtl]. That is one UPDATE
     * over the table; it used to run on every submit and every pickup, which
     * anyone with a code (or nothing, with code-less applications) can send
     * in a loop. At most every [EXPIRY_INTERVAL_MS] now; a pickup of a request
     * that is itself overdue expires at once ([pickup]).
     */
    private fun expireLapsed(force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force && now - lastExpiry < EXPIRY_INTERVAL_MS) return
        lastExpiry = now
        policies.expirePending(pendingTtl)
    }

    /** The policy [code] belongs to, or null when it is not a policy code. */
    fun policyFor(code: String): EnrollmentPolicy? = policies.findByCode(code)

    /** Whether code-less applications are on: a device may ask without a token. */
    fun acceptsApplications(): Boolean = policies.openPolicy()?.acceptsNewDevices() == true

    /**
     * A device asks without a code (code-less applications, the dashboard's
     * switch): it waits in the list until an administrator lets it in.
     */
    suspend fun submitWithoutCode(call: ApplicationCall, json: JsonObject?) {
        val policy = policies.openPolicy() ?: return tokenRequired(call)
        submit(call, policy, json)
    }

    /** A device came with [policy]'s code. */
    suspend fun submit(call: ApplicationCall, policy: EnrollmentPolicy, json: JsonObject?) {
        val csr = parseCsr(call, json) ?: return
        // The approver reads it, and it goes into the audit log and the webhook:
        // printable, one line, short. (Anyone holding the code can send it.)
        val deviceAlias = displayAlias(json.string("deviceAlias"))
        // autoEnroll (code-less) sends the device id as `deviceId` too.
        val deviceUid = json.string("deviceUid") ?: json.string("deviceId")
        if (deviceUid != null && !isValidIdentifier(deviceUid)) {
            return call.respondError(HttpStatusCode.BadRequest, "invalid_device_uid", "Letters, digits, '.', '_', ':' and '-' only, at most 64.")
        }
        val remote = call.request.origin.remoteAddress
        expireLapsed()

        // The same key asking again — a retry, or an answer that got lost:
        // what was decided for it stands, it never takes a second slot.
        policies.findRequest(policy.id, csr.spkiSha256)?.let { return answer(call, it, csr, json) }

        val now = Instant.now()
        if (!policy.acceptsNewDevices(now)) {
            // Code-less applications turned off meanwhile: as if they never were on.
            if (policy.openApplications) return tokenRequired(call)
            // A stopped or expired code is just an invalid code, like a used token.
            if (policy.stoppedAt != null || !now.isBefore(Instant.parse(policy.expiresAt))) {
                return call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
            }
            return limitReached(call, policy, remote)
        }

        // One active identity per device, as for tokens. With approval the
        // administrator sees the clash and decides (revoke the old one first).
        val holder = deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = "") }
        if (holder != null && !policy.requireApproval) {
            return deviceAlreadyEnrolled(call, "device $deviceUid is enrolled as $holder (policy ${policy.name})", remote)
        }

        if (policy.requireApproval) {
            val waitingCap = if (policy.openApplications) openMaxPending else policy.maxDevices
            if (policies.countPending(policy.id) >= waitingCap) {
                refusals?.report(remote, "POST", call.request.path(), reason = "too many devices waiting with policy ${policy.name}")
                return call.respondError(HttpStatusCode.TooManyRequests, "too_many_pending_requests",
                    "Too many devices are waiting for approval. Ask an administrator.")
            }
            // Anyone can ask without a code: a source address gets a few new requests per window.
            if (policy.openApplications && openLimiter != null && !openLimiter.allow("apply|${com.example.pinvault.server.service.RateLimiter.sourceKey(remote)}")) {
                refusals?.report(remote, "POST", call.request.path(), reason = "too many code-less applications from this address")
                return call.respondError(HttpStatusCode.TooManyRequests, "too_many_applications",
                    "Too many applications from this address. Try again later.")
            }
            // The device key's attestation, before anything is recorded: under
            // enforce a key without a passing one never waits in the list.
            val verdict = attestationOf(call, json, csr, remote, policy) ?: return
            val integrityNote = integrityOf(call, json, remote, policy) ?: return
            val recorded = policies.createRequest(policy, csr.spkiSha256, EnrollmentRequest.PENDING, configApiId,
                deviceAlias, deviceUid, remote, now, attestation = verdict.record)
            if (!recorded.created) return answer(call, recorded.request, csr, json)
            val request = recorded.request
            audit?.record(
                "enrollment_request_pending",
                "${deviceAlias ?: deviceUid ?: "A device"} asks to enroll as ${request.clientId} " +
                    (if (policy.openApplications) "without a code" else "with policy ${policy.name}") +
                    " (verification code ${request.verificationCode}; ${verdict.note}$integrityNote)" +
                    (holder?.let { "; this device is enrolled as $it" } ?: ""),
                configApiId, request.clientId, actor = request.clientId, ip = remote,
                detail = buildJsonObject {
                    put("policy", policy.name)
                    put("requestId", request.id)
                    deviceUid?.let { put("deviceUid", it) }
                    holder?.let { put("enrolledAs", it) }
                    put("spkiSha256", request.spkiSha256)
                    verdict.record?.let { a ->
                        put("attested", a.attested)
                        a.reason?.let { put("attestationReason", it) }
                    }
                }
            )
            return respondPending(call, request)
        }

        // The device key's attestation and the device's integrity, before a slot is taken.
        val verdict = attestationOf(call, json, csr, remote, policy) ?: return
        val integrityNote = integrityOf(call, json, remote, policy) ?: return
        // No approval: take a slot, then issue.
        if (!policies.reserveSlot(policy.id)) {
            val current = policies.get(policy.id)
            if (current?.stoppedAt != null) {
                return call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
            }
            return limitReached(call, policy, remote)
        }
        val recorded = policies.createRequest(policy, csr.spkiSha256, EnrollmentRequest.APPROVED, configApiId,
            deviceAlias, deviceUid, remote, now, attestation = verdict.record)
        if (!recorded.created) {
            // The same key won a race with itself: one slot is enough.
            policies.releaseSlot(policy.id)
            return answer(call, recorded.request, csr, json)
        }
        issue(call, recorded.request, csr, json, integrityNote)
    }

    /**
     * The device key's attestation verdict for a new request, or null after
     * answering 403 (`ENROLLMENT_ATTESTATION=enforce` and no passing chain).
     * Without a verifier: proceed, nothing recorded.
     */
    private suspend fun attestationOf(
        call: ApplicationCall,
        json: JsonObject?,
        csr: CertificateService.ParsedCsr,
        remote: String,
        policy: EnrollmentPolicy
    ): com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Proceed? {
        // The device id the request records: what a passing chain proves.
        val outcome = attestation?.check(json, csr.publicKey, json.string("deviceUid") ?: json.string("deviceId"))
            ?: return com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Proceed(null)
        return when (outcome) {
            is com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Proceed -> outcome
            is com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Refuse -> {
                refusals?.report(remote, "POST", call.request.path(),
                    reason = "device key not attested (${outcome.reason ?: outcome.error}) with policy ${policy.name}")
                call.respondText(outcome.body(), ContentType.Application.Json, HttpStatusCode.Forbidden)
                null
            }
        }
    }

    /**
     * The device's integrity for a new request: "" when not checked, else
     * "; <note>" for the audit text; null after answering 403
     * (`INTEGRITY_VERIFICATION=enforce` and no passing verdict).
     */
    private suspend fun integrityOf(
        call: ApplicationCall,
        json: JsonObject?,
        remote: String,
        policy: EnrollmentPolicy
    ): String? {
        val outcome = integrity?.check(json) ?: return ""
        return when (outcome) {
            is com.example.pinvault.server.service.EnrollmentIntegrity.Outcome.Proceed ->
                if (outcome.verdict == null) "" else "; ${outcome.note}"
            is com.example.pinvault.server.service.EnrollmentIntegrity.Outcome.Refuse -> {
                refusals?.report(remote, "POST", call.request.path(),
                    reason = "device integrity not verified (${outcome.reason ?: outcome.error}) with policy ${policy.name}")
                call.respondText(outcome.body(), ContentType.Application.Json, HttpStatusCode.Forbidden)
                null
            }
        }
    }

    /**
     * A device asks again, by the request id it was given, whether it was let in.
     *
     * The request is looked up before anything of the CSR is parsed, and the
     * CSR's signature is verified only when it carries the request's key: an
     * id nobody was given, or somebody else's, costs a database read.
     */
    suspend fun pickup(call: ApplicationCall, requestId: String, json: JsonObject?) {
        val remote = call.request.origin.remoteAddress
        // A waiting device asks every few seconds; a loop asking faster costs a
        // lookup and a CSR check each time. Per request id (assigned by the
        // server) and per source address.
        if (limits.pickupsPerSource?.allow(com.example.pinvault.server.service.RateLimiter.sourceKey(remote)) == false ||
            limits.pickupsPerRequest?.allow("pickup|$requestId") == false) {
            call.response.header(HttpHeaders.RetryAfter, RETRY_AFTER_SECONDS.toString())
            return call.respondError(HttpStatusCode.TooManyRequests, "rate_limited", "Asked too often. Wait for Retry-After, then ask again.")
        }
        expireLapsed()
        var request = policies.getRequest(requestId)
            ?: return call.respondError(HttpStatusCode.NotFound, "enrollment_request_not_found",
                "No such enrollment request. Enroll again with the code.")
        // Overdue itself: expired now, whatever the interval.
        if (request.status == EnrollmentRequest.PENDING &&
            runCatching { Instant.parse(request.createdAt).plus(pendingTtl).isBefore(Instant.now()) }.getOrDefault(false)) {
            expireLapsed(force = true)
            request = policies.getRequest(requestId) ?: request
        }
        val candidate = inspectCsr(call, json) ?: return
        if (request.spkiSha256 != candidate.spkiSha256) {
            refusals?.report(call.request.origin.remoteAddress, "POST", call.request.path(), actor = request.clientId,
                reason = "request ${request.id} picked up with another key")
            return call.respondError(HttpStatusCode.Forbidden, "enrollment_request_mismatch",
                "This request was made with another key.")
        }
        val csr = verifyCsr(call, candidate) ?: return
        answer(call, request, csr, json)
    }

    /** Answers by what was decided for [request]. */
    private suspend fun answer(call: ApplicationCall, request: EnrollmentRequest, csr: CertificateService.ParsedCsr, json: JsonObject?) {
        when (request.status) {
            EnrollmentRequest.PENDING -> respondPending(call, request)
            EnrollmentRequest.REJECTED -> call.respondError(HttpStatusCode.Forbidden, "enrollment_rejected",
                "An administrator turned this device away.")
            EnrollmentRequest.EXPIRED -> call.respondError(HttpStatusCode.Gone, "enrollment_request_expired",
                "Nobody decided on this request in time. Ask again.")
            EnrollmentRequest.APPROVED, EnrollmentRequest.ISSUED -> issue(call, request, csr, json)
            else -> call.respondError(HttpStatusCode.Conflict, "enrollment_request_unknown_state", request.status)
        }
    }

    /**
     * The attestation an issued identity is stored with: the request's, when it
     * passed; otherwise the chain this call carries is checked (a request
     * recorded before `ENROLLMENT_ATTESTATION=enforce`, or under warn without
     * one). Null after answering 403 — enforce, and still no passing chain.
     */
    private suspend fun issuingAttestation(
        call: ApplicationCall,
        request: EnrollmentRequest,
        csr: CertificateService.ParsedCsr,
        json: JsonObject?
    ): Issuing? {
        val checker = attestation
        if (checker == null || checker.mode == com.example.pinvault.server.service.EnrollmentAttestationMode.OFF ||
            request.attestation?.attested == true) return Issuing(request.attestation)
        return when (val outcome = checker.check(json, csr.publicKey, request.deviceUid)) {
            is com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Proceed ->
                Issuing(if (outcome.record?.attested == true) outcome.record else request.attestation ?: outcome.record)
            is com.example.pinvault.server.service.EnrollmentAttestation.Outcome.Refuse -> {
                refusals?.report(call.request.origin.remoteAddress, "POST", call.request.path(), actor = request.clientId,
                    reason = "request ${request.id}: device key not attested (${outcome.reason ?: outcome.error})")
                call.respondText(outcome.body(), ContentType.Application.Json, HttpStatusCode.Forbidden)
                null
            }
        }
    }

    /** Issues the certificate of an approved (or already issued) request over the CSR's key. */
    private suspend fun issue(
        call: ApplicationCall,
        request: EnrollmentRequest,
        csr: CertificateService.ParsedCsr,
        json: JsonObject?,
        /** "; <integrity note>" for the audit text when the request was checked now; "" otherwise. */
        integrityNote: String = ""
    ) {
        val remote = call.request.origin.remoteAddress
        val clientId = request.clientId
        // client_certs.add below would un-revoke a revoked id: a revoked one stays revoked.
        if (clientCerts.get(clientId)?.revoked == true || identities.get(clientId)?.revoked == true) {
            return call.respondError(HttpStatusCode.Forbidden, "revoked", "This client id was revoked. Enroll again with the code.")
        }
        // The request's client id was free when it was made; should something
        // have enrolled under it since (an administrator's token for that id),
        // a request never replaces that identity's key. Its own key picking up
        // again is fine: that is this request's identity.
        val activeIdentity = identities.get(clientId)?.takeUnless { it.revoked }
        val activeCert = clientCerts.get(clientId)?.takeUnless { it.revoked }
        if ((activeIdentity != null || activeCert != null) && activeIdentity?.spkiSha256 != csr.spkiSha256) {
            refusals?.report(remote, "POST", call.request.path(), actor = clientId,
                reason = "request ${request.id}: $clientId is enrolled over another key")
            return call.respondError(HttpStatusCode.Conflict, "identity_already_enrolled",
                "This client id is enrolled over another key. Ask an administrator.")
        }
        // Checked again here: the device may have enrolled under another id since it asked.
        val holder = request.deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = clientId) }
        if (holder != null) {
            return deviceAlreadyEnrolled(call, "device ${request.deviceUid} is enrolled as $holder (policy ${request.policyName})", remote)
        }
        // The same key asking again for an identity it already has (a lost
        // answer, a retry loop, the code stopped meanwhile): the certificate it
        // was given, while half its lifetime is left — not a new signature,
        // audit entry and webhook per request.
        if (activeIdentity != null && request.status == EnrollmentRequest.ISSUED) {
            certService.reusableClientCertificate(clientId, csr.spkiSha256, identities.certPem(clientId))?.let { existing ->
                return respondIssuedClientCert(call, clientId, existing, extra = mapOf("policy" to JsonPrimitive(request.policyName)))
            }
        }
        // Certificates per client id: the rest is a loop.
        if (limits.issuance?.allow("issue|$clientId") == false) {
            call.response.header(HttpHeaders.RetryAfter, "600")
            return call.respondError(HttpStatusCode.TooManyRequests, "rate_limited", "Too many certificates for this client id. Try again later.")
        }
        // Under enforce a request recorded without a passing attestation (before
        // the switch) is issued only with one now.
        val keyAttestation = (issuingAttestation(call, request, csr, json) ?: return).record

        val issued = certService.issueClientCertificate(clientId, csr, ttlFor(clientId))
        val now = Instant.now().toString()
        val registered = identities.register(
            clientId, configApiId, issued.spkiSha256, issued.serialHex,
            issued.notBefore.toString(), issued.notAfter.toString(), request.deviceAlias, request.deviceUid, now,
            // client_certs in the same transaction, never over a revoked row —
            // nor while another identity holds the device id. The device id is
            // proven only by a passing attestation (its challenge is the id).
            certRecord = ClientIdentityStore.CertRecord(issued.commonName, issued.fingerprint,
                deviceUidProven = request.deviceUid != null && (request.deviceUid == clientId || keyAttestation?.attested == true)),
            attestation = keyAttestation
        )
        if (!registered) {
            request.deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = clientId) }?.let { racing ->
                return deviceAlreadyEnrolled(call, "device ${request.deviceUid} is enrolled as $racing (policy ${request.policyName})", remote)
            }
            return call.respondError(HttpStatusCode.Forbidden, "revoked", "This client id was revoked. Enroll again with the code.")
        }
        identities.setCertPem(clientId, issued.chainPem.first())
        policies.markIssued(request.id)
        audit?.record(
            "client_cert_issued",
            "Certificate issued to $clientId over its own key with policy ${request.policyName} (valid until ${issued.notAfter}; " +
                "${attestationNote(keyAttestation)}$integrityNote)",
            configApiId, clientId, actor = clientId, ip = remote,
            detail = buildJsonObject {
                put("serial", issued.serialHex)
                put("notAfter", issued.notAfter.toString())
                put("spkiSha256", issued.spkiSha256)
                put("policy", request.policyName)
                put("requestId", request.id)
                request.decidedBy?.let { put("approvedBy", it) }
                keyAttestation?.let { a ->
                    put("attested", a.attested)
                    a.reason?.let { put("attestationReason", it) }
                }
            }
        )
        respondIssuedClientCert(call, clientId, issued, extra = mapOf("policy" to JsonPrimitive(request.policyName)))
    }

    private suspend fun respondPending(call: ApplicationCall, request: EnrollmentRequest) {
        val body = buildJsonObject {
            put("status", "pending")
            put("requestId", request.id)
            put("clientId", request.clientId)
            put("policy", request.policyName)
            put("verificationCode", request.verificationCode)
            put("openApplication", request.openApplication)
            put("message", "Waiting for an administrator to approve this device. Ask again with the requestId.")
        }
        call.response.header(HttpHeaders.RetryAfter, RETRY_AFTER_SECONDS.toString())
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respondText(body.toString(), ContentType.Application.Json, HttpStatusCode.Accepted)
    }

    /** What a device asking without a token is told while code-less applications are off. */
    private suspend fun tokenRequired(call: ApplicationCall) =
        call.respondText(
            """{"error":"Token required for enrollment. Generate a token via management API (POST /api/v1/enrollment-tokens/generate). To allow deviceId-only enrollment (not recommended for production), set ENROLLMENT_MODE=open"}""",
            ContentType.Application.Json, HttpStatusCode.Forbidden
        )

    private suspend fun limitReached(call: ApplicationCall, policy: EnrollmentPolicy, remote: String) {
        refusals?.report(remote, "POST", call.request.path(), reason = "policy ${policy.name} is full (${policy.maxDevices} devices)")
        call.respondError(HttpStatusCode.Forbidden, "enrollment_limit_reached",
            "This enrollment code has reached its device limit. Ask an administrator.")
    }

    private suspend fun deviceAlreadyEnrolled(call: ApplicationCall, reason: String, remote: String) {
        refusals?.report(remote, "POST", call.request.path(), reason = reason)
        call.respondError(HttpStatusCode.Conflict, "device_already_enrolled",
            "This device is enrolled under another client id. Ask an administrator to revoke it, then retry with the same code.")
    }

    /** The CSR every policy call needs; answers 400 itself and returns null when it is missing or broken. */
    private suspend fun parseCsr(call: ApplicationCall, json: JsonObject?): CertificateService.ParsedCsr? =
        inspectCsr(call, json)?.let { verifyCsr(call, it) }

    /** The CSR's shape and key, no signature work ([CertificateService.inspectCsr]); null after answering 400. */
    private suspend fun inspectCsr(call: ApplicationCall, json: JsonObject?): CertificateService.CsrCandidate? {
        val features = call.request.header("X-PinVault-Features").orEmpty().split(',').map { it.trim() }
        val csrB64 = json.string("csr")
        if ("csr" !in features || csrB64 == null) {
            call.respondError(HttpStatusCode.BadRequest, "csr_required",
                "An enrollment code works only with a CSR over a key the device keeps.")
            return null
        }
        return try {
            certService.inspectCsr(csrB64)
        } catch (e: IllegalArgumentException) {
            invalidCsr(call, e)
        }
    }

    /** The proof that the caller holds the key; null after answering 400, or 403 for a retired key. */
    private suspend fun verifyCsr(call: ApplicationCall, candidate: CertificateService.CsrCandidate): CertificateService.ParsedCsr? {
        val csr = try {
            certService.verifyCsr(candidate)
        } catch (e: IllegalArgumentException) {
            return invalidCsr(call, e)
        }
        // A key retired with a forgotten identity never gets a certificate again.
        if (identities.isRetired(csr.spkiSha256)) {
            call.respondError(HttpStatusCode.Forbidden, "revoked", "This key was revoked. Enroll again with a new key.")
            return null
        }
        return csr
    }

    private suspend fun invalidCsr(call: ApplicationCall, cause: IllegalArgumentException): Nothing? {
        policyLog.warn("Policy enrollment with a broken CSR: {}", cause.message)
        call.respondError(HttpStatusCode.BadRequest, "invalid_csr", "The CSR is not a valid, self-signed PKCS#10 request.")
        return null
    }

    /** The attestation an identity is issued with ([issuingAttestation]); [record] null = not checked. */
    private class Issuing(val record: com.example.pinvault.server.store.KeyAttestation?)

    companion object {
        /** How long a waiting device is asked to wait before asking again. */
        const val RETRY_AFTER_SECONDS = 15

        /** The least time between two runs of the table-wide expiry ([expireLapsed]). */
        const val EXPIRY_INTERVAL_MS = 30_000L
    }
}

/** A device's name for itself, fit to show an administrator: letters, digits, a little punctuation, at most 64. */
internal fun displayAlias(raw: String?): String? =
    raw?.filter { it.isLetterOrDigit() || it in " ._:()+-'" }?.trim()?.take(64)?.ifBlank { null }

/**
 * A string field of a JSON body; JSON `null` counts as absent, and so does an
 * object or an array where a value was expected (`jsonPrimitive` would throw,
 * and a device endpoint would answer 500 to a body anyone can send).
 */
internal fun JsonObject?.string(name: String): String? =
    (this?.get(name) as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String, message: String) =
    respondText(buildJsonObject { put("error", error); put("message", message) }.toString(), ContentType.Application.Json, status)
