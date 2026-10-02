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
import java.util.Base64

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
    private val openLimiter: com.example.pinvault.server.service.RateLimiter? = null
) {

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
        policies.expirePending(pendingTtl)

        // The same key asking again — a retry, or an answer that got lost:
        // what was decided for it stands, it never takes a second slot.
        policies.findRequest(policy.id, csr.spkiSha256)?.let { return answer(call, it, csr) }

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
            if (policy.openApplications && openLimiter != null && !openLimiter.allow("apply|$remote")) {
                refusals?.report(remote, "POST", call.request.path(), reason = "too many code-less applications from this address")
                return call.respondError(HttpStatusCode.TooManyRequests, "too_many_applications",
                    "Too many applications from this address. Try again later.")
            }
            val recorded = policies.createRequest(policy, csr.spkiSha256, EnrollmentRequest.PENDING, configApiId,
                deviceAlias, deviceUid, remote, now)
            if (!recorded.created) return answer(call, recorded.request, csr)
            val request = recorded.request
            audit?.record(
                "enrollment_request_pending",
                "${deviceAlias ?: deviceUid ?: "A device"} asks to enroll as ${request.clientId} " +
                    (if (policy.openApplications) "without a code" else "with policy ${policy.name}") +
                    " (verification code ${request.verificationCode})" +
                    (holder?.let { "; this device is enrolled as $it" } ?: ""),
                configApiId, request.clientId, actor = request.clientId, ip = remote,
                detail = buildJsonObject {
                    put("policy", policy.name)
                    put("requestId", request.id)
                    deviceUid?.let { put("deviceUid", it) }
                    holder?.let { put("enrolledAs", it) }
                    put("spkiSha256", request.spkiSha256)
                }
            )
            return respondPending(call, request)
        }

        // No approval: take a slot, then issue.
        if (!policies.reserveSlot(policy.id)) {
            val current = policies.get(policy.id)
            if (current?.stoppedAt != null) {
                return call.respondText("""{"error":"Gecersiz token"}""", ContentType.Application.Json, HttpStatusCode.Unauthorized)
            }
            return limitReached(call, policy, remote)
        }
        val recorded = policies.createRequest(policy, csr.spkiSha256, EnrollmentRequest.APPROVED, configApiId,
            deviceAlias, deviceUid, remote, now)
        if (!recorded.created) {
            // The same key won a race with itself: one slot is enough.
            policies.releaseSlot(policy.id)
            return answer(call, recorded.request, csr)
        }
        issue(call, recorded.request, csr)
    }

    /** A device asks again, by the request id it was given, whether it was let in. */
    suspend fun pickup(call: ApplicationCall, requestId: String, json: JsonObject?) {
        val csr = parseCsr(call, json) ?: return
        policies.expirePending(pendingTtl)
        val request = policies.getRequest(requestId)
            ?: return call.respondError(HttpStatusCode.NotFound, "enrollment_request_not_found",
                "No such enrollment request. Enroll again with the code.")
        if (request.spkiSha256 != csr.spkiSha256) {
            refusals?.report(call.request.origin.remoteAddress, "POST", call.request.path(), actor = request.clientId,
                reason = "request ${request.id} picked up with another key")
            return call.respondError(HttpStatusCode.Forbidden, "enrollment_request_mismatch",
                "This request was made with another key.")
        }
        answer(call, request, csr)
    }

    /** Answers by what was decided for [request]. */
    private suspend fun answer(call: ApplicationCall, request: EnrollmentRequest, csr: CertificateService.ParsedCsr) {
        when (request.status) {
            EnrollmentRequest.PENDING -> respondPending(call, request)
            EnrollmentRequest.REJECTED -> call.respondError(HttpStatusCode.Forbidden, "enrollment_rejected",
                "An administrator turned this device away.")
            EnrollmentRequest.EXPIRED -> call.respondError(HttpStatusCode.Gone, "enrollment_request_expired",
                "Nobody decided on this request in time. Ask again.")
            EnrollmentRequest.APPROVED, EnrollmentRequest.ISSUED -> issue(call, request, csr)
            else -> call.respondError(HttpStatusCode.Conflict, "enrollment_request_unknown_state", request.status)
        }
    }

    /** Issues the certificate of an approved (or already issued) request over the CSR's key. */
    private suspend fun issue(call: ApplicationCall, request: EnrollmentRequest, csr: CertificateService.ParsedCsr) {
        val remote = call.request.origin.remoteAddress
        val clientId = request.clientId
        // client_certs.add below would un-revoke a revoked id: a revoked one stays revoked.
        if (clientCerts.get(clientId)?.revoked == true || identities.get(clientId)?.revoked == true) {
            return call.respondError(HttpStatusCode.Forbidden, "revoked", "This client id was revoked. Enroll again with the code.")
        }
        // Checked again here: the device may have enrolled under another id since it asked.
        val holder = request.deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = clientId) }
        if (holder != null) {
            return deviceAlreadyEnrolled(call, "device ${request.deviceUid} is enrolled as $holder (policy ${request.policyName})", remote)
        }

        val issued = certService.issueClientCertificate(clientId, csr, ttlFor(clientId))
        val now = Instant.now().toString()
        val registered = identities.register(
            clientId, configApiId, issued.spkiSha256, issued.serialHex,
            issued.notBefore.toString(), issued.notAfter.toString(), request.deviceAlias, request.deviceUid, now
        )
        if (!registered) {
            return call.respondError(HttpStatusCode.Forbidden, "revoked", "This client id was revoked. Enroll again with the code.")
        }
        clientCerts.add(clientId, issued.commonName, issued.fingerprint, now,
            deviceAlias = request.deviceAlias, deviceUid = request.deviceUid)
        policies.markIssued(request.id)
        audit?.record(
            "client_cert_issued",
            "Certificate issued to $clientId over its own key with policy ${request.policyName} (valid until ${issued.notAfter})",
            configApiId, clientId, actor = clientId, ip = remote,
            detail = buildJsonObject {
                put("serial", issued.serialHex)
                put("notAfter", issued.notAfter.toString())
                put("spkiSha256", issued.spkiSha256)
                put("policy", request.policyName)
                put("requestId", request.id)
                request.decidedBy?.let { put("approvedBy", it) }
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
    private suspend fun parseCsr(call: ApplicationCall, json: JsonObject?): CertificateService.ParsedCsr? {
        val features = call.request.header("X-PinVault-Features").orEmpty().split(',').map { it.trim() }
        val csrB64 = json.string("csr")
        if ("csr" !in features || csrB64 == null) {
            call.respondError(HttpStatusCode.BadRequest, "csr_required",
                "An enrollment code works only with a CSR over a key the device keeps.")
            return null
        }
        val csr = try {
            certService.parseCsr(Base64.getDecoder().decode(csrB64))
        } catch (e: IllegalArgumentException) {
            policyLog.warn("Policy enrollment with a broken CSR: {}", e.message)
            call.respondError(HttpStatusCode.BadRequest, "invalid_csr", "The CSR is not a valid, self-signed PKCS#10 request.")
            return null
        }
        // A key retired with a forgotten identity never gets a certificate again.
        if (identities.isRetired(csr.spkiSha256)) {
            call.respondError(HttpStatusCode.Forbidden, "revoked", "This key was revoked. Enroll again with a new key.")
            return null
        }
        return csr
    }

    companion object {
        /** How long a waiting device is asked to wait before asking again. */
        const val RETRY_AFTER_SECONDS = 15
    }
}

/** A device's name for itself, fit to show an administrator: letters, digits, a little punctuation, at most 64. */
internal fun displayAlias(raw: String?): String? =
    raw?.filter { it.isLetterOrDigit() || it in " ._:()+-'" }?.trim()?.take(64)?.ifBlank { null }

/** A string field of a JSON body; JSON `null` counts as absent. */
private fun JsonObject?.string(name: String): String? =
    (this?.get(name) as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String, message: String) =
    respondText(buildJsonObject { put("error", error); put("message", message) }.toString(), ContentType.Application.Json, status)
