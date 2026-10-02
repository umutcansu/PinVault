package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.adminName
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.EnrollmentPolicy
import com.example.pinvault.server.store.EnrollmentPolicyStore
import com.example.pinvault.server.store.EnrollmentRequest
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.time.Duration

/** `POST /api/v1/enrollment-policies`: the new policy and its code, shown this once. */
@Serializable
data class CreatedEnrollmentPolicy(val policy: EnrollmentPolicy, val code: String)

@Serializable
data class EnrollmentDecision(val id: String, val status: String, val clientId: String)

/** `GET`/`PUT /api/v1/enrollment-open`: the code-less applications switch and its limits. */
@Serializable
data class OpenApplicationsStatus(
    val enabled: Boolean,
    /** The policy collecting them; null until they were turned on once. */
    val policy: EnrollmentPolicy? = null,
    val maxPending: Int,
    val requestTtlHours: Long,
    /** New applications one source address may make per 10 minutes; 0 = no limit. */
    val rateLimitPer10Minutes: Int
)

/** Longest policy name: it prefixes client ids (`<name>-<6 chars>`, 64 at most). */
private const val MAX_POLICY_NAME = 40

/**
 * Management endpoints of enrollment policies (admin key required): create a
 * code, list and stop codes, and let waiting devices in or turn them away.
 * The device side is [PolicyEnrollment].
 */
fun Route.enrollmentPolicyRoutes(
    policies: EnrollmentPolicyStore,
    clientCerts: ClientCertStore,
    audit: AuditLog,
    /** How long a request waits for a decision (ENROLLMENT_REQUEST_TTL_HOURS). */
    pendingTtl: Duration = Duration.ofHours(24),
    /** Shown with the code-less switch: OPEN_ENROLLMENT_MAX_PENDING and _RATE_LIMIT. */
    openMaxPending: Int = 50,
    openRateLimit: Int = 20
) {
    get("/api/v1/enrollment-policies") {
        call.respond(policies.getAll())
    }

    fun openStatus(): OpenApplicationsStatus {
        val policy = policies.openPolicy()
        return OpenApplicationsStatus(
            enabled = policy?.acceptsNewDevices() == true,
            policy = policy,
            maxPending = openMaxPending,
            requestTtlHours = pendingTtl.toHours(),
            rateLimitPer10Minutes = openRateLimit
        )
    }

    // Code-less applications: devices ask without a token, each waits for approval.
    get("/api/v1/enrollment-open") {
        call.respond(openStatus())
    }

    put("/api/v1/enrollment-open") {
        val json = call.jsonBody() ?: return@put call.policyError(HttpStatusCode.BadRequest, "invalid_body", "A JSON body is required.")
        val enabled = (json["enabled"] as? JsonPrimitive)?.booleanOrNull
            ?: return@put call.policyError(HttpStatusCode.BadRequest, "invalid_enabled", "enabled: true or false.")
        val before = openStatus().enabled
        policies.openApplications(enabled, call.adminName())
        if (before != enabled) {
            audit.record(
                "enrollment_open_changed",
                if (enabled) "Code-less applications turned on: devices may ask without a code, each waits for approval"
                else "Code-less applications turned off: devices already waiting can still be decided",
                target = EnrollmentPolicyStore.OPEN_NAME,
                detail = buildJsonObject { put("enabled", enabled) }
            )
        }
        call.respond(openStatus())
    }

    post("/api/v1/enrollment-policies") {
        val json = call.jsonBody() ?: return@post call.policyError(HttpStatusCode.BadRequest, "invalid_body", "A JSON body is required.")
        val name = (json["name"] as? JsonPrimitive)?.content?.trim()
        val maxDevices = (json["maxDevices"] as? JsonPrimitive)?.intOrNull
        val validDays = (json["validDays"] as? JsonPrimitive)?.intOrNull
        // Approval unless turned off explicitly: a leaked code then only lets strangers ask.
        val requireApproval = (json["requireApproval"] as? JsonPrimitive)?.booleanOrNull ?: true
        if (name == null || name.length > MAX_POLICY_NAME || !isValidIdentifier(name)) {
            return@post call.policyError(HttpStatusCode.BadRequest, "invalid_name",
                "Letters, digits, '.', '_', ':' and '-' only, at most $MAX_POLICY_NAME.")
        }
        if (maxDevices == null || maxDevices !in 1..10_000) {
            return@post call.policyError(HttpStatusCode.BadRequest, "invalid_max_devices", "maxDevices must be 1..10000.")
        }
        if (validDays == null || validDays !in 1..365) {
            return@post call.policyError(HttpStatusCode.BadRequest, "invalid_valid_days", "validDays must be 1..365.")
        }
        val created = policies.create(name, maxDevices, Duration.ofDays(validDays.toLong()), requireApproval, call.adminName())
        val policy = created.policy
        audit.record(
            "enrollment_policy_created",
            "Enrollment code $name: up to $maxDevices device(s) until ${policy.expiresAt}" +
                if (requireApproval) ", each approved by an administrator" else ", no approval",
            target = name,
            detail = buildJsonObject {
                put("policyId", policy.id)
                put("codePrefix", policy.codePrefix)
                put("maxDevices", maxDevices)
                put("expiresAt", policy.expiresAt)
                put("requireApproval", requireApproval)
            }
        )
        // The code exists in plain text only in this answer.
        call.response.header(HttpHeaders.CacheControl, "no-store")
        call.respond(CreatedEnrollmentPolicy(policy, created.code))
    }

    post("/api/v1/enrollment-policies/{id}/stop") {
        val id = call.parameters["id"].orEmpty()
        val policy = policies.get(id)
            ?: return@post call.policyError(HttpStatusCode.NotFound, "policy_not_found", "No such enrollment policy.")
        if (!policies.stop(id, call.adminName())) {
            return@post call.policyError(HttpStatusCode.Conflict, "policy_stopped", "This enrollment code is already stopped.")
        }
        audit.record(
            "enrollment_policy_stopped",
            "Enrollment code ${policy.name} stopped: no new devices; devices still waiting were turned away",
            target = policy.name,
            detail = buildJsonObject { put("policyId", policy.id) }
        )
        call.respond(policies.get(id)!!)
    }

    get("/api/v1/enrollment-requests") {
        policies.expirePending(pendingTtl)
        val status = call.request.queryParameters["status"]
            ?.takeIf { it in setOf(EnrollmentRequest.PENDING, EnrollmentRequest.APPROVED, EnrollmentRequest.REJECTED, EnrollmentRequest.ISSUED, EnrollmentRequest.EXPIRED) }
        // The same device (by device id) asking more than once — say, reinstalled
        // before anyone decided — is flagged on each of its waiting requests.
        val waitingPerDevice = policies.requests(EnrollmentRequest.PENDING, limit = 1000)
            .mapNotNull { it.deviceUid }.groupingBy { it }.eachCount()
        val requests = policies.requests(status).map { request ->
            // A device that already has another active identity: approving it
            // needs that one revoked first (one active identity per device).
            val open = request.status == EnrollmentRequest.PENDING || request.status == EnrollmentRequest.APPROVED
            val sameDevice = request.deviceUid?.let { (waitingPerDevice[it] ?: 0) - (if (request.status == EnrollmentRequest.PENDING) 1 else 0) } ?: 0
            request.copy(
                heldBy = if (open) request.deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = request.clientId) } else null,
                sameDevicePending = if (open) sameDevice else 0
            )
        }
        call.respond(requests)
    }

    post("/api/v1/enrollment-requests/{id}/approve") {
        val id = call.parameters["id"].orEmpty()
        val request = policies.getRequest(id)
            ?: return@post call.policyError(HttpStatusCode.NotFound, "request_not_found", "No such enrollment request.")
        val holder = request.deviceUid?.let { clientCerts.activeHolderOf(it, exceptId = request.clientId) }
        if (request.status == EnrollmentRequest.PENDING && holder != null) {
            return@post call.respondText(
                buildJsonObject {
                    put("error", "device_already_enrolled")
                    put("heldBy", holder)
                    put("message", "This device is enrolled as $holder. Revoke that one first, then approve.")
                }.toString(),
                ContentType.Application.Json, HttpStatusCode.Conflict
            )
        }
        when (policies.approve(id, call.adminName())) {
            EnrollmentPolicyStore.Approval.APPROVED -> {
                audit.record(
                    "enrollment_request_approved",
                    "${request.deviceAlias ?: request.deviceUid ?: "Device"} may enroll as ${request.clientId} (code ${request.policyName})",
                    request.configApiId, request.clientId,
                    detail = buildJsonObject {
                        put("requestId", request.id)
                        put("policy", request.policyName)
                        request.deviceUid?.let { put("deviceUid", it) }
                        put("sourceIp", request.sourceIp)
                    }
                )
                call.respond(EnrollmentDecision(id, EnrollmentRequest.APPROVED, request.clientId))
            }
            EnrollmentPolicyStore.Approval.NOT_FOUND ->
                call.policyError(HttpStatusCode.NotFound, "request_not_found", "No such enrollment request.")
            EnrollmentPolicyStore.Approval.NOT_PENDING ->
                call.policyError(HttpStatusCode.Conflict, "not_pending", "This request was already decided (${policies.getRequest(id)?.status}).")
            EnrollmentPolicyStore.Approval.POLICY_STOPPED ->
                call.policyError(HttpStatusCode.Conflict, "policy_stopped", "This enrollment code was stopped.")
            EnrollmentPolicyStore.Approval.LIMIT_REACHED ->
                call.policyError(HttpStatusCode.Conflict, "enrollment_limit_reached", "This enrollment code has no device left.")
        }
    }

    post("/api/v1/enrollment-requests/{id}/reject") {
        val id = call.parameters["id"].orEmpty()
        val request = policies.getRequest(id)
            ?: return@post call.policyError(HttpStatusCode.NotFound, "request_not_found", "No such enrollment request.")
        if (!policies.reject(id, call.adminName())) {
            return@post call.policyError(HttpStatusCode.Conflict, "not_pending", "This request was already decided (${request.status}).")
        }
        audit.record(
            "enrollment_request_rejected",
            "${request.deviceAlias ?: request.deviceUid ?: "Device"} turned away: no certificate for ${request.clientId} (code ${request.policyName})",
            request.configApiId, request.clientId,
            detail = buildJsonObject {
                put("requestId", request.id)
                put("policy", request.policyName)
                put("sourceIp", request.sourceIp)
            }
        )
        call.respond(EnrollmentDecision(id, EnrollmentRequest.REJECTED, request.clientId))
    }
}

private suspend fun ApplicationCall.jsonBody(): JsonObject? =
    try { Json.parseToJsonElement(receiveText()).jsonObject } catch (_: Exception) { null }

private suspend fun ApplicationCall.policyError(status: HttpStatusCode, error: String, message: String) =
    respondText(buildJsonObject { put("error", error); put("message", message) }.toString(), ContentType.Application.Json, status)
