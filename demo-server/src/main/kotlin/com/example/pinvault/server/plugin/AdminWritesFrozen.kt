package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

class AdminWritesFrozenConfig {
    /** `ADMIN_WRITES_FROZEN=true`. Read once at start; the operator restarts the server to change it. */
    var frozen: Boolean = false
}

/**
 * `ADMIN_WRITES_FROZEN=true`: every admin change is refused (`423
 * admin_writes_frozen`); admin reads and everything devices do — config
 * fetches, enrollment, renewal, attestation, vault downloads, reports — go on.
 *
 * For a server whose subscription or licence lapsed (suspend it this way,
 * never by stopping it: devices must keep the pins they rely on), and for
 * maintenance. What only takes trust away still goes through
 * ([isTrustReducing]): revoking, stopping a code, closing code-less
 * applications, rejecting a waiting device. A request counts as an
 * admin change when an admin key authenticated it ([AdminPrincipalKey], set by
 * [ApiKeyAuth]) and its method writes; device routes carry no admin principal,
 * so they are never touched. Install AFTER [ApiKeyAuth] and BEFORE the
 * approval gate, so a frozen change is not even queued for approval.
 */
val AdminWritesFrozen = createApplicationPlugin("AdminWritesFrozen", ::AdminWritesFrozenConfig) {
    if (!pluginConfig.frozen) return@createApplicationPlugin
    onCall { call ->
        if (call.response.isCommitted) return@onCall
        if (call.attributes.getOrNull(AdminPrincipalKey) == null) return@onCall
        val method = call.request.httpMethod
        if (method == HttpMethod.Get || method == HttpMethod.Head || method == HttpMethod.Options) return@onCall
        // Taking trust AWAY stays possible: a server frozen because its licence
        // lapsed is frozen by someone other than its operator, and a stolen
        // device must still be revoked. Matched on the path as routing resolves it.
        if (isTrustReducing(method, com.example.pinvault.server.service.PinAffectingRoutes.canonicalPath(call.request.path()))) return@onCall
        call.respondText(
            """{"error":"admin_writes_frozen","message":"Changes are frozen on this server (ADMIN_WRITES_FROZEN). Devices are served as before; admin reads still work."}""",
            ContentType.Application.Json, HttpStatusCode.Locked
        )
    }
}

/**
 * Admin changes that only take trust away, allowed while writes are frozen:
 * revoking a client identity, stopping an enrollment code, turning code-less
 * applications off, rejecting a device that asked to enroll. The same
 * operations the approval gate lets through at once as emergencies.
 *
 * NOT here, on purpose: "forget" (it lets the identity's id enroll again),
 * rotating or deleting a token key and restoring pins (each can add trust or
 * break devices).
 */
internal fun isTrustReducing(method: HttpMethod, canonicalPath: String): Boolean =
    TRUST_REDUCING.any { (m, pattern) -> m == method && pattern.matches(canonicalPath) }

private val TRUST_REDUCING = listOf(
    HttpMethod.Delete to Regex("^/api/v1/client-certs/[^/]+$"),
    HttpMethod.Post to Regex("^/api/v1/enrollment-policies/[^/]+/stop$"),
    HttpMethod.Delete to Regex("^/api/v1/enrollment-open$"),
    HttpMethod.Post to Regex("^/api/v1/enrollment-requests/[^/]+/reject$")
)

/** `ADMIN_WRITES_FROZEN`: true or false (unset = false), in any case; anything else stops the start. */
fun adminWritesFrozenFromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): Boolean {
    val raw = env["ADMIN_WRITES_FROZEN"]?.trim().orEmpty()
    return when (raw.lowercase()) {
        "", "false" -> false
        "true" -> true
        else -> error("ADMIN_WRITES_FROZEN must be true or false (got '$raw')")
    }
}
