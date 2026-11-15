package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
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
 * For a hosted server whose subscription lapsed (PinVault Cloud suspends a
 * tenant this way, never by stopping it: devices must keep the pins they rely
 * on), and for a self-hosted server during maintenance. A request counts as an
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
        call.respondText(
            """{"error":"admin_writes_frozen","message":"Changes are frozen on this server (ADMIN_WRITES_FROZEN). Devices are served as before; admin reads still work."}""",
            ContentType.Application.Json, HttpStatusCode.Locked
        )
    }
}

/** `ADMIN_WRITES_FROZEN`: true or false (unset = false), in any case; anything else stops the start. */
fun adminWritesFrozenFromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): Boolean {
    val raw = env["ADMIN_WRITES_FROZEN"]?.trim().orEmpty()
    return when (raw.lowercase()) {
        "", "false" -> false
        "true" -> true
        else -> error("ADMIN_WRITES_FROZEN must be true or false (got '$raw')")
    }
}
