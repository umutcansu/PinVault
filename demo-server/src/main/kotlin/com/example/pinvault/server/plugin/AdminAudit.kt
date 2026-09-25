package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.AuditContext
import com.example.pinvault.server.service.AuditLog
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.application.hooks.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.util.*
import kotlinx.coroutines.withContext

class AdminAuditConfig {
    var audit: AuditLog? = null

    /**
     * Called at the START of every authenticated admin write, before its
     * handler runs (the signature cache drops what it holds, so nothing
     * signed before the change is served after it).
     */
    var onAdminWrite: (() -> Unit)? = null
}

private val AuditScopeKey = AttributeKey<AuditContext.Scope>("PinVaultAuditScope")

/**
 * Admin POSTs that change nothing (a dry run): neither logged as a write nor
 * allowed to drop the signature cache.
 */
private val READ_ONLY_POSTS = setOf("/api/v1/pins/live-check")

private fun isWrite(method: HttpMethod, path: String): Boolean =
    method != HttpMethod.Get && method != HttpMethod.Head && method != HttpMethod.Options && path !in READ_ONLY_POSTS

/**
 * Records every successful admin write in the audit log, attributed to the
 * admin [ApiKeyAuth] identified. Install it AFTER [ApiKeyAuth].
 *
 * Calls that already produced a specific entry — a pin diff, an approval, a
 * key change — are not logged a second time as a bare `http` entry.
 */
val AdminAudit = createApplicationPlugin("AdminAudit", ::AdminAuditConfig) {
    val audit = pluginConfig.audit ?: return@createApplicationPlugin
    val onAdminWrite = pluginConfig.onAdminWrite

    // Make the admin known to code deep inside the call (the pin store's save
    // listener) by running the rest of the pipeline in an AuditContext.
    application.intercept(ApplicationCallPipeline.Plugins) {
        val principal = call.attributes.getOrNull(AdminPrincipalKey)
        if (principal == null || call.response.isCommitted) {
            proceed()
            return@intercept
        }
        if (isWrite(call.request.httpMethod, call.request.path())) {
            onAdminWrite?.invoke()
        }
        // remoteAddress: no reverse-DNS lookup on the event loop, no caller-chosen name.
        // An approved change is replayed over loopback; its entries carry the
        // approver's address instead of 127.0.0.1.
        val ip = call.attributes.getOrNull(ApprovedReplayIpKey) ?: call.request.origin.remoteAddress
        val scope = AuditContext.Scope(principal.name, ip)
        call.attributes.put(AuditScopeKey, scope)
        withContext(AuditContext.element(scope)) { proceed() }
    }

    on(ResponseSent) { call ->
        val scope = call.attributes.getOrNull(AuditScopeKey) ?: return@on
        val method = call.request.httpMethod
        if (!isWrite(method, call.request.path())) return@on
        val status = call.response.status()?.value ?: return@on
        if (status !in 200..299 || scope.recorded) return@on
        val query = call.request.queryString().takeIf { it.isNotEmpty() }?.let { "?$it" } ?: ""
        audit.record(
            action = AuditLog.HTTP_ACTION,
            summary = "HTTP $status",
            configApiId = call.request.queryParameters["configApiId"] ?: "",
            target = "${method.value} ${call.request.path()}$query",
            actor = scope.actor,
            ip = scope.ip
        )
    }
}
