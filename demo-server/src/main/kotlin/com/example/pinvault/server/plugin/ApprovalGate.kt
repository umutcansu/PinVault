package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.PinAffectingRoutes
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*

class ApprovalGateConfig {
    var approvals: ApprovalService? = null

    /**
     * False on the Config API listeners: with approvals on, pin changes are
     * accepted only through the management API, where they can wait for a
     * second admin. The device-facing ports then refuse them outright.
     */
    var managementListener: Boolean = true
}

/**
 * Holds pin- and key-affecting admin requests for a second admin's approval
 * (`PIN_CHANGE_APPROVALS` >= 2; does nothing otherwise). Install it AFTER
 * [ApiKeyAuth] and [AdminAudit].
 *
 * The request is stored — method, path, query, body — and answered with
 * `202 {"pendingApproval":true,"changeRequestId":…}`; it runs only when
 * [ApprovalService.approve] replays it. The replay carries a one-time token
 * that [ApiKeyAuth] turns into [ApprovedReplayKey], which lets it through here.
 */
val ApprovalGate = createApplicationPlugin("ApprovalGate", ::ApprovalGateConfig) {
    val approvals = pluginConfig.approvals ?: return@createApplicationPlugin
    if (!approvals.enabled) return@createApplicationPlugin
    val management = pluginConfig.managementListener

    onCall { call ->
        if (call.response.isCommitted) return@onCall
        val method = call.request.httpMethod
        val rawPath = call.request.path()
        // Match on the path as ROUTING sees it — empty segments dropped,
        // percent-escapes decoded — not on the raw spelling. Matching the raw
        // path let `PUT /api//v1/certificate-config` or `…/certificate%2Dconfig`
        // reach the handler while slipping past the gate.
        val path = PinAffectingRoutes.canonicalPath(rawPath)
        val op = PinAffectingRoutes.match(method, path) ?: return@onCall
        // Unauthenticated calls never get here with a principal: ApiKeyAuth
        // already answered them.
        val principal = call.attributes.getOrNull(AdminPrincipalKey) ?: return@onCall

        if (!management) {
            call.respond(
                HttpStatusCode.Conflict,
                mapOf("error" to "Pin changes need approval (PIN_CHANGE_APPROVALS) and are accepted only through the management API.")
            )
            return@onCall
        }
        if (call.attributes.contains(ApprovedReplayKey)) return@onCall

        // A shared key names nobody: a change requested with it could be
        // approved by anyone who also holds a personal key — including the
        // person who made it.
        if (principal.name == AdminRegistry.LEGACY_NAME || principal.name == "anonymous") {
            call.respond(
                HttpStatusCode.Conflict,
                mapOf("error" to "With PIN_CHANGE_APPROVALS on, pin and key changes need a personal admin key (ADMIN_KEYS); the shared API_KEY cannot request them.")
            )
            return@onCall
        }

        // The approver judges a description built from the body as UTF-8
        // JSON; a body in another charset would be read differently by the
        // handler than by the description.
        val contentType = call.request.header(HttpHeaders.ContentType).orEmpty()
        val charset = call.request.contentCharset()
        if (contentType.startsWith("application/json") && charset != null && charset != Charsets.UTF_8) {
            call.respond(HttpStatusCode.UnsupportedMediaType, mapOf("error" to "Changes that need approval must be UTF-8 JSON"))
            return@onCall
        }

        val body = call.receive<ByteArray>()
        try {
            val pending = approvals.submit(
                requestedBy = principal.name,
                op = op,
                method = method.value,
                // Replayed exactly as sent, so it reaches the same handler; the
                // description is built from the canonical path.
                path = rawPath,
                canonicalPath = path,
                query = call.request.queryString(),
                contentType = contentType,
                body = body
            )
            call.respond(HttpStatusCode.Accepted, pending)
        } catch (e: ApprovalService.Refused) {
            call.respond(e.status, mapOf("error" to (e.message ?: "refused")))
        }
    }
}
