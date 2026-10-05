package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.PinAffectingRoutes
import com.example.pinvault.server.service.AuditContext
import com.example.pinvault.server.service.CertPlan
import com.example.pinvault.server.store.ChangeRequest
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.application.hooks.ResponseSent
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ApprovalGateConfig {
    var approvals: ApprovalService? = null

    /**
     * False on the Config API listeners: with approvals on, pin changes are
     * accepted only through the management API, where they can wait for a
     * second admin. The device-facing ports then refuse them outright.
     */
    var managementListener: Boolean = true

    /**
     * The largest body a gated request of an operation may carry. It is read
     * into memory and stored with the change request, so it is capped while
     * reading: 413 beyond it. Vault uploads get `VAULT_MAX_FILE_BYTES`.
     */
    var maxBodyBytes: (operation: String) -> Long = { DEFAULT_ADMIN_BODY_MAX_BYTES }
}

/** The plan stored with the approved change this call replays (a [CertPlan]); see [approvedCertPlan]. */
val ApprovedPlanKey = AttributeKey<ByteArray>("PinVaultApprovedPlan")

/** The body the gate already read, handed to the handler again when the request runs after all. */
private val GateBodyKey = AttributeKey<ByteArray>("PinVaultGateBody")

/** The approved request this call spends (the requester running it; see [ApprovalService.claim]). */
private val ApprovedRunKey = AttributeKey<ChangeRequest>("PinVaultApprovedRun")

/** An approved change is being replayed, but no plan was stored with it: never applied from a fresh fetch. */
class MissingApprovedPlan(id: Long) : IllegalStateException(
    "Change request #$id was approved without a stored certificate plan; it cannot be applied. Request the change again."
)

/**
 * The certificate plan the approver of this call was shown, or null when the
 * call is not the replay of an approved change (approvals off, or an exempt
 * operation): the handler then works the plan out itself and applies it at once.
 *
 * A replay WITHOUT a stored plan is refused ([MissingApprovedPlan]): fetching
 * or generating again at approval time is exactly what the plan exists to
 * prevent.
 */
fun ApplicationCall.approvedCertPlan(): CertPlan? {
    val replayed = attributes.getOrNull(ApprovedReplayKey) ?: return null
    val stored = attributes.getOrNull(ApprovedPlanKey) ?: throw MissingApprovedPlan(replayed)
    return CertPlan.decode(stored)
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
 *
 * Operations whose answer carries a secret ([PinAffectingRoutes.requesterRun])
 * are not replayed: once approved, the requester sends the same request again
 * and it passes here once, the body the gate read handed on to the handler.
 */
val ApprovalGate = createApplicationPlugin("ApprovalGate", ::ApprovalGateConfig) {
    val approvals = pluginConfig.approvals ?: return@createApplicationPlugin
    if (!approvals.enabled) return@createApplicationPlugin
    val management = pluginConfig.managementListener

    val maxBodyBytes = pluginConfig.maxBodyBytes

    // A request the gate lets through after reading its body: the handler
    // receives that body. (A second receive carries no channel, only Ktor's
    // "already consumed" marker; this puts the bytes back in its place.)
    application.receivePipeline.intercept(ApplicationReceivePipeline.Before) {
        val body = call.attributes.getOrNull(GateBodyKey) ?: return@intercept
        proceedWith(ByteReadChannel(body))
    }

    on(ResponseSent) { call ->
        val run = call.attributes.getOrNull(ApprovedRunKey) ?: return@on
        approvals.finishRun(run, call.response.status()?.value ?: 0)
    }

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
        // Taken out of the two-person rule by the operator (APPROVAL_EXEMPT_OPERATIONS).
        if (op in approvals.exempt) return@onCall
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
        call.attributes.getOrNull(ApprovedReplayKey)?.let { replayed ->
            // What the approver was shown, for the handler to apply as it is.
            approvals.prepared(replayed)?.let { call.attributes.put(ApprovedPlanKey, it) }
            return@onCall
        }

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

        // Kept in memory and stored with the request: capped while it is read (413).
        val body = call.receiveLimitedBytes(maxBodyBytes(op)) ?: return@onCall

        // Approved earlier and now sent again by its requester: runs once.
        if (op in PinAffectingRoutes.requesterRun) {
            val approved = approvals.claim(principal.name, method.value, path, call.request.queryString(), body)
            if (approved != null) {
                call.attributes.put(GateBodyKey, body)
                call.attributes.put(ApprovedRunKey, approved)
                // What the handler audits names both people, as a replayed change does.
                AuditContext.scope()?.actor = "${approved.requestedBy} (approved by ${approved.approvedBy.joinToString(", ")})"
                return@onCall
            }
        }
        try {
            // Describing a change may probe a host or fetch its certificate: off the event loop.
            val pending = withContext(Dispatchers.IO) {
                approvals.submit(
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
            }
            call.respond(HttpStatusCode.Accepted, pending)
        } catch (e: ApprovalService.Refused) {
            val answer = e.body
            if (answer != null) call.respondText(answer.toString(), ContentType.Application.Json, e.status)
            else call.respond(e.status, mapOf("error" to (e.message ?: "refused")))
        }
    }
}
