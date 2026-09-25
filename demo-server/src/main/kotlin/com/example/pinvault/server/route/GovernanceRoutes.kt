package com.example.pinvault.server.route

import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.plugin.AdminRegistry
import com.example.pinvault.server.plugin.adminName
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.WebhookNotifier
import com.example.pinvault.server.store.AuditEntry
import com.example.pinvault.server.store.AuditLogStore
import io.ktor.http.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable
data class AdminMe(
    val name: String,
    val admins: List<String>,
    val approvalsRequired: Int,
    val liveCheck: String,
    val liveCheckOverridable: Boolean,
    val notificationsConfigured: Boolean,
    val signatureCache: Boolean
)

@Serializable
data class AuditPage(val total: Int, val entries: List<AuditEntry>)

/**
 * `POST /api/v1/notifications/test`. A typed body: `mapOf("sent" to true,
 * "auditId" to id)` mixes Boolean and Long, which kotlinx.serialization
 * refuses — the endpoint answered 500 after queueing the notification.
 */
@Serializable
data class NotificationTestResult(val sent: Boolean, val auditId: Long)

/**
 * Management-only governance endpoints: who am I, the audit log, change
 * requests awaiting approval, webhook status, and the live-check dry run.
 */
fun Route.governanceRoutes(
    registry: AdminRegistry,
    audit: AuditLog,
    auditStore: AuditLogStore,
    approvals: ApprovalService,
    liveGate: LiveCertificateGate,
    envelopes: SignedConfigService
) {
    get("/api/v1/admin/me") {
        call.respond(
            AdminMe(
                name = call.adminName(),
                admins = registry.names,
                approvalsRequired = approvals.required,
                liveCheck = liveGate.mode.name.lowercase(),
                liveCheckOverridable = liveGate.allowOverride,
                notificationsConfigured = audit.notifier != null,
                signatureCache = envelopes.cacheEnabled
            )
        )
    }

    // ── Audit log ───────────────────────────────────────────────────────

    get("/api/v1/audit-log") {
        val limit = call.request.queryParameters["limit"]?.toIntOrNull()?.coerceIn(1, 500) ?: 50
        val offset = call.request.queryParameters["offset"]?.toIntOrNull()?.coerceAtLeast(0) ?: 0
        val action = call.request.queryParameters["action"]
        val scope = call.request.queryParameters["configApiId"]
        call.respond(AuditPage(auditStore.count(action, scope), auditStore.page(limit, offset, action, scope)))
    }

    get("/api/v1/audit-log/verify") {
        call.respond(auditStore.verify())
    }

    // ── Change requests (PIN_CHANGE_APPROVALS >= 2) ─────────────────────

    get("/api/v1/change-requests") {
        val status = call.request.queryParameters["status"]?.takeIf { it.isNotBlank() && it != "all" }
        call.respond(approvals.list(status))
    }

    get("/api/v1/change-requests/{id}") {
        val id = call.parameters["id"]?.toLongOrNull()
            ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "id must be a number"))
        val cr = approvals.get(id)
            ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "Change request #$id not found"))
        call.respond(cr)
    }

    post("/api/v1/change-requests/{id}/approve") {
        val id = call.parameters["id"]?.toLongOrNull()
            ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "id must be a number"))
        val approver = call.adminName()
        try {
            // The approval replays the stored request through this server's
            // own management port — blocking I/O, so off the call thread.
            val approverIp = call.request.origin.remoteAddress
            val cr = withContext(Dispatchers.IO) { approvals.approve(id, approver, approverIp) }
            call.respond(cr)
        } catch (e: ApprovalService.Refused) {
            // A refused approval (own request, shared key, stale, expired) is
            // worth knowing about: record who tried — under the request's
            // Config API and target like every other change_* entry, so a
            // per-scope view of the log (`?configApiId=`) shows it too.
            val cr = runCatching { approvals.get(id) }.getOrNull()
            audit.record(
                "change_approval_refused", "#$id: ${e.message}",
                configApiId = cr?.configApiId ?: "",
                target = cr?.let { "${it.method} ${it.path}" } ?: "",
                actor = approver
            )
            call.respond(e.status, mapOf("error" to (e.message ?: "refused")))
        }
    }

    post("/api/v1/change-requests/{id}/reject") {
        val id = call.parameters["id"]?.toLongOrNull()
            ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "id must be a number"))
        val reason = runCatching {
            Json.parseToJsonElement(call.receiveText()).jsonObject["reason"]?.jsonPrimitive?.content
        }.getOrNull()
        try {
            call.respond(approvals.reject(id, call.adminName(), reason?.take(500)))
        } catch (e: ApprovalService.Refused) {
            call.respond(e.status, mapOf("error" to (e.message ?: "refused")))
        }
    }

    // ── Notifications ───────────────────────────────────────────────────

    get("/api/v1/notifications") {
        val notifier = audit.notifier
            ?: return@get call.respond(
                WebhookNotifier.Status(configured = false, target = null, signed = false, events = emptyList(), recent = emptyList())
            )
        call.respond(notifier.status())
    }

    post("/api/v1/notifications/test") {
        if (audit.notifier == null) {
            return@post call.respond(HttpStatusCode.Conflict, mapOf("error" to "NOTIFY_WEBHOOK_URL is not set"))
        }
        val entry = audit.record("notification_test", "Test notification requested from the dashboard", notify = true)
        call.respond(NotificationTestResult(sent = true, auditId = entry.id))
    }

    // ── Live certificate check, dry run ─────────────────────────────────

    // Body: {"pins":[{"hostname":"api.example.com","sha256":["…","…"]}]}.
    // Checks each entry against the certificate its host serves now, whatever
    // PIN_LIVE_CHECK is set to — the pin editor calls this before saving.
    post("/api/v1/pins/live-check") {
        val config = try {
            call.receive<PinConfig>()
        } catch (_: Exception) {
            return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Body must be {\"pins\":[{\"hostname\":…,\"sha256\":[…]}]}"))
        }
        if (config.pins.size > 50) {
            return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "At most 50 hosts per check"))
        }
        call.respond(withContext(Dispatchers.IO) { liveGate.checkPins(config.pins) })
    }
}
