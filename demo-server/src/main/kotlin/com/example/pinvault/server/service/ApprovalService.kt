package com.example.pinvault.server.service

import com.example.pinvault.server.plugin.ApprovalReplay
import com.example.pinvault.server.store.ChangeRequest
import com.example.pinvault.server.store.ChangeRequestStore
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

/** Routes that change what devices trust: with approvals on, they wait for a second admin. */
object PinAffectingRoutes {
    private val rules: List<Triple<HttpMethod, Regex, String>> = listOf(
        Triple(HttpMethod.Put, Regex("^/api/v1/certificate-config/?$"), "pins_update"),
        Triple(HttpMethod.Post, Regex("^/api/v1/certificate-config/force-update(/[^/]+)?$"), "force_on"),
        Triple(HttpMethod.Post, Regex("^/api/v1/certificate-config/clear-force(/[^/]+)?$"), "force_off"),
        Triple(HttpMethod.Post, Regex("^/api/v1/config/[^/]+/update$"), "pins_update"),
        Triple(HttpMethod.Post, Regex("^/api/v1/management/hosts/[^/]+/generate-cert$"), "host_add"),
        Triple(HttpMethod.Post, Regex("^/api/v1/hosts/(generate-cert|fetch-from-url|upload-cert)$"), "host_add"),
        Triple(HttpMethod.Post, Regex("^/api/v1/hosts/[^/]+/(regenerate-cert|rotate-to-backup|upload-cert|fetch-cert-url|toggle-mtls|upload-client-cert)$"), "host_cert"),
        Triple(HttpMethod.Post, Regex("^/api/v1/config-apis/delete$"), "config_api_delete"),
        // Starting or stopping a listener decides which scope's pins a port
        // serves — stopping production and starting another scope on its port
        // would publish that scope's pins without touching a single pin.
        Triple(HttpMethod.Post, Regex("^/api/v1/config-apis/(start|stop)$"), "config_api_lifecycle"),
        Triple(HttpMethod.Post, Regex("^/api/v1/server-tls-pins/(regenerate|rotate-to-backup|upload|fetch-from-url)$"), "bootstrap_pins"),
        Triple(HttpMethod.Post, Regex("^/api/v1/signing-key/regenerate$"), "signing_key"),
        Triple(HttpMethod.Put, Regex("^/api/v1/signing-keyset$"), "signing_keyset")
    )

    /** The kind of change [method] + [path] makes, or null when it does not affect pins or keys. Pass a [canonicalPath]. */
    fun match(method: HttpMethod, path: String): String? =
        rules.firstOrNull { (m, pattern, _) -> m == method && pattern.matches(path) }?.third

    /** Every kind of change [match] can answer — the dashboard labels each one (`op_<name>`). */
    val operations: Set<String> get() = rules.mapTo(linkedSetOf()) { it.third }

    /**
     * [raw] as Ktor routing resolves it: empty segments dropped and each
     * segment percent-decoded. The gate must decide on this form — two
     * spellings that route to the same handler must get the same answer.
     */
    fun canonicalPath(raw: String): String =
        "/" + raw.split('/').filter { it.isNotEmpty() }.joinToString("/") { percentDecode(it) }

    /** `%XX` escapes → UTF-8 text, as routing decodes a path segment ('+' stays '+'). */
    private fun percentDecode(segment: String): String {
        if ('%' !in segment) return segment
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < segment.length) {
            val c = segment[i]
            if (c == '%' && i + 2 < segment.length) {
                val hex = segment.substring(i + 1, i + 3).toIntOrNull(16)
                if (hex != null) {
                    out.write(hex)
                    i += 3
                    continue
                }
            }
            out.write(c.toString().toByteArray(Charsets.UTF_8))
            i++
        }
        return out.toString(Charsets.UTF_8)
    }
}

/**
 * Two-person rule for pin and key changes (`PIN_CHANGE_APPROVALS`, default 1 = off).
 *
 * With `PIN_CHANGE_APPROVALS=2` a pin-affecting request is not executed: it
 * becomes a pending change request, and only when another admin approves it
 * does the server replay that exact request — as the requester — through its
 * own management API. `3` needs two approvers besides the requester, and so on.
 * Nobody can approve their own request; requests expire after
 * `APPROVAL_TTL_HOURS` (default 24).
 *
 * Needs named admins (`ADMIN_KEYS`): with a single shared key there is nobody
 * to approve.
 */
class ApprovalService(
    private val store: ChangeRequestStore,
    private val audit: AuditLog,
    val required: Int,
    private val ttlHours: Long = 24,
    private val managementPort: Int,
    private val describe: (op: String, path: String, query: String, body: ByteArray) -> Description,
    /**
     * A fingerprint of a Config API's current pins. A request records it; the
     * approval re-checks it, so a full-config write approved late cannot undo
     * a change that was approved in between.
     */
    private val stateHash: (configApiId: String) -> String = { "" },
    private val replay: (ChangeRequest, ByteArray, String) -> Pair<Int, String> = { cr, body, token ->
        loopbackReplay(managementPort, cr, body, token)
    }
) {
    val enabled: Boolean get() = required > 1

    /** What a pending change does, for the approver. */
    data class Description(
        val configApiId: String,
        val summary: String,
        val detail: JsonObject,
        /** Set for changes computed against the scope's current pins (see [stateHash]). */
        val baseHash: String? = null
    )

    class Refused(val status: HttpStatusCode, message: String) : Exception(message)

    @Serializable
    data class Pending(
        val pendingApproval: Boolean = true,
        val changeRequestId: Long,
        val summary: String,
        val approvalsRequired: Int,
        val message: String
    )

    /**
     * Stores a change request. [path] is the path as sent (the replay goes to
     * exactly the same handler); [canonicalPath] is what routing resolved it
     * to, which is what the description — and the approver — must look at.
     * A request that cannot be described is refused: an approver must never
     * be asked to approve something they cannot see.
     */
    fun submit(
        requestedBy: String,
        op: String,
        method: String,
        path: String,
        canonicalPath: String = path,
        query: String,
        contentType: String,
        body: ByteArray
    ): Pending {
        val description = try {
            describe(op, canonicalPath, query, body)
        } catch (e: Exception) {
            throw Refused(HttpStatusCode.BadRequest, "This change cannot be described for approval: ${e.message ?: e.javaClass.simpleName}")
        }
        val now = Instant.now()
        val id = store.create(
            createdAt = now.toString(),
            expiresAt = now.plus(Duration.ofHours(ttlHours)).toString(),
            requestedBy = requestedBy,
            method = method,
            path = path,
            query = query,
            contentType = contentType,
            body = body,
            configApiId = description.configApiId,
            summary = description.summary,
            detail = JsonObject(
                description.detail + (description.baseHash?.let { mapOf("baseHash" to kotlinx.serialization.json.JsonPrimitive(it)) } ?: emptyMap())
            ).toString()
        )
        audit.record(
            action = "change_requested",
            summary = "#$id ${description.summary}",
            configApiId = description.configApiId,
            target = "$method $path",
            detail = description.detail,
            actor = requestedBy
        )
        return Pending(
            changeRequestId = id,
            summary = description.summary,
            approvalsRequired = required,
            message = "Change #$id is waiting for approval by ${required - 1} other admin(s)."
        )
    }

    fun list(status: String?): List<ChangeRequest> {
        expireOverdue()
        return store.list(status)
    }

    fun get(id: Long): ChangeRequest? {
        expireOverdue()
        return store.get(id)
    }

    /**
     * Records [approver]'s approval; once enough distinct admins other than
     * the requester approved, replays the request and returns its outcome.
     * [approverIp] goes on the audit entries the replay writes.
     */
    @Synchronized
    fun approve(id: Long, approver: String, approverIp: String = ""): ChangeRequest {
        expireOverdue()
        val cr = store.get(id) ?: throw Refused(HttpStatusCode.NotFound, "Change request #$id not found")
        if (cr.status != "pending") throw Refused(HttpStatusCode.Conflict, "Change request #$id is ${cr.status}")
        if (Instant.parse(cr.expiresAt).isBefore(Instant.now())) {
            if (store.decideIfPending(id, "expired", null, Instant.now().toString(), "not approved within ${ttlHours}h", null, null)) {
                audit.record("change_expired", "#$id expired unapproved — ${cr.summary}", cr.configApiId, "${cr.method} ${cr.path}", actor = "system")
            }
            throw Refused(HttpStatusCode.Conflict, "Change request #$id expired")
        }
        // 409, not 403: the dashboard treats 401/403 as "wrong key" and prompts for another.
        if (approver == cr.requestedBy) {
            throw Refused(HttpStatusCode.Conflict, "The admin who requested a change cannot approve it — another admin must.")
        }
        if (approver == com.example.pinvault.server.plugin.AdminRegistry.LEGACY_NAME || approver == "anonymous") {
            throw Refused(
                HttpStatusCode.Conflict,
                "A shared key (API_KEY) cannot approve: it does not say WHO approves. Use a personal key from ADMIN_KEYS."
            )
        }
        val base = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(cr.detail).let { it as JsonObject }["baseHash"]
                ?.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        }.getOrNull()
        if (base != null && base != stateHash(cr.configApiId)) {
            store.decideIfPending(id, "stale", approver, Instant.now().toString(), "pins changed since the request was made", null, null)
            audit.record("change_stale", "#$id not applied: ${cr.configApiId} changed since it was requested — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            throw Refused(HttpStatusCode.Conflict, "The pins of ${cr.configApiId} changed after #$id was requested. Ask for a fresh request.")
        }
        if (approver in cr.approvedBy) throw Refused(HttpStatusCode.Conflict, "$approver already approved #$id")

        store.addApproval(id, approver)
        val approvers = cr.approvedBy + approver
        if (approvers.size < required - 1) {
            audit.record("change_approved", "#$id approved by $approver (${approvers.size}/${required - 1}) — ${cr.summary}",
                cr.configApiId, "${cr.method} ${cr.path}", actor = approver)
            return store.get(id)!!
        }

        val actor = "${cr.requestedBy} (approved by ${approvers.joinToString(", ")})"
        val token = ApprovalReplay.issue(id, actor, cr.method, cr.path, cr.query, approverIp)
        val (status, body) = try {
            replay(cr, store.body(id) ?: ByteArray(0), token)
        } catch (e: Exception) {
            0 to (e.message ?: e.javaClass.simpleName)
        }
        val applied = status in 200..299
        store.decideIfPending(id, if (applied) "applied" else "failed", approver, Instant.now().toString(), null, status, body.take(2000))
        audit.record(
            action = if (applied) "change_applied" else "change_failed",
            summary = "#$id ${if (applied) "applied" else "failed (HTTP $status)"} — ${cr.summary}",
            configApiId = cr.configApiId,
            target = "${cr.method} ${cr.path}",
            detail = buildJsonObject {
                put("requestedBy", cr.requestedBy)
                put("approvedBy", approvers.joinToString(","))
                put("resultStatus", status)
                if (!applied) put("result", body.take(500))
            },
            actor = approver
        )
        return store.get(id)!!
    }

    /** Rejects a pending request; its requester may also withdraw it this way. */
    @Synchronized
    fun reject(id: Long, by: String, reason: String?): ChangeRequest {
        expireOverdue()
        val cr = store.get(id) ?: throw Refused(HttpStatusCode.NotFound, "Change request #$id not found")
        if (cr.status != "pending") throw Refused(HttpStatusCode.Conflict, "Change request #$id is ${cr.status}")
        store.decideIfPending(id, "rejected", by, Instant.now().toString(), reason, null, null)
        audit.record(
            action = "change_rejected",
            summary = "#$id ${if (by == cr.requestedBy) "withdrawn" else "rejected"} by $by" +
                (reason?.takeIf { it.isNotBlank() }?.let { ": $it" } ?: "") + " — ${cr.summary}",
            configApiId = cr.configApiId,
            target = "${cr.method} ${cr.path}",
            actor = by
        )
        return store.get(id)!!
    }

    private fun expireOverdue() {
        val now = Instant.now()
        // Every overdue request, not just the newest page of pending ones; and
        // only a request still pending is expired (never an applied one).
        store.pendingExpiredBefore(now.toString()).forEach { cr ->
            if (store.decideIfPending(cr.id, "expired", null, now.toString(), "not approved within ${ttlHours}h", null, null)) {
                audit.record("change_expired", "#${cr.id} expired unapproved — ${cr.summary}", cr.configApiId,
                    "${cr.method} ${cr.path}", actor = "system")
            }
        }
    }

    companion object {
        private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

        /** Sends the stored request to this server's own management port. */
        fun loopbackReplay(port: Int, cr: ChangeRequest, body: ByteArray, token: String): Pair<Int, String> {
            val uri = URI("http://127.0.0.1:$port${cr.path}${if (cr.query.isNotEmpty()) "?" + cr.query else ""}")
            val request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(120))
                .header(ApprovalReplay.HEADER, token)
                .apply { if (cr.contentType.isNotBlank()) header("Content-Type", cr.contentType) }
                .method(cr.method, HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            return response.statusCode() to response.body()
        }

        fun requiredFromEnv(env: Map<String, String> = System.getenv()): Int =
            env["PIN_CHANGE_APPROVALS"]?.toIntOrNull()?.coerceAtLeast(1) ?: 1
    }
}
