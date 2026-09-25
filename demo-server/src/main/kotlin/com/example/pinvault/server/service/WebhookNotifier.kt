package com.example.pinvault.server.service

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pushes security events to a webhook the moment they happen (`NOTIFY_WEBHOOK_URL`).
 *
 * The body is JSON with a Slack-compatible `text` field, so a Slack or
 * Mattermost incoming-webhook URL works as is; anything else can read the
 * structured fields. With `NOTIFY_WEBHOOK_SECRET` set, every request carries
 * `X-PinVault-Signature: sha256=<hex HMAC of the body>` so the receiver can
 * tell it came from this server. `NOTIFY_EVENTS` (comma-separated, default
 * `*`) limits which audit actions are sent.
 *
 * Delivery is asynchronous with retries and never blocks or fails the admin
 * request that caused it. The last deliveries are kept for the dashboard.
 */
class WebhookNotifier(
    private val url: String,
    private val secret: String?,
    private val events: Set<String>,
    private val serverName: String = "PinVault"
) {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    private val executor = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "webhook-notifier").apply { isDaemon = true } }
    private val recent = ConcurrentLinkedDeque<Delivery>()

    @Serializable
    data class Delivery(
        val event: String,
        val at: String,
        val auditId: Long? = null,
        val status: Int? = null,
        val attempts: Int,
        val error: String? = null
    )

    @Serializable
    data class Status(val configured: Boolean, val target: String?, val signed: Boolean, val events: List<String>, val recent: List<Delivery>)

    fun status() = Status(
        configured = true,
        // Host only: the URL path of a Slack/Teams webhook is itself the secret.
        target = runCatching { URI(url).let { "${it.scheme}://${it.host}${if (it.port > 0) ":${it.port}" else ""}" } }.getOrNull(),
        signed = secret != null,
        events = events.toList(),
        recent = recent.toList()
    )

    fun wants(event: String): Boolean = "*" in events || event in events

    /** Deliveries queued or waiting for a retry; bounded so a burst cannot grow memory without limit. */
    private val pending = java.util.concurrent.atomic.AtomicInteger()

    fun notify(
        event: String,
        actor: String,
        summary: String,
        configApiId: String = "",
        target: String = "",
        auditId: Long? = null,
        detail: JsonElement? = null,
        /** The audit entry's chain hash: an outside copy of the chain head, so a rewrite of the log shows. */
        auditHash: String? = null
    ) {
        if (!wants(event)) return
        val at = Instant.now().toString()
        val body = buildJsonObject {
            put("event", event)
            put("actor", actor)
            put("summary", summary)
            put("configApiId", configApiId)
            put("target", target)
            put("at", at)
            auditId?.let { put("auditId", it) }
            auditHash?.let { put("auditHash", it) }
            detail?.let { put("detail", it) }
            put("text", "[$serverName] $event by $actor: $summary")
        }.toString()
        if (pending.incrementAndGet() > MAX_PENDING) {
            pending.decrementAndGet()
            recent.addFirst(Delivery(event, at, auditId, null, 0, "dropped: $MAX_PENDING deliveries already queued"))
            while (recent.size > KEEP) recent.pollLast()
            return
        }
        send(event, at, auditId, body, attempt = 1)
    }

    private fun send(event: String, at: String, auditId: Long?, body: String, attempt: Int) {
        executor.execute {
            val result = try {
                val request = HttpRequest.newBuilder(URI(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("X-PinVault-Event", event)
                    .apply { secret?.let { header("X-PinVault-Signature", "sha256=" + hmacHex(it, body)) } }
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build()
                val response = client.send(request, HttpResponse.BodyHandlers.discarding())
                response.statusCode() to null
            } catch (e: Exception) {
                null to (e.message ?: e.javaClass.simpleName)
            }
            val (status, error) = result
            val delivered = status != null && status in 200..299
            if (!delivered && attempt < MAX_ATTEMPTS) {
                executor.schedule({ send(event, at, auditId, body, attempt + 1) }, BACKOFF_SECONDS[attempt - 1], TimeUnit.SECONDS)
                return@execute
            }
            pending.decrementAndGet()
            recent.addFirst(Delivery(event, at, auditId, status, attempt, error ?: if (!delivered) "HTTP $status" else null))
            while (recent.size > KEEP) recent.pollLast()
            if (!delivered) println("WebhookNotifier: '$event' not delivered after $attempt attempt(s): ${error ?: "HTTP $status"}")
        }
    }

    private fun hmacHex(secret: String, body: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(body.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    companion object {
        private const val MAX_ATTEMPTS = 3
        private val BACKOFF_SECONDS = longArrayOf(1, 5)
        private const val KEEP = 50
        private const val MAX_PENDING = 500

        fun fromEnv(env: Map<String, String> = System.getenv()): WebhookNotifier? {
            val url = env["NOTIFY_WEBHOOK_URL"]?.takeIf { it.isNotBlank() } ?: return null
            return WebhookNotifier(
                url = url,
                secret = env["NOTIFY_WEBHOOK_SECRET"]?.takeIf { it.isNotBlank() },
                events = (env["NOTIFY_EVENTS"]?.takeIf { it.isNotBlank() } ?: "*")
                    .split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            )
        }
    }
}
