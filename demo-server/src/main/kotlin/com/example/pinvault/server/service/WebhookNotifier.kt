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
 * `X-PinVault-Timestamp: <Unix seconds>` and
 * `X-PinVault-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`,
 * so the receiver can tell it came from this server AND when: a receiver
 * that refuses timestamps more than a few minutes old (and an `auditId` it
 * has already seen) cannot be fed a captured delivery again. The timestamp is
 * taken per attempt, so a retry is not stale. `NOTIFY_EVENTS` (comma-separated, default
 * `*`) limits which audit actions are sent. `*` leaves out [ROUTINE_EVENTS]:
 * things every device does once, which anyone who can reach a device port
 * can also cause at will, so they would bury the events worth a message. Name
 * one in `NOTIFY_EVENTS` to receive it anyway.
 *
 * Delivery is asynchronous with retries and never blocks or fails the admin
 * request that caused it. The last deliveries are kept for the dashboard.
 */
class WebhookNotifier(
    private val url: String,
    private val secret: String?,
    private val events: Set<String>,
    private val serverName: String = "PinVault",
    private val clock: () -> Long = System::currentTimeMillis
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

    fun wants(event: String): Boolean = event in events || ("*" in events && event !in ROUTINE_EVENTS)

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
        // The last [RESERVED_FOR_SECURITY] places are kept for what an operator
        // must hear about: a flood of routine entries (enrollments, reports,
        // registrations — anyone can cause those) used to fill the queue and
        // drop a pin change or a revocation that came after.
        val cap = if (isSecurityEvent(event)) MAX_PENDING else MAX_PENDING - RESERVED_FOR_SECURITY
        if (pending.incrementAndGet() > cap) {
            pending.decrementAndGet()
            recent.addFirst(Delivery(event, at, auditId, null, 0, "dropped: $cap deliveries already queued"))
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
                    .apply {
                        secret?.let {
                            val timestamp = (clock() / 1000).toString()
                            header(TIMESTAMP_HEADER, timestamp)
                            header(SIGNATURE_HEADER, "sha256=" + signature(it, timestamp, body))
                        }
                    }
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

    companion object {
        const val TIMESTAMP_HEADER = "X-PinVault-Timestamp"
        const val SIGNATURE_HEADER = "X-PinVault-Signature"

        /** Hex HMAC-SHA256 of `<timestamp>.<body>` under [secret]: what a receiver recomputes. */
        fun signature(secret: String, timestamp: String, body: String): String {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
            return mac.doFinal("$timestamp.$body".toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }

        private const val MAX_ATTEMPTS = 3
        private val BACKOFF_SECONDS = longArrayOf(1, 5)
        private const val KEEP = 50
        private const val MAX_PENDING = 500

        /** Queue places only [isSecurityEvent] deliveries may take. */
        private const val RESERVED_FOR_SECURITY = 100

        /**
         * Events that keep their place when the queue is nearly full: what
         * devices trust, who is let in or cut off, approvals, refused admin
         * keys. Everything else (enrollments, reports, key registrations) is
         * dropped first.
         */
        fun isSecurityEvent(event: String): Boolean =
            event in SECURITY_EVENTS || SECURITY_PREFIXES.any { event.startsWith(it) }

        private val SECURITY_EVENTS = setOf(
            "pins_changed", "client_cert_revoked", "client_identity_forgotten", "device_key_replaced", "device_key_reset",
            "vault_token_revoked", "auth_failed", "admin_request_refused", "enrollment_open_changed", "enrollment_policy_created",
            "enrollment_request_approved", "client_cert_uploaded", "client_cert_generated", "private_key_downloaded", "cert_expiring"
        )
        private val SECURITY_PREFIXES = listOf("change_", "signing_", "live_check_", "keyset_", "attestation_policy", "attestation_token_secret")

        /** Recorded in the audit log, but sent only when named in `NOTIFY_EVENTS`. */
        val ROUTINE_EVENTS = setOf("device_key_registered", "device_key_attested", "attestation_rejected")

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
