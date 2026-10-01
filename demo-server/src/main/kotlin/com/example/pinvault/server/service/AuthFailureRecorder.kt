package com.example.pinvault.server.service

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Audits failed authentication attempts without letting anyone flood the log.
 *
 * The first failure of a minute is recorded (and pushed to the webhook) at
 * once. Further failures in that minute are only counted, with up to
 * [MAX_SOURCES] sample addresses, and written as one summary entry when the
 * minute is over. Memory stays bounded however many addresses an attacker
 * rotates through, and the device-facing ports cannot be used to spam the
 * append-only audit log or a Slack channel.
 *
 * One instance per kind of failure: invalid admin keys (`auth_failed`), and
 * refused client-certificate renewals (`client_cert_auth_failed`).
 */
class AuthFailureRecorder(
    private val audit: AuditLog,
    private val windowMs: Long = 60_000,
    /** The audit action recorded. */
    private val action: String = "auth_failed",
    /** What failed, as the summary starts: "<what> from <address>". */
    private val what: String = "Invalid X-API-Key",
    /** The same thing in the summary of a minute: "<n> more <attemptsLabel> attempt(s) …". */
    private val attemptsLabel: String = "invalid X-API-Key"
) {

    private var windowStart = 0L
    private var suppressed = 0
    private val sources = LinkedHashSet<String>()
    private var moreSources = false

    init {
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "auth-failure-flush").apply { isDaemon = true } }
            .scheduleAtFixedRate({ flush() }, windowMs, windowMs, TimeUnit.MILLISECONDS)
    }

    @Synchronized
    fun report(remoteAddress: String, method: String, path: String, actor: String = "unknown", reason: String? = null) {
        val now = System.currentTimeMillis()
        if (now - windowStart >= windowMs) {
            flushLocked()
            windowStart = now
            audit.record(
                action, "$what from $remoteAddress${reason?.let { " ($it)" } ?: ""}",
                target = "$method $path", actor = actor, ip = remoteAddress
            )
        } else {
            suppressed++
            if (sources.size < MAX_SOURCES) sources += remoteAddress else if (remoteAddress !in sources) moreSources = true
        }
    }

    @Synchronized
    fun flush() = flushLocked()

    private fun flushLocked() {
        if (suppressed == 0) return
        audit.record(
            action,
            "$suppressed more $attemptsLabel attempt(s) in the same minute from " +
                "${sources.size}${if (moreSources) "+" else ""} address(es): ${sources.joinToString()}",
            actor = "unknown"
        )
        suppressed = 0
        sources.clear()
        moreSources = false
    }

    companion object {
        const val MAX_SOURCES = 20
    }
}
