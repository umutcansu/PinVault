package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.api.ConfigUpdateStatus
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Opt-in [PinVaultConnectionListener] that forwards
 * [PinVaultConnectionEvent.Connection] (TLS handshake outcomes) and
 * [PinVaultConnectionEvent.ConfigUpdate] (config rotation outcomes) to
 * the **PinVault demo-server**:
 *
 * - `POST /api/v1/connection-history/client-report` — handshake reports
 * - `POST /api/v1/connection-history/config-update-report` — config swaps
 *
 * This is a thin convenience for projects that already run the bundled
 * demo-server (or a fork of it). It hard-codes the JSON shape that the
 * server's [com.example.pinvault.server.route.CertificateConfigRoute]
 * expects:
 *
 * Connection (`client-report`):
 * ```json
 * {
 *   "hostname":            "...",
 *   "status":              "healthy" | "pin_mismatch",
 *   "responseTimeMs":      0,
 *   "pinMatched":          true | false,
 *   "pinVersion":          int,
 *   "deviceManufacturer":  "...",
 *   "deviceModel":         "...",
 *   "serverCertPin":       "...",
 *   "storedPin":           "..."
 * }
 * ```
 *
 * ConfigUpdate (`config-update-report`):
 * ```json
 * {
 *   "status":              "config_updated" | "config_unchanged" | "config_update_failed",
 *   "pinVersion":          int,
 *   "deviceManufacturer":  "...",
 *   "deviceModel":         "...",
 *   "failureReason":       "..."   // only on config_update_failed
 * }
 * ```
 *
 * The config-update endpoint may not exist on every demo-server fork —
 * a 404 is logged at WARN and swallowed, the next event proceeds normally.
 *
 * If your backend speaks a different language, **do not use this class.**
 * Implement [PinVaultConnectionListener] directly and emit your own format
 * — that's exactly what the listener API is for. PinVault's core never
 * touches this reporter; it's simply registered as a callback when the
 * consumer opts in.
 *
 * Network errors are logged at WARN level and otherwise swallowed; a
 * misbehaving backend can never break the underlying TLS connection.
 *
 * ### Throttling and filtering
 *
 * Two independent knobs, both optional. They apply to the "healthy"
 * stream — Connection successes and ConfigUpdate UPDATED/UNCHANGED
 * outcomes. The anomaly stream — Connection pin-mismatch and ConfigUpdate
 * FAILED — bypasses both filters; those signals must never be silenced.
 *
 * - [reportSuccessEvents] decides *what* gets reported. When `false`,
 *   only anomalies are POSTed; the healthy stream is suppressed entirely.
 *   Useful for fleets that only care about pin mismatches and update
 *   failures.
 * - [dedupWindowMs] decides *how often* a healthy Connection event
 *   repeats. When `> 0`, duplicate Connection reports for the same
 *   `(hostname, pinVersion, serverCertPin)` tuple inside the window are
 *   dropped. ConfigUpdate events are not deduped — they are already
 *   periodic (default 24h WorkManager refresh).
 *
 * @param managementUrl Demo-server management base URL, e.g.
 *   `"http://192.168.1.80:6650/"`. The reporter appends
 *   `api/v1/connection-history/client-report` automatically.
 * @param httpClient Optional preconfigured OkHttpClient. Defaults to a
 *   short-timeout client that is fine for fire-and-forget telemetry.
 * @param reportSuccessEvents When `false`, the reporter only POSTs pin
 *   mismatch events. Defaults to `true` (legacy: every handshake is a
 *   POST). Pin mismatches are always reported regardless of this flag.
 * @param dedupWindowMs Minimum interval, in milliseconds, between
 *   duplicate "healthy" reports for the same host/version/cert. Defaults
 *   to 0 (no deduplication). Ignored when [reportSuccessEvents] is
 *   `false`. A production fleet that does want heartbeats should set
 *   this to 60_000 or higher.
 */
class PinVaultBackendReporter @JvmOverloads constructor(
    managementUrl: String,
    private val httpClient: OkHttpClient = defaultClient(),
    private val reportSuccessEvents: Boolean = true,
    private val dedupWindowMs: Long = 0L
) : PinVaultConnectionListener {

    private val connectionEndpoint: String = buildEndpoint(managementUrl, CONNECTION_PATH)
    private val configUpdateEndpoint: String = buildEndpoint(managementUrl, CONFIG_UPDATE_PATH)

    /** Last-sent timestamp per `host|pinVersion|cert` tuple. */
    private val lastReportedMs = ConcurrentHashMap<String, Long>()

    override fun onEvent(event: PinVaultConnectionEvent) {
        when (event) {
            is PinVaultConnectionEvent.Connection -> handleConnection(event)
            is PinVaultConnectionEvent.ConfigUpdate -> handleConfigUpdate(event)
        }
    }

    private fun handleConnection(event: PinVaultConnectionEvent.Connection) {
        if (event.success) {
            if (!reportSuccessEvents) return
            if (isDuplicateWithinWindow(event)) return
        }

        val status = if (event.success) "healthy" else "pin_mismatch"
        val firstExpected = event.expectedPins.firstOrNull().orEmpty()

        // Hand-built JSON; pulling kotlinx.serialization in just for this would
        // bloat the AAR for every consumer, including those using a custom
        // listener that never goes near this class.
        val json = buildString {
            append('{')
            appendField("hostname", event.hostname); append(',')
            appendField("status", status); append(',')
            append("\"responseTimeMs\":0,")
            append("\"pinMatched\":${event.success},")
            append("\"pinVersion\":${event.pinVersion},")
            appendField("deviceManufacturer", event.deviceManufacturer); append(',')
            appendField("deviceModel", event.deviceModel); append(',')
            appendField("serverCertPin", event.actualPin); append(',')
            appendField("storedPin", firstExpected)
            append('}')
        }

        post(connectionEndpoint, json)
    }

    private fun handleConfigUpdate(event: PinVaultConnectionEvent.ConfigUpdate) {
        val isFailure = event.status == ConfigUpdateStatus.FAILED
        if (!isFailure && !reportSuccessEvents) return

        val statusString = when (event.status) {
            ConfigUpdateStatus.UPDATED -> "config_updated"
            ConfigUpdateStatus.UNCHANGED -> "config_unchanged"
            ConfigUpdateStatus.FAILED -> "config_update_failed"
        }

        val json = buildString {
            append('{')
            appendField("status", statusString); append(',')
            append("\"pinVersion\":${event.newVersion},")
            appendField("deviceManufacturer", event.deviceManufacturer); append(',')
            appendField("deviceModel", event.deviceModel)
            event.failureReason?.let {
                append(',')
                appendField("failureReason", it)
            }
            append('}')
        }

        post(configUpdateEndpoint, json)
    }

    private fun post(endpoint: String, json: String) {
        val request = Request.Builder()
            .url(endpoint)
            .post(json.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Timber.w(
                        "PinVaultBackendReporter: %s returned HTTP %d",
                        endpoint, response.code
                    )
                }
            }
        } catch (e: Exception) {
            // OkHttp throws IOException on network failure; we never want
            // the reporter to take down the listener pipeline.
            Timber.w(e, "PinVaultBackendReporter: failed to POST to %s", endpoint)
        }
    }

    private fun isDuplicateWithinWindow(event: PinVaultConnectionEvent.Connection): Boolean {
        if (dedupWindowMs <= 0L) return false
        val key = "${event.hostname}|${event.pinVersion}|${event.actualPin}"
        val now = System.currentTimeMillis()
        // putIfAbsent + replace pattern: first writer wins inside the window,
        // subsequent callers see the recorded timestamp and drop. Once the
        // window expires the next caller writes a fresh timestamp.
        val previous = lastReportedMs[key]
        if (previous != null && now - previous < dedupWindowMs) return true
        lastReportedMs[key] = now
        return false
    }

    private fun StringBuilder.appendField(key: String, value: String) {
        append('"').append(key).append("\":\"")
        // Minimal JSON string escaping — quotes and backslashes only;
        // payload values come from Build.MANUFACTURER / MODEL / hostnames /
        // base64 hashes, none of which contain control characters in practice.
        for (ch in value) {
            when (ch) {
                '\\' -> append("\\\\")
                '"'  -> append("\\\"")
                else -> append(ch)
            }
        }
        append('"')
    }

    private companion object {
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
        const val CONNECTION_PATH = "api/v1/connection-history/client-report"
        const val CONFIG_UPDATE_PATH = "api/v1/connection-history/config-update-report"

        fun buildEndpoint(managementUrl: String, path: String): String {
            val base = managementUrl.trimEnd('/')
            return "$base/$path"
        }

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()
    }
}
