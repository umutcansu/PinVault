package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Opt-in [PinVaultConnectionListener] that forwards every
 * [PinVaultConnectionEvent.Connection] to the **PinVault demo-server**
 * `POST /api/v1/connection-history/client-report` endpoint.
 *
 * This is a thin convenience for projects that already run the bundled
 * demo-server (or a fork of it). It hard-codes the JSON shape that the
 * server's [com.example.pinvault.server.route.CertificateConfigRoute]
 * expects:
 *
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
 *   "storedPin":           "..."   // first expected pin
 * }
 * ```
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
 * @param managementUrl Demo-server management base URL, e.g.
 *   `"http://192.168.1.80:6650/"`. The reporter appends
 *   `api/v1/connection-history/client-report` automatically.
 * @param httpClient Optional preconfigured OkHttpClient. Defaults to a
 *   short-timeout client that is fine for fire-and-forget telemetry.
 */
class PinVaultBackendReporter @JvmOverloads constructor(
    managementUrl: String,
    private val httpClient: OkHttpClient = defaultClient()
) : PinVaultConnectionListener {

    private val endpoint: String = buildEndpoint(managementUrl)

    override fun onEvent(event: PinVaultConnectionEvent) {
        if (event !is PinVaultConnectionEvent.Connection) return

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
        const val REPORT_PATH = "api/v1/connection-history/client-report"

        fun buildEndpoint(managementUrl: String): String {
            val base = managementUrl.trimEnd('/')
            return "$base/$REPORT_PATH"
        }

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()
    }
}
