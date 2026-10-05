package com.example.pinvault.server.route

import com.example.pinvault.server.service.RateLimiter
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.response.respondText
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * What the report endpoints share (`POST /api/v1/vault/report`,
 * `…/connection-history/client-report`, `…/config-update-report`).
 *
 * A report needs no credential on a TLS listener — it is telemetry, and a
 * device that cannot authenticate is exactly the one whose report matters —
 * so everything in it is the sender's claim. The routes therefore take
 * nothing as it comes: ids and statuses are checked against a fixed shape or
 * list (400 otherwise), free text is cut to a printable line, the time is the
 * server's, and [ReportLimits] bounds how many reports one address or one
 * device can file. What is stored is trimmed per Config API, failures apart
 * from the rest (see the stores).
 */

/** How many reports a source address, and a device, may file per window; null = no limit. */
class ReportLimits(
    /** Reports per source address (`REPORT_RATE_LIMIT`). */
    private val perAddress: RateLimiter? = null,
    /** Reports per reporting device (`REPORT_DEVICE_RATE_LIMIT`). */
    private val perDevice: RateLimiter? = null
) {
    /** Counts a report from [remoteAddress]; checked before the body is read. */
    fun allowAddress(remoteAddress: String): Boolean =
        perAddress?.allow(RateLimiter.sourceKey(remoteAddress)) != false

    /**
     * Counts a report of [device] in [configApiId]. The id is the sender's
     * claim on a TLS listener: an address is counted first, so it cannot make
     * up more device windows than its own quota allows.
     */
    fun allowDevice(configApiId: String, device: String): Boolean =
        perDevice?.allow("$configApiId|$device") != false
}

/** Counts this report against its source address; false after answering 429. */
internal suspend fun ApplicationCall.reportAllowedFromAddress(limits: ReportLimits?): Boolean {
    if (limits == null || limits.allowAddress(request.origin.remoteAddress)) return true
    respondReportRateLimited()
    return false
}

/** Counts this report against [device]; false after answering 429. */
internal suspend fun ApplicationCall.reportAllowedForDevice(limits: ReportLimits?, configApiId: String, device: String): Boolean {
    if (limits == null || limits.allowDevice(configApiId, device)) return true
    respondReportRateLimited()
    return false
}

private suspend fun ApplicationCall.respondReportRateLimited() = respondText(
    """{"error":"rate_limited","message":"Too many reports. Try again later."}""",
    ContentType.Application.Json, HttpStatusCode.TooManyRequests
)

/** 400 with the field that was refused. */
internal suspend fun ApplicationCall.respondInvalidReport(field: String, message: String) = respondText(
    buildJsonObject { put("error", "Invalid $field format"); put("field", field); put("message", message) }.toString(),
    ContentType.Application.Json, HttpStatusCode.BadRequest
)

/** A number field; absent, `null` or not a number: null. Never throws on a body anyone can send. */
internal fun JsonObject.int(name: String): Int? = (this[name] as? JsonPrimitive)?.intOrNull
internal fun JsonObject.long(name: String): Long? = (this[name] as? JsonPrimitive)?.longOrNull
internal fun JsonObject.bool(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull

/**
 * Free text a device sent (a failure reason, an error message), fit to store
 * and show: one printable line of at most [max] characters. Blank: null.
 */
internal fun reportText(raw: String?, max: Int = REPORT_TEXT_MAX): String? =
    raw?.map { if (it.isISOControl()) ' ' else it }?.joinToString("")?.trim()?.take(max)?.ifBlank { null }

internal const val REPORT_TEXT_MAX = 300

/** A pin as a device reports it: Base64 of a SHA-256, with or without a `sha256/` prefix. Empty = none. */
internal val REPORT_PIN_REGEX = Regex("^[A-Za-z0-9+/=_-]{0,100}$")

/** The longest a connection may plausibly have taken; a reported time is brought into 0..this. */
internal const val REPORT_MAX_RESPONSE_MS = 10 * 60_000L
