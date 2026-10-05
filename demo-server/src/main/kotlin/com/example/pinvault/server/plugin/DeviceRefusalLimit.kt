package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.RateLimiter
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.hooks.ResponseSent
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * Cuts off a source address that keeps being refused on the device endpoints.
 *
 * Enrollment, E2E key registration, vault downloads and host client
 * certificate downloads ask for no admin key, and each refusal costs the
 * server something: a token lookup, a CSR to parse, a key to check. Every
 * answer that turns the caller away (400, 401, 403, 404, 409, 411, 413) is
 * counted against its address ([RateLimiter.sourceKey]); once the quota of a
 * window is used up the address gets `429 rate_limited` before the body is
 * read, a token is looked at or anything is parsed. Requests that are served
 * are never counted, so devices sharing an address (one office, one NAT) are
 * not held to a common quota for working normally — and nothing the caller
 * chooses (a client id, a device id) is part of the key.
 *
 * Certificate renewal counts for itself (it is also mounted alone on the
 * recovery listener); the report endpoints count every report.
 */
class DeviceRefusalLimitConfig {
    /** Refusals a source address may collect per window (`DEVICE_REFUSAL_RATE_LIMIT`); null = no limit. */
    var limiter: RateLimiter? = null

    /** Which requests are counted and cut off. */
    var appliesTo: (path: String, method: HttpMethod) -> Boolean = { path, method -> isRefusalLimitedEndpoint(path, method) }

    /** Records the cut-offs without flooding the audit log; null = not recorded. */
    var refusals: AuthFailureRecorder? = null
}

val DeviceRefusalLimit = createApplicationPlugin(name = "DeviceRefusalLimit", ::DeviceRefusalLimitConfig) {
    val limiter = pluginConfig.limiter ?: return@createApplicationPlugin
    val appliesTo = pluginConfig.appliesTo
    val refusals = pluginConfig.refusals

    onCall { call ->
        // Another plugin already answered (an oversized body, a revoked certificate).
        if (call.response.isCommitted) return@onCall
        if (!appliesTo(call.request.path(), call.request.httpMethod)) return@onCall
        val remote = call.request.origin.remoteAddress
        if (!limiter.exceeded(RateLimiter.sourceKey(remote))) return@onCall
        refusals?.report(remote, call.request.httpMethod.value, call.request.path(), reason = "too many refused requests")
        call.respondText(
            """{"error":"rate_limited","message":"Too many refused requests from this address. Try again later."}""",
            ContentType.Application.Json, HttpStatusCode.TooManyRequests
        )
    }

    on(ResponseSent) { call ->
        if (call.response.status()?.value !in COUNTED_REFUSALS) return@on
        if (!appliesTo(call.request.path(), call.request.httpMethod)) return@on
        // Over the quota now (its own window, or its network's while the table is
        // full): the next request is cut off before it is read (exceeded above).
        // The first refusal beyond the quota is recorded here.
        val remote = call.request.origin.remoteAddress
        if (!limiter.allow(RateLimiter.sourceKey(remote))) {
            refusals?.report(remote, call.request.httpMethod.value, call.request.path(), reason = "refusal quota used up")
        }
    }
}

/**
 * The answers that count as a refusal. Not 412 (a device without a key yet is
 * told to register one), not 410 (a request that lapsed is told to ask
 * again), not 429 (already limited).
 */
private val COUNTED_REFUSALS = setOf(400, 401, 403, 404, 409, 411, 413)

private val PUBLIC_KEY_PATH = Regex("/api/v1/vault/devices/[^/]+/public-key")
private val HOST_CERT_DOWNLOAD_PATH = Regex("/api/v1/client-certs/[^/]+/download")
private val VAULT_FILE_PATH = Regex("/api/v1/vault/([A-Za-z0-9._-]{1,64})")

/** The device endpoints [DeviceRefusalLimit] watches by default. */
internal fun isRefusalLimitedEndpoint(path: String, method: HttpMethod): Boolean = when (method) {
    HttpMethod.Post -> path == "/api/v1/client-certs/enroll" || PUBLIC_KEY_PATH.matches(path)
    HttpMethod.Get -> HOST_CERT_DOWNLOAD_PATH.matches(path) ||
        VAULT_FILE_PATH.matchEntire(path)?.groupValues?.get(1)?.let { it !in RESERVED_VAULT_SEGMENTS } == true
    else -> false
}
