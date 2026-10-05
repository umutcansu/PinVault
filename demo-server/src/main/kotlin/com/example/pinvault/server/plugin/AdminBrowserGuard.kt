package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class AdminBrowserGuardConfig {
    /**
     * Anonymous-admin mode (`ALLOW_ANONYMOUS_ADMIN=true`): every admin request
     * must name this machine in its `Host` header — `localhost`, `127.0.0.1`
     * or `[::1]` with one of [listenerPorts] — or an entry of [allowedHosts].
     */
    var requireLocalHost: Boolean = false

    /** The ports this listener answers on (`PORT`, `MANAGEMENT_HTTPS_PORT`). */
    var listenerPorts: Set<Int> = emptySet()

    /** `MANAGEMENT_ALLOWED_HOSTS`: more `host:port` values the `Host` header may carry (lower case). */
    var allowedHosts: Set<String> = emptySet()

    /** `ADMIN_ALLOWED_ORIGINS`: origins besides the server's own that may send admin writes (a reverse proxy that rewrites `Host`). */
    var allowedOrigins: Set<String> = emptySet()
}

/**
 * Keeps other web pages in an administrator's browser away from the admin API.
 *
 * The admin API is reachable from the browser the dashboard runs in, so any
 * page that browser has open can aim requests at it:
 *
 *  - **Cross-site writes (CSRF).** A state-changing admin request is refused
 *    when its `Origin` is present and is not this server's own origin (the
 *    request's `Host`), or when `Sec-Fetch-Site` says `cross-site` or
 *    `same-site`. Browsers set both themselves; a page cannot forge them.
 *  - **"Simple" requests.** A cross-site form can send a body without a
 *    preflight only as a form or `text/plain`. An admin write must therefore
 *    be `application/json`, or carry a header no form can add: `X-API-Key`
 *    or `X-PinVault-Admin` (the dashboard sends it with every request). 415
 *    otherwise.
 *  - **DNS rebinding.** With no admin key (`ALLOW_ANONYMOUS_ADMIN=true`)
 *    nothing but the network keeps a page out: a name the attacker points at
 *    127.0.0.1 makes the browser treat the admin API as that page's own
 *    origin. So in that mode every admin request, reads included, must carry
 *    a `Host` that names this machine ([AdminBrowserGuardConfig.requireLocalHost]).
 *    With keys, a rebound page has no key: it is stored per origin.
 *
 * Device endpoints ([isPublicEndpoint]) are not touched. Tools that send no
 * `Origin` (curl, the library, the approval replay) pass the first check by
 * construction and the second with their key or JSON body. Install it BEFORE
 * [ApiKeyAuth].
 */
val AdminBrowserGuard = createApplicationPlugin("AdminBrowserGuard", ::AdminBrowserGuardConfig) {
    val requireLocalHost = pluginConfig.requireLocalHost
    val allowedOrigins = pluginConfig.allowedOrigins.map { it.trim().trimEnd('/').lowercase() }.toSet()
    val localHosts = pluginConfig.listenerPorts.flatMap { port -> LOCAL_NAMES.map { "$it:$port" } }.toSet() +
        pluginConfig.allowedHosts.map { it.trim().lowercase() }

    onCall { call ->
        if (call.response.isCommitted) return@onCall
        val method = call.request.httpMethod
        val path = call.request.path()
        if (isPublicEndpoint(path, method)) return@onCall

        // The name the request was addressed to: the Host header, or over
        // HTTP/2 the :authority Ktor exposes as the origin's server host.
        val scheme = call.request.origin.scheme
        val host = call.request.header(HttpHeaders.Host)?.trim()?.lowercase()
            ?: call.request.origin.let { "${it.serverHost.lowercase()}:${it.serverPort}" }
        if (requireLocalHost && withPort(host, scheme) !in localHosts) {
            return@onCall call.refuse(HttpStatusCode.Forbidden, "host_not_allowed",
                "Without an admin key this API answers only when it is addressed as this machine " +
                    "(localhost, 127.0.0.1 or [::1] with its port). Set MANAGEMENT_ALLOWED_HOSTS to add a name.")
        }
        if (method == HttpMethod.Get || method == HttpMethod.Head || method == HttpMethod.Options) return@onCall

        when (call.request.header("Sec-Fetch-Site")?.trim()?.lowercase()) {
            "cross-site", "same-site" -> return@onCall call.refuse(HttpStatusCode.Forbidden, "cross_site_request",
                "Admin changes are accepted only from the dashboard this server serves, not from another site.")
        }
        val origin = call.request.header(HttpHeaders.Origin)?.trim()?.trimEnd('/')?.lowercase()
        if (origin != null && origin !in allowedOrigins && !sameOrigin(origin, host, scheme)) {
            return@onCall call.refuse(HttpStatusCode.Forbidden, "cross_origin_request",
                "Admin changes are accepted only from this server's own origin. Behind a proxy that changes the Host header, set ADMIN_ALLOWED_ORIGINS.")
        }

        val json = call.request.header(HttpHeaders.ContentType)?.substringBefore(';')?.trim()
            .equals("application/json", ignoreCase = true)
        val marked = MARKER_HEADERS.any { call.request.header(it) != null }
        if (!json && !marked) {
            return@onCall call.refuse(HttpStatusCode.UnsupportedMediaType, "admin_write_needs_json",
                "Send admin changes as application/json, or with the X-API-Key or X-PinVault-Admin header.")
        }
    }
}

/** Names a browser on this machine uses for it. */
private val LOCAL_NAMES = listOf("localhost", "127.0.0.1", "[::1]")

/** Headers a cross-site form cannot add without a preflight this server never answers. */
private val MARKER_HEADERS = listOf("X-API-Key", "X-PinVault-Admin", ApprovalReplay.HEADER)

/** Whether [origin] (`scheme://host[:port]`, lower case) is the origin the request was addressed to ([host], on [scheme]). */
internal fun sameOrigin(origin: String, host: String?, scheme: String): Boolean {
    if (host == null) return false
    val originScheme = origin.substringBefore("://", "")
    val authority = origin.substringAfter("://", "")
    if (originScheme.isEmpty() || authority.isEmpty() || '/' in authority) return false
    // A TLS-terminating proxy keeps Host and changes the scheme: compare host and port.
    return withPort(authority, originScheme) == withPort(host, if (hasPort(authority)) scheme else originScheme)
}

private fun hasPort(authority: String): Boolean = authority.substringAfterLast(']').contains(':')

/** [authority] with its port spelled out: the default of [scheme] when it names none. */
private fun withPort(authority: String, scheme: String): String =
    if (hasPort(authority)) authority else "$authority:${if (scheme == "https") 443 else 80}"

/**
 * Refused admin requests, forwarded to whoever registers [listener] (the
 * audit log, through a summariser: a page hammering the API is one entry a
 * minute, not one per request).
 */
object BrowserGuardRefusals {
    @Volatile
    var listener: ((remoteAddress: String, method: String, path: String, reason: String) -> Unit)? = null
}

private suspend fun ApplicationCall.refuse(status: HttpStatusCode, error: String, message: String) {
    try {
        BrowserGuardRefusals.listener?.invoke(request.origin.remoteAddress, request.httpMethod.value, request.path(), error)
    } catch (_: Exception) { /* auditing must never break the refusal */ }
    respondText(buildJsonObject { put("error", error); put("message", message) }.toString(), ContentType.Application.Json, status)
}
