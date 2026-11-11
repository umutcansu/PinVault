package io.github.umutcansu.pinvault.ssl

import okhttp3.Call
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber
import java.io.IOException
import java.util.Collections
import java.util.WeakHashMap

/**
 * Keeps an app's credentials on the origin it sent them to when OkHttp
 * follows a redirect (review 2026-11-12).
 *
 * OkHttp drops only `Authorization` when a redirect changes host; every other
 * header the app set — a session `Cookie`, an `X-API-Key`, a header its own
 * interceptor adds — goes along to whatever host the `Location` names, and a
 * 307/308 sends the request body there again. The iOS transport and the
 * bridges' `PinVault.fetch` keep only neutral headers on such a hop; clients
 * from `getClient()` and `applyTo` did not.
 *
 * As a network interceptor it sees every hop of a call. The first hop's
 * headers are remembered; on a hop to another origin (scheme, host or port)
 * every header that carries the SAME value as on the first hop is removed —
 * it is the app's, carried over — except [NEUTRAL] ones. What OkHttp makes
 * for the new hop itself (`Host`, cookies the cookie jar holds for the new
 * host) differs and stays. A body is not sent to another origin: the hop
 * fails with an [IOException] instead.
 *
 * Same-origin redirects are untouched. `PinVault-Token` / `-Proof` are
 * dropped by their own interceptor already; plain `http` targets are refused
 * by `followSslRedirects(false)` on the library's clients.
 */
internal object CrossOriginRedirectGuard : Interceptor {

    /** Headers that say nothing about who the caller is: kept on any hop. */
    internal val NEUTRAL = setOf("accept", "accept-language", "user-agent", "accept-encoding", "connection", "host")

    private val firstHops: MutableMap<Call, Pair<HttpUrl, Headers>> = Collections.synchronizedMap(WeakHashMap())

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val call = chain.call()
        val first = firstHops.getOrPut(call) { request.url to request.headers }
        val (origin, firstHeaders) = first
        if (sameOrigin(origin, request.url)) return chain.proceed(request)

        if (request.body != null) {
            throw IOException(
                "Not following a redirect from ${origin.host}:${origin.port} to ${request.url.host}:${request.url.port}: " +
                    "it would send the request body to another origin"
            )
        }
        val carried = request.headers.names().filter { name ->
            name.lowercase() !in NEUTRAL && firstHeaders.values(name).isNotEmpty() && firstHeaders.values(name) == request.headers.values(name)
        }
        if (carried.isEmpty()) return chain.proceed(request)
        Timber.d("Redirect to another origin (%s:%d): dropped %d header(s) of the first request", request.url.host, request.url.port, carried.size)
        val stripped = request.newBuilder().apply { carried.forEach { removeHeader(it) } }.build()
        return chain.proceed(stripped)
    }

    private fun sameOrigin(a: HttpUrl, b: HttpUrl): Boolean =
        a.scheme == b.scheme && a.host.equals(b.host, ignoreCase = true) && a.port == b.port
}
