package io.github.umutcansu.pinvault.ssl

import okhttp3.Call
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.io.IOException

/**
 * A WebSocket handshake that is redirected to another origin is not followed
 * (review 2026-11-14).
 *
 * OkHttp runs a WebSocket upgrade as a call WITHOUT network interceptors
 * (`RealCall`: `if (!forWebSocket) interceptors += client.networkInterceptors`),
 * so none of the library's per-hop checks see it — in particular not
 * [CrossOriginRedirectGuard]. A `302` on the upgrade request therefore took
 * the app's `Cookie`, its API key, the headers of its interceptors and the
 * `PinVault-Token` to whatever origin the `Location` named. Browsers never
 * follow a redirect on a WebSocket handshake; for a hop to another origin
 * (scheme, host or port) neither does a client the library configured.
 * Redirects on the same origin are followed as before.
 *
 * How, without a network interceptor: this application interceptor marks
 * the thread while an upgrade request is inside `proceed()` — every hop of a
 * call runs on that thread — and the cookie jar the library wraps
 * ([HopWatchingCookieJar]) is asked for cookies by OkHttp's bridge at the
 * start of EVERY hop, before a connection is looked for. When a hop leaves
 * the origin of the upgrade's first hop, the jar cancels the call and hands
 * out no cookies; OkHttp then fails the hop with "Canceled" before it
 * connects (`ExchangeFinder.findConnection`, and again in
 * `RealCall.initExchange` before any header is written). Nothing reaches
 * the other origin. The interceptor turns that into an [IOException] that
 * says what happened; a WebSocket listener gets it in `onFailure`.
 *
 * Should the app have replaced the cookie jar after `applyTo`, the wrapper
 * is gone and the hop is not stopped. The upgrade is still failed afterwards
 * (the response's chain of prior responses shows a hop to another origin),
 * so no socket to the other origin is handed to the app — but its headers
 * went there. Set the cookie jar before `applyTo`.
 */
internal object WebSocketUpgradeGuard : Interceptor {

    /** The upgrade the current thread is carrying down the chain. */
    private class Upgrade(val call: Call) {
        /** Where the first hop went: the request after all of the app's interceptors. */
        var origin: HttpUrl? = null
        /** The hop that left [origin] and was stopped. */
        var refusedHop: HttpUrl? = null
    }

    private val upgrades = ThreadLocal<Upgrade?>()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (!isUpgrade(request)) return chain.proceed(request)

        val outer = upgrades.get()
        val upgrade = Upgrade(chain.call())
        upgrades.set(upgrade)
        val response = try {
            chain.proceed(request)
        } catch (e: IOException) {
            // The "Canceled" OkHttp raised after the jar stopped the hop.
            upgrade.refusedHop?.let { throw refusal(upgrade.origin ?: request.url, it, e) }
            throw e
        } finally {
            upgrades.set(outer)
        }
        upgrade.refusedHop?.let {
            response.close()
            throw refusal(upgrade.origin ?: request.url, it, null)
        }
        // The belt: without the jar wrapper the hops were not watched. The
        // chain of prior responses holds every hop of this pass, the cached
        // ones included, newest first.
        var hop: Response? = response
        var first = response.request.url
        while (hop != null) {
            first = hop.request.url
            hop = hop.priorResponse
        }
        hop = response
        while (hop != null) {
            val url = hop.request.url
            if (!CrossOriginRedirectGuard.sameOrigin(first, url)) {
                response.close()
                chain.call().cancel()
                Timber.e(
                    "WebSocket upgrade for %s:%d was redirected to %s:%d and the hop was not stopped " +
                        "(the builder's CookieJar was replaced after applyTo) — the upgrade is failed",
                    first.host, first.port, url.host, url.port
                )
                throw refusal(first, url, null)
            }
            hop = hop.priorResponse
        }
        return response
    }

    /**
     * Called by [HopWatchingCookieJar] at the start of every hop. True when
     * the hop belongs to an upgrade and leaves its origin: the call is
     * cancelled here, and the jar must hand out nothing for it.
     */
    fun stopsHop(url: HttpUrl): Boolean {
        val upgrade = upgrades.get() ?: return false
        val origin = upgrade.origin ?: run {
            upgrade.origin = url
            return false
        }
        if (CrossOriginRedirectGuard.sameOrigin(origin, url)) return false
        upgrade.refusedHop = url
        // Before the bridge goes on: the hop fails with "Canceled" when it
        // looks for a connection, ahead of any byte to the other origin.
        upgrade.call.cancel()
        return true
    }

    private fun isUpgrade(request: Request): Boolean =
        request.headers("Upgrade").any { it.trim().equals("websocket", ignoreCase = true) }

    private fun refusal(origin: HttpUrl, hop: HttpUrl, cause: IOException?) = IOException(
        "WebSocket upgrade for ${origin.host}:${origin.port} was redirected to another origin " +
            "(${hop.scheme}://${hop.host}:${hop.port}); a WebSocket handshake does not follow such a redirect",
        cause
    )
}

/**
 * The cookie jar of a client the library configured: the app's own jar, and
 * the one place that hears of every hop of every call before it starts —
 * OkHttp's bridge asks it for cookies ahead of the cache and the network,
 * for WebSocket upgrades too. [WebSocketUpgradeGuard] stops a hop here;
 * [CrossOriginRedirectGuard] learns where a call really starts.
 */
internal class HopWatchingCookieJar(internal val delegate: CookieJar) : CookieJar {

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        CrossOriginRedirectGuard.onHop(url)
        val cookies = if (WebSocketUpgradeGuard.stopsHop(url)) emptyList() else delegate.loadForRequest(url)
        // The only Cookie a hop to another origin may carry (see CrossOriginRedirectGuard).
        CrossOriginRedirectGuard.onJarCookies(url, cookies)
        return cookies
    }

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) = delegate.saveFromResponse(url, cookies)
}

/**
 * Installs what keeps a client's requests where they were sent, the one
 * implementation behind `applyTo` and — through
 * [io.github.umutcansu.pinvault.internal.BridgeNetworking] — the bridges:
 *
 *  - both halves of [CrossOriginRedirectGuard] and [WebSocketUpgradeGuard]
 *    (each once, however often a builder comes by);
 *  - with [httpsOnly], the builder's TLS connection specs only: a pin is
 *    checked in a TLS handshake, and a request that goes out as plain HTTP is
 *    checked by nothing. The app's own TLS specs stay (it may have narrowed
 *    cipher suites or versions); OkHttp's default list is MODERN_TLS +
 *    CLEARTEXT, of which MODERN_TLS stays. Nothing is widened;
 *  - with [wrapCookieJar], [HopWatchingCookieJar] around the jar the builder
 *    has. A jar that is wrapped already stays as it is.
 *
 * A builder does not show what it holds; a client built from it does. So
 * for the last two a client is built here: the builder needs its
 * `sslSocketFactory` by then.
 */
internal fun OkHttpClient.Builder.hardenHops(httpsOnly: Boolean, wrapCookieJar: Boolean) {
    if (WebSocketUpgradeGuard !in interceptors()) addInterceptor(WebSocketUpgradeGuard)
    if (CrossOriginRedirectGuard.applicationSide !in interceptors()) addInterceptor(CrossOriginRedirectGuard.applicationSide)
    if (CrossOriginRedirectGuard !in networkInterceptors()) addNetworkInterceptor(CrossOriginRedirectGuard)
    if (!httpsOnly && !wrapCookieJar) return

    val asConfigured = build()
    if (httpsOnly) {
        connectionSpecs(asConfigured.connectionSpecs.filter { it.isTls }.ifEmpty { listOf(okhttp3.ConnectionSpec.MODERN_TLS) })
    }
    val jar = asConfigured.cookieJar
    if (wrapCookieJar && jar !is HopWatchingCookieJar) cookieJar(HopWatchingCookieJar(jar))
}
