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
 * ## Two halves (review 2026-11-14)
 * The guard used to be this network interceptor alone and took "the origin"
 * and "the app's headers" from the call's first NETWORK hop. Two things got
 * past that:
 *  - a redirect answered from the client's `Cache` (a 301/308 with a
 *    lifetime): the call's first network hop is then the redirect TARGET, so
 *    the target was taken for the origin and got every header;
 *  - a header whose value changed between two attempts of one call (a
 *    session header refreshed after a 401): only the first attempt's value
 *    was known, the refreshed one travelled on.
 *
 * So there is an application-side half now ([applicationSide], installed
 * with this one by [hardenHops]). It sees the request as the application's
 * interceptor chain hands it down — before the cache — and records, per
 * call, where the request is going and which headers it carries, every time
 * it passes (an interceptor further out may retry with new values). The
 * cookie jar wrapper ([HopWatchingCookieJar]) refines the origin to the first
 * hop OkHttp actually starts, which is the request after ALL of the app's
 * interceptors, also those added to the builder after `applyTo`.
 *
 * As a network interceptor this half sees every hop that goes on the wire.
 * A hop to the call's origin adds its headers to what is known as the
 * app's. On a hop to another origin (scheme, host or port) every header that
 * carries a value seen before on this call is removed — it is the app's,
 * carried over — except [NEUTRAL] ones. What OkHttp makes for the new hop
 * itself (`Host`, cookies the cookie jar holds for the new host) differs and
 * stays. A body is not sent to another origin: the hop fails with an
 * [IOException] instead.
 *
 * When a pass never reached its origin on the wire (the cached redirect),
 * the headers of interceptors added after `applyTo` were never seen. Nothing
 * says then which headers are the app's, so only [NEUTRAL] headers and the
 * ones OkHttp's own layers write per hop ([PER_HOP]) are kept.
 *
 * Same-origin redirects are untouched. `PinVault-Token` / `-Proof` are
 * dropped by their own interceptor already. WebSocket upgrades never pass a
 * network interceptor; [WebSocketUpgradeGuard] covers them.
 */
internal object CrossOriginRedirectGuard : Interceptor {

    /** Headers that say nothing about who the caller is: kept on any hop. */
    internal val NEUTRAL = setOf("accept", "accept-language", "user-agent", "accept-encoding", "connection", "host")

    /**
     * Headers OkHttp's bridge and cache write for each hop on their own: the
     * jar's cookies for the hop's URL, the validators of a cached response
     * for it. Kept on a hop to another origin unless they carry a value the
     * app sent (then it is the app's `Cookie`, not the jar's).
     */
    private val PER_HOP = setOf("cookie", "if-none-match", "if-modified-since")

    /** Distinct values remembered per header name; a header that changes more often is dropped whatever it says. */
    private const val MAX_VALUES_PER_HEADER = 8

    /** What is known about one call: where it is going and the header values it carried there. */
    internal class Trail(origin: HttpUrl) {
        @Volatile
        var origin: HttpUrl = origin
            private set

        /** True once a request of the current pass went to [origin] on the wire. */
        @Volatile
        var reachedOrigin = false

        /** Lower-case header name → the value lists seen under it. */
        private val seen = HashMap<String, MutableSet<List<String>>>()

        /** Names with more distinct values than are kept: dropped on a cross-origin hop whatever the value. */
        private val volatileNames = HashSet<String>()

        /**
         * A pass down the application's chain starts, for [url]. Nothing of
         * it has been on the wire yet — what an earlier pass sent there says
         * nothing about the headers the inner interceptors add this time.
         */
        fun startPass(url: HttpUrl) {
            reachedOrigin = false
            origin = url
        }

        /** The first hop of the pass is known: requests of the call go to [url] from here on. */
        fun headFor(url: HttpUrl) {
            if (!sameOrigin(origin, url)) reachedOrigin = false
            origin = url
        }

        @Synchronized
        fun remember(headers: Headers) {
            for (name in headers.names()) {
                val key = name.lowercase()
                if (key in NEUTRAL || key in volatileNames) continue
                val values = seen.getOrPut(key) { HashSet() }
                values.add(headers.values(name))
                if (values.size > MAX_VALUES_PER_HEADER) {
                    // Fail closed rather than forget a value: a header that
                    // takes a new value on every attempt is the app's.
                    seen.remove(key)
                    volatileNames += key
                }
            }
        }

        /** True when [name] with [values] was sent by the app on this call. */
        @Synchronized
        fun carried(name: String, values: List<String>): Boolean {
            val key = name.lowercase()
            return key in volatileNames || seen[key]?.contains(values) == true
        }
    }

    private val trails: MutableMap<Call, Trail> = Collections.synchronizedMap(WeakHashMap())

    /** The pass the current thread is carrying down the chain; see [applicationSide]. */
    private class Pass(val trail: Trail) {
        var firstHopSeen = false
    }

    private val passes = ThreadLocal<Pass?>()

    /**
     * The application-side half: records the call's destination and headers
     * before the cache or the network sees the request. Every pass counts —
     * an interceptor outside this one may send the request again with other
     * values, or to another host — and every pass's headers stay on record.
     */
    val applicationSide: Interceptor = Interceptor { chain ->
        val request = chain.request()
        val trail = synchronized(trails) {
            trails[chain.call()] ?: Trail(request.url).also { trails[chain.call()] = it }
        }
        trail.startPass(request.url)
        trail.remember(request.headers)
        // All hops of this pass run on this thread, inside proceed(): the
        // cookie jar wrapper finds the pass here. Restored afterwards, for an
        // interceptor that makes a call of its own on the same thread.
        val outer = passes.get()
        passes.set(Pass(trail))
        try {
            chain.proceed(request)
        } finally {
            passes.set(outer)
        }
    }

    /**
     * Called by [HopWatchingCookieJar] for every hop OkHttp starts (cached or
     * not). The first one of a pass is the request as the LAST application
     * interceptor left it: an interceptor added after `applyTo` may have sent
     * it to another host than the one [applicationSide] saw, and that host is
     * then the origin — not a redirect target.
     */
    fun onHop(url: HttpUrl) {
        val pass = passes.get() ?: return
        if (pass.firstHopSeen) return
        pass.firstHopSeen = true
        pass.trail.headFor(url)
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val call = chain.call()
        // Without the application-side half (a client that carries only this
        // interceptor): the call's own request is the application's.
        val trail = synchronized(trails) {
            trails[call] ?: Trail(call.request().url).also {
                it.remember(call.request().headers)
                trails[call] = it
            }
        }
        val origin = trail.origin
        if (sameOrigin(origin, request.url)) {
            trail.reachedOrigin = true
            trail.remember(request.headers)
            return chain.proceed(request)
        }

        if (request.body != null) {
            throw IOException(
                "Not following a redirect from ${origin.host}:${origin.port} to ${request.url.host}:${request.url.port}: " +
                    "it would send the request body to another origin"
            )
        }
        val reachedOrigin = trail.reachedOrigin
        val dropped = request.headers.names().filter { name ->
            val key = name.lowercase()
            key !in NEUTRAL && (trail.carried(name, request.headers.values(name)) || (!reachedOrigin && key !in PER_HOP))
        }
        if (dropped.isEmpty()) return chain.proceed(request)
        if (reachedOrigin) {
            Timber.d("Redirect to another origin (%s:%d): dropped %d header(s) of the request", request.url.host, request.url.port, dropped.size)
        } else {
            // Worth a warning: besides a cached redirect this is what an
            // interceptor that rewrites the URL looks like when it was added
            // after applyTo AND the builder's cookie jar was replaced after
            // applyTo (the wrapper that tells the two apart is gone).
            Timber.w(
                "Request for %s:%d goes to %s:%d without having reached its origin on the network (a redirect answered " +
                    "from the cache; or an interceptor added after applyTo rewrites the URL while the builder's " +
                    "CookieJar was replaced after applyTo) — dropped %d header(s)",
                origin.host, origin.port, request.url.host, request.url.port, dropped.size
            )
        }
        val stripped = request.newBuilder().apply { dropped.forEach { removeHeader(it) } }.build()
        return chain.proceed(stripped)
    }

    internal fun sameOrigin(a: HttpUrl, b: HttpUrl): Boolean =
        a.scheme == b.scheme && a.host.equals(b.host, ignoreCase = true) && a.port == b.port
}
