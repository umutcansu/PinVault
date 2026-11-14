package io.github.umutcansu.pinvault.ssl

import okhttp3.Cache
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/**
 * Review 2026-11-12: on Android an app's own headers (a session cookie, an
 * API key, what its interceptor adds) and a 307 body followed a redirect to
 * another origin; OkHttp drops only Authorization. iOS kept them back.
 * Two MockWebServers on different ports are two origins.
 */
@RunWith(RobolectricTestRunner::class)
class CrossOriginRedirectGuardTest {

    private val origin = MockWebServer()
    private val other = MockWebServer()

    @Before
    fun setUp() { origin.start(); other.start() }

    @After
    fun tearDown() { origin.shutdown(); other.shutdown() }

    private fun client(jar: CookieJar = CookieJar.NO_COOKIES) = OkHttpClient.Builder()
        // An app interceptor adds its own credential, as many do.
        .addInterceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-App-Session", "s3cr3t").build()) }
        .addNetworkInterceptor(CrossOriginRedirectGuard)
        .cookieJar(jar)
        .build()

    private fun request(url: HttpUrl) = Request.Builder().url(url)
        .header("Cookie", "session=abc")
        .header("X-API-Key", "key-123")
        .header("Accept", "application/json")

    @Test
    fun `a redirect to another origin drops the app's headers and keeps the neutral ones`() {
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/landed")))
        other.enqueue(MockResponse().setBody("ok"))

        client().newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }

        val first = origin.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("key-123", first.getHeader("X-API-Key"))
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("Cookie"))
        assertNull(landed.getHeader("X-API-Key"))
        assertNull(landed.getHeader("X-App-Session"))
        assertEquals("application/json", landed.getHeader("Accept"))
    }

    @Test
    fun `a redirect on the same origin keeps every header`() {
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", origin.url("/landed")))
        origin.enqueue(MockResponse().setBody("ok"))

        client().newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }

        origin.takeRequest(1, TimeUnit.SECONDS)
        val landed = origin.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("session=abc", landed.getHeader("Cookie"))
        assertEquals("key-123", landed.getHeader("X-API-Key"))
        assertEquals("s3cr3t", landed.getHeader("X-App-Session"))
    }

    @Test
    fun `a 307 does not send the body to another origin`() {
        origin.enqueue(MockResponse().setResponseCode(307).setHeader("Location", other.url("/landed")))

        val call = client().newCall(request(origin.url("/start")).post("secret-body".toRequestBody("text/plain".toMediaType())).build())
        val failure = runCatching { call.execute().close() }.exceptionOrNull()
        assertTrue("expected an IOException, got $failure", failure is IOException)
        assertTrue(failure!!.message!!.contains("request body to another origin"))
        assertEquals(0, other.requestCount)
    }

    // ── Both halves, as applyTo installs them (review 2026-11-14) ──

    private val cacheDir = Files.createTempDirectory("redirect-guard-cache").toFile()

    @After
    fun deleteCache() { cacheDir.deleteRecursively() }

    /**
     * A builder the way `applyTo` leaves it as far as redirects go: the app's
     * interceptor from before the call, then the guards. [afterApplyTo] is
     * what an app adds to its builder afterwards.
     */
    private fun guarded(cache: Boolean = false, afterApplyTo: OkHttpClient.Builder.() -> Unit = {}): OkHttpClient =
        OkHttpClient.Builder()
            .addInterceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-App-Session", "s3cr3t").build()) }
            .apply { hardenHops(httpsOnly = false, wrapCookieJar = true) }
            .apply { if (cache) cache(Cache(cacheDir, 1L shl 20)) }
            .apply(afterApplyTo)
            .build()

    private fun cachedRedirect() = MockResponse().setResponseCode(301)
        .setHeader("Location", other.url("/landed"))
        .setHeader("Cache-Control", "max-age=3600")

    @Test
    fun `a redirect answered from the cache does not make its target the origin`() {
        val client = guarded(cache = true)
        origin.enqueue(cachedRedirect())
        other.enqueue(MockResponse().setBody("ok"))
        other.enqueue(MockResponse().setBody("ok"))

        client.newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }
        assertNull(other.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-API-Key"))

        // The second call never reaches the origin: the 301 comes from the
        // cache and the redirect target is the call's first network hop.
        client.newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }

        assertEquals("the redirect was answered from the cache", 1, origin.requestCount)
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("X-API-Key"))
        assertNull(landed.getHeader("Cookie"))
        assertNull(landed.getHeader("X-App-Session"))
        assertEquals("application/json", landed.getHeader("Accept"))
    }

    @Test
    fun `a cached redirect does not carry what an interceptor added after applyTo sends either`() {
        // Nothing saw this header on its way to the origin: the application-side
        // half sits before the interceptor, and no request went on the wire there.
        val client = guarded(cache = true) {
            addInterceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-Late", "added-later").build()) }
        }
        origin.enqueue(cachedRedirect())
        other.enqueue(MockResponse().setBody("ok"))
        other.enqueue(MockResponse().setBody("ok"))

        client.newCall(request(origin.url("/start")).build()).execute().close()
        assertNull(other.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-Late"))
        client.newCall(request(origin.url("/start")).build()).execute().close()

        assertEquals(1, origin.requestCount)
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("X-Late"))
        assertNull(landed.getHeader("X-API-Key"))
        assertEquals("application/json", landed.getHeader("Accept"))
    }

    @Test
    fun `a header whose value changed between two attempts of a call is dropped too`() {
        // A session header refreshed after a 401, by an interceptor of the
        // app: the redirect that follows carries the NEW value, which is not
        // the one the call started with.
        val client = guarded {
            addInterceptor { chain ->
                val first = chain.proceed(chain.request().newBuilder().header("X-Session", "stale").build())
                if (first.code != 401) return@addInterceptor first
                first.close()
                chain.proceed(chain.request().newBuilder().header("X-Session", "refreshed").build())
            }
        }
        origin.enqueue(MockResponse().setResponseCode(401))
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/landed")))
        other.enqueue(MockResponse().setBody("ok"))

        client.newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }

        assertEquals("stale", origin.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-Session"))
        assertEquals("refreshed", origin.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-Session"))
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("X-Session"))
        assertNull(landed.getHeader("X-API-Key"))
    }

    @Test
    fun `a retry by an interceptor outside the guard is judged with its new values`() {
        // Outside = added before applyTo: the application-side half sees each pass.
        var attempt = 0
        val client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                val first = chain.proceed(chain.request().newBuilder().header("X-Session", "attempt-${++attempt}").build())
                if (first.code != 401) return@addInterceptor first
                first.close()
                chain.proceed(chain.request().newBuilder().header("X-Session", "attempt-${++attempt}").build())
            }
            .apply { hardenHops(httpsOnly = false, wrapCookieJar = true) }
            .cache(Cache(cacheDir, 1L shl 20))
            .build()
        // The 401 is not cached, the redirect is: the second pass of the
        // second call goes straight to the other origin.
        origin.enqueue(cachedRedirect())
        other.enqueue(MockResponse().setBody("ok"))
        client.newCall(request(origin.url("/start")).build()).execute().close()
        other.takeRequest(1, TimeUnit.SECONDS)

        other.enqueue(MockResponse().setResponseCode(401))
        other.enqueue(MockResponse().setBody("ok"))
        client.newCall(request(origin.url("/start")).build()).execute().use { assertEquals(200, it.code) }

        assertEquals(1, origin.requestCount)
        assertNull(other.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-Session"))
        assertNull("the value of the second pass is the app's as well", other.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-Session"))
    }

    @Test
    fun `an interceptor added after applyTo may send the request to another host`() {
        // A base-URL switch, say. The first hop OkHttp starts is the request
        // after ALL application interceptors: that is the origin, not a
        // redirect target, and it gets the headers and the body.
        val client = guarded {
            addInterceptor { chain -> chain.proceed(chain.request().newBuilder().url(other.url("/moved")).build()) }
        }
        other.enqueue(MockResponse().setBody("ok"))

        val call = client.newCall(request(origin.url("/start")).post("body".toRequestBody("text/plain".toMediaType())).build())
        call.execute().use { assertEquals(200, it.code) }

        assertEquals(0, origin.requestCount)
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("key-123", landed.getHeader("X-API-Key"))
        assertEquals("s3cr3t", landed.getHeader("X-App-Session"))
        assertEquals("body", landed.body.readUtf8())
    }

    @Test
    fun `applyTo installs both halves and keeps the app's cookie jar working`() {
        val jar = object : CookieJar {
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {}
            override fun loadForRequest(url: HttpUrl): List<Cookie> =
                listOf(Cookie.Builder().name(if (url.port == other.port) "theirs" else "ours").value("1").domain(url.host).build())
        }
        val builder = OkHttpClient.Builder().cookieJar(jar).cache(Cache(cacheDir, 1L shl 20))
        DynamicSSLManager().applyTo(builder) { null }
        // MockWebServer speaks plain HTTP here; applyTo took cleartext off.
        val client = builder.connectionSpecs(listOf(okhttp3.ConnectionSpec.MODERN_TLS, okhttp3.ConnectionSpec.CLEARTEXT)).build()
        origin.enqueue(cachedRedirect())
        other.enqueue(MockResponse().setBody("ok"))
        other.enqueue(MockResponse().setBody("ok"))

        client.newCall(Request.Builder().url(origin.url("/start")).header("X-API-Key", "key-123").build()).execute().close()
        assertEquals("ours=1", origin.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("Cookie"))
        other.takeRequest(1, TimeUnit.SECONDS)
        client.newCall(Request.Builder().url(origin.url("/start")).header("X-API-Key", "key-123").build()).execute().close()

        assertEquals(1, origin.requestCount)
        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("X-API-Key"))
        assertEquals("the jar's cookie for that host is OkHttp's own for the hop", "theirs=1", landed.getHeader("Cookie"))
    }

    @Test
    fun `cookies the jar holds for the new host still go there`() {
        val jar = object : CookieJar {
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {}
            override fun loadForRequest(url: HttpUrl): List<Cookie> =
                if (url.port == other.port) listOf(Cookie.Builder().name("theirs").value("1").domain(url.host).build()) else emptyList()
        }
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/landed")))
        other.enqueue(MockResponse().setBody("ok"))

        // No Cookie set by the app here: the jar's cookie for the other host is OkHttp's own for that hop.
        client(jar).newCall(Request.Builder().url(origin.url("/start")).build()).execute().close()

        origin.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("theirs=1", other.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("Cookie"))
    }
}
