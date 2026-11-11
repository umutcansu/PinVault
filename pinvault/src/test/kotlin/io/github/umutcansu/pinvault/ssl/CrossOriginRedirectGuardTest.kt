package io.github.umutcansu.pinvault.ssl

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
