package io.github.umutcansu.pinvault.ssl

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Review 2026-11-14: OkHttp runs a WebSocket upgrade without network
 * interceptors, so a 302 on the handshake took the app's cookie, API key and
 * interceptor headers to another origin — the redirect guard never saw it.
 * A handshake redirected to another origin is not followed now, and nothing
 * is sent there. Two MockWebServers on different ports are two origins.
 */
@RunWith(RobolectricTestRunner::class)
class WebSocketUpgradeGuardTest {

    private val origin = MockWebServer()
    private val other = MockWebServer()

    @Before
    fun setUp() { origin.start(); other.start() }

    @After
    fun tearDown() { origin.shutdown(); other.shutdown() }

    /** What the socket's listener heard: opened, or failed with what. */
    private class Outcome : WebSocketListener() {
        val done = CountDownLatch(1)
        @Volatile var opened: Response? = null
        @Volatile var failure: Throwable? = null

        override fun onOpen(webSocket: WebSocket, response: Response) {
            opened = response
            webSocket.close(1000, null)
            done.countDown()
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            failure = t
            done.countDown()
        }

        fun await() = apply { assertTrue("the listener heard nothing", done.await(5, TimeUnit.SECONDS)) }
    }

    /** The server's end of a socket: answers the client's close, so the server can shut down. */
    private val serverSide = object : WebSocketListener() {
        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(code, null)
        }
    }

    /** The app's jar: one cookie per host, so a test can tell whose cookie went where. */
    private val appJar = object : CookieJar {
        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {}
        override fun loadForRequest(url: HttpUrl): List<Cookie> =
            listOf(Cookie.Builder().name("jar").value("port-${url.port}").domain(url.host).build())
    }

    /** A builder the way `applyTo` leaves it as far as hops go, with an app interceptor that adds a credential. */
    private fun builder() = OkHttpClient.Builder()
        .addInterceptor { chain -> chain.proceed(chain.request().newBuilder().header("X-App-Session", "s3cr3t").build()) }
        .cookieJar(appJar)
        .apply { hardenHops(httpsOnly = false, wrapCookieJar = true) }

    private fun upgradeRequest(url: HttpUrl) = Request.Builder().url(url)
        .header("X-API-Key", "key-123")
        .header("PinVault-Token", "token-abc")
        .build()

    @Test
    fun `an upgrade redirected to another origin is not followed and nothing reaches that origin`() {
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/ws")))
        other.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

        val outcome = Outcome()
        builder().build().newWebSocket(upgradeRequest(origin.url("/ws")), outcome)
        outcome.await()

        assertNull("the socket must not open on the other origin", outcome.opened)
        val failure = outcome.failure!!
        assertTrue(failure.message, failure.message!!.contains("redirected to another origin"))
        assertTrue(failure.message, failure.message!!.contains("${other.hostName}:${other.port}"))
        assertEquals("the origin got the handshake, with the app's headers", "key-123", origin.takeRequest(1, TimeUnit.SECONDS)!!.getHeader("X-API-Key"))
        assertNull("no request at all went to the other origin", other.takeRequest(500, TimeUnit.MILLISECONDS))
        assertEquals(0, other.requestCount)
    }

    @Test
    fun `an upgrade redirected on its own origin still opens`() {
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", origin.url("/ws-v2")))
        origin.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

        val outcome = Outcome()
        builder().build().newWebSocket(upgradeRequest(origin.url("/ws")), outcome)
        outcome.await()

        assertNull("${outcome.failure}", outcome.failure)
        assertNotNull(outcome.opened)
        origin.takeRequest(1, TimeUnit.SECONDS)
        val landed = origin.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("/ws-v2", landed.path)
        assertEquals("key-123", landed.getHeader("X-API-Key"))
        assertEquals("token-abc", landed.getHeader("PinVault-Token"))
        assertEquals("the app's cookie jar still serves the upgrade", "jar=port-${origin.port}", landed.getHeader("Cookie"))
    }

    @Test
    fun `an upgrade that is not redirected opens as before`() {
        origin.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

        val outcome = Outcome()
        builder().build().newWebSocket(upgradeRequest(origin.url("/ws")), outcome)
        outcome.await()

        assertNull("${outcome.failure}", outcome.failure)
        assertEquals(101, outcome.opened!!.code)
    }

    @Test
    fun `an ordinary call through the same client still follows a redirect to another origin`() {
        // Not an upgrade: followed, with the redirect guard's rules (the
        // app's headers stay behind, the jar's cookie for the new host goes).
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/landed")))
        other.enqueue(MockResponse().setBody("ok"))

        builder().build().newCall(upgradeRequest(origin.url("/start")).newBuilder().removeHeader("PinVault-Token").build())
            .execute().use { assertEquals(200, it.code) }

        val landed = other.takeRequest(1, TimeUnit.SECONDS)!!
        assertNull(landed.getHeader("X-API-Key"))
        assertNull(landed.getHeader("X-App-Session"))
        assertEquals("jar=port-${other.port}", landed.getHeader("Cookie"))
    }

    @Test
    fun `an interceptor added after applyTo may send the upgrade to another host`() {
        // The origin of an upgrade is where its first hop goes, after all of
        // the app's interceptors — not a redirect.
        val client = builder()
            .addInterceptor { chain -> chain.proceed(chain.request().newBuilder().url(other.url("/ws")).build()) }
            .build()
        other.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

        val outcome = Outcome()
        client.newWebSocket(upgradeRequest(origin.url("/ws")), outcome)
        outcome.await()

        assertNull("${outcome.failure}", outcome.failure)
        assertEquals(0, origin.requestCount)
    }

    @Test
    fun `with the cookie jar replaced after applyTo the redirected upgrade is still failed`() {
        // The wrapper is gone, so the hop is not stopped before it is sent —
        // but the app is not handed a socket to the other origin.
        val client = builder().cookieJar(appJar).build()
        origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/ws")))
        other.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

        val outcome = Outcome()
        client.newWebSocket(upgradeRequest(origin.url("/ws")), outcome)
        outcome.await()

        assertNull(outcome.opened)
        assertTrue(outcome.failure!!.message, outcome.failure!!.message!!.contains("redirected to another origin"))
    }

    @Test
    fun `applyTo wraps the builder's cookie jar once and keeps it`() {
        val builder = OkHttpClient.Builder().cookieJar(appJar)
        val manager = DynamicSSLManager()
        manager.applyTo(builder) { null }
        manager.applyTo(builder) { null }

        val jar = builder.build().cookieJar
        assertTrue("$jar", jar is HopWatchingCookieJar)
        assertSame("wrapped once, around the app's own jar", appJar, (jar as HopWatchingCookieJar).delegate)
        assertEquals("jar=port-443", jar.loadForRequest(HttpUrl.Builder().scheme("https").host("example.test").build()).joinToString { "${it.name}=${it.value}" })
    }
}
