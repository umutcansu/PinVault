package io.github.umutcansu.pinvault.reactnative

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * PinVaultNetworking's mechanics, with `PinVault.applyTo` replaced by a fake
 * that installs a recognisable socket factory and interceptors.
 */
class NetworkPinningTest {

    private val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(null as java.security.KeyStore?) }.trustManagers.first() as X509TrustManager
    private val pinnedFactory = RecordingFactory(SSLContext.getDefault().socketFactory)
    private val marker = Interceptor { it.proceed(it.request().newBuilder().header("X-Pinned", "1").build()) }
    private val networkMarker = Interceptor { it.proceed(it.request()) }
    private var applied = 0
    private val cache = okhttp3.Cache(java.io.File(System.getProperty("java.io.tmpdir"), "pv-rn-test-cache"), 1024 * 1024)
    /** `android:debuggable` off; the tests speak plain http to MockWebServer, so most run as a debug build. */
    private var release = false
    private val pinning = NetworkPinning(
        applier = { b ->
            applied++
            b.sslSocketFactory(pinnedFactory, tm).addInterceptor(marker).addNetworkInterceptor(networkMarker)
        },
        httpCache = { cache },
        httpsOnly = { release },
    )

    @Test fun `before start an https request through RN's networking is refused`() {
        val builder = OkHttpClient.Builder()
        pinning.configurePerRequest(builder)
        try {
            builder.build().newCall(Request.Builder().url("https://example.invalid/").build()).execute()
            fail("not refused")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("PinVault has not started"))
        }
        assertEquals(0, applied)
    }

    @Test fun `plain http is left alone (Metro in debug builds)`() {
        val server = MockWebServer().apply { enqueue(MockResponse().setBody("metro")); start() }
        try {
            val builder = OkHttpClient.Builder()
            pinning.configurePerRequest(builder)
            val body = builder.build().newCall(Request.Builder().url(server.url("/status")).build()).execute().body!!.string()
            assertEquals("metro", body)
        } finally {
            server.shutdown()
        }
    }

    @Test fun `after start every request gets the pinned factory and interceptors of one template`() {
        pinning.activate()
        val base = OkHttpClient.Builder().build()
        val first = base.newBuilder().also(pinning::configurePerRequest).build()
        val second = base.newBuilder().also(pinning::configurePerRequest).build()
        assertSame(pinnedFactory, first.sslSocketFactory)
        // The same factory instance for every request: OkHttp keeps reusing pooled connections.
        assertSame(first.sslSocketFactory, second.sslSocketFactory)
        assertTrue(marker in first.interceptors && networkMarker in first.networkInterceptors)
        assertEquals(1, applied)
        // Installing the hook after start() works: RN calls it per request.
        val again = first.newBuilder().also(pinning::configurePerRequest).build()
        assertEquals(1, again.interceptors.count { it === marker })
    }

    @Test fun `a new start builds a new template`() {
        pinning.activate()
        pinning.activate()
        assertEquals(2, applied)
        pinning.deactivate()
        val builder = OkHttpClient.Builder()
        pinning.configurePerRequest(builder)
        assertTrue(builder.interceptors().none { it === marker })
    }

    @Test fun `long-lived clients refuse TLS before start and use the pinned factory after`() {
        val client = pinning.configureLongLived(OkHttpClient.Builder()).build()
        val forwarding = client.sslSocketFactory
        try {
            forwarding.createSocket(Socket(), "example.com", 443, true)
            fail("TLS before start")
        } catch (_: SSLHandshakeException) {
        }
        try {
            client.newCall(Request.Builder().url("https://example.invalid/").build()).execute()
            fail("https before start")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("PinVault has not started"))
        }
        pinning.activate()
        runCatching { forwarding.createSocket(Socket(), "example.com", 443, true) }
        assertEquals(1, pinnedFactory.created)
    }

    @Test fun `a WebSocket client is pinned whether RN builds it bare or from the provider's client`() {
        // RN 0.81: WebSocketModule starts from OkHttpClient.Builder(); 0.87: from the
        // provider's client, which configureLongLived already set up — once, not twice.
        val bare = pinning.configureWebSocket(OkHttpClient.Builder()).build()
        val derived = pinning.configureWebSocket(pinning.configureLongLived(OkHttpClient.Builder()).build().newBuilder()).build()
        for (client in listOf(bare, derived)) {
            // The https gate and the library's two guards; the forwarding
            // network interceptor and the library's redirect guard.
            assertEquals(3, client.interceptors.size)
            assertEquals(2, client.networkInterceptors.size)
            try {
                client.newCall(Request.Builder().url("wss://example.invalid/socket").build()).execute()
                fail("wss before start")
            } catch (e: IOException) {
                assertTrue(e.message!!.contains("PinVault has not started"))
            }
        }
        pinning.activate()
        runCatching { derived.sslSocketFactory.createSocket(Socket(), "example.com", 443, true) }
        assertEquals(1, pinnedFactory.created)
    }

    @Test fun `RN's disk cache and cookie jar are off by default, kept on request`() {
        val jar = object : okhttp3.CookieJar {
            override fun saveFromResponse(url: okhttp3.HttpUrl, cookies: List<okhttp3.Cookie>) {}
            override fun loadForRequest(url: okhttp3.HttpUrl): List<okhttp3.Cookie> = emptyList()
        }
        // RN's base client carries its 10 MiB cache and its persistent jar.
        val base = OkHttpClient.Builder().cache(cache).cookieJar(jar).build()
        pinning.activate(NetworkingOptions())
        val plain = base.newBuilder().also(pinning::configurePerRequest).build()
        assertEquals(null, plain.cache)
        assertSame(okhttp3.CookieJar.NO_COOKIES, plain.cookieJar)
        pinning.activate(NetworkingOptions(keepHttpCache = true, keepCookies = true))
        val kept = OkHttpClient.Builder().cookieJar(jar).build().newBuilder().also(pinning::configurePerRequest).build()
        assertSame(cache, kept.cache)
        assertSame(jar, kept.cookieJar)
        // Long-lived clients (WebSocket, images) never get a disk cache.
        assertEquals(null, pinning.configureLongLived(OkHttpClient.Builder().cache(cache)).build().cache)
    }

    @Test fun `https to http redirects are not followed, per request and long-lived`() {
        pinning.activate()
        val perRequest = OkHttpClient.Builder().also(pinning::configurePerRequest).build()
        assertEquals(false, perRequest.followSslRedirects)
        assertEquals(true, perRequest.followRedirects) // same-scheme redirects still are
        assertEquals(false, pinning.configureLongLived(OkHttpClient.Builder()).build().followSslRedirects)
        // Before start too.
        pinning.deactivate()
        assertEquals(false, OkHttpClient.Builder().also(pinning::configurePerRequest).build().followSslRedirects)
    }

    @Test fun `a request built twice before start carries the gate once`() {
        val b = OkHttpClient.Builder()
        pinning.configurePerRequest(b)
        val once = b.interceptors().toList()
        pinning.configurePerRequest(b)
        assertEquals(once, b.interceptors())
        // The gate, and the library's redirect and WebSocket-upgrade guards.
        assertEquals(3, once.size)
    }

    // ── Plain http: a debug build keeps it, a release build does not (review 2026-11-14) ──

    private fun assertCleartextRefused(client: OkHttpClient, server: MockWebServer) {
        try {
            client.newCall(Request.Builder().url(server.url("/api")).build()).execute()
            fail("plain http went out")
        } catch (e: java.net.UnknownServiceException) {
            assertTrue(e.message!!, e.message!!.contains("CLEARTEXT communication not enabled"))
        }
    }

    @Test fun `a release build refuses plain http on every client, before and after start`() {
        release = true
        val server = MockWebServer().apply { start() }
        try {
            // Before start: the hooks are installed when the process starts.
            assertCleartextRefused(OkHttpClient.Builder().also(pinning::configurePerRequest).build(), server)
            val base = pinning.configureLongLived(OkHttpClient.Builder()).build()
            assertCleartextRefused(base, server)
            assertCleartextRefused(pinning.configureWebSocket(OkHttpClient.Builder()).build(), server)

            pinning.activate()
            // RN derives each request from its base client; a bare builder (hooks installed late) is covered too.
            assertCleartextRefused(base.newBuilder().also(pinning::configurePerRequest).build(), server)
            assertCleartextRefused(OkHttpClient.Builder().also(pinning::configurePerRequest).build(), server)
            assertCleartextRefused(pinning.configureWebSocket(base.newBuilder()).build(), server)
            assertEquals("nothing was sent in the clear", 0, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test fun `a release build keeps the TLS specs of React Native's builder`() {
        release = true
        val specs = listOf(okhttp3.ConnectionSpec.RESTRICTED_TLS, okhttp3.ConnectionSpec.CLEARTEXT)
        val client = pinning.configureLongLived(OkHttpClient.Builder().connectionSpecs(specs)).build()
        assertEquals(listOf(okhttp3.ConnectionSpec.RESTRICTED_TLS), client.connectionSpecs)
    }

    @Test fun `a debug build reaches Metro over http after start too, per request and long-lived`() {
        val server = MockWebServer().apply { repeat(3) { enqueue(MockResponse().setBody("metro")) }; start() }
        try {
            pinning.activate()
            val base = pinning.configureLongLived(OkHttpClient.Builder()).build()
            val clients = listOf(
                base,
                base.newBuilder().also(pinning::configurePerRequest).build(),
                pinning.configureWebSocket(base.newBuilder()).build(),
            )
            for (client in clients) {
                assertTrue(okhttp3.ConnectionSpec.CLEARTEXT in client.connectionSpecs)
                assertEquals("metro", client.newCall(Request.Builder().url(server.url("/status")).build()).execute().body!!.string())
            }
        } finally {
            server.shutdown()
        }
    }

    // ── Redirects to another origin (review 2026-11-14) ──

    /** What a socket's listener heard. */
    private class Outcome : okhttp3.WebSocketListener() {
        val done = java.util.concurrent.CountDownLatch(1)
        @Volatile var opened = false
        @Volatile var failure: Throwable? = null
        override fun onOpen(webSocket: okhttp3.WebSocket, response: okhttp3.Response) {
            opened = true
            webSocket.close(1000, null)
            done.countDown()
        }
        override fun onFailure(webSocket: okhttp3.WebSocket, t: Throwable, response: okhttp3.Response?) {
            failure = t
            done.countDown()
        }
        fun await() = apply { assertTrue("the listener heard nothing", done.await(5, java.util.concurrent.TimeUnit.SECONDS)) }
    }

    private val serverSide = object : okhttp3.WebSocketListener() {
        override fun onClosing(webSocket: okhttp3.WebSocket, code: Int, reason: String) { webSocket.close(code, null) }
    }

    /** A socket's client the way WebSocketModule makes it: its own jar first, then the hook, then build. */
    private fun webSocketClient() =
        pinning.configureWebSocket(OkHttpClient.Builder().cookieJar(okhttp3.CookieJar.NO_COOKIES)).build()

    /** The upgrade request as WebSocketModule sends it: RN's cookies and the caller's headers as request headers. */
    private fun upgrade(server: MockWebServer) = Request.Builder().url(server.url("/ws"))
        .header("Cookie", "session=abc").header("Authorization", "Bearer app-token").header("X-Api-Key", "key-123").build()

    @Test fun `a WebSocket handshake redirected to another origin is not followed and nothing is sent there`() {
        val origin = MockWebServer().apply { start() }
        val other = MockWebServer().apply { start() }
        try {
            origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/ws")))
            other.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

            val outcome = Outcome()
            webSocketClient().newWebSocket(upgrade(origin), outcome)
            outcome.await()

            assertEquals(false, outcome.opened)
            assertTrue(outcome.failure!!.message!!, outcome.failure!!.message!!.contains("redirected to another origin"))
            assertEquals("session=abc", origin.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!.getHeader("Cookie"))
            assertEquals("not a byte went to the other origin", 0, other.requestCount)
        } finally {
            origin.shutdown(); other.shutdown()
        }
    }

    @Test fun `a WebSocket that stays on its origin opens, redirected or not`() {
        val origin = MockWebServer().apply { start() }
        try {
            origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", origin.url("/ws-v2")))
            origin.enqueue(MockResponse().withWebSocketUpgrade(serverSide))

            val outcome = Outcome()
            webSocketClient().newWebSocket(upgrade(origin), outcome)
            outcome.await()

            assertTrue("${outcome.failure}", outcome.opened)
            origin.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)
            val landed = origin.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
            assertEquals("/ws-v2", landed.path)
            assertEquals("RN's Cookie header is not replaced by the jar wrapper", "session=abc", landed.getHeader("Cookie"))
        } finally {
            origin.shutdown()
        }
    }

    @Test fun `a fetch redirected to another origin leaves the request's own headers behind`() {
        val origin = MockWebServer().apply { start() }
        val other = MockWebServer().apply { start() }
        try {
            origin.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/landed")))
            other.enqueue(MockResponse().setBody("ok"))
            pinning.activate()
            val client = pinning.configureLongLived(OkHttpClient.Builder()).build().newBuilder().also(pinning::configurePerRequest).build()

            client.newCall(upgrade(origin).newBuilder().header("Accept", "application/json").build()).execute().close()

            assertEquals("key-123", origin.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!.getHeader("X-Api-Key"))
            val landed = other.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)!!
            assertEquals(null, landed.getHeader("X-Api-Key"))
            assertEquals(null, landed.getHeader("Cookie"))
            assertEquals("the template's own interceptor header is the app's too", null, landed.getHeader("X-Pinned"))
            assertEquals("application/json", landed.getHeader("Accept"))
        } finally {
            origin.shutdown(); other.shutdown()
        }
    }

    @Test fun `only a WebSocket's client gets the cookie jar wrapper, the factory's clients keep React Native's jar`() {
        // NetworkingModule reads its CookieJarContainer from the base client's cookieJar by type.
        val jar = object : okhttp3.CookieJar {
            override fun saveFromResponse(url: okhttp3.HttpUrl, cookies: List<okhttp3.Cookie>) {}
            override fun loadForRequest(url: okhttp3.HttpUrl): List<okhttp3.Cookie> = emptyList()
        }
        release = true // the mode in which the hook reads the builder at all
        assertSame(jar, pinning.configureLongLived(OkHttpClient.Builder().cookieJar(jar)).build().cookieJar)
        pinning.activate(NetworkingOptions(keepCookies = true))
        assertSame(jar, OkHttpClient.Builder().cookieJar(jar).also(pinning::configurePerRequest).build().cookieJar)

        val socket = pinning.configureWebSocket(OkHttpClient.Builder().cookieJar(jar)).build()
        assertEquals("HopWatchingCookieJar", socket.cookieJar.javaClass.simpleName)
        // Wrapped once, however often RN's builder comes by.
        val again = pinning.configureWebSocket(socket.newBuilder()).build()
        assertSame(socket.cookieJar, again.cookieJar)
    }

    private class RecordingFactory(private val d: SSLSocketFactory) : SSLSocketFactory() {
        var created = 0
        override fun getDefaultCipherSuites(): Array<String> = d.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites
        override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
            created++
            return d.createSocket(s, host, port, autoClose)
        }
        override fun createSocket(host: String?, port: Int): Socket = d.createSocket(host, port)
        override fun createSocket(host: String?, port: Int, lh: java.net.InetAddress?, lp: Int): Socket = d.createSocket(host, port, lh, lp)
        override fun createSocket(host: java.net.InetAddress?, port: Int): Socket = d.createSocket(host, port)
        override fun createSocket(a: java.net.InetAddress?, p: Int, la: java.net.InetAddress?, lp: Int): Socket = d.createSocket(a, p, la, lp)
    }
}
