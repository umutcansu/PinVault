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
    private val pinning = NetworkPinning(
        applier = { b ->
            applied++
            b.sslSocketFactory(pinnedFactory, tm).addInterceptor(marker).addNetworkInterceptor(networkMarker)
        },
        httpCache = { cache },
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
        val bare = pinning.configureLongLived(OkHttpClient.Builder()).build()
        val derived = pinning.configureLongLived(bare.newBuilder()).build()
        for (client in listOf(bare, derived)) {
            assertEquals(1, client.interceptors.size)
            assertEquals(1, client.networkInterceptors.size)
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
        pinning.configurePerRequest(b)
        assertEquals(1, b.interceptors().size)
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
