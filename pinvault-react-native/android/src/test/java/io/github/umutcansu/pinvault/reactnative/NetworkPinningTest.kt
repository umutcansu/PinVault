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
    private val pinning = NetworkPinning { b ->
        applied++
        b.sslSocketFactory(pinnedFactory, tm).addInterceptor(marker).addNetworkInterceptor(networkMarker)
    }

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
