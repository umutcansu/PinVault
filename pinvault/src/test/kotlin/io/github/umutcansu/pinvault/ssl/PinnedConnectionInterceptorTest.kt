package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigExpiredException
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import io.github.umutcansu.pinvault.util.TestCertUtil
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.security.KeyStore
import java.security.cert.CertificateException
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException

/**
 * Real connections against a self-signed MockWebServer: a connection that
 * was opened under one config must not carry requests once the pins that
 * admitted it are gone or the config has expired — the trust manager is not
 * asked again for a pooled connection, the network interceptor is.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class PinnedConnectionInterceptorTest {

    private val password = "changeit"
    private val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
    private val otherPin = TestCertUtil.generateSelfSigned(cn = "rotated").sha256Pin
    private lateinit var server: MockWebServer
    private lateinit var manager: DynamicSSLManager
    private var now = 1_800_000_000_000L
    private val hour = 3_600_000L

    @Before
    fun setUp() {
        manager = DynamicSSLManager().also { it.clock = { now } }
        server = MockWebServer()
        val ks = KeyStore.getInstance("PKCS12").apply { load(serverCert.p12Bytes.inputStream(), password.toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password.toCharArray()) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        server.useHttps(ctx.socketFactory, false)
        server.start()
    }

    @After
    fun tearDown() = server.shutdown()

    private fun matching(expiresAt: Long = 0L) = CertificateConfig(
        version = 1,
        pins = listOf(HostPin(server.hostName, listOf(serverCert.sha256Pin, serverCert.sha256Pin), version = 1)),
        expiresAt = expiresAt
    )

    /** The server's pin has been rotated away: the host is still pinned, to other keys. */
    private fun rotated() = CertificateConfig(
        version = 2,
        pins = listOf(HostPin(server.hostName, listOf(otherPin, otherPin), version = 2))
    )

    private fun get(client: OkHttpClient): Int {
        server.enqueue(MockResponse().setBody("ok"))
        return client.newCall(Request.Builder().url(server.url("/")).build()).execute().use {
            it.body?.string()
            it.code
        }
    }

    private fun assertRefused(client: OkHttpClient): IOException = try {
        get(client)
        throw AssertionError("the request should have been refused")
    } catch (e: IOException) {
        // The enqueued response was not consumed; drop it for the next call.
        e
    }

    /** A client the app builds itself: the library never touches its connection pool. */
    private fun appClient(config: () -> CertificateConfig?): OkHttpClient =
        OkHttpClient.Builder().hostnameVerifier { _, _ -> true }.also { manager.applyTo(it, config) }.build()

    @Test
    fun `a pooled connection is refused once its pin is gone, and closed`() {
        var live: CertificateConfig? = matching()
        val client = appClient { live }
        assertEquals(200, get(client))
        assertEquals(0, server.takeRequest().sequenceNumber)
        assertEquals(1, client.connectionPool.connectionCount())

        // The pin is rotated. No new handshake happens for a pooled
        // connection, so the trust manager is never asked.
        live = rotated()
        val refused = assertRefused(client)

        assertTrue("same type as a failed handshake: $refused", refused is SSLHandshakeException)
        assertTrue(refused.cause is CertificateException)
        assertTrue(refused.message, refused.message!!.contains("Certificate pinning failure"))
        assertEquals("nothing reached the server on the old connection", 1, server.requestCount)

        // The connection was closed, not put back: once the pins match again
        // the next request opens a new one.
        live = matching()
        assertEquals(200, get(client))
        assertEquals("a new connection", 0, server.takeRequest().sequenceNumber)
    }

    @Test
    fun `a pooled connection is refused once the host has no pin entry`() {
        var live: CertificateConfig? = matching()
        val client = appClient { live }
        assertEquals(200, get(client))

        live = CertificateConfig(version = 2, pins = listOf(HostPin("elsewhere.test", listOf(otherPin, otherPin))))
        val refused = assertRefused(client)
        assertTrue(refused.cause is io.github.umutcansu.pinvault.model.UnpinnedHostException)

        live = null
        assertTrue(assertRefused(client).message!!.contains("No pins configured"))
    }

    @Test
    fun `a pooled connection is refused once the config has expired`() {
        var live: CertificateConfig? = matching(expiresAt = now + hour)
        val client = appClient { live }
        assertEquals(200, get(client))

        now += 2 * hour
        val refused = assertRefused(client)
        assertTrue(refused is SSLHandshakeException)
        assertTrue(refused.cause!!.cause is ConfigExpiredException)

        // A fresh config (same pins, later expiresAt) makes requests work again.
        live = matching(expiresAt = now + hour)
        assertEquals(200, get(client))
    }

    @Test
    fun `grace keeps a pooled connection usable that much longer`() {
        manager.expiredConfigGraceMs = 3 * hour
        val client = appClient { matching(expiresAt = now + hour) }
        assertEquals(200, get(client))
        now += 2 * hour
        assertEquals(200, get(client))
    }

    @Test
    fun `an unchanged config keeps reusing the pooled connection`() {
        val config = matching()
        val client = appClient { config }
        assertEquals(200, get(client))
        assertEquals(200, get(client))
        assertEquals(0, server.takeRequest().sequenceNumber)
        assertEquals("the second request rode the same connection", 1, server.takeRequest().sequenceNumber)
    }

    @Test
    fun `an expired config is refreshed by the recovery interceptor and the request retried`() {
        val provider = HttpClientProvider(manager)
        provider.swap(matching(expiresAt = now + hour))
        var refetches = 0
        provider.recoveryUpdater = {
            refetches++
            provider.replaceConfigInPlace(matching(expiresAt = now + hour))
            true
        }
        val client = provider.get().newBuilder().hostnameVerifier { _, _ -> true }.build()
        assertEquals(200, get(client))

        now += 2 * hour
        // The pooled connection fails the per-request check; recovery
        // refetches and the retry goes through.
        assertEquals(200, get(client))
        assertEquals(1, refetches)
    }

    @Test
    fun `a pin change closes the pooled connections of every client the library built`() {
        val provider = HttpClientProvider(manager)
        provider.swap(matching())
        val shared = provider.get().newBuilder().hostnameVerifier { _, _ -> true }.build()
        val custom = manager.buildDynamicClient({ provider.currentConfig }, HttpConnectionSettings())
            .newBuilder().hostnameVerifier { _, _ -> true }.build()
        assertEquals(200, get(shared))
        assertEquals(200, get(custom))
        assertEquals(1, shared.connectionPool.connectionCount())
        assertEquals(1, custom.connectionPool.connectionCount())

        provider.swap(rotated())

        // Eviction runs on a background thread.
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline &&
            (shared.connectionPool.connectionCount() > 0 || custom.connectionPool.connectionCount() > 0)
        ) Thread.sleep(20)
        assertEquals(0, shared.connectionPool.connectionCount())
        assertEquals("getClient(settings) clients are evicted too", 0, custom.connectionPool.connectionCount())
    }

    @Test
    fun `after a pin change a new connection runs a full handshake`() {
        // The trust manager reports every handshake it is asked about; a
        // resumed TLS session would not ask it. A fresh SSLContext per pin
        // generation has no session to resume.
        val handshakes = java.util.concurrent.atomic.AtomicInteger()
        val latch = java.util.concurrent.Semaphore(0)
        manager.setConnectionListener { event ->
            if (event is io.github.umutcansu.pinvault.api.PinVaultConnectionEvent.Connection) {
                handshakes.incrementAndGet()
                latch.release()
            }
        }
        val config = matching()
        val client = appClient { config }
        assertEquals(200, get(client))
        assertTrue(latch.tryAcquire(5, java.util.concurrent.TimeUnit.SECONDS))

        manager.onPinsChanged()
        client.connectionPool.evictAll()
        assertEquals(200, get(client))

        assertTrue("the trust manager saw the second connection", latch.tryAcquire(5, java.util.concurrent.TimeUnit.SECONDS))
        assertEquals(2, handshakes.get())
    }

    @Test
    fun `sockets enable TLS 1_2 and newer only, and TLS 1_3 where the platform has it`() {
        val config = matching()
        val client = appClient { config }
        val socket = client.sslSocketFactory.createSocket() as javax.net.ssl.SSLSocket

        val enabled = socket.enabledProtocols.toSet()
        assertTrue("enabled: $enabled", enabled.isNotEmpty() && enabled.all { it == "TLSv1.2" || it == "TLSv1.3" })
        if ("TLSv1.3" in socket.supportedProtocols) {
            assertTrue("TLS 1.3 must not be capped away: $enabled", "TLSv1.3" in enabled)
        }

        // And a real connection negotiates one of them.
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { response ->
            val version = response.handshake!!.tlsVersion
            assertTrue("negotiated $version", version == okhttp3.TlsVersion.TLS_1_2 || version == okhttp3.TlsVersion.TLS_1_3)
        }
    }

    @Test
    fun `requireCaTrust is checked per request too, not only at the handshake`() {
        var caTrusts = true
        manager.caCheck = ServerCaCheck { _, _, _ -> if (!caTrusts) throw CertificateException("not issued by a trusted CA") }
        manager.requireCaTrust(listOf(server.hostName))
        var live: CertificateConfig? = matching()
        val client = appClient { live }
        assertEquals(200, get(client))
        assertEquals(1, client.connectionPool.connectionCount())

        // The CA verdict changes (here: the check itself; on a device, an
        // HTTP/2 connection reused for a host the handshake did not judge). A
        // new config object makes the interceptor look at the pooled connection again.
        caTrusts = false
        live = matching()
        val refused = assertRefused(client)
        assertTrue("$refused", refused is SSLHandshakeException)
        assertTrue(refused.cause is io.github.umutcansu.pinvault.model.CaTrustException)
        assertEquals("nothing reached the server on that connection", 1, server.requestCount)
    }
}
