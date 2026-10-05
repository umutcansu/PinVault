package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CaTrustException
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigExpiredException
import io.github.umutcansu.pinvault.model.HostPin
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
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Real TLS handshakes against a self-signed MockWebServer:
 *  - Y1: a config past its expiresAt (plus grace) pins nothing.
 *  - Y3: `requireCaTrust` hosts need the platform CAs as well as a pin.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CaTrustAndExpiryHandshakeTest {

    private val password = "changeit"
    private val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
    private lateinit var server: MockWebServer
    private lateinit var manager: DynamicSSLManager
    private val now = 1_800_000_000_000L

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

    private fun config(expiresAt: Long = 0L) = CertificateConfig(
        version = 1,
        pins = listOf(HostPin(server.hostName, listOf(serverCert.sha256Pin, serverCert.sha256Pin))),
        expiresAt = expiresAt
    )

    private fun call(config: CertificateConfig): Int {
        server.enqueue(MockResponse().setBody("ok"))
        val builder = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }
        manager.applyTo(builder) { config }
        return builder.build().newCall(Request.Builder().url(server.url("/")).build()).execute().use { it.code }
    }

    private inline fun <reified T : Throwable> assertRefusedWith(block: () -> Unit) {
        try {
            block()
            fail("handshake should have been refused")
        } catch (e: IOException) {
            val chain = generateSequence<Throwable>(e) { it.cause }.take(10).toList()
            assertTrue("expected ${T::class.simpleName} in $chain", chain.any { it is T })
        }
    }

    /** A check over a trust store holding only the test server's certificate: a "CA" that knows it. */
    private fun trustingTheServer() = TrustManagerCaCheck {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("server", serverCert.certificate) }
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            .trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    // ── Y1 ──────────────────────────────────────────────────────────────

    @Test
    fun `unexpired config pins as before`() {
        assertEquals(200, call(config(expiresAt = now + 60_000)))
    }

    @Test
    fun `expired config refuses the handshake`() {
        assertRefusedWith<ConfigExpiredException> { call(config(expiresAt = now - 1)) }
    }

    @Test
    fun `grace keeps an expired config working that much longer`() {
        manager.expiredConfigGraceMs = 60_000
        assertEquals(200, call(config(expiresAt = now - 30_000)))
        assertRefusedWith<ConfigExpiredException> { call(config(expiresAt = now - 90_000)) }
    }

    @Test
    fun `a freshness write-back reaches the provider's client`() {
        // swap(expired) → the write-back of a fresh envelope with the same pins
        // (replaceConfigInPlace) → the client get() hands out must handshake.
        val provider = HttpClientProvider(manager)
        provider.swap(config(expiresAt = now - 1))
        fun viaProvider(): Int {
            server.enqueue(MockResponse().setBody("ok"))
            val client = provider.get().newBuilder().hostnameVerifier { _, _ -> true }.build()
            return client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { it.code }
        }
        assertRefusedWith<ConfigExpiredException> { viaProvider() }

        provider.replaceConfigInPlace(config(expiresAt = now + 60_000))

        assertEquals(200, viaProvider())
    }

    @Test
    fun `config without expiresAt is never refused for age`() {
        assertEquals(200, call(config(expiresAt = 0L)))
    }

    // ── Y3 ──────────────────────────────────────────────────────────────

    @Test
    fun `pinned but not CA-trusted host is refused when requireCaTrust names it`() {
        manager.requireCaTrust(listOf(server.hostName))
        // The platform trust store does not know a self-signed certificate.
        assertRefusedWith<CaTrustException> { call(config()) }
    }

    @Test
    fun `pin and CA both passing is accepted`() {
        manager.requireCaTrust(listOf(server.hostName))
        manager.caCheck = trustingTheServer()
        assertEquals(200, call(config()))
    }

    @Test
    fun `CA trust does not replace the pin`() {
        manager.requireCaTrust(listOf(server.hostName))
        manager.caCheck = trustingTheServer()
        val wrongPins = CertificateConfig(
            version = 1,
            pins = listOf(HostPin(server.hostName, listOf("A".repeat(43) + "=", "B".repeat(43) + "="))),
        )
        assertRefusedWith<java.security.cert.CertificateException> { call(wrongPins) }
    }

    @Test
    fun `hosts not named keep pin-only trust`() {
        manager.requireCaTrust(listOf("api.example.com", "*.example.org"))
        assertEquals(200, call(config()))
    }

    @Test
    fun `port-specific pattern applies to that port only`() {
        manager.requireCaTrust(listOf("${server.hostName}:${server.port}"))
        assertRefusedWith<CaTrustException> { call(config()) }

        manager.requireCaTrust(listOf("${server.hostName}:1"))
        assertEquals(200, call(config()))
    }
}
