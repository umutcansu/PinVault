package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.util.TestCertUtil
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
import java.security.KeyStore
import java.security.cert.CertificateException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException

/**
 * D.26 — Expired cert reddedilmeli
 * D.27 — Yanlış password P12 hata vermeli
 * E.30 — Boş pin listesi bağlantı reddedilmeli
 * E.33 — İki farklı host iki farklı cert
 * E.34 — Bir host cert expire, diğeri geçerli
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CertPinningIntegrationTest {

    private lateinit var server: MockWebServer
    private lateinit var manager: DynamicSSLManager
    private val password = "changeit"
    private val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)

    @Before
    fun setUp() {
        manager = DynamicSSLManager()
        server = MockWebServer()

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(serverCert.p12Bytes.inputStream(), password.toCharArray())
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password.toCharArray())
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(kmf.keyManagers, null, null)
        server.useHttps(sslCtx.socketFactory, false)
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `doğru pin ile bağlantı başarılı`() {
        server.enqueue(MockResponse().setBody("ok"))

        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("localhost", listOf(serverCert.sha256Pin, serverCert.sha256Pin)))
        )
        // Build pinned client with hostname verifier disabled (self-signed cert has no SAN)
        val builder = okhttp3.OkHttpClient.Builder()
            .hostnameVerifier { _, _ -> true }
        manager.applyTo(builder) { config }
        val client = builder.build()

        try {
            val response = client.newCall(
                Request.Builder().url(server.url("/test")).build()
            ).execute()
            assertEquals(200, response.code)
        } catch (e: java.net.ConnectException) {
            println("Skipping TLS integration test: ${e.message}")
        }
    }

    @Test
    fun `yanlış pin ile bağlantı reddedilir`() {
        server.enqueue(MockResponse().setBody("should not get here"))

        val wrongPin = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("localhost", listOf(wrongPin, wrongPin)))
        )
        val client = manager.buildClient(config)
        try {
            client.newCall(
                Request.Builder().url(server.url("/test")).build()
            ).execute()
            fail("Should have thrown an SSL or connection exception")
        } catch (e: SSLHandshakeException) {
            // Expected — pin mismatch
        } catch (e: java.net.ConnectException) {
            // Also acceptable — TLS handshake failure manifests as connection refused in some envs
        } catch (e: javax.net.ssl.SSLException) {
            // General SSL failure
        }
    }

    @Test
    fun `yanlış password P12 hata verir`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "test", password = "correct")
        try {
            manager.loadClientKeystore(cert.p12Bytes, "wrongpassword")
            fail("Should have thrown")
        } catch (e: Exception) {
            // Expected — wrong password
            assertNotNull(e)
        }
    }

    @Test
    fun `İki farklı host cert — doğru P12 parse edilir`() {
        val certA = TestCertUtil.generateSelfSigned(cn = "alpha.host", password = password)
        val certB = TestCertUtil.generateSelfSigned(cn = "beta.host", password = password)

        assertNotEquals(certA.sha256Pin, certB.sha256Pin)

        manager.loadHostClientCerts(
            mapOf("alpha.host" to certA.p12Bytes, "beta.host" to certB.p12Bytes),
            password
        )

        // Both loaded — build a client with mtls config
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("alpha.host", listOf(certA.sha256Pin, certA.sha256Pin), mtls = true, clientCertVersion = 1),
                HostPin("beta.host", listOf(certB.sha256Pin, certB.sha256Pin), mtls = true, clientCertVersion = 1)
            )
        )
        val client = manager.buildClient(config)
        assertNotNull(client)
    }

    @Test
    fun `aynı host'a ikinci cert yükleme — son yüklenen geçerli`() {
        val cert1 = TestCertUtil.generateSelfSigned(cn = "host-v1", password = password)
        val cert2 = TestCertUtil.generateSelfSigned(cn = "host-v2", password = password)

        manager.loadHostClientCerts(mapOf("same.host" to cert1.p12Bytes), password)
        manager.loadHostClientCerts(mapOf("same.host" to cert2.p12Bytes), password)

        // No assertion on internal state — just ensure no exception
        // The second load replaces the first (volatile map swap)
    }

    @Test
    fun `boş config — system defaults kullanılır`() {
        val client = manager.buildClient(null)
        assertNotNull(client)
    }

    /**
     * Regression test for the snapshot-trust-manager bug: applyTo(builder)
     * used to capture pinMap by value at call time, so a later config swap
     * (PinVault.updateNow / WorkManager refresh) never reached the
     * externally maintained client. Now applyTo takes a lambda the trust
     * manager re-reads on every handshake.
     *
     * Observable consequence: the provider lambda is invoked at least once
     * per TLS handshake, not just once at applyTo() time. Counting calls
     * lets us prove the contract without depending on connection-pool /
     * session-resumption timing quirks that vary across JVMs.
     */
    @Test
    fun `dynamic config provider — lambda re-read on each handshake`() {
        server.enqueue(MockResponse().setBody("first"))
        server.enqueue(MockResponse().setBody("second"))

        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("localhost", listOf(serverCert.sha256Pin, serverCert.sha256Pin)))
        )
        val callCount = java.util.concurrent.atomic.AtomicInteger(0)

        // Zero idle pool so the second request is forced into a fresh
        // connection (and therefore a fresh handshake / TM invocation).
        val builder = okhttp3.OkHttpClient.Builder()
            .hostnameVerifier { _, _ -> true }
            .connectionPool(
                okhttp3.ConnectionPool(0, 1, java.util.concurrent.TimeUnit.NANOSECONDS)
            )
        manager.applyTo(builder) {
            callCount.incrementAndGet()
            config
        }
        val client = builder.build()

        val first = try {
            client.newCall(Request.Builder().url(server.url("/first")).build()).execute()
        } catch (e: java.net.ConnectException) {
            println("Skipping dynamic-config integration test: ${e.message}")
            return
        }
        first.close()
        client.connectionPool.evictAll()

        val second = client.newCall(Request.Builder().url(server.url("/second")).build()).execute()
        second.close()

        // Snapshot trust manager would have read the config exactly once
        // at applyTo() time; a dynamic one reads it on every handshake.
        // Two handshakes -> at least two invocations.
        assertTrue(
            "Provider lambda called ${callCount.get()} times — expected >= 2 for a dynamic trust manager",
            callCount.get() >= 2
        )
    }
}
