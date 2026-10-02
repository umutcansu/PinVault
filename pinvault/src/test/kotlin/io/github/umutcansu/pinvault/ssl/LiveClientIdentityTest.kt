package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.util.TestCertUtil
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * A client built through `applyTo` lives as long as the app keeps it, while
 * the client identity changes underneath it. It used to keep presenting the
 * certificate loaded when it was built — after a renewal the superseded one,
 * after a re-enrollment a revoked one — and a new connection could also
 * resume the old TLS session with the old certificate. Each new connection
 * now presents the identity loaded at that moment.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class LiveClientIdentityTest {

    private lateinit var server: MockWebServer
    private lateinit var manager: DynamicSSLManager
    private val password = "changeit"
    private val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
    private val clientA = TestCertUtil.generateSelfSigned(cn = "client-a", password = password, alias = "client")
    private val clientB = TestCertUtil.generateSelfSigned(cn = "client-b", password = password, alias = "client")
    private val config = CertificateConfig(
        version = 1,
        pins = listOf(HostPin("localhost", listOf(serverCert.sha256Pin, serverCert.sha256Pin)))
    )

    @Before
    fun setUp() {
        manager = DynamicSSLManager()
        server = MockWebServer()
        val ks = KeyStore.getInstance("PKCS12").apply { load(serverCert.p12Bytes.inputStream(), password.toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password.toCharArray()) }
        val acceptAnyClient = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, arrayOf(acceptAnyClient), null) }
        server.useHttps(ctx.socketFactory, false)
        server.requestClientAuth()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun client(): OkHttpClient = OkHttpClient.Builder()
        .hostnameVerifier { _, _ -> true }
        .also { manager.applyTo(it) { config } }
        .build()

    private fun call(client: OkHttpClient) {
        server.enqueue(MockResponse().setBody("ok"))
        client.newCall(Request.Builder().url(server.url("/")).build()).execute().use {
            assertEquals(200, it.code)
            it.body?.string()
        }
    }

    /** Subject of the client certificate the server saw on a new connection, or null. */
    private fun presentedBy(client: OkHttpClient): String? {
        // Open connections keep the identity they were made with; a new one shows the current.
        client.connectionPool.evictAll()
        call(client)
        val presented = server.takeRequest().handshake?.peerCertificates?.firstOrNull() as? X509Certificate
        return presented?.subjectX500Principal?.name
    }

    @Test
    fun `after a renewal the same client presents the new certificate`() {
        manager.loadClientKey(clientA.keyPair.private, arrayOf(clientA.certificate))
        val client = client()
        assertEquals("CN=client-a", presentedBy(client))

        manager.loadClientKey(clientB.keyPair.private, arrayOf(clientB.certificate))
        assertEquals("CN=client-b", presentedBy(client))
    }

    @Test
    fun `a client built before enrollment presents the certificate once enrolled`() {
        val client = client()
        assertNull(presentedBy(client))

        manager.loadClientKeystore(clientA.p12Bytes, password)
        assertEquals("CN=client-a", presentedBy(client))
    }

    @Test
    fun `after unenroll the same client presents no certificate`() {
        manager.loadClientKeystore(clientA.p12Bytes, password)
        val client = client()
        assertEquals("CN=client-a", presentedBy(client))

        manager.clearClientKeystore()
        assertNull(presentedBy(client))
    }

    @Test
    fun `without an identity change the pooled connection is reused`() {
        manager.loadClientKey(clientA.keyPair.private, arrayOf(clientA.certificate))
        val client = client()
        call(client)
        call(client)
        assertEquals(0, server.takeRequest().sequenceNumber)
        // The second request rode the same connection.
        assertEquals(1, server.takeRequest().sequenceNumber)
    }
}
