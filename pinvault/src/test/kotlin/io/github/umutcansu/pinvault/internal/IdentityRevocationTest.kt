package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.ReenrollRequiredInterceptor
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.util.TestCertUtil
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
 * `403 reenroll_required` is not signed. It may delete a device's vault files
 * (`wipeVaultFilesOnRevocation()`) only when the server gave it while looking
 * at this device's client certificate: on a connection that presented the
 * identity loaded now. Over real TLS, with the real interceptor.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class IdentityRevocationTest {

    private val password = "changeit"
    private val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
    private val device = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
    private val other = TestCertUtil.generateSelfSigned(cn = "device-2", password = password, alias = "client")

    private lateinit var server: MockWebServer
    private val manager = DynamicSSLManager()
    private val revocation = IdentityRevocation { manager.defaultClientCertificate() }

    private var wipes = 0
    private val presented = mutableListOf<String?>()

    private val revoked = MockResponse().setResponseCode(403).setBody("""{"error":"reenroll_required","message":"revoked"}""")

    @Before
    fun setUp() {
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
    fun tearDown() = server.shutdown()

    /** A pinned client with the interceptor wired the way `ConfigApiClient` wires it. */
    private fun client(mtlsHost: Boolean): OkHttpClient {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("localhost", listOf(serverCert.sha256Pin, serverCert.sha256Pin), mtls = mtlsHost))
        )
        return OkHttpClient.Builder()
            .hostnameVerifier { _, _ -> true }
            .addInterceptor(ReenrollRequiredInterceptor { _, cert ->
                presented += cert?.subjectX500Principal?.name
                if (revocation.refusedOnConnection(cert)) wipes++
            })
            .also { manager.applyTo(it) { config } }
            .build()
    }

    private fun request(client: OkHttpClient) {
        client.newCall(Request.Builder().url(server.url("/api/v1/vault/x")).build()).execute().use { it.body?.string() }
    }

    @Test
    fun `a refusal on a connection that presented the identity wipes, once`() {
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        val client = client(mtlsHost = true)
        repeat(3) { server.enqueue(revoked) }

        repeat(3) { request(client) }

        assertEquals(listOf<String?>("CN=device-1", "CN=device-1", "CN=device-1"), presented)
        assertEquals("a revoked device hears it on every request; its files go once", 1, wipes)
    }

    @Test
    fun `a refusal on a block without an identity wipes nothing`() {
        // A TLS-only block: nothing enrolled, nothing presented.
        val client = client(mtlsHost = true)
        server.enqueue(revoked)

        request(client)

        assertEquals(listOf<String?>(null), presented)
        assertEquals(0, wipes)
    }

    @Test
    fun `a refusal on a connection that did not present the loaded identity wipes nothing`() {
        // An identity is loaded, but this host is not one it is shown to
        // (not the block's own listener, not an mtls host).
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        val client = client(mtlsHost = false)
        server.enqueue(revoked)

        request(client)

        assertEquals(listOf<String?>(null), presented)
        assertEquals(0, wipes)
    }

    @Test
    fun `only the identity loaded now counts, and a new identity can be refused again`() {
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        assertFalse("another certificate is not this device's", revocation.presentedCurrent(other.certificate))
        assertFalse(revocation.presentedCurrent(null))
        assertTrue(revocation.presentedCurrent(device.certificate))

        assertTrue(revocation.refusedOnConnection(device.certificate))
        assertFalse(revocation.refusedOnConnection(device.certificate))

        // Re-enrolled: a new certificate, a new notice.
        manager.loadClientKey(other.keyPair.private, arrayOf(other.certificate))
        assertFalse("the old certificate no longer speaks for the device", revocation.refusedOnConnection(device.certificate))
        assertTrue(revocation.refusedOnConnection(other.certificate))
    }

    @Test
    fun `the answer to the identity's own renewal counts once, and never without an identity`() {
        assertFalse("nothing loaded: nothing to revoke", revocation.claim())
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        assertTrue(revocation.claim())
        assertFalse(revocation.claim())
        // The request path and the renewal path share the one notice.
        assertFalse(revocation.refusedOnConnection(device.certificate))
    }
}
