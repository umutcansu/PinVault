package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.util.TestCertUtil
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.security.cert.CertificateException
import javax.net.ssl.X509ExtendedTrustManager

/**
 * The client a Config API block reaches its backend with is pinned and
 * HTTPS-only unless the block said `allowUnpinnedConfigApi()` — it used to
 * fall back to the system's CAs without pins and to send plain HTTP.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class BootstrapClientRulesTest {

    private val manager = DynamicSSLManager()
    private val cert = TestCertUtil.generateSelfSigned(cn = "config.test")
    private val pins = listOf(HostPin("config.test", listOf(cert.sha256Pin, cert.sha256Pin)))
    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
    }

    @After
    fun tearDown() = server.shutdown()

    private fun get(client: okhttp3.OkHttpClient): Int {
        server.enqueue(MockResponse().setBody("ok"))
        return client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { it.code }
    }

    @Test
    fun `plain HTTP is refused before anything is sent`() {
        try {
            get(manager.buildBootstrapClient(pins))
            fail("a plain-HTTP Config API must be refused")
        } catch (e: IOException) {
            assertTrue(e.message, e.message!!.contains("plain-HTTP"))
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `without bootstrap pins every TLS handshake is refused, not left to the system CAs`() {
        val client = manager.buildBootstrapClient(emptyList())
        val trustManager = client.x509TrustManager as X509ExtendedTrustManager
        try {
            trustManager.checkServerTrusted(
                arrayOf(cert.certificate), "RSA", javax.net.ssl.SSLContext.getDefault().createSSLEngine("config.test", 443)
            )
            fail("no pins must mean no connection")
        } catch (e: CertificateException) {
            assertTrue(e.message!!.contains("No pins configured"))
        }
    }

    @Test
    fun `allowUnpinned keeps plain HTTP and system trust working for tests and demos`() {
        assertEquals(200, get(manager.buildBootstrapClient(emptyList(), allowUnpinned = true)))
        assertEquals(200, get(manager.buildBootstrapClient(pins, allowUnpinned = true)))
    }
}
