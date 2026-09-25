package io.github.umutcansu.pinvault.reporter

import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.cert.CertificateException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509ExtendedTrustManager

/** Reports can go to a pinned HTTPS endpoint without an unpinned client. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ReporterPinnedClientTest {

    private val server = TestCertUtil.generateSelfSigned(cn = "reports.test")
    private val backup = TestCertUtil.generateSelfSigned(cn = "reports-backup.test")

    private fun trustManager() = PinVaultBackendReporter.pinnedClient("reports.test", listOf(server.sha256Pin, backup.sha256Pin))
        .x509TrustManager as X509ExtendedTrustManager

    private fun engine(host: String) = SSLContext.getDefault().createSSLEngine(host, 443)

    @Test
    fun `accepts the pinned certificate and refuses any other`() {
        trustManager().checkServerTrusted(arrayOf(server.certificate), "RSA", engine("reports.test"))
        try {
            trustManager().checkServerTrusted(arrayOf(TestCertUtil.generateSelfSigned(cn = "reports.test").certificate), "RSA", engine("reports.test"))
            fail("An unpinned certificate must be refused")
        } catch (e: CertificateException) {
            assertTrue(e.message!!.contains("pinning failure"))
        }
    }

    @Test
    fun `pins only the named host and keeps short timeouts`() {
        try {
            trustManager().checkServerTrusted(arrayOf(server.certificate), "RSA", engine("elsewhere.test"))
            fail("The pins belong to reports.test only")
        } catch (e: CertificateException) {
            assertTrue(e.message!!.contains("No pin entry"))
        }
        val client = PinVaultBackendReporter.pinnedClient("reports.test", listOf(server.sha256Pin, backup.sha256Pin))
        assertTrue(client.connectTimeoutMillis == TimeUnit.SECONDS.toMillis(5).toInt())
    }
}
