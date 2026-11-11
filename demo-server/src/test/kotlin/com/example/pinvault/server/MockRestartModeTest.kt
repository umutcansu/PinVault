package com.example.pinvault.server

import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.MockServerManager
import java.io.File
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A host's mock listeners after its certificate changes (pre-production
 * review, F-10). The restart was one `start(hostname, port, keystore)` with
 * the port of whichever mock answered `getPort`: a host whose only mock was
 * mTLS came back on that port as plain TLS — no client certificate asked, no
 * revocation check. Every running mode now comes back in its own mode on its
 * own port, by the call the server start uses too.
 */
class MockRestartModeTest {

    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private val mocks = MockServerManager()
    private val host = "mock.restart.test"

    @BeforeTest
    fun setUp() {
        certsDir = kotlin.io.path.createTempDirectory("pinvault-mock-restart-").toFile()
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
    }

    @AfterTest
    fun tearDown() {
        mocks.stopAll()
        certsDir.deleteRecursively()
    }

    private fun freePort(): Int = java.net.ServerSocket(0).use { it.localPort }

    private fun keystore(id: String): String = certService.generateCertificate(id, "localhost").keystorePath

    /** `GET /health` with no client certificate: the status, or -1 when the listener would not talk to us. */
    private fun healthWithoutCertificate(port: Int): Int {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
        val connection = URL("https://localhost:$port/health").openConnection() as HttpsURLConnection
        connection.sslSocketFactory = context.socketFactory
        connection.setHostnameVerifier { _, _ -> true }
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        return try {
            connection.responseCode
        } catch (_: java.io.IOException) {
            -1
        } finally {
            connection.disconnect()
        }
    }

    @Test
    fun `an mTLS-only mock comes back as mTLS on its port, never as TLS`() {
        val port = freePort()
        mocks.startInMode(host, port, keystore("first"), mtls = true, certService)
        assertNotEquals(200, healthWithoutCertificate(port), "an mTLS mock asks for a client certificate")

        mocks.restartWithKeystore(host, keystore("second"), certService)

        assertTrue(mocks.isMtlsRunning(host))
        assertFalse(mocks.isTlsRunning(host), "no TLS mock appeared in its place")
        assertEquals(port, mocks.getMtlsPort(host))
        assertEquals("mtls", mocks.getMode(host))
        assertNotEquals(200, healthWithoutCertificate(port), "still no way in without a client certificate")
    }

    @Test
    fun `with both modes running each comes back in its own mode on its own port`() {
        val tlsPort = freePort()
        val mtlsPort = freePort()
        mocks.startInMode(host, tlsPort, keystore("first"), mtls = false, certService)
        mocks.startInMode(host, mtlsPort, keystore("first"), mtls = true, certService)

        mocks.restartWithKeystore(host, keystore("second"), certService)

        assertEquals("both", mocks.getMode(host))
        assertEquals(tlsPort, mocks.getTlsPort(host))
        assertEquals(mtlsPort, mocks.getMtlsPort(host))
        assertEquals(200, healthWithoutCertificate(tlsPort))
        assertNotEquals(200, healthWithoutCertificate(mtlsPort))
    }

    @Test
    fun `an mTLS mock that cannot have its truststore is stopped, not downgraded`() {
        val port = freePort()
        mocks.startInMode(host, port, keystore("first"), mtls = true, certService)
        assertTrue(certService.getTrustStoreFile().delete(), "the client truststore goes missing")

        mocks.restartWithKeystore(host, keystore("second"), certService)

        assertFalse(mocks.isRunning(host), "neither as mTLS without a truststore nor as TLS")
        assertNull(mocks.getPort(host))
        assertEquals(-1, healthWithoutCertificate(port), "nothing listens there any more")
        // The server start goes through the same call: an mTLS mock is not brought back as TLS there either.
        assertFailsWith<IllegalStateException> { mocks.startInMode(host, port, keystore("third"), mtls = true, certService) }
        assertFalse(mocks.isRunning(host))
    }
}
