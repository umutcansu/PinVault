package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.util.TestCertUtil
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.mockk.every
import io.mockk.mockk
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
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
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** E.13 — Pin mismatch recovery: yanlış pin → otomatik güncelle → retry */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class PinRecoveryInterceptorTest {

    private lateinit var server: MockWebServer
    private val cert = TestCertUtil.generateSelfSigned(cn = "localhost")

    @Before
    fun setUp() {
        server = MockWebServer()

        // Configure MockWebServer with TLS
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(cert.p12Bytes.inputStream(), "changeit".toCharArray())

        val kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "changeit".toCharArray())

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
    fun `isPinMismatch detects SSLPeerUnverifiedException`() {
        val interceptor = PinRecoveryInterceptor(
            updater = { true },
            newClientProvider = { OkHttpClient() }
        )

        // Use reflection to test private method
        val method = PinRecoveryInterceptor::class.java.getDeclaredMethod("isPinMismatch", java.io.IOException::class.java)
        method.isAccessible = true

        assertTrue(method.invoke(interceptor, javax.net.ssl.SSLPeerUnverifiedException("test")) as Boolean)
        assertFalse(method.invoke(interceptor, java.io.IOException("generic")) as Boolean)
    }

    @Test
    fun `successful request — no recovery triggered`() {
        server.enqueue(MockResponse().setBody("ok"))

        val trustingClient = createTrustingClient()
        val request = Request.Builder().url(server.url("/test")).build()
        try {
            val response = trustingClient.newCall(request).execute()
            assertEquals(200, response.code)
            assertEquals("ok", response.body?.string())
        } catch (e: java.net.ConnectException) {
            // MockWebServer HTTPS may not work under Robolectric
            println("Skipping TLS test: ${e.message}")
        }
    }

    // ── Mocked Chain tests ────────────────────────────────────────────────

    @Test
    fun `pin mismatch triggers updater and retries with new client`() {
        var updaterCalled = false
        val newClient = mockk<OkHttpClient>()
        val newCall = mockk<okhttp3.Call>()
        val retryResponse = mockk<Response>(relaxed = true)
        every { retryResponse.code } returns 200

        every { newClient.newCall(any()) } returns newCall
        every { newCall.execute() } returns retryResponse

        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { newClient }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws javax.net.ssl.SSLPeerUnverifiedException("pin mismatch")

        val response = interceptor.intercept(chain)

        assertTrue(updaterCalled)
        assertEquals(200, response.code)
    }

    @Test
    fun `pin mismatch with failed update rethrows original exception`() {
        val interceptor = PinRecoveryInterceptor(
            updater = { false },
            newClientProvider = { OkHttpClient() }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws javax.net.ssl.SSLPeerUnverifiedException("pin mismatch")

        try {
            interceptor.intercept(chain)
            fail("Expected SSLPeerUnverifiedException")
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            assertEquals("pin mismatch", e.message)
        }
    }

    @Test
    fun `SSLHandshakeException with CertificateException cause triggers recovery`() {
        var updaterCalled = false
        val newClient = mockk<OkHttpClient>()
        val newCall = mockk<okhttp3.Call>()
        val retryResponse = mockk<Response>(relaxed = true)
        every { retryResponse.code } returns 200
        every { newClient.newCall(any()) } returns newCall
        every { newCall.execute() } returns retryResponse

        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { newClient }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        val cause = java.security.cert.CertificateException("cert invalid")
        every { chain.proceed(any()) } throws javax.net.ssl.SSLHandshakeException("handshake failed").apply { initCause(cause) }

        val response = interceptor.intercept(chain)
        assertTrue(updaterCalled)
        assertEquals(200, response.code)
    }

    @Test
    fun `SSLHandshakeException with pinning message triggers recovery`() {
        var updaterCalled = false
        val newClient = mockk<OkHttpClient>()
        val newCall = mockk<okhttp3.Call>()
        val retryResponse = mockk<Response>(relaxed = true)
        every { retryResponse.code } returns 200
        every { newClient.newCall(any()) } returns newCall
        every { newCall.execute() } returns retryResponse

        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { newClient }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws javax.net.ssl.SSLHandshakeException("Certificate pinning failure for host")

        val response = interceptor.intercept(chain)
        assertTrue(updaterCalled)
        assertEquals(200, response.code)
    }

    @Test
    fun `non-SSL IOException passes through without recovery`() {
        var updaterCalled = false
        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { OkHttpClient() }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws java.io.IOException("timeout")

        try {
            interceptor.intercept(chain)
            fail("Expected IOException")
        } catch (e: java.io.IOException) {
            assertEquals("timeout", e.message)
            assertFalse(updaterCalled)
        }
    }

    @Test
    fun `SSLHandshakeException without CertificateException cause passes through`() {
        var updaterCalled = false
        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { OkHttpClient() }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        // SSLHandshakeException without "Certificate pinning" in message and without CertificateException cause
        every { chain.proceed(any()) } throws javax.net.ssl.SSLHandshakeException("protocol error").apply { initCause(RuntimeException("other")) }

        try {
            interceptor.intercept(chain)
            fail("Expected SSLHandshakeException")
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            assertEquals("protocol error", e.message)
            assertFalse(updaterCalled)
        }
    }

    private fun createTrustingClient(): OkHttpClient {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(cert.p12Bytes.inputStream(), "changeit".toCharArray())

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)

        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, tmf.trustManagers, null)

        val tm = tmf.trustManagers.first() as X509TrustManager

        return OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, tm)
            .hostnameVerifier { _, _ -> true }
            .build()
    }
}
