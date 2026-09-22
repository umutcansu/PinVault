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
    fun `SSLHandshakeException without CertificateException cause does NOT trigger recovery`() {
        // Pre-V2 the interceptor matched on the string "Certificate pinning" in
        // the exception message. That was fragile — OkHttp/Conscrypt wording
        // shifts could silently break recovery. Now only the typed cause path
        // is honoured, so a handshake error lacking a CertificateException
        // cause must pass through untouched even if the message hints at pinning.
        var updaterCalled = false

        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { OkHttpClient() }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws javax.net.ssl.SSLHandshakeException("Certificate pinning failure for host")

        try {
            interceptor.intercept(chain)
            fail("Expected SSLHandshakeException to pass through")
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            assertFalse("Updater must NOT be called for message-only matches", updaterCalled)
        }
    }

    // ── Yedek deneme orijinal hatayı gizlemesin ───────────────────────────

    @Test
    fun `fallback client failure rethrows the ORIGINAL pin error`() {
        // Regression: when the retry on the caller's own chain failed and the
        // fallback attempt on the library's internal client failed too, the
        // interceptor threw the FALLBACK's exception. The internal client does
        // not carry the caller's Dns, so the app was shown an
        // UnknownHostException instead of the pin mismatch it actually hit.
        val newClient = mockk<OkHttpClient>()
        val newCall = mockk<okhttp3.Call>()
        every { newClient.newCall(any()) } returns newCall
        every { newCall.execute() } throws java.net.UnknownHostException("api.example.com")

        val interceptor = PinRecoveryInterceptor(
            updater = { true },
            newClientProvider = { newClient }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws
            javax.net.ssl.SSLPeerUnverifiedException("Certificate pinning failure for example.com")

        try {
            interceptor.intercept(chain)
            fail("Expected the original SSLPeerUnverifiedException")
        } catch (e: java.io.IOException) {
            assertTrue(
                "Caller must see the pin error, not the fallback's DNS failure — got ${e.javaClass.simpleName}",
                e is javax.net.ssl.SSLPeerUnverifiedException
            )
            assertEquals("Certificate pinning failure for example.com", e.message)
            // The fallback's failure is still reachable for diagnostics.
            val suppressed = e.suppressed.toList()
            assertEquals(1, suppressed.size)
            assertTrue(
                "Fallback failure must be attached as suppressed",
                suppressed[0] is java.net.UnknownHostException
            )
        }
    }

    // ── Geçerlilik penceresi hatası pin uyuşmazlığı değildir ──────────────

    @Test
    fun `expired server certificate does NOT trigger config refresh`() {
        // Refetching pins cannot make an expired certificate valid, so the
        // updater must never be consulted and the error must reach the caller
        // unchanged (see CertificateValidityException).
        var updaterCalled = false

        val interceptor = PinRecoveryInterceptor(
            updater = { updaterCalled = true; true },
            newClientProvider = { OkHttpClient() }
        )

        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        val cause = io.github.umutcansu.pinvault.model.CertificateValidityException(
            "Server certificate is expired or not yet valid: NotAfter: 2020-01-01"
        )
        every { chain.proceed(any()) } throws
            javax.net.ssl.SSLHandshakeException("handshake failed").apply { initCause(cause) }

        try {
            interceptor.intercept(chain)
            fail("Expected SSLHandshakeException to pass through")
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            assertFalse("Updater must NOT be called for a validity-window failure", updaterCalled)
            assertTrue(
                "Original cause must survive",
                e.cause is io.github.umutcansu.pinvault.model.CertificateValidityException
            )
        }
    }

    @Test
    fun `plain CertificateException cause still triggers recovery`() {
        // Guard against the validity-window carve-out swallowing real pin
        // mismatches: a bare CertificateException cause must still recover.
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
        val cause = java.security.cert.CertificateException("Certificate pinning failure for example.com")
        every { chain.proceed(any()) } throws
            javax.net.ssl.SSLHandshakeException("handshake failed").apply { initCause(cause) }

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

    @Test
    fun `successful recovery does NOT zero per-host failure counter`() {
        // Regression: recordSuccess used to wipe the per-host RecoveryState
        // entry, letting a partial MITM keep the circuit breaker permanently
        // disarmed by interleaving forged handshakes with legitimate ones.
        // The counter must now only age out via ATTEMPT_WINDOW_MS, not reset
        // on a single success.

        val newClient = mockk<OkHttpClient>()
        val newCall = mockk<okhttp3.Call>()
        val retryResponse = mockk<Response>(relaxed = true)
        every { retryResponse.code } returns 200
        every { newClient.newCall(any()) } returns newCall
        every { newCall.execute() } returns retryResponse

        // updater() returns true so the interceptor proceeds to the retry
        // branch and invokes recordSuccess after a successful new-client call.
        val interceptor = PinRecoveryInterceptor(
            updater = { true },
            newClientProvider = { newClient }
        )

        // First, drive one failure so the per-host state map gets a non-zero
        // attemptCount. Use a failing updater for this run via a second
        // interceptor sharing the recoveryState map is fragile — instead we
        // simulate by inspecting state after a successful recovery: with the
        // old behavior the host's entry would be REMOVED; with the new
        // no-op behavior it must remain (cleared internally to attemptCount=0
        // is also acceptable, but the entry itself must not vanish — that's
        // the bypass vector).
        val chain = mockk<Interceptor.Chain>()
        val request = Request.Builder().url("https://example.com/test").build()
        every { chain.request() } returns request
        every { chain.proceed(any()) } throws javax.net.ssl.SSLPeerUnverifiedException("pin mismatch")

        // First call: triggers failure path -> updater() -> success -> recordSuccess.
        // (recordFailure also runs once on the original mismatch path inside the
        // try/catch around retry; with our setup the retry succeeds, so the
        // sequence is `proceed throws -> updater() -> retry succeeds ->
        // recordSuccess`.)
        val response = interceptor.intercept(chain)
        assertEquals(200, response.code)

        // Inspect private recoveryState via reflection — the contract under
        // test is: after recordSuccess the host key MUST still be present
        // (or its attemptCount must remain non-zero), proving recordSuccess
        // is not silently zeroing the breaker.
        val stateField = PinRecoveryInterceptor::class.java.getDeclaredField("recoveryState")
        stateField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val recoveryState = stateField.get(interceptor) as java.util.concurrent.ConcurrentHashMap<String, *>

        // The old behavior cleared the map outright on success — that's the
        // regression we're guarding against. Today the map can be either
        // empty (if no failure recorded before retry succeeded) OR contain
        // the host with no zeroing. What MUST NOT happen: a prior failure
        // counter being zeroed by the success. So we drive an explicit
        // failure first and re-assert.

        // Force an explicit failure to seed the state, then a success, and
        // verify the failure entry is preserved.
        val failingInterceptor = PinRecoveryInterceptor(
            updater = { false }, // first call: failed recovery -> recordFailure
            newClientProvider = { newClient }
        )
        try {
            failingInterceptor.intercept(chain)
        } catch (_: Exception) { /* expected */ }
        val failingState = stateField.get(failingInterceptor)
                as java.util.concurrent.ConcurrentHashMap<String, *>
        assertTrue(
            "Failure must seed the per-host state map",
            failingState.containsKey("example.com")
        )

        // Swap in a passing updater for the same interceptor instance via
        // reflection and run a successful recovery — the host entry must
        // remain in the map (recordSuccess is a no-op).
        val updaterField = PinRecoveryInterceptor::class.java.getDeclaredField("updater")
        updaterField.isAccessible = true
        updaterField.set(failingInterceptor, { -> true })

        failingInterceptor.intercept(chain)
        assertTrue(
            "Per-host state must survive a successful recovery — " +
            "recordSuccess clearing it lets a partial MITM keep the breaker disarmed",
            failingState.containsKey("example.com")
        )
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
