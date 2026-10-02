package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.ClientCertRenewalResponse
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
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

/**
 * A revoked identity is answered `403 {"error":"reenroll_required"}` on every
 * mTLS request. Every request of a Config API reports it — not only renewal,
 * which used to be the only place it was read.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ReenrollRequiredDetectionTest {

    private lateinit var server: MockWebServer
    private val reasons = mutableListOf<String>()

    private val revoked = MockResponse().setResponseCode(403)
        .setBody("""{"error":"reenroll_required","message":"This identity was revoked."}""")

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun createApi(): DefaultCertificateConfigApi {
        val sslManager = mockk<DynamicSSLManager>()
        // The real manager adds the interceptor to its bootstrap client; so does this one.
        every { sslManager.buildBootstrapClient(any(), any()) } answers {
            OkHttpClient.Builder().apply { secondArg<Interceptor?>()?.let { addInterceptor(it) } }.build()
        }
        return DefaultCertificateConfigApi(
            configUrl = server.url("/").toString(),
            bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
            sslManager = sslManager,
            onReenrollRequired = { reasons += it }
        )
    }

    private suspend fun expectFailure(block: suspend () -> Unit) {
        try {
            block()
            fail("The refused request should still fail")
        } catch (_: Exception) {
        }
    }

    @Test
    fun `config fetch refused as reenroll_required is reported`() = runTest {
        server.enqueue(revoked)
        expectFailure { createApi().fetchConfig(currentVersion = 3) }
        assertEquals(listOf("This identity was revoked."), reasons)
    }

    @Test
    fun `vault file download refused as reenroll_required is reported`() = runTest {
        server.enqueue(revoked)
        expectFailure { createApi().downloadVaultFileWithMeta("api/v1/vault/ml-model", deviceId = "dev-1") }
        assertEquals(listOf("This identity was revoked."), reasons)
    }

    @Test
    fun `device key registration refused as reenroll_required is reported`() = runTest {
        server.enqueue(revoked)
        try {
            createApi().registerDevicePublicKey("dev-1", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
        } catch (_: Exception) {
        }
        assertEquals(listOf("This identity was revoked."), reasons)
    }

    @Test
    fun `a refused renewal is reported and still read as ReenrollRequired`() = runTest {
        server.enqueue(revoked)
        val response = createApi().renewClientCert("dev-1", ByteArray(8))
        // The interceptor only peeks: the renewal code still reads the body.
        assertEquals("This identity was revoked.", (response as ClientCertRenewalResponse.ReenrollRequired).reason)
        assertEquals(listOf("This identity was revoked."), reasons)
    }

    @Test
    fun `a missing message falls back to the error code`() = runTest {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"reenroll_required"}"""))
        expectFailure { createApi().fetchConfig(currentVersion = 0) }
        assertEquals(listOf("reenroll_required"), reasons)
    }

    @Test
    fun `other refusals are not reported`() = runTest {
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"device_identity_mismatch"}"""))
        server.enqueue(MockResponse().setResponseCode(403).setBody("<html>forbidden</html>"))
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"reenroll_required"}"""))
        val api = createApi()
        repeat(3) { expectFailure { api.fetchConfig(currentVersion = 0) } }
        assertTrue(reasons.isEmpty())
    }
}
