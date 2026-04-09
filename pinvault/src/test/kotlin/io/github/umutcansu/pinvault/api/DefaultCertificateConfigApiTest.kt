package io.github.umutcansu.pinvault.api

import com.google.gson.Gson
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DefaultCertificateConfigApiTest {

    private lateinit var server: MockWebServer
    private lateinit var sslManager: DynamicSSLManager
    private val gson = Gson()

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        sslManager = mockk()
        every { sslManager.buildBootstrapClient(any()) } returns OkHttpClient()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun createApi(signaturePublicKey: String? = null): DefaultCertificateConfigApi {
        return DefaultCertificateConfigApi(
            configUrl = server.url("/").toString(),
            signaturePublicKey = signaturePublicKey,
            bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
            sslManager = sslManager
        )
    }

    @Test
    fun `healthCheck returns true when status is ok`() = runTest {
        server.enqueue(MockResponse().setBody("""{"status":"ok"}"""))

        val api = createApi()
        assertTrue(api.healthCheck())
    }

    @Test
    fun `healthCheck returns false when status is not ok`() = runTest {
        server.enqueue(MockResponse().setBody("""{"status":"degraded"}"""))

        val api = createApi()
        assertFalse(api.healthCheck())
    }

    @Test
    fun `healthCheck returns false on network error`() = runTest {
        val api = createApi()
        server.shutdown()

        assertFalse(api.healthCheck())
    }

    @Test
    fun `fetchConfig without signature parses config directly`() = runTest {
        val config = CertificateConfig(
            version = 3,
            pins = listOf(
                HostPin("api.example.com", listOf("hash1", "hash2"), version = 3)
            )
        )
        server.enqueue(MockResponse().setBody(gson.toJson(config)))

        val api = createApi(signaturePublicKey = null)
        val result = api.fetchConfig(1)

        assertEquals(3, result.version)
        assertEquals(1, result.pins.size)
        assertEquals("api.example.com", result.pins[0].hostname)
    }

    @Test
    fun `fetchConfig with valid signature verifies and parses`() = runTest {
        val ecKeyPair = TestCertUtil.generateEcKeyPair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.public.encoded)

        val config = CertificateConfig(
            version = 5,
            pins = listOf(
                HostPin("secure.example.com", listOf("pin1", "pin2"), version = 5)
            )
        )
        val payload = gson.toJson(config)
        val signature = TestCertUtil.signPayload(payload, ecKeyPair.private)

        val signedResponse = SignedConfigResponse(payload = payload, signature = signature)
        server.enqueue(MockResponse().setBody(gson.toJson(signedResponse)))

        val api = createApi(signaturePublicKey = publicKeyBase64)
        val result = api.fetchConfig(1)

        assertEquals(5, result.version)
        assertEquals("secure.example.com", result.pins[0].hostname)
    }

    @Test
    fun `fetchConfig with invalid signature throws SecurityException`() = runTest {
        val ecKeyPair = TestCertUtil.generateEcKeyPair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.public.encoded)

        val signedResponse = SignedConfigResponse(
            payload = """{"version":1,"pins":[]}""",
            signature = "aW52YWxpZHNpZ25hdHVyZQ=="  // invalid signature
        )
        server.enqueue(MockResponse().setBody(gson.toJson(signedResponse)))

        val api = createApi(signaturePublicKey = publicKeyBase64)

        try {
            api.fetchConfig(0)
            fail("Expected SecurityException")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("tampering"))
        }
    }

    @Test
    fun `fetchConfig passes currentVersion as query parameter`() = runTest {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("a.com", listOf("h1", "h2")))
        )
        server.enqueue(MockResponse().setBody(gson.toJson(config)))

        val api = createApi()
        api.fetchConfig(42)

        val request = server.takeRequest()
        assertTrue(request.requestUrl.toString().contains("currentVersion=42"))
    }

    @Test
    fun `downloadHostClientCert returns binary bytes`() = runTest {
        val expectedBytes = byteArrayOf(0x50, 0x4B, 0x03, 0x04, 0x10, 0x20)
        server.enqueue(
            MockResponse()
                .setBody(okio.Buffer().write(expectedBytes))
                .setHeader("Content-Type", "application/octet-stream")
        )

        val api = createApi()
        val result = api.downloadHostClientCert("host.com")

        assertArrayEquals(expectedBytes, result)
    }

    @Test
    fun `downloadHostClientCert constructs correct URL path`() = runTest {
        server.enqueue(
            MockResponse()
                .setBody(okio.Buffer().write(byteArrayOf(0x01)))
                .setHeader("Content-Type", "application/octet-stream")
        )

        val api = createApi()
        api.downloadHostClientCert("api.example.com")

        val request = server.takeRequest()
        assertTrue(request.path!!.contains("api/v1/client-certs/api.example.com/download"))
    }
}
