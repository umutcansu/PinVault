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

        val now = System.currentTimeMillis()
        val config = CertificateConfig(
            version = 5,
            pins = listOf(
                HostPin("secure.example.com", listOf("pin1", "pin2"), version = 5)
            ),
            issuedAt = now,
            expiresAt = now + 3600_000L
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
    fun `fetchConfig rejects signed config missing expiresAt`() = runTest {
        val ecKeyPair = TestCertUtil.generateEcKeyPair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.public.encoded)

        // Payload omits issuedAt/expiresAt — simulates a legacy server (or an
        // attacker stripping the freshness fields before re-signing with a
        // leaked key). The client must reject regardless of signature validity.
        val config = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("a.com", listOf("p1", "p2"), version = 5))
        )
        val payload = gson.toJson(config)
        val signature = TestCertUtil.signPayload(payload, ecKeyPair.private)
        val signedResponse = SignedConfigResponse(payload = payload, signature = signature)
        server.enqueue(MockResponse().setBody(gson.toJson(signedResponse)))

        val api = createApi(signaturePublicKey = publicKeyBase64)
        try {
            api.fetchConfig(1)
            fail("Expected SecurityException for missing expiresAt")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("expiresAt"))
        }
    }

    @Test
    fun `fetchConfig rejects signed config with expired window`() = runTest {
        val ecKeyPair = TestCertUtil.generateEcKeyPair()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.public.encoded)

        // expiresAt in the past — captured-and-replayed signed payload after
        // its freshness window has elapsed. Even though signature is valid,
        // client must refuse to apply.
        val now = System.currentTimeMillis()
        val config = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("a.com", listOf("p1", "p2"), version = 5)),
            issuedAt = now - 86_400_000L,
            expiresAt = now - 60_000L
        )
        val payload = gson.toJson(config)
        val signature = TestCertUtil.signPayload(payload, ecKeyPair.private)
        val signedResponse = SignedConfigResponse(payload = payload, signature = signature)
        server.enqueue(MockResponse().setBody(gson.toJson(signedResponse)))

        val api = createApi(signaturePublicKey = publicKeyBase64)
        try {
            api.fetchConfig(1)
            fail("Expected SecurityException for expired config")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("expired") || e.message!!.contains("replay"))
        }
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

    // ── Several signers and signing-key sets on the wire ────────────────────

    private fun apiWithTrust(trust: io.github.umutcansu.pinvault.crypto.SignatureTrust) = DefaultCertificateConfigApi(
        configUrl = server.url("/").toString(),
        bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
        sslManager = sslManager,
        signatureTrust = trust
    )

    private fun freshConfigPayload(version: Int = 7): String {
        val now = System.currentTimeMillis()
        return gson.toJson(
            CertificateConfig(
                version = version,
                pins = listOf(HostPin("secure.example.com", listOf("pin1", "pin2"), version = version)),
                issuedAt = now,
                expiresAt = now + 3600_000L
            )
        )
    }

    private fun b64(key: java.security.PublicKey) = Base64.getEncoder().encodeToString(key.encoded)

    @Test
    fun `fetchConfig accepts an envelope carrying all signatures for a 2-of-2 block`() = runTest {
        val k1 = TestCertUtil.generateEcKeyPair()
        val k2 = TestCertUtil.generateEcKeyPair()
        val trust = io.github.umutcansu.pinvault.crypto.SignatureTrust(
            "default", listOf(b64(k1.public), b64(k2.public)), 2, emptyList(), 1, null
        )
        val payload = freshConfigPayload()
        val first = TestCertUtil.signPayload(payload, k1.private)
        val second = TestCertUtil.signPayload(payload, k2.private)

        // Only the legacy single field → one signer → rejected.
        server.enqueue(MockResponse().setBody(gson.toJson(SignedConfigResponse(payload, first))))
        try {
            apiWithTrust(trust).fetchConfig(1)
            fail("Expected SecurityException for 1 of 2 signatures")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("1 of 2 required signatures valid"))
        }

        server.enqueue(
            MockResponse().setBody(
                gson.toJson(
                    SignedConfigResponse(
                        payload = payload,
                        signature = first,
                        signatures = listOf(
                            io.github.umutcansu.pinvault.model.SignatureEntry(signature = first),
                            io.github.umutcansu.pinvault.model.SignatureEntry(signature = second)
                        )
                    )
                )
            )
        )
        assertEquals(7, apiWithTrust(trust).fetchConfig(1).version)
    }

    @Test
    fun `fetchConfig applies a key set and accepts a config signed by the key it introduces`() = runTest {
        val oldKey = TestCertUtil.generateEcKeyPair()
        val newKey = TestCertUtil.generateEcKeyPair()
        val recovery = TestCertUtil.generateEcKeyPair()
        val trust = io.github.umutcansu.pinvault.crypto.SignatureTrust(
            "default", listOf(b64(oldKey.public)), 1, listOf(b64(recovery.public)), 1, null
        )
        val keySetPayload = """{"type":"pinvault-signing-keys","version":1,"keys":["${b64(newKey.public)}"]}"""
        val keySet = io.github.umutcansu.pinvault.model.SignedKeySet(
            keySetPayload,
            listOf(io.github.umutcansu.pinvault.model.SignatureEntry(signature = TestCertUtil.signPayload(keySetPayload, recovery.private)))
        )
        val payload = freshConfigPayload()
        server.enqueue(
            MockResponse().setBody(
                gson.toJson(SignedConfigResponse(payload, TestCertUtil.signPayload(payload, newKey.private), signingKeys = keySet))
            )
        )

        assertEquals(7, apiWithTrust(trust).fetchConfig(1).version)
        assertEquals(1, trust.keySetVersion())

        // The old key is revoked from now on, even without a set in the response.
        val next = freshConfigPayload(version = 8)
        server.enqueue(MockResponse().setBody(gson.toJson(SignedConfigResponse(next, TestCertUtil.signPayload(next, oldKey.private)))))
        try {
            apiWithTrust(trust).fetchConfig(7)
            fail("Expected SecurityException for a revoked key")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("revoked by signing-key set v1"))
        }
    }

    @Test
    fun `fetchConfig rejects the whole response when its key set is forged`() = runTest {
        val signingKey = TestCertUtil.generateEcKeyPair()
        val recovery = TestCertUtil.generateEcKeyPair()
        val attacker = TestCertUtil.generateEcKeyPair()
        val trust = io.github.umutcansu.pinvault.crypto.SignatureTrust(
            "default", listOf(b64(signingKey.public)), 1, listOf(b64(recovery.public)), 1, null
        )
        val keySetPayload = """{"type":"pinvault-signing-keys","version":5,"keys":["${b64(attacker.public)}"]}"""
        val forged = io.github.umutcansu.pinvault.model.SignedKeySet(
            keySetPayload,
            listOf(io.github.umutcansu.pinvault.model.SignatureEntry(signature = TestCertUtil.signPayload(keySetPayload, signingKey.private)))
        )
        val payload = freshConfigPayload()
        server.enqueue(
            MockResponse().setBody(
                gson.toJson(SignedConfigResponse(payload, TestCertUtil.signPayload(payload, signingKey.private), signingKeys = forged))
            )
        )

        try {
            apiWithTrust(trust).fetchConfig(1)
            fail("Expected SecurityException for a forged key set")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("Signing-key set rejected"))
        }
        assertEquals(0, trust.keySetVersion())
    }

    @Test
    fun `signed config requests advertise what this client understands`() = runTest {
        val key = TestCertUtil.generateEcKeyPair()
        val payload = freshConfigPayload()
        server.enqueue(MockResponse().setBody(gson.toJson(SignedConfigResponse(payload, TestCertUtil.signPayload(payload, key.private)))))

        createApi(signaturePublicKey = b64(key.public)).fetchConfig(1)

        val features = server.takeRequest().getHeader("X-PinVault-Features").orEmpty().split(',').map { it.trim() }
        assertTrue(features.toString(), features.containsAll(listOf("redelivery", "multisig", "keyset")))
    }
}
