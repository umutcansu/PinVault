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

    // ── P12 passwords: negotiated per response, never carried by the app ──

    private fun opens(p12: ByteArray, password: String) =
        runCatching { java.security.KeyStore.getInstance("PKCS12").load(p12.inputStream(), password.toCharArray()) }.isSuccess

    @Test
    fun `a host client certificate sent with a one-off password comes back under the block password`() = runTest {
        val oneOff = TestCertUtil.generateSelfSigned(cn = "host-client", password = "one-off-7Qx").p12Bytes
        server.enqueue(
            MockResponse()
                .setBody(okio.Buffer().write(oneOff))
                .setHeader("Content-Type", "application/octet-stream")
                .setHeader("X-P12-Password", "one-off-7Qx")
        )
        val api = DefaultCertificateConfigApi(
            configUrl = server.url("/").toString(),
            bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
            sslManager = sslManager,
            clientKeyPassword = "block-pass"
        )
        val bytes = api.downloadHostClientCert("host.com")

        assertEquals("p12password", server.takeRequest().getHeader("X-PinVault-Features"))
        assertTrue(opens(bytes, "block-pass"))
        assertFalse(opens(bytes, "one-off-7Qx"))
    }

    @Test
    fun `enrollment asks for a one-off password and returns it with the bundle`() = runTest {
        val bundle = TestCertUtil.generateSelfSigned(cn = "device", password = "one-off-9Kz").p12Bytes
        server.enqueue(
            MockResponse()
                .setBody(okio.Buffer().write(bundle))
                .setHeader("X-P12-SHA256", "hash")
                .setHeader("X-P12-Password", "one-off-9Kz")
        )
        val result = createApi().enroll(token = "t", deviceId = null, deviceAlias = null, deviceUid = null)

        assertEquals("p12password", server.takeRequest().getHeader("X-PinVault-Features"))
        assertEquals("one-off-9Kz", result.p12Password)
        assertFalse("the password stays out of logs", result.toString().contains("one-off-9Kz"))
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

    // ── CSR enrollment and renewal ──────────────────────────────────────────

    private val csr = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x00)
    private val chainJson = """{"clientId":"dev-1","chain":["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"]}"""

    @Test
    fun `enrollWithCsr sends the CSR and the csr feature and reads a PEM chain`() = runTest {
        server.enqueue(
            MockResponse().setBody(chainJson)
                .setHeader("Content-Type", "application/json")
                .setHeader("X-PinVault-Cert-Format", "pem-chain")
        )
        val result = createApi().enrollWithCsr("tok", null, "alias", "uid", csr)

        val request = server.takeRequest()
        assertEquals("/api/v1/client-certs/enroll", request.path)
        val features = request.getHeader("X-PinVault-Features").orEmpty().split(',').map { it.trim() }
        assertTrue(features.toString(), features.containsAll(listOf("p12password", "csr")))
        val body = org.json.JSONObject(request.body.readUtf8())
        assertEquals("tok", body.getString("token"))
        assertEquals("alias", body.getString("deviceAlias"))
        assertEquals(Base64.getEncoder().encodeToString(csr), body.getString("csr"))

        assertTrue(result.isCertificateChain)
        assertEquals(2, result.certificateChainPem!!.size)
        assertEquals(0, result.p12Bytes.size)
    }

    @Test
    fun `enrollment goes to the enrollment URL when one is set`() = runTest {
        val tls = MockWebServer().also { it.start() }
        try {
            tls.enqueue(MockResponse().setBody(chainJson).setHeader("X-PinVault-Cert-Format", "pem-chain"))
            val api = DefaultCertificateConfigApi(
                configUrl = server.url("/").toString(),
                bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
                sslManager = sslManager,
                enrollmentUrl = tls.url("/").toString()
            )
            assertTrue(api.enrollWithCsr("tok", null, null, null, csr).isCertificateChain)
            assertEquals("/api/v1/client-certs/enroll", tls.takeRequest().path)
            assertEquals(0, server.requestCount)
        } finally {
            tls.shutdown()
        }
    }

    @Test
    fun `enrollWithCsr falls back to a P12 when the server ignores the CSR`() = runTest {
        val bundle = TestCertUtil.generateSelfSigned(cn = "device", password = "changeit").p12Bytes
        server.enqueue(MockResponse().setBody(okio.Buffer().write(bundle)).setHeader("X-P12-SHA256", "hash"))

        val result = createApi().enrollWithCsr("tok", null, null, null, csr)

        assertFalse(result.isCertificateChain)
        assertArrayEquals(bundle, result.p12Bytes)
        assertEquals("hash", result.p12Hash)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `enrollWithCsr rejects a chain answer without a chain`() = runTest {
        server.enqueue(MockResponse().setBody("""{"clientId":"x"}""").setHeader("X-PinVault-Cert-Format", "pem-chain"))
        try {
            createApi().enrollWithCsr("tok", null, null, null, csr)
            fail("expected an exception")
        } catch (e: Exception) {
            assertTrue(e.message!!.contains("chain"))
        }
    }

    @Test
    fun `renewClientCert over the block returns the issued chain`() = runTest {
        server.enqueue(MockResponse().setBody(chainJson))
        val response = createApi().renewClientCert("dev-1", csr, null)

        val request = server.takeRequest()
        assertEquals("/api/v1/client-certs/renew", request.path)
        assertEquals("csr", request.getHeader("X-PinVault-Features"))
        val body = org.json.JSONObject(request.body.readUtf8())
        assertEquals("dev-1", body.getString("clientId"))
        assertEquals(Base64.getEncoder().encodeToString(csr), body.getString("csr"))

        val issued = response as io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.Issued
        assertEquals(2, issued.certificateChainPem.size)
    }

    @Test
    fun `renewClientCert uses the recovery URL verbatim when given`() = runTest {
        val recovery = MockWebServer().also { it.start() }
        try {
            recovery.enqueue(MockResponse().setBody(chainJson))
            val response = createApi().renewClientCert("dev-1", csr, recovery.url("/recover/").toString())

            assertEquals(0, server.requestCount)
            assertEquals("/recover/api/v1/client-certs/renew", recovery.takeRequest().path)
            assertTrue(response is io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.Issued)
        } finally {
            recovery.shutdown()
        }
    }

    @Test
    fun `renewClientCert maps 403 reenroll_required, 404 unsupported and other codes to failures`() = runTest {
        val api = createApi()

        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"reenroll_required","message":"revoked"}"""))
        val refused = api.renewClientCert("dev-1", csr) as io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.ReenrollRequired
        assertEquals("revoked", refused.reason)

        server.enqueue(MockResponse().setResponseCode(404))
        assertEquals(io.github.umutcansu.pinvault.model.ClientCertRenewalResponse.Unsupported, api.renewClientCert("dev-1", csr))

        server.enqueue(MockResponse().setResponseCode(429).setBody("""{"error":"rate_limited"}"""))
        try {
            api.renewClientCert("dev-1", csr)
            fail("expected an exception")
        } catch (e: Exception) {
            assertTrue(e.message!!.contains("429"))
        }

        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"something_else"}"""))
        try {
            api.renewClientCert("dev-1", csr)
            fail("expected an exception")
        } catch (e: Exception) {
            assertTrue(e.message!!.contains("403"))
        }
    }

    @Test
    fun `rebuildBootstrapClient asks the SSL manager for a fresh client and requests use it`() = runTest {
        val api = createApi()
        io.mockk.verify(exactly = 1) { sslManager.buildBootstrapClient(any()) }

        api.rebuildBootstrapClient()
        io.mockk.verify(exactly = 2) { sslManager.buildBootstrapClient(any()) }

        // Retrofit calls resolve the client per request, so they keep working after a rebuild.
        server.enqueue(MockResponse().setBody("""{"status":"ok"}"""))
        assertTrue(api.healthCheck())
    }

    @Test
    fun `registerDevicePublicKey sends the key proof headers only when it has a proof`() = runTest {
        server.enqueue(MockResponse().setBody("""{"registered":"true"}"""))
        server.enqueue(MockResponse().setBody("""{"registered":"true"}"""))
        val api = createApi()

        api.registerDevicePublicKey("android-07", "PEM")
        val plain = server.takeRequest()
        assertEquals("/api/v1/vault/devices/android-07/public-key", plain.path)
        assertNull(plain.getHeader("X-Vault-Key"))
        assertNull(plain.getHeader("X-Vault-Token"))

        api.registerDevicePublicKey("android-07", "PEM", DeviceKeyProof("secret-model", "tok-123"))
        val proven = server.takeRequest()
        assertEquals("secret-model", proven.getHeader("X-Vault-Key"))
        assertEquals("tok-123", proven.getHeader("X-Vault-Token"))
    }

    @Test
    fun `registerDevicePublicKey reports a refused key change and a foreign certificate`() = runTest {
        server.enqueue(MockResponse().setResponseCode(409).setBody("""{"error":"key_change_requires_proof"}"""))
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"device_identity_mismatch"}"""))
        val api = createApi()

        val conflict = runCatching { api.registerDevicePublicKey("android-07", "PEM") }.exceptionOrNull()
        assertTrue(conflict?.message.orEmpty(), conflict?.message.orEmpty().contains("409"))
        val foreign = runCatching { api.registerDevicePublicKey("android-07", "PEM") }.exceptionOrNull()
        assertTrue(foreign?.message.orEmpty(), foreign?.message.orEmpty().contains("403"))
    }

    @Test
    fun `a key proof never prints its token`() {
        assertFalse(DeviceKeyProof("secret-model", "tok-123").toString().contains("tok-123"))
    }
}
