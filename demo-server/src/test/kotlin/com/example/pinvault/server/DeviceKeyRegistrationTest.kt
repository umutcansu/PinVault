package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.*

/**
 * Who may set a device's E2E key (audit M-2). It used to be anyone who could
 * reach the port; now a client certificate must belong to the device, and on
 * plain TLS a registered key is only replaced with the device's token for an
 * end_to_end file. And, since TLS asks for no credential, what one may
 * store: a valid RSA key, within a per-address quota and a per-scope cap.
 */
class DeviceKeyRegistrationTest {

    private val scope = "keys-api"
    private val deviceId = "android-07"

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var files: VaultFileStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var clientCerts: ClientCertStore
    private lateinit var auditStore: AuditLogStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-keys-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokens)
        clientCerts = ClientCertStore(db)
        auditStore = AuditLogStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.configureApp(
        presented: X509Certificate? = null,
        limiter: RateLimiter? = null,
        maxKeys: Int = Int.MAX_VALUE
    ) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        if (presented != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
            })
        }
        routing {
            // Vault administration is served by the management listener only.
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = AuditLog(auditStore, null))
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService(),
                clientCertStore = clientCerts, audit = AuditLog(auditStore, null),
                keyRefusals = AuthFailureRecorder(AuditLog(auditStore, null), action = "device_key_refused"),
                keyLimiter = limiter, maxDeviceKeys = maxKeys)
        }
    }

    private fun rsaPem(): String {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public
        val body = Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    /** A client certificate as the mTLS listener would have verified it. */
    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private suspend fun ApplicationTestBuilder.register(
        pem: String,
        device: String = deviceId,
        proofKey: String? = null,
        proofToken: String? = null
    ): HttpResponse = client.post("/api/v1/vault/devices/$device/public-key") {
        contentType(ContentType.Application.Json)
        proofKey?.let { header("X-Vault-Key", it) }
        proofToken?.let { header("X-Vault-Token", it) }
        setBody("""{"publicKeyPem": ${JsonPrimitive(pem)}}""")
    }

    private fun registeredPem() = keys.get(deviceId, scope)?.publicKeyPem

    private fun actions() = auditStore.page(100, 0).map { it.action }

    // ── plain TLS: no certificate ────────────────────────────────────────

    @Test
    fun `the first key of a device is accepted and audited`() = testApplication {
        configureApp()
        val pem = rsaPem()
        assertEquals(HttpStatusCode.OK, register(pem).status)
        assertEquals(pem, registeredPem())
        assertEquals(listOf("device_key_registered"), actions())
    }

    @Test
    fun `the same key again is accepted without proof and not audited twice`() = testApplication {
        configureApp()
        val pem = rsaPem()
        register(pem)
        // Same key, different line breaks: still the device's own key.
        assertEquals(HttpStatusCode.OK, register(pem.replace("\n", "\r\n")).status)
        assertEquals(1, actions().count { it == "device_key_registered" })
    }

    @Test
    fun `a different key without proof is refused and the registered key stays`() = testApplication {
        configureApp()
        val original = rsaPem()
        register(original)

        val response = register(rsaPem())
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertTrue(response.bodyAsText().contains("key_change_requires_proof"))
        assertEquals(original, registeredPem())
    }

    @Test
    fun `the device's token for an end_to_end file lets it replace its key`() = testApplication {
        configureApp()
        register(rsaPem())
        files.put(scope, "secret-model", "x".toByteArray(), "token", "end_to_end")
        val token = tokenService.generate(scope, "secret-model", deviceId)

        val replacement = rsaPem()
        assertEquals(HttpStatusCode.OK, register(replacement, proofKey = "secret-model", proofToken = token.plaintext).status)
        assertEquals(replacement, registeredPem())
        assertTrue(actions().contains("device_key_replaced"))
    }

    @Test
    fun `a token that is not for an end_to_end file, or not for this device, is not proof`() = testApplication {
        configureApp()
        val original = rsaPem()
        register(original)
        files.put(scope, "flags", "x".toByteArray(), "token", "plain")
        files.put(scope, "secret-model", "x".toByteArray(), "token", "end_to_end")
        val plainFileToken = tokenService.generate(scope, "flags", deviceId)
        val otherDeviceToken = tokenService.generate(scope, "secret-model", "android-08")

        assertEquals(HttpStatusCode.Conflict, register(rsaPem(), proofKey = "flags", proofToken = plainFileToken.plaintext).status)
        assertEquals(HttpStatusCode.Conflict, register(rsaPem(), proofKey = "secret-model", proofToken = otherDeviceToken.plaintext).status)
        assertEquals(HttpStatusCode.Conflict, register(rsaPem(), proofKey = "secret-model", proofToken = "guess").status)
        assertEquals(original, registeredPem())
    }

    @Test
    fun `an administrator reset frees the slot for the next key`() = testApplication {
        configureApp()
        register(rsaPem())

        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key").status)
        assertNull(registeredPem())
        assertEquals(HttpStatusCode.NotFound, client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key").status)

        val fresh = rsaPem()
        assertEquals(HttpStatusCode.OK, register(fresh).status)
        assertEquals(fresh, registeredPem())
        assertTrue(actions().contains("device_key_reset"))
    }

    // ── mTLS: a certificate was presented ────────────────────────────────

    @Test
    fun `a certificate whose device id is proven may register and replace its key`() = testApplication {
        // Proven (V20): an attested key, or a token an administrator bound to the device.
        clientCerts.addUnlessRevoked("tablet-07", "PinVault Client: tablet-07", "fp", "2026-10-01T00:00:00Z", deviceUid = deviceId, deviceUidProven = true)
        configureApp(presented = clientCert("tablet-07"))

        assertEquals(HttpStatusCode.OK, register(rsaPem()).status)
        val replacement = rsaPem()
        assertEquals(HttpStatusCode.OK, register(replacement).status)
        assertEquals(replacement, registeredPem())
    }

    @Test
    fun `a certificate that only claims the device registers a first key but replaces none without proof`() = testApplication {
        // The device id the enrolling party sent, nothing more: anyone with a token
        // who knows the victim's ANDROID_ID could have enrolled so.
        clientCerts.add("tablet-09", "PinVault Client: tablet-09", "fp", "2026-10-01T00:00:00Z", deviceUid = deviceId)
        configureApp(presented = clientCert("tablet-09"))

        val first = rsaPem()
        assertEquals(HttpStatusCode.OK, register(first).status, "first key: as on TLS")
        val refused = register(rsaPem())
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertTrue(refused.bodyAsText().contains("key_change_requires_proof"))
        assertEquals(first, registeredPem())
        // The device's token for an end_to_end file is proof, over mTLS as over TLS.
        files.put(scope, "secret-model", "x".toByteArray(), "token", "end_to_end")
        val token = tokenService.generate(scope, "secret-model", deviceId)
        val replacement = rsaPem()
        assertEquals(HttpStatusCode.OK, register(replacement, proofKey = "secret-model", proofToken = token.plaintext).status)
        assertEquals(replacement, registeredPem())
    }

    @Test
    fun `under auto-enrollment the certificate's client id is the device id`() = testApplication {
        configureApp(presented = clientCert(deviceId))
        assertEquals(HttpStatusCode.OK, register(rsaPem()).status)
    }

    @Test
    fun `another device's certificate is refused and the key stays`() = testApplication {
        val original = rsaPem()
        keys.register(deviceId, scope, original, timestamp = "2026-10-01T00:00:00Z")
        clientCerts.add("tablet-08", "PinVault Client: tablet-08", "fp", "2026-10-01T00:00:00Z", deviceUid = "android-08")
        configureApp(presented = clientCert("tablet-08"))

        val response = register(rsaPem())
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("device_identity_mismatch"))
        assertEquals(original, registeredPem())
        // Over mTLS the certificate decides: a file token does not stand in for it.
        files.put(scope, "secret-model", "x".toByteArray(), "token", "end_to_end")
        val token = tokenService.generate(scope, "secret-model", deviceId)
        assertEquals(HttpStatusCode.Forbidden, register(rsaPem(), proofKey = "secret-model", proofToken = token.plaintext).status)
    }

    @Test
    fun `a revoked certificate is refused`() = testApplication {
        clientCerts.add("tablet-07", "PinVault Client: tablet-07", "fp", "2026-10-01T00:00:00Z", deviceUid = deviceId)
        clientCerts.revoke("tablet-07")
        configureApp(presented = clientCert("tablet-07"))
        assertEquals(HttpStatusCode.Forbidden, register(rsaPem()).status)
        assertNull(registeredPem())
    }

    // ── what a registration may store: no credential is asked on TLS ─────

    @Test
    fun `a malformed device id is refused`() = testApplication {
        configureApp()
        val response = register(rsaPem(), device = "x".repeat(65))
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.bodyAsText().contains("invalid_device_id"))
        assertEquals(0, keys.count(scope))
    }

    @Test
    fun `only an RSA key the server can encrypt for is stored`() = testApplication {
        configureApp()
        fun pemOf(key: java.security.PublicKey) = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n") + "\n-----END PUBLIC KEY-----"
        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public
        val weak = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().public

        for (junk in listOf("not a key", "x".repeat(60_000), pemOf(ec), pemOf(weak))) {
            val response = register(junk)
            assertEquals(HttpStatusCode.BadRequest, response.status)
            assertTrue(response.bodyAsText().contains("invalid_public_key"))
        }
        val otherAlgorithm = client.post("/api/v1/vault/devices/$deviceId/public-key") {
            contentType(ContentType.Application.Json)
            setBody("""{"publicKeyPem": ${JsonPrimitive(rsaPem())}, "algorithm": "RSA-PKCS1"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, otherAlgorithm.status)
        assertTrue(otherAlgorithm.bodyAsText().contains("unsupported_algorithm"))
        assertNull(registeredPem())
        assertTrue(actions().isEmpty())
    }

    @Test
    fun `a key is stored re-encoded, whatever spacing it arrived with`() = testApplication {
        configureApp()
        val pem = rsaPem()
        assertEquals(HttpStatusCode.OK, register(pem.replace("\n", "\r\n\r\n   ") + "\n\n\n").status)
        assertEquals(pem, registeredPem())
    }

    @Test
    fun `a source address writes at most its quota of keys over TLS`() = testApplication {
        configureApp(limiter = RateLimiter(maxAttempts = 2, windowMs = 60_000))
        val first = rsaPem()
        assertEquals(HttpStatusCode.OK, register(first, device = "made-up-1").status)
        assertEquals(HttpStatusCode.OK, register(rsaPem(), device = "made-up-2").status)

        val third = register(rsaPem(), device = "made-up-3")
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertTrue(third.bodyAsText().contains("rate_limited"))
        assertNull(keys.get("made-up-3", scope))
        assertTrue(actions().contains("device_key_refused"))
        // A device repeating its own key writes nothing new and is not held back.
        assertEquals(HttpStatusCode.OK, register(first, device = "made-up-1").status)
    }

    @Test
    fun `a certificate writing its own slot is not counted`() = testApplication {
        configureApp(presented = clientCert(deviceId), limiter = RateLimiter(maxAttempts = 1, windowMs = 60_000))
        repeat(3) { assertEquals(HttpStatusCode.OK, register(rsaPem()).status) }
    }

    @Test
    fun `a full scope refuses new devices and keeps serving known ones`() = testApplication {
        configureApp(maxKeys = 2)
        val first = rsaPem()
        assertEquals(HttpStatusCode.OK, register(first, device = "dev-1").status)
        assertEquals(HttpStatusCode.OK, register(rsaPem(), device = "dev-2").status)

        val third = register(rsaPem(), device = "dev-3")
        assertEquals(HttpStatusCode.ServiceUnavailable, third.status)
        assertTrue(third.bodyAsText().contains("device_key_limit_reached"))
        assertEquals(2, keys.count(scope))
        assertEquals(HttpStatusCode.OK, register(first, device = "dev-1").status)
    }

    @Test
    fun `a known device may still replace its key when the scope is full`() = testApplication {
        configureApp(presented = clientCert(deviceId), maxKeys = 1)
        assertEquals(HttpStatusCode.OK, register(rsaPem()).status)
        val replacement = rsaPem()
        assertEquals(HttpStatusCode.OK, register(replacement).status)
        assertEquals(replacement, registeredPem())
    }
}
