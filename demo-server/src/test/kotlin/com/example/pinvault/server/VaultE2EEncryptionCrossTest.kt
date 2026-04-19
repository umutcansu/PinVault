package com.example.pinvault.server

import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionRoundtripTestHelper
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64
import kotlin.test.*

/** Test-only stand-in for the library-side DeviceKeyProvider. */
private class TestDevice(bits: Int = 2048) {
    val keyPair: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
    val publicKeyPem: String
        get() {
            val b64 = Base64.getEncoder().encodeToString(keyPair.public.encoded).chunked(64).joinToString("\n")
            return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----"
        }
}

/**
 * Full end-to-end cross-layer: admin uploads a file marked
 * `encryption=end_to_end`, a "device" registers its public key, then
 * fetches. The response body is the server-side RSA-OAEP + AES-GCM
 * envelope; the library's [VaultFileDecryptor] unwraps it using the
 * device's private key. Verifies that both sides use the exact same
 * envelope format and that wire traffic never carries plaintext.
 */
class VaultE2EEncryptionCrossTest {

    private val testApi = "e2e-cross-api"

    private lateinit var db: DatabaseManager
    private lateinit var vfs: VaultFileStore
    private lateinit var dist: VaultDistributionStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var pks: DevicePublicKeyStore
    private lateinit var tokenSvc: VaultAccessTokenService
    private lateinit var encSvc: VaultEncryptionService
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("cross-e2e-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        vfs = VaultFileStore(db)
        dist = VaultDistributionStore(db)
        tokens = VaultFileTokenStore(db)
        pks = DevicePublicKeyStore(db)
        tokenSvc = VaultAccessTokenService(tokens)
        encSvc = VaultEncryptionService()
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { vaultRoutes(testApi, vfs, dist, tokens, pks, tokenSvc, encSvc) }
    }

    @Test
    fun `full e2e flow — admin uploads, device registers key, fetches, decrypts`() = testApplication {
        configureApp()

        // 1. Admin uploads with end_to_end encryption + token policy.
        val plaintext = """{"secret":"top-secret-value","nonce":"abc123"}"""
        client.put("/api/v1/vault/encrypted-config?policy=token&encryption=end_to_end") {
            setBody(plaintext.toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        // 2. Device-side: generate RSA key pair (software provider).
        val device = TestDevice()
        val deviceId = "mi-9t-test"

        // 3. Device registers public key with the server.
        client.post("/api/v1/vault/devices/$deviceId/public-key") {
            contentType(ContentType.Application.Json)
            setBody("""{"publicKeyPem": ${kotlinx.serialization.json.JsonPrimitive(device.publicKeyPem)}}""")
        }

        // 4. Admin issues a token for this device.
        val token = tokenSvc.generate(testApi, "encrypted-config", deviceId)

        // 5. Device fetches: server wraps plaintext with device's public key.
        val response = client.get("/api/v1/vault/encrypted-config") {
            header("X-Device-Id", deviceId)
            header("X-Vault-Token", token.plaintext)
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("end_to_end", response.headers["X-Vault-Encryption"])

        val envelope = response.readRawBytes()
        // Wire body must NOT contain the plaintext anywhere.
        assertFalse(
            envelope.toString(Charsets.UTF_8).contains("top-secret-value"),
            "Envelope must not contain plaintext secret"
        )

        // 6. Device decrypts with its private key.
        val decrypted = VaultEncryptionRoundtripTestHelper.decrypt(envelope, device.keyPair.private)
        assertEquals(plaintext, String(decrypted))
    }

    @Test
    fun `fetching E2E file without registered public key returns precondition failed`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/e2e-orphan?policy=token&encryption=end_to_end") {
            setBody("content".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        val token = tokenSvc.generate(testApi, "e2e-orphan", "never-registered")

        val response = client.get("/api/v1/vault/e2e-orphan") {
            header("X-Device-Id", "never-registered")
            header("X-Vault-Token", token.plaintext)
        }
        assertEquals(HttpStatusCode.PreconditionFailed, response.status)
        assertTrue(response.bodyAsText().contains("public-key", ignoreCase = true))
    }

    @Test
    fun `wrong device key cannot decrypt another device's envelope`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/shared-e2e?policy=token&encryption=end_to_end") {
            setBody("secret-for-alice".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        val alice = TestDevice()
        val mallory = TestDevice()

        // Alice registers her key.
        client.post("/api/v1/vault/devices/alice/public-key") {
            contentType(ContentType.Application.Json)
            setBody("""{"publicKeyPem": ${kotlinx.serialization.json.JsonPrimitive(alice.publicKeyPem)}}""")
        }
        val aliceToken = tokenSvc.generate(testApi, "shared-e2e", "alice")

        // Alice fetches her envelope.
        val envelope = client.get("/api/v1/vault/shared-e2e") {
            header("X-Device-Id", "alice"); header("X-Vault-Token", aliceToken.plaintext)
        }.readRawBytes()

        // Alice decrypts successfully.
        assertEquals("secret-for-alice",
            String(VaultEncryptionRoundtripTestHelper.decrypt(envelope, alice.keyPair.private)))

        // Mallory with her own private key cannot decrypt.
        try {
            VaultEncryptionRoundtripTestHelper.decrypt(envelope, mallory.keyPair.private)
            fail("Mallory should not be able to decrypt Alice's envelope")
        } catch (_: Exception) { /* expected */ }
    }

    @Test
    fun `two fetches of same E2E file produce different ciphertexts`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/rerolled?policy=token&encryption=end_to_end") {
            setBody("deterministic-plaintext".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }

        val device = TestDevice()
        client.post("/api/v1/vault/devices/rr/public-key") {
            contentType(ContentType.Application.Json)
            setBody("""{"publicKeyPem": ${kotlinx.serialization.json.JsonPrimitive(device.publicKeyPem)}}""")
        }
        val token = tokenSvc.generate(testApi, "rerolled", "rr")

        // Don't 304 — use version=0 so the server always returns a fresh envelope.
        val env1 = client.get("/api/v1/vault/rerolled?version=0") {
            header("X-Device-Id", "rr"); header("X-Vault-Token", token.plaintext)
        }.readRawBytes()
        val env2 = client.get("/api/v1/vault/rerolled?version=0") {
            header("X-Device-Id", "rr"); header("X-Vault-Token", token.plaintext)
        }.readRawBytes()

        // Ciphertexts differ (fresh session key + IV every time),
        // but decrypt to the same plaintext.
        assertFalse(env1.contentEquals(env2), "Ciphertexts must differ between fetches")
        val p1 = VaultEncryptionRoundtripTestHelper.decrypt(env1, device.keyPair.private)
        val p2 = VaultEncryptionRoundtripTestHelper.decrypt(env2, device.keyPair.private)
        assertContentEquals(p1, p2)
    }
}
