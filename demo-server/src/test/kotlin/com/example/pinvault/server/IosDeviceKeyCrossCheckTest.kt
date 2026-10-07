package com.example.pinvault.server

import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.UserAuthAttestationMode
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.service.VaultEncryptionService.Companion.RSA_OAEP_SHA256_MGF1_SHA256
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.test.*

/**
 * The iOS device keys against this server (PORTING.md §3/§4).
 *
 * 1. Cross-check: the PEM the iOS `DeviceKeys.software` provider exported
 *    (`pinvault-ios/Tests/PinVaultTests/Fixtures/vault/ios-device-key.spki.txt`)
 *    registers through the real route with `RSA-OAEP-SHA256-MGF1-SHA256` for
 *    both purposes, and the download route wraps for it with MGF1-SHA256. The
 *    envelopes the route makes are the fixtures the Swift side opens
 *    (`DeviceKeyServerCrossCheckTests`); `PINVAULT_WRITE_IOS_FIXTURES=1`
 *    rewrites them, otherwise the committed ones are checked.
 * 2. What a screen-lock (user_auth) key without an Android attestation chain —
 *    every iOS key until App Attest is accepted — can do on today's route.
 */
class IosDeviceKeyCrossCheckTest {

    private val scope = "ios-api"
    private val device = "ios-cross-check"
    private val fixtures = File("../pinvault-ios/Tests/PinVaultTests/Fixtures/vault")
    private val endToEndPlaintext = "pinvault iOS cross-check: end_to_end".toByteArray()
    private val userAuthPlaintext = "pinvault iOS cross-check: user_auth".toByteArray()

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var files: VaultFileStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-ios-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokens)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp(mode: UserAuthAttestationMode = UserAuthAttestationMode.WARN) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        val audit = AuditLog(AuditLogStore(db), null)
        routing {
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService(),
                audit = audit, keyRefusals = AuthFailureRecorder(audit, action = "device_key_refused"),
                userAuthAttestationMode = mode)
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = audit)
        }
    }

    private suspend fun ApplicationTestBuilder.register(
        pem: String,
        purpose: String? = null,
        token: String? = null,
        proofKey: String = "wallet"
    ): HttpResponse = client.post("/api/v1/vault/devices/$device/public-key") {
        contentType(ContentType.Application.Json)
        token?.let {
            header("X-Vault-Key", proofKey)
            header("X-Vault-Token", it)
        }
        // What the iOS library sends: the provider's PEM, the iOS algorithm, no attestationChain.
        setBody(buildJsonObject {
            put("publicKeyPem", pem)
            put("algorithm", RSA_OAEP_SHA256_MGF1_SHA256)
            purpose?.let { put("purpose", it) }
        }.toString())
    }

    private suspend fun ApplicationTestBuilder.download(key: String): HttpResponse =
        client.get("/api/v1/vault/$key") { header("X-Device-Id", device) }

    private suspend fun HttpResponse.field(name: String): String? =
        Json.parseToJsonElement(bodyAsText()).jsonObject[name]?.jsonPrimitive?.content

    private fun iosPem(): String = File(fixtures, "ios-device-key.spki.txt").readText().trim()

    /** The provider's private key: PKCS#1, as `SecKeyCopyExternalRepresentation` gives it. */
    private fun iosPrivateKey(): PrivateKey {
        val rsa = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(File(fixtures, "ios-device-key.pkcs1.bin").readBytes())
        return KeyFactory.getInstance("RSA").generatePrivate(RSAPrivateCrtKeySpec(
            rsa.modulus, rsa.publicExponent, rsa.privateExponent, rsa.prime1, rsa.prime2, rsa.exponent1, rsa.exponent2, rsa.coefficient
        ))
    }

    /** Opens an envelope with plain JCA and the given MGF1 hash. */
    private fun open(envelope: ByteArray, key: PrivateKey, mgf1: MGF1ParameterSpec): ByteArray {
        val wrappedLength = java.nio.ByteBuffer.wrap(envelope, 0, 4).int
        val wrapped = envelope.copyOfRange(4, 4 + wrappedLength)
        val iv = envelope.copyOfRange(4 + wrappedLength, 4 + wrappedLength + 12)
        val rsa = Cipher.getInstance("RSA/ECB/OAEPPadding")
        rsa.init(Cipher.DECRYPT_MODE, key, OAEPParameterSpec("SHA-256", "MGF1", mgf1, PSource.PSpecified.DEFAULT))
        val sessionKey = SecretKeySpec(rsa.doFinal(wrapped), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))
            doFinal(envelope.copyOfRange(4 + wrappedLength + 12, envelope.size))
        }
    }

    // ── 1. Cross-check ──────────────────────────────────────────────────

    @Test
    fun `the iOS provider's key registers with the iOS algorithm and the route wraps for it with MGF1-SHA256`() = testApplication {
        configureApp()
        files.put(scope, "e2e-file", endToEndPlaintext, "public", "end_to_end")
        files.put(scope, "ua-file", userAuthPlaintext, "public", "user_auth")
        val pem = iosPem()
        val privateKey = iosPrivateKey()

        assertEquals(HttpStatusCode.OK, register(pem).status)
        assertEquals(HttpStatusCode.OK, register(pem, purpose = "user_auth").status)
        assertEquals(RSA_OAEP_SHA256_MGF1_SHA256, keys.get(device, scope)!!.algorithm)
        assertEquals(RSA_OAEP_SHA256_MGF1_SHA256, keys.userAuthKeys().get(device, scope)!!.algorithm)

        for ((key, plaintext, fixture) in listOf(
            Triple("e2e-file", endToEndPlaintext, "server-end-to-end.envelope.bin"),
            Triple("ua-file", userAuthPlaintext, "server-user-auth.envelope.bin")
        )) {
            val response = download(key)
            assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
            val envelope = response.readRawBytes()
            assertEquals(256, java.nio.ByteBuffer.wrap(envelope, 0, 4).int, "RSA-2048")
            assertContentEquals(plaintext, open(envelope, privateKey, MGF1ParameterSpec.SHA256))
            assertFails("$key must not open with MGF1-SHA1 (what Android uses)") { open(envelope, privateKey, MGF1ParameterSpec.SHA1) }

            val committed = File(fixtures, fixture)
            if (System.getenv("PINVAULT_WRITE_IOS_FIXTURES") == "1") committed.writeBytes(envelope)
            assertTrue(committed.exists(), "missing fixture ${committed.path}")
            assertContentEquals(plaintext, open(committed.readBytes(), privateKey, MGF1ParameterSpec.SHA256), "committed $fixture")
        }
    }

    // ── 2. Today's rules for an iOS screen-lock key ─────────────────────

    private fun freshPem(): String {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.public.encoded).chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----"
    }

    private fun deviceToken(): String {
        if (files.get(scope, "wallet") == null) files.put(scope, "wallet", "x".toByteArray(), "token", "user_auth")
        return tokenService.generate(scope, "wallet", device).plaintext
    }

    @Test
    fun `warn - the first key is taken, a new key is refused even with the device's token, an admin reset frees the slot`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        val first = freshPem()
        assertEquals(HttpStatusCode.OK, register(first, purpose = "user_auth").status, "first registration: accepted on first use")
        assertEquals(HttpStatusCode.OK, register(first, purpose = "user_auth").status, "the same key again: a no-op")

        // A new key (the passcode was removed and set again, a wipe, a new install with the same device id):
        val second = freshPem()
        val bare = register(second, purpose = "user_auth")
        assertEquals(HttpStatusCode.Conflict, bare.status)
        assertEquals("user_auth_key_exists", bare.field("error"))
        assertEquals("credential_required", bare.field("reason"))
        val proven = register(second, purpose = "user_auth", token = deviceToken())
        assertEquals(HttpStatusCode.Conflict, proven.status, "the token is not enough: an Android attestation is needed too")
        assertEquals("chain_missing", proven.field("reason"))

        // Files are still sealed for the first key (the device can no longer open them).
        files.put(scope, "ua-file", userAuthPlaintext, "public", "user_auth")
        assertEquals(HttpStatusCode.OK, download("ua-file").status)

        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$scope/vault/devices/$device/public-key?purpose=user_auth").status)
        assertEquals(HttpStatusCode.OK, register(second, purpose = "user_auth").status, "after the reset: a first key again")
    }

    @Test
    fun `off - the same, and a token-proven replacement is refused as attestation_off`() = testApplication {
        configureApp(UserAuthAttestationMode.OFF)
        assertEquals(HttpStatusCode.OK, register(freshPem(), purpose = "user_auth").status)
        val replaced = register(freshPem(), purpose = "user_auth", token = deviceToken())
        assertEquals(HttpStatusCode.Conflict, replaced.status)
        assertEquals("attestation_off", replaced.field("reason"))
    }

    @Test
    fun `enforce - an iOS key is refused outright, and a stored unattested key gets 412`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val refused = register(freshPem(), purpose = "user_auth")
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("attestation_required", refused.field("error"))

        // A key stored before enforce was switched on is not sealed for: 412, and registering it again is 403.
        keys.userAuthKeys().register(device, scope, freshPem(), RSA_OAEP_SHA256_MGF1_SHA256, "2026-10-01T00:00:00Z")
        files.put(scope, "ua-file", userAuthPlaintext, "public", "user_auth")
        val download = download("ua-file")
        assertEquals(HttpStatusCode.PreconditionFailed, download.status)
        assertEquals("user_auth_key_required", download.field("error"))
    }

    @Test
    fun `the end_to_end key is replaced with the device's token, without an attestation`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        assertEquals(HttpStatusCode.OK, register(freshPem()).status)
        val bare = register(freshPem())
        assertEquals(HttpStatusCode.Conflict, bare.status)
        assertEquals("key_change_requires_proof", bare.field("error"))
        files.put(scope, "model", "m".toByteArray(), "token", "end_to_end")
        val token = tokenService.generate(scope, "model", device).plaintext
        assertEquals(HttpStatusCode.OK, register(freshPem(), token = token, proofKey = "model").status)
    }
}
