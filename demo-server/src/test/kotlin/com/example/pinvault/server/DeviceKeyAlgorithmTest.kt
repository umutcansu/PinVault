package com.example.pinvault.server

import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionRoundtripTestHelper
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.service.VaultEncryptionService.Companion.RSA_OAEP_SHA256
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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.test.*

/**
 * The MGF1 hash of RSA-OAEP per device key (PORTING.md §3): Android keys are
 * `RSA-OAEP-SHA256` (SHA-256 + MGF1-SHA1, the default), iOS keys
 * `RSA-OAEP-SHA256-MGF1-SHA256` (Apple's `.rsaEncryptionOAEPSHA256`, which
 * cannot open MGF1-SHA1). The algorithm is stored with each key and every
 * end_to_end and user_auth file is wrapped with it — checked here by opening
 * the envelope with plain JCA and each MGF1 spec.
 */
class DeviceKeyAlgorithmTest {

    private val scope = "alg-api"
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var files: VaultFileStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var auditStore: AuditLogStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-alg-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        keys = DevicePublicKeyStore(db)
        auditStore = AuditLogStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        val tokens = VaultFileTokenStore(db)
        val tokenService = VaultAccessTokenService(tokens)
        val audit = AuditLog(auditStore, null)
        routing {
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService(),
                audit = audit, keyRefusals = AuthFailureRecorder(audit, action = "device_key_refused"))
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = audit)
        }
    }

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun KeyPair.pem(): String =
        "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(public.encoded).chunked(64).joinToString("\n") + "\n-----END PUBLIC KEY-----"

    private suspend fun ApplicationTestBuilder.register(device: String, pair: KeyPair, algorithm: String?, purpose: String? = null): HttpResponse =
        client.post("/api/v1/vault/devices/$device/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("publicKeyPem", pair.pem())
                algorithm?.let { put("algorithm", it) }
                purpose?.let { put("purpose", it) }
            }.toString())
        }

    private suspend fun ApplicationTestBuilder.download(key: String, device: String): ByteArray {
        val response = client.get("/api/v1/vault/$key") { header("X-Device-Id", device) }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return response.readRawBytes()
    }

    /** Opens an envelope with plain JCA and the given MGF1 hash — what the device's platform does. */
    private fun open(envelope: ByteArray, pair: KeyPair, mgf1: MGF1ParameterSpec): ByteArray {
        val wrappedLength = java.nio.ByteBuffer.wrap(envelope, 0, 4).int
        val wrapped = envelope.copyOfRange(4, 4 + wrappedLength)
        val iv = envelope.copyOfRange(4 + wrappedLength, 4 + wrappedLength + 12)
        val rsa = Cipher.getInstance("RSA/ECB/OAEPPadding")
        rsa.init(Cipher.DECRYPT_MODE, pair.private, OAEPParameterSpec("SHA-256", "MGF1", mgf1, PSource.PSpecified.DEFAULT))
        val sessionKey = SecretKeySpec(rsa.doFinal(wrapped), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))
            doFinal(envelope.copyOfRange(4 + wrappedLength + 12, envelope.size))
        }
    }

    @Test
    fun `each algorithm is stored with its key and its files are wrapped with that MGF1 hash`() = testApplication {
        configureApp()
        val content = "per-device secret".toByteArray()
        files.put(scope, "e2e-file", content, "public", "end_to_end")
        files.put(scope, "ua-file", content, "public", "user_auth")
        for ((device, algorithm, sent) in listOf(
            Triple("android-dev", RSA_OAEP_SHA256, null),            // the default: what an older client sends (nothing)
            Triple("android-explicit", RSA_OAEP_SHA256, RSA_OAEP_SHA256),
            Triple("ios-dev", RSA_OAEP_SHA256_MGF1_SHA256, RSA_OAEP_SHA256_MGF1_SHA256)
        )) {
            val e2e = rsa()
            val userAuth = rsa()
            assertEquals(HttpStatusCode.OK, register(device, e2e, sent).status)
            assertEquals(HttpStatusCode.OK, register(device, userAuth, sent, purpose = "user_auth").status)
            assertEquals(algorithm, keys.get(device, scope)!!.algorithm)
            assertEquals(algorithm, keys.userAuthKeys().get(device, scope)!!.algorithm)

            val (right, wrong) = if (algorithm == RSA_OAEP_SHA256) MGF1ParameterSpec.SHA1 to MGF1ParameterSpec.SHA256
                else MGF1ParameterSpec.SHA256 to MGF1ParameterSpec.SHA1
            for ((file, pair) in listOf("e2e-file" to e2e, "ua-file" to userAuth)) {
                val envelope = download(file, device)
                assertContentEquals(content, open(envelope, pair, right), "$device $file with $right")
                assertFails("$device $file must not open with the other MGF1 hash") { open(envelope, pair, wrong) }
                // The helper the other tests use, given the key's algorithm.
                assertContentEquals(content, VaultEncryptionRoundtripTestHelper.decrypt(envelope, pair.private, algorithm))
            }
        }
    }

    @Test
    fun `an unknown algorithm is refused naming both, and the same key under another algorithm is a change`() = testApplication {
        configureApp()
        val pair = rsa()
        val refused = register("dev-1", pair, "RSA-OAEP-SHA1")
        assertEquals(HttpStatusCode.BadRequest, refused.status)
        val body = Json.parseToJsonElement(refused.bodyAsText()).jsonObject
        assertEquals("unsupported_algorithm", body["error"]!!.jsonPrimitive.content)
        val message = body["message"]!!.jsonPrimitive.content
        assertTrue(RSA_OAEP_SHA256 in message && RSA_OAEP_SHA256_MGF1_SHA256 in message, message)
        assertNull(keys.get("dev-1", scope))

        assertEquals(HttpStatusCode.OK, register("dev-1", pair, RSA_OAEP_SHA256).status)
        // The same key and algorithm again: a no-op.
        assertEquals(HttpStatusCode.OK, register("dev-1", pair, null).status)
        // The same key under the other algorithm would change how files are wrapped:
        // without the device's proof it is refused like any other key change.
        val switched = register("dev-1", pair, RSA_OAEP_SHA256_MGF1_SHA256)
        assertEquals(HttpStatusCode.Conflict, switched.status)
        assertTrue(switched.bodyAsText().contains("key_change_requires_proof"))
        assertEquals(RSA_OAEP_SHA256, keys.get("dev-1", scope)!!.algorithm)
        // A user-auth key is held to more: the device's credential and a passing attestation.
        assertEquals(HttpStatusCode.OK, register("dev-1", pair, RSA_OAEP_SHA256, purpose = "user_auth").status)
        val uaSwitched = register("dev-1", pair, RSA_OAEP_SHA256_MGF1_SHA256, purpose = "user_auth")
        assertEquals(HttpStatusCode.Conflict, uaSwitched.status)
        assertTrue(uaSwitched.bodyAsText().contains("user_auth_key_exists"))
        assertEquals(RSA_OAEP_SHA256, keys.userAuthKeys().get("dev-1", scope)!!.algorithm)
        // An administrator's reset frees the slot for the iOS algorithm.
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$scope/vault/devices/dev-1/public-key").status)
        assertEquals(HttpStatusCode.OK, register("dev-1", pair, RSA_OAEP_SHA256_MGF1_SHA256).status)
        assertEquals(RSA_OAEP_SHA256_MGF1_SHA256, keys.get("dev-1", scope)!!.algorithm)
        assertTrue(auditStore.page(100, 0).any { it.action == "device_key_registered" && it.summary.endsWith(RSA_OAEP_SHA256_MGF1_SHA256) })
    }

    @Test
    fun `the admin API lists a device's two keys with their algorithm`() = testApplication {
        configureApp()
        register("ios-dev", rsa(), RSA_OAEP_SHA256_MGF1_SHA256)
        val listed = Json.parseToJsonElement(client.get("/api/v1/config-apis/$scope/vault/devices/ios-dev/keys").bodyAsText()).jsonObject
        assertEquals("ios-dev", listed["deviceId"]!!.jsonPrimitive.content)
        assertEquals(RSA_OAEP_SHA256_MGF1_SHA256, listed["e2e"]!!.jsonObject["algorithm"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, listed["userAuth"])
    }

    @Test
    fun `the service refuses an unknown algorithm rather than guess`() {
        val pair = rsa()
        assertFailsWith<IllegalArgumentException> { VaultEncryptionService().encryptForDevice("x".toByteArray(), pair.pem(), "RSA-OAEP-SHA512") }
        val envelope = VaultEncryptionService().encryptForDevice("x".toByteArray(), pair.pem(), RSA_OAEP_SHA256_MGF1_SHA256)
        assertContentEquals("x".toByteArray(), open(envelope, pair, MGF1ParameterSpec.SHA256))
        assertFails { open(envelope, pair, MGF1ParameterSpec.SHA1) }
        assertFails { VaultEncryptionRoundtripTestHelper.decrypt(envelope, pair.private) }
    }
}
