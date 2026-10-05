package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultAtRestCipher
import com.example.pinvault.server.service.VaultEncryptionRoundtripTestHelper
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
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.*

/**
 * Vault encryption `user_auth`: the file is wrapped with the device's
 * USER-AUTH key (one the phone uses only after the user unlocked), never sent
 * in plaintext. The key is registered with `"purpose":"user_auth"`, kept apart
 * from the E2E key; unlike it, neither a token nor a client certificate
 * replaces it (attestation: UserAuthAttestationRouteTest).
 */
class UserAuthVaultTest {

    private val scope = "ua-api"
    private val deviceId = "android-ua"

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var files: VaultFileStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var userAuthKeys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var clientCerts: ClientCertStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var signingService: ConfigSigningService
    private var presented: X509Certificate? = null

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-userauth-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        userAuthKeys = keys.userAuthKeys()
        tokenService = VaultAccessTokenService(tokens)
        clientCerts = ClientCertStore(db)
        auditStore = AuditLogStore(db)
        signingService = ConfigSigningService(File.createTempFile("pinvault-userauth-signing-", ".pem").also { it.delete(); it.deleteOnExit() })
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.configureApp(maxKeys: Int = Int.MAX_VALUE) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(createApplicationPlugin("FakePeerCert") {
            onCall { call -> presented?.let { call.attributes.put(TLS_PEER_CERTIFICATE, it) } }
        })
        val audit = AuditLog(auditStore, null)
        routing {
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService(), signingService,
                clientCertStore = clientCerts, audit = audit,
                keyRefusals = AuthFailureRecorder(audit, action = "device_key_refused"),
                maxDeviceKeys = maxKeys)
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = audit)
        }
    }

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun KeyPair.pem(): String {
        val body = Base64.getEncoder().encodeToString(public.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

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
        purpose: String? = "user_auth",
        proofKey: String? = null,
        proofToken: String? = null
    ): HttpResponse = client.post("/api/v1/vault/devices/$deviceId/public-key") {
        contentType(ContentType.Application.Json)
        proofKey?.let { header("X-Vault-Key", it) }
        proofToken?.let { header("X-Vault-Token", it) }
        setBody(buildJsonObject {
            put("publicKeyPem", pem)
            purpose?.let { put("purpose", it) }
        }.toString())
    }

    private fun userAuthPem() = userAuthKeys.get(deviceId, scope)?.publicKeyPem
    private fun e2ePem() = keys.get(deviceId, scope)?.publicKeyPem

    private fun canonical(pair: KeyPair) = pair.pem()

    private fun actions() = auditStore.page(100, 0).map { it.action }

    // ── registration ─────────────────────────────────────────────────────

    @Test
    fun `a user-auth key is stored apart from the E2E key and neither overwrites the other`() = testApplication {
        configureApp()
        val e2e = rsa()
        val userAuth = rsa()
        assertEquals(HttpStatusCode.OK, register(e2e.pem(), purpose = null).status)
        val registered = register(userAuth.pem())
        assertEquals(HttpStatusCode.OK, registered.status)
        assertEquals("user_auth", Json.parseToJsonElement(registered.bodyAsText()).jsonObject["purpose"]!!.jsonPrimitive.content)
        assertEquals(canonical(e2e), e2ePem())
        assertEquals(canonical(userAuth), userAuthPem())

        // "e2e" spelled out is the E2E key, and the first one is kept on TLS.
        assertEquals(HttpStatusCode.Conflict, register(rsa().pem(), purpose = "e2e").status)
        assertEquals(canonical(e2e), e2ePem())
        assertEquals(canonical(userAuth), userAuthPem(), "an E2E registration never touches the user-auth key")
        val entries = auditStore.page(100, 0).filter { it.action == "device_key_registered" }
        assertEquals(2, entries.size)
        assertTrue(entries.any { it.summary.startsWith("User-auth key") && it.detail.contains("user_auth") })
    }

    @Test
    fun `an unknown purpose and a key that is not RSA 2048-4096 are refused`() = testApplication {
        configureApp()
        val unknown = register(rsa().pem(), purpose = "biometric")
        assertEquals(HttpStatusCode.BadRequest, unknown.status)
        assertTrue(unknown.bodyAsText().contains("unsupported_purpose"))
        val small = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        assertEquals(HttpStatusCode.BadRequest, register(small.pem()).status)
        assertNull(userAuthPem())
    }

    @Test
    fun `on TLS the first user-auth key is kept and no file token replaces it`() = testApplication {
        configureApp()
        val original = rsa()
        assertEquals(HttpStatusCode.OK, register(original.pem()).status)
        assertEquals(HttpStatusCode.OK, register(original.pem()).status, "the same key again is a no-op")

        val refused = register(rsa().pem())
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertTrue(refused.bodyAsText().contains("user_auth_key_exists"))
        assertEquals(canonical(original), userAuthPem())

        // Root code running as the app holds the app's tokens: no token of any
        // file replaces a user-auth key (a passing attestation does, see
        // UserAuthAttestationRouteTest, or an administrator's reset).
        files.put(scope, "flags", "x".toByteArray(), "token", "plain")
        files.put(scope, "wallet", "x".toByteArray(), "token", "user_auth")
        files.put(scope, "model", "x".toByteArray(), "token", "end_to_end")
        for (file in listOf("flags", "wallet", "model")) {
            val token = tokenService.generate(scope, file, deviceId).plaintext
            val response = register(rsa().pem(), proofKey = file, proofToken = token)
            assertEquals(HttpStatusCode.Conflict, response.status, file)
            assertTrue(response.bodyAsText().contains("user_auth_key_exists"), file)
        }
        assertEquals(canonical(original), userAuthPem())
        assertFalse(actions().contains("device_key_replaced"))
        val walletToken = tokenService.generate(scope, "wallet", deviceId).plaintext

        // A user_auth file token is no proof for the E2E key (unchanged rule).
        assertEquals(HttpStatusCode.OK, register(rsa().pem(), purpose = null).status)
        assertEquals(HttpStatusCode.Conflict, register(rsa().pem(), purpose = null, proofKey = "wallet", proofToken = walletToken).status)
    }

    @Test
    fun `with a client certificate only the device's own may set its user-auth key, and it does not replace one`() = testApplication {
        configureApp()
        presented = clientCert("someone-else")
        val mismatch = register(rsa().pem())
        assertEquals(HttpStatusCode.Forbidden, mismatch.status)
        assertTrue(mismatch.bodyAsText().contains("device_identity_mismatch"))
        assertNull(userAuthPem())

        presented = clientCert(deviceId)
        val first = rsa()
        assertEquals(HttpStatusCode.OK, register(first.pem()).status)
        // Unlike the E2E key: the certificate is in the app's hands, root's too.
        val replacement = register(rsa().pem())
        assertEquals(HttpStatusCode.Conflict, replacement.status)
        assertTrue(replacement.bodyAsText().contains("user_auth_key_exists"))
        assertEquals(canonical(first), userAuthPem())
        presented = null
    }

    @Test
    fun `the per-scope key limit counts user-auth keys on their own`() = testApplication {
        configureApp(maxKeys = 1)
        assertEquals(HttpStatusCode.OK, register(rsa().pem(), purpose = null).status)
        assertEquals(HttpStatusCode.OK, register(rsa().pem()).status, "the E2E key does not fill the user-auth table")
        val second = client.post("/api/v1/vault/devices/android-two/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", rsa().pem()); put("purpose", "user_auth") }.toString())
        }
        assertEquals(HttpStatusCode.ServiceUnavailable, second.status)
    }

    @Test
    fun `an administrator deletes the user-auth key alone, on the management listener only`() = testApplication {
        configureApp()
        register(rsa().pem(), purpose = null)
        register(rsa().pem())

        // The device-facing listener has no reset route any more: nothing there to call.
        assertEquals(HttpStatusCode.NotFound, client.delete("/api/v1/vault/devices/$deviceId/public-key?purpose=user_auth").status)
        assertNotNull(userAuthPem(), "nothing was removed through the device listener")

        val admin = "/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key"
        assertEquals(HttpStatusCode.BadRequest, client.delete("$admin?purpose=other").status)
        assertEquals(HttpStatusCode.OK, client.delete("$admin?purpose=user_auth").status)
        assertNull(userAuthPem())
        assertNotNull(e2ePem(), "the E2E key stays")
        assertEquals(HttpStatusCode.NotFound, client.delete("$admin?purpose=user_auth").status)
        assertTrue(auditStore.page(100, 0).any { it.action == "device_key_reset" && it.summary.startsWith("User-auth key") })

        // The next key is a first registration again.
        assertEquals(HttpStatusCode.OK, register(rsa().pem()).status)
        assertEquals(HttpStatusCode.OK,
            client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key?purpose=user_auth").status)
        assertNull(userAuthPem())
        assertNotNull(e2ePem())
        assertEquals(HttpStatusCode.BadRequest,
            client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key?purpose=other").status)
    }

    // ── download ─────────────────────────────────────────────────────────

    @Test
    fun `a user_auth file is wrapped with the device's user-auth key, never its E2E key`() = testApplication {
        configureApp()
        val e2e = rsa()
        val userAuth = rsa()
        register(e2e.pem(), purpose = null)
        register(userAuth.pem())
        val content = "seed phrase".toByteArray()
        files.put(scope, "wallet", content, "public", "user_auth")

        val response = client.get("/api/v1/vault/wallet") { header("X-Device-Id", deviceId) }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("user_auth", response.headers["X-Vault-Encryption"])
        assertEquals("1", response.headers["X-Vault-Version"])
        val envelope = response.readRawBytes()
        assertFalse(String(envelope, Charsets.ISO_8859_1).contains("seed phrase"), "never plaintext on the wire")
        assertContentEquals(content, VaultEncryptionRoundtripTestHelper.decrypt(envelope, userAuth.private))
        assertFails { VaultEncryptionRoundtripTestHelper.decrypt(envelope, e2e.private) }
        // Signed over the plaintext, as for every other encryption.
        val signature = assertNotNull(response.headers["X-Vault-Signature"])
        val hex = java.security.MessageDigest.getInstance("SHA-256").digest(content).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertTrue(signingService.verify("pinvault-vault-file:v1:wallet:1:$hex", signature))
    }

    @Test
    fun `without a user-auth key the device gets 412, even with an E2E key`() = testApplication {
        configureApp()
        register(rsa().pem(), purpose = null)
        files.put(scope, "wallet", "x".toByteArray(), "public", "user_auth")
        val response = client.get("/api/v1/vault/wallet") { header("X-Device-Id", deviceId) }
        assertEquals(HttpStatusCode.PreconditionFailed, response.status)
        assertEquals("user_auth_key_required",
            Json.parseToJsonElement(response.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/vault/wallet").status, "X-Device-Id required")
    }

    @Test
    fun `the access policy is checked before the key`() = testApplication {
        configureApp()
        register(rsa().pem())
        files.put(scope, "wallet", "x".toByteArray(), "token", "user_auth")
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/vault/wallet") { header("X-Device-Id", deviceId) }.status)
        val token = tokenService.generate(scope, "wallet", deviceId).plaintext
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/vault/wallet") {
            header("X-Device-Id", deviceId); header("X-Vault-Token", token)
        }.status)
        // Another device with the token of nobody: 401 before anything is looked up.
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/vault/wallet") {
            header("X-Device-Id", "android-other"); header("X-Vault-Token", token)
        }.status)
    }

    @Test
    fun `a user_auth file is stored encrypted at rest like end_to_end`() {
        files.put(scope, "wallet", "seed phrase".toByteArray(), "public", "user_auth")
        val stored = db.connection().use { conn ->
            conn.prepareStatement("SELECT content FROM vault_files WHERE config_api_id = ? AND key = 'wallet'").use { stmt ->
                stmt.setString(1, scope)
                stmt.executeQuery().use { rs -> rs.next(); rs.getBytes(1) }
            }
        }
        assertTrue(VaultAtRestCipher.isEncrypted(stored))
        assertContentEquals("seed phrase".toByteArray(), files.get(scope, "wallet")!!.content)
    }

    @Test
    fun `deleting a Config API removes its user-auth keys`() {
        userAuthKeys.register(deviceId, scope, rsa().pem(), timestamp = "now")
        userAuthKeys.register(deviceId, "kept", rsa().pem(), timestamp = "now")
        ConfigApiRegistry(db).purge(scope)
        assertNull(userAuthKeys.get(deviceId, scope))
        assertNotNull(userAuthKeys.get(deviceId, "kept"))
    }
}
