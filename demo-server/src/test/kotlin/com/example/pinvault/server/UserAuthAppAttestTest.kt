package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.IntegrityRequestHash
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.TestAttestationChains.Description
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.pem
import com.example.pinvault.server.service.TestAttestationChains.rsa
import com.example.pinvault.server.service.UserAuthAttestationMode
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.service.attestation.AppAttestAdmission
import com.example.pinvault.server.service.attestation.AppAttestFixtures
import com.example.pinvault.server.service.attestation.AppAttestVerifier
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
import java.util.Date
import kotlin.test.*

/**
 * An iPhone's screen-lock (user-auth) key under USER_AUTH_ATTESTATION
 * (PORTING.md §6): with App Attest configured, `appAttestation` — a fresh App
 * Attest key's attestation whose client data hash binds it to the device id
 * and the key — stands in for the Android chain, for a first key and for a
 * replacement, under the route's other rules (the device's credential for a
 * replacement, revocation, limits). The key is recorded as kind `app_attest`.
 * Without App Attest the field is not read; Android keys are judged as before.
 */
class UserAuthAppAttestTest {

    private val scope = "aa-api"
    private val deviceId = "3f2c9a4e-ios"
    private val pki = Pki()
    private val apple = AppAttestFixtures.Pki()

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var files: VaultFileStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var auditStore: AuditLogStore
    private var presented: X509Certificate? = null

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-aa-userauth-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokens)
        auditStore = AuditLogStore(db)
        presented = null
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp(
        mode: UserAuthAttestationMode,
        appAttest: AppAttestVerifier? = apple.verifier(),
        requirePerUse: Boolean = false,
        keyLimiter: RateLimiter? = null
    ) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(createApplicationPlugin("FakePeerCert") {
            onCall { call -> presented?.let { call.attributes.put(TLS_PEER_CERTIFICATE, it) } }
        })
        val audit = AuditLog(auditStore, null)
        routing {
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService(),
                clientCertStore = ClientCertStore(db), audit = audit,
                keyRefusals = AuthFailureRecorder(audit, action = "device_key_refused"),
                keyLimiter = keyLimiter,
                userAuthAttestation = pki.verifier(requirePerUse = requirePerUse), userAuthAttestationMode = mode,
                appAttest = appAttest)
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = audit)
        }
    }

    /** The token the iOS library sends for [key]: a fresh App Attest key attested over the key's client data hash. */
    private fun appAttestationFor(
        key: KeyPair,
        device: String = deviceId,
        pki: AppAttestFixtures.Pki = apple,
        appId: String = AppAttestFixtures.APP_ID,
        clientDataHash: ByteArray = AppAttestAdmission.userAuthClientDataHash(device, key.public.encoded)
    ): String {
        val aaKey = AppAttestFixtures.Key()
        return AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, aaKey, clientDataHash, appId = appId))
    }

    private suspend fun ApplicationTestBuilder.register(
        key: KeyPair,
        appAttestation: String? = null,
        chain: List<String>? = null,
        proofKey: String? = null,
        proofToken: String? = null,
        purpose: String = "user_auth"
    ): HttpResponse = client.post("/api/v1/vault/devices/$deviceId/public-key") {
        contentType(ContentType.Application.Json)
        proofKey?.let { header("X-Vault-Key", it) }
        proofToken?.let { header("X-Vault-Token", it) }
        setBody(buildJsonObject {
            put("publicKeyPem", pem(key.public))
            put("purpose", purpose)
            put("algorithm", VaultEncryptionService.RSA_OAEP_SHA256_MGF1_SHA256)
            chain?.let { put("attestationChain", JsonArray(it.map { c -> JsonPrimitive(c) })) }
            appAttestation?.let { put("appAttestation", it) }
        }.toString())
    }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject
    private suspend fun HttpResponse.error(): String? = json()["error"]?.jsonPrimitive?.content
    private suspend fun HttpResponse.reason(): String? = json()["reason"]?.jsonPrimitive?.content
    private fun stored() = keys.userAuthKeys().get(deviceId, scope)

    /** The device's token for a user_auth file of this scope: its credential on a TLS listener. */
    private fun deviceToken(): String {
        if (files.get(scope, "wallet") == null) files.put(scope, "wallet", "x".toByteArray(), "token", "user_auth")
        return tokenService.generate(scope, "wallet", deviceId).plaintext
    }

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    // ── enforce ─────────────────────────────────────────────────────────

    @Test
    fun `under enforce an iPhone registers its first user-auth key with App Attest, recorded as kind app_attest`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        val response = register(key, appAttestationFor(key))
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals(AppAttestAdmission.record(), stored()!!.attestation)
        assertEquals(KeyAttestation(true, null, "app_attest", keyKind = "app_attest"), stored()!!.attestation)
        assertEquals(VaultEncryptionService.RSA_OAEP_SHA256_MGF1_SHA256, stored()!!.algorithm)
        val registered = auditStore.page(50, 0).first { it.action == "device_key_registered" }
        assertTrue(registered.summary.contains("admitted by App Attest"), registered.summary)
        assertTrue(registered.detail.contains("\"attestedBy\":\"app_attest\""), registered.detail)
        // The administrator's list shows the kind.
        val listed = Json.parseToJsonElement(client.get("/api/v1/config-apis/$scope/vault/devices/user-auth-keys").bodyAsText()).jsonArray
        assertEquals("app_attest", listed.single().jsonObject["attestation"]!!.jsonObject["keyKind"]!!.jsonPrimitive.content)
        // The same key again (with or without its attestation) is a no-op that keeps the record.
        assertEquals(HttpStatusCode.OK, register(key).status)
        assertEquals(AppAttestAdmission.record(), stored()!!.attestation)
    }

    @Test
    fun `under enforce an App Attest attestation made for another key, device, app or root is refused`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        for ((token, reason) in listOf(
            appAttestationFor(rsa()) to "app_attest_nonce_mismatch",                      // another key
            appAttestationFor(key, device = "someone-else") to "app_attest_nonce_mismatch", // another device id
            appAttestationFor(key, appId = "ZZZZZ99999.com.evil") to "app_attest_app_id_mismatch",
            appAttestationFor(key, pki = AppAttestFixtures.Pki("CN=Not Apple")) to "app_attest_chain_invalid",
            "garbage" to "app_attest_malformed"
        )) {
            val refused = register(key, token)
            assertEquals(HttpStatusCode.Forbidden, refused.status, reason)
            assertEquals("attestation_invalid", refused.error(), reason)
            assertEquals(reason, refused.reason())
            assertTrue(refused.json()["message"]!!.jsonPrimitive.content.contains("App Attest"))
        }
        // An assertion is no registration: a fresh key's attestation is.
        val aaKey = AppAttestFixtures.Key()
        val assertion = AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, ByteArray(32), 1))
        assertEquals("app_attest_attestation_required", register(key, assertion).reason())
        // Each place needs its own: an enrollment's or an attestation round's attestation is not a key's.
        val csr = ByteArray(64) { 9 }
        assertEquals("app_attest_nonce_mismatch", register(key, appAttestationFor(key,
            clientDataHash = AppAttestVerifier.enrollmentClientDataHash(IntegrityRequestHash.of(deviceId, csr)))).reason())
        assertEquals("app_attest_nonce_mismatch", register(key, appAttestationFor(key,
            clientDataHash = AppAttestVerifier.roundClientDataHash("some-nonce", deviceId))).reason())
        assertNull(stored(), "nothing stored")
        // Nothing at all: attestation_required, and the message names both ways in.
        val missing = register(key)
        assertEquals("attestation_required", missing.error())
        assertTrue(missing.json()["message"]!!.jsonPrimitive.content.contains("appAttestation"))
    }

    @Test
    fun `a replacement needs the device's credential and a passing App Attest, as with a chain`() {
        for (mode in listOf(UserAuthAttestationMode.WARN, UserAuthAttestationMode.ENFORCE)) testApplication {
            setUp()
            configureApp(mode)
            val original = rsa()
            assertEquals(HttpStatusCode.OK, register(original, appAttestationFor(original)).status, "$mode first key")

            // Apple's word alone (a stranger's iPhone with the genuine app) is not the device's credential.
            val stranger = rsa()
            val noCredential = register(stranger, appAttestationFor(stranger))
            assertEquals(HttpStatusCode.Conflict, noCredential.status, "$mode")
            assertEquals("user_auth_key_exists", noCredential.error())
            assertEquals("credential_required", noCredential.reason())
            // The credential alone (root running as the app) is not enough either.
            val replacement = rsa()
            val token = deviceToken()
            assertEquals("app_attest_nonce_mismatch", register(replacement, appAttestationFor(original), proofKey = "wallet", proofToken = token).reason())
            assertEquals("chain_missing", register(replacement, proofKey = "wallet", proofToken = token).reason())
            assertEquals(pem(original.public), stored()!!.publicKeyPem, "$mode: the key stays")

            // Both: replaced, by token and by a bound certificate.
            val byToken = register(replacement, appAttestationFor(replacement), proofKey = "wallet", proofToken = token)
            assertEquals(HttpStatusCode.OK, byToken.status, "$mode ${byToken.bodyAsText()}")
            assertEquals(pem(replacement.public), stored()!!.publicKeyPem)
            assertEquals(AppAttestAdmission.record(), stored()!!.attestation)
            val replaced = auditStore.page(50, 0).first { it.action == "device_key_replaced" }
            assertTrue(replaced.summary.contains("admitted by App Attest"), replaced.summary)
            presented = clientCert(deviceId)
            val third = rsa()
            assertEquals(HttpStatusCode.OK, register(third, appAttestationFor(third)).status, "$mode certificate")
            presented = null
            assertEquals(pem(third.public), stored()!!.publicKeyPem)
        }
    }

    @Test
    fun `warn records a failing App Attest of a first key with its reason`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, appAttestationFor(rsa())).status)
        assertEquals(KeyAttestation(false, null, "app_attest_nonce_mismatch"), stored()!!.attestation)
        // The same key with its own attestation: now admitted, nothing replaced.
        assertEquals(HttpStatusCode.OK, register(key, appAttestationFor(key)).status)
        assertEquals(AppAttestAdmission.record(), stored()!!.attestation)
        assertTrue(auditStore.page(50, 0).any { it.action == "device_key_attested" && it.summary.contains("admitted by App Attest") })
    }

    @Test
    fun `an App Attest key opens user_auth files under enforce and USER_AUTH_REQUIRE_PER_USE`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE, requirePerUse = true)
        files.put(scope, "wallet", "secret".toByteArray(), "public", "user_auth")
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, appAttestationFor(key)).status)
        val download = client.get("/api/v1/vault/wallet?version=0") { header("X-Device-Id", deviceId) }
        assertEquals(HttpStatusCode.OK, download.status, download.bodyAsText())
        // A key of unknown kind on file is still asked again, as before.
        keys.userAuthKeys().register(deviceId, scope, pem(key.public), timestamp = "2026-01-01T00:00:00Z",
            attestation = KeyAttestation(true, "tee", "ok"))
        assertEquals("key_kind_unknown", client.get("/api/v1/vault/wallet?version=0") { header("X-Device-Id", deviceId) }.reason())
    }

    @Test
    fun `an unauthenticated App Attest flood is rate limited before it is verified`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE, keyLimiter = RateLimiter(maxAttempts = 3))
        val key = rsa()
        val token = appAttestationFor(rsa())   // fails: nothing is stored, every request is a first key
        val statuses = (1..6).map { register(key, token).status }
        assertEquals(List(3) { HttpStatusCode.Forbidden } + List(3) { HttpStatusCode.TooManyRequests }, statuses)
    }

    // ── what does not change ────────────────────────────────────────────

    @Test
    fun `without App Attest configured the field is not read and an iPhone is refused under enforce`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE, appAttest = null)
        val key = rsa()
        val refused = register(key, appAttestationFor(key))
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("attestation_required", refused.error())
        assertEquals("This server needs the key's Android Key Attestation chain (attestationChain).", refused.json()["message"]!!.jsonPrimitive.content)
        assertNull(stored())
    }

    @Test
    fun `without App Attest configured warn takes the first key as before, recorded without a chain`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN, appAttest = null)
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, appAttestationFor(key)).status)
        assertEquals(KeyAttestation(false, null, "chain_missing"), stored()!!.attestation)
    }

    @Test
    fun `Android keys are judged by their chain, with App Attest configured`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        // A chain decides when there is one: a failing chain is not rescued by an App Attest attestation next to it.
        val wrong = TestAttestationChains.chain(pki, key.public, Description(deviceId, challenge = ByteArray(32)))
        assertEquals("challenge_mismatch", register(key, appAttestationFor(key), chain = wrong).reason())
        val good = TestAttestationChains.chain(pki, key.public, Description(deviceId))
        assertEquals(HttpStatusCode.OK, register(key, chain = good).status)
        assertEquals(KeyAttestation(true, "tee", "ok", keyKind = "per_use", biometricOnly = true), stored()!!.attestation)
    }

    @Test
    fun `the E2E key ignores appAttestation`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, "garbage", purpose = "e2e").status)
        assertNotNull(keys.get(deviceId, scope))
        assertNull(keys.get(deviceId, scope)!!.attestation)
    }
}
