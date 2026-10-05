package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AndroidKeyAttestation
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.TestAttestationChains.Description
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.pem
import com.example.pinvault.server.service.TestAttestationChains.rsa
import com.example.pinvault.server.service.UserAuthAttestationMode
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
 * USER_AUTH_ATTESTATION on the registration route: a user-auth key is
 * replaced only with BOTH the device's credential (bound certificate or
 * token) and a new key whose Android Key Attestation passes with the app
 * binding configured — a credential alone is what root running as the app
 * has, an attestation alone is what a stranger with a phone of their own
 * has — or after an administrator's reset; `enforce` needs a passing
 * attestation for the first key too.
 */
class UserAuthAttestationRouteTest {

    private val scope = "att-api"
    private val deviceId = "android-att"
    private val pki = Pki()

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
        dbFile = File.createTempFile("pinvault-attestation-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokens)
        auditStore = AuditLogStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp(
        mode: UserAuthAttestationMode,
        verifier: AndroidKeyAttestation = pki.verifier(),
        keyLimiter: RateLimiter? = null,
        deviceRevoked: (String) -> Boolean = { false }
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
                keyLimiter = keyLimiter, deviceRevoked = deviceRevoked,
                userAuthAttestation = verifier, userAuthAttestationMode = mode)
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, tokenService, publicKeyStore = keys, audit = audit)
        }
    }

    private fun chainFor(key: KeyPair, description: Description = Description(deviceId)) =
        TestAttestationChains.chain(pki, key.public, description)

    /** The device's token for a user_auth file of this scope: its credential on a TLS listener. */
    private fun deviceToken(device: String = deviceId): String {
        if (files.get(scope, "wallet") == null) files.put(scope, "wallet", "x".toByteArray(), "token", "user_auth")
        return tokenService.generate(scope, "wallet", device).plaintext
    }

    private suspend fun HttpResponse.reason(): String? = json()["reason"]?.jsonPrimitive?.content

    private suspend fun ApplicationTestBuilder.register(
        key: KeyPair,
        chain: List<String>? = null,
        proofKey: String? = null,
        proofToken: String? = null,
        device: String = deviceId
    ): HttpResponse = client.post("/api/v1/vault/devices/$device/public-key") {
        contentType(ContentType.Application.Json)
        proofKey?.let { header("X-Vault-Key", it) }
        proofToken?.let { header("X-Vault-Token", it) }
        setBody(buildJsonObject {
            put("publicKeyPem", pem(key.public))
            put("purpose", "user_auth")
            chain?.let { put("attestationChain", JsonArray(it.map { c -> JsonPrimitive(c) })) }
        }.toString())
    }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject
    private fun stored() = keys.userAuthKeys().get(deviceId, scope)
    private fun storedPem() = stored()?.publicKeyPem

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    // ── warn (default) ──────────────────────────────────────────────────

    @Test
    fun `warn accepts a first key without attestation, records it, and a later chain upgrades it`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key).status)
        assertEquals(KeyAttestation(false, null, "chain_missing"), stored()!!.attestation)
        val registered = auditStore.page(50, 0).first { it.action == "device_key_registered" }
        assertTrue(registered.summary.contains("accepted on first use"), registered.summary)
        assertTrue(registered.detail.contains("\"attested\":false"), registered.detail)

        // The same key with a passing chain: now attested, nothing replaced.
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key)).status)
        assertEquals(KeyAttestation(true, "tee", "ok", keyKind = "per_use", biometricOnly = true), stored()!!.attestation)
        assertTrue(auditStore.page(50, 0).any { it.action == "device_key_attested" })
        // ...and keeps it when the same key comes again without one.
        assertEquals(HttpStatusCode.OK, register(key).status)
        assertEquals(true, stored()!!.attestation?.attested)
        assertFalse(auditStore.page(50, 0).any { it.action == "device_key_replaced" })
    }

    @Test
    fun `warn stores a failing attestation of a first key with its reason`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key, Description(deviceId, attestationLevel = 0))).status)
        assertEquals(KeyAttestation(false, "software", "software_attestation"), stored()!!.attestation)
    }

    // ── replacement ─────────────────────────────────────────────────────

    @Test
    fun `neither a file token nor a client certificate replaces a user-auth key without a passing attestation, in any mode`() {
        for (mode in UserAuthAttestationMode.entries) testApplication {
            setUp()
            configureApp(mode)
            val original = rsa()
            assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status, "$mode first key")
            val token = deviceToken()
            val noChain = if (mode == UserAuthAttestationMode.OFF) "attestation_off" else "chain_missing"

            val byToken = register(rsa(), proofKey = "wallet", proofToken = token)
            assertEquals(HttpStatusCode.Conflict, byToken.status, "$mode token")
            assertEquals("user_auth_key_exists", byToken.json()["error"]!!.jsonPrimitive.content)
            assertEquals(noChain, byToken.reason(), "$mode token")

            presented = clientCert(deviceId)
            val byCert = register(rsa())
            presented = null
            assertEquals(HttpStatusCode.Conflict, byCert.status, "$mode certificate")
            assertEquals("user_auth_key_exists", byCert.json()["error"]!!.jsonPrimitive.content)
            assertEquals(noChain, byCert.reason(), "$mode certificate")

            // A failing chain does not do it either; the reason is given.
            val other = rsa()
            val wrongChallenge = register(other, chainFor(other, Description(deviceId, challenge = ByteArray(32))), proofKey = "wallet", proofToken = token)
            assertEquals(HttpStatusCode.Conflict, wrongChallenge.status, "$mode failing chain")
            assertEquals(if (mode == UserAuthAttestationMode.OFF) "attestation_off" else "challenge_mismatch", wrongChallenge.reason())
            assertEquals(pem(original.public), storedPem(), "$mode: the registered key stays")
            assertTrue(auditStore.page(50, 0).any { it.action == "device_key_refused" && it.summary.contains("user-auth key replacement refused") })
        }
    }

    @Test
    fun `a stranger's valid attestation without the device's credential does not replace the key`() {
        // A genuine locked phone, the genuine app (or any app, were the signer not bound),
        // a key made with the VICTIM's challenge: the chain passes, but it came with
        // no certificate and no token of the victim's device.
        for (mode in listOf(UserAuthAttestationMode.WARN, UserAuthAttestationMode.ENFORCE)) testApplication {
            setUp()
            configureApp(mode)
            val original = rsa()
            assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status)
            val attacker = rsa()
            val refused = register(attacker, chainFor(attacker))
            assertEquals(HttpStatusCode.Conflict, refused.status, "$mode")
            assertEquals("user_auth_key_exists", refused.json()["error"]!!.jsonPrimitive.content)
            assertEquals("credential_required", refused.reason())
            // A token for another device, or a made-up one, is no credential either.
            val wrongToken = register(attacker, chainFor(attacker), proofKey = "wallet", proofToken = deviceToken("android-other"))
            assertEquals("credential_required", wrongToken.reason())
            assertEquals(pem(original.public), storedPem(), "$mode: the victim's key stays")
            assertFalse(auditStore.page(50, 0).any { it.action == "device_key_replaced" })
        }
    }

    @Test
    fun `a certificate of another device is refused before anything else`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        presented = clientCert("someone-else")
        val key = rsa()
        val refused = register(key, chainFor(key))
        presented = null
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("device_identity_mismatch", refused.json()["error"]!!.jsonPrimitive.content)
        assertNull(stored())
    }

    @Test
    fun `the device's credential with a passing attestation replaces the old key, and the webhook hears of it`() {
        for (mode in listOf(UserAuthAttestationMode.WARN, UserAuthAttestationMode.ENFORCE)) {
            for (credential in listOf("token", "certificate")) testApplication {
                setUp()
                configureApp(mode)
                val original = rsa()
                assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status)
                val replacement = rsa()
                val response = if (credential == "token") {
                    register(replacement, chainFor(replacement), proofKey = "wallet", proofToken = deviceToken())
                } else {
                    presented = clientCert(deviceId)
                    register(replacement, chainFor(replacement)).also { presented = null }
                }
                assertEquals(HttpStatusCode.OK, response.status, "$mode $credential")
                assertEquals(pem(replacement.public), storedPem())
                assertEquals(KeyAttestation(true, "tee", "ok", keyKind = "per_use", biometricOnly = true), stored()!!.attestation)
                val replaced = auditStore.page(50, 0).first { it.action == "device_key_replaced" }
                assertTrue(replaced.summary.contains("attested: tee"), replaced.summary)
                assertTrue(replaced.detail.contains("\"attested\":true"), replaced.detail)
                // device_key_replaced is not a routine event: NOTIFY_EVENTS=* pushes it.
                assertFalse("device_key_replaced" in com.example.pinvault.server.service.WebhookNotifier.ROUTINE_EVENTS)
            }
        }
    }

    @Test
    fun `warn without the package and signer binding lets no attestation count`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN, verifier = pki.verifier(signerDigests = emptySet()))
        val original = rsa()
        // First key: trusted on first use, its passing chain stored as not counting.
        assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status)
        assertEquals(KeyAttestation(false, "tee", "app_binding_not_configured"), stored()!!.attestation)
        // Credential + a chain that would pass: still refused, an administrator resets.
        val replacement = rsa()
        val refused = register(replacement, chainFor(replacement), proofKey = "wallet", proofToken = deviceToken())
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertEquals("app_binding_not_configured", refused.reason())
        assertEquals(pem(original.public), storedPem())
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key?purpose=user_auth").status)
        assertEquals(HttpStatusCode.OK, register(replacement, chainFor(replacement)).status)
        assertEquals(pem(replacement.public), storedPem())
    }

    @Test
    fun `an attestation alone does not reveal that a device was revoked`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN, deviceRevoked = { it == deviceId })
        val key = rsa()
        // Anyone can attest a key for any device id: handled as for any device id —
        // the first key is kept, a different one without a credential is refused.
        val stranger = register(key, chainFor(key))
        assertEquals(HttpStatusCode.OK, stranger.status)
        assertFalse(stranger.bodyAsText().contains("reenroll_required"))
        assertNotNull(stored())
        val other = rsa()
        val second = register(other, chainFor(other))
        assertEquals(HttpStatusCode.Conflict, second.status)
        assertFalse(second.bodyAsText().contains("reenroll_required"))
        // The device's token: told to enroll again.
        val withToken = register(key, chainFor(key), proofKey = "wallet", proofToken = deviceToken())
        assertEquals(HttpStatusCode.Forbidden, withToken.status)
        assertEquals("reenroll_required", withToken.json()["error"]!!.jsonPrimitive.content)
    }

    @Test
    fun `an unauthenticated flood is rate limited before any chain is verified`() = testApplication {
        var verified = 0
        val counting = object : AndroidKeyAttestation(listOf(pki.root), setOf(TestAttestationChains.PACKAGE),
            setOf(TestAttestationChains.SIGNER_HEX)) {
            override fun verify(chainBase64: List<String>?, publicKey: java.security.PublicKey, deviceId: String): Verdict {
                verified++
                return super.verify(chainBase64, publicKey, deviceId)
            }
        }
        configureApp(UserAuthAttestationMode.ENFORCE, verifier = counting, keyLimiter = RateLimiter(maxAttempts = 3))
        val key = rsa()
        // Chains that fail (another device's challenge): nothing is stored, every request is a "first key".
        val chain = chainFor(key, Description("someone-else"))
        val statuses = (1..10).map { register(key, chain).status }
        assertEquals(List(3) { HttpStatusCode.Forbidden } + List(7) { HttpStatusCode.TooManyRequests }, statuses)
        assertEquals(3, verified, "the 429s cost no signature check")
    }

    @Test
    fun `a replacement without a credential is refused without verifying its chain`() = testApplication {
        var verified = 0
        val counting = object : AndroidKeyAttestation(listOf(pki.root), setOf(TestAttestationChains.PACKAGE),
            setOf(TestAttestationChains.SIGNER_HEX)) {
            override fun verify(chainBase64: List<String>?, publicKey: java.security.PublicKey, deviceId: String): Verdict {
                verified++
                return super.verify(chainBase64, publicKey, deviceId)
            }
        }
        configureApp(UserAuthAttestationMode.WARN, verifier = counting)
        val original = rsa()
        assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status)
        assertEquals(1, verified)
        // The same, already attested key again: nothing to verify.
        assertEquals(HttpStatusCode.OK, register(original, chainFor(original)).status)
        assertEquals(1, verified)
        val stranger = rsa()
        repeat(5) { assertEquals("credential_required", register(stranger, chainFor(stranger)).reason()) }
        assertEquals(1, verified)
    }

    @Test
    fun `with attestation off a replacement is an administrator's job`() = testApplication {
        configureApp(UserAuthAttestationMode.OFF)
        val original = rsa()
        assertEquals(HttpStatusCode.OK, register(original).status)
        assertNull(stored()!!.attestation, "not checked")
        val replacement = rsa()
        val refused = register(replacement, chainFor(replacement))
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertEquals("credential_required", refused.reason())
        // With the device's token too: nothing is checked, so nothing replaces it.
        assertEquals("attestation_off", register(replacement, chainFor(replacement), proofKey = "wallet", proofToken = deviceToken()).reason())

        // Admin reset, then the next key is a first registration again.
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$scope/vault/devices/$deviceId/public-key?purpose=user_auth").status)
        assertNull(stored())
        assertEquals(HttpStatusCode.OK, register(replacement).status)
        assertEquals(pem(replacement.public), storedPem())
    }

    // ── enforce ─────────────────────────────────────────────────────────

    @Test
    fun `enforce needs a passing attestation for the first key`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        val missing = register(key)
        assertEquals(HttpStatusCode.Forbidden, missing.status)
        assertEquals("attestation_required", missing.json()["error"]!!.jsonPrimitive.content)

        for ((description, reason) in listOf(
            Description(deviceId, challenge = ByteArray(32)) to "challenge_mismatch",
            Description(deviceId, attestationLevel = 0) to "software_attestation",
            Description(deviceId, noAuthRequired = true) to "no_user_auth",
            Description(deviceId, deviceLocked = false) to "device_unlocked",
            Description(deviceId, packages = listOf("com.evil")) to "package_not_allowed",
            Description(deviceId, signers = listOf(ByteArray(32) { 5 })) to "signer_not_allowed"
        )) {
            val refused = register(key, chainFor(key, description))
            assertEquals(HttpStatusCode.Forbidden, refused.status, reason)
            assertEquals("attestation_invalid", refused.json()["error"]!!.jsonPrimitive.content)
            assertEquals(reason, refused.json()["reason"]!!.jsonPrimitive.content)
        }
        // Another key's chain, and a chain that is not a list of strings.
        val other = rsa()
        assertEquals("key_mismatch", register(key, chainFor(other)).json()["reason"]!!.jsonPrimitive.content)
        val malformed = client.post("/api/v1/vault/devices/$deviceId/public-key") {
            contentType(ContentType.Application.Json)
            setBody("""{"publicKeyPem":${JsonPrimitive(pem(key.public))},"purpose":"user_auth","attestationChain":[1,2]}""")
        }
        assertEquals("chain_malformed", malformed.json()["reason"]!!.jsonPrimitive.content)
        assertNull(stored(), "nothing stored")

        assertEquals(HttpStatusCode.OK, register(key, chainFor(key)).status)
        assertEquals(KeyAttestation(true, "tee", "ok", keyKind = "per_use", biometricOnly = true), stored()!!.attestation)
    }

    @Test
    fun `the E2E key ignores attestation, even under enforce`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val response = client.post("/api/v1/vault/devices/$deviceId/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", pem(rsa().public)) }.toString())
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertNotNull(keys.get(deviceId, scope))
    }

    @Test
    fun `an administrator lists the user-auth keys with their attestation`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        val key = rsa()
        register(key, chainFor(key))
        val listed = Json.parseToJsonElement(client.get("/api/v1/config-apis/$scope/vault/devices/user-auth-keys").bodyAsText()).jsonArray
        assertEquals(1, listed.size)
        val entry = listed[0].jsonObject
        assertEquals(deviceId, entry["deviceId"]!!.jsonPrimitive.content)
        assertEquals(true, entry["attestation"]!!.jsonObject["attested"]!!.jsonPrimitive.boolean)
        assertEquals("tee", entry["attestation"]!!.jsonObject["securityLevel"]!!.jsonPrimitive.content)
        // How the key asks for the user.
        assertEquals("per_use", entry["attestation"]!!.jsonObject["keyKind"]!!.jsonPrimitive.content)
        assertEquals(true, entry["attestation"]!!.jsonObject["biometricOnly"]!!.jsonPrimitive.boolean)
    }

    // ── N1: root running as the app, and keys from before enforce ────────

    private fun putWallet() = files.put(scope, "wallet", "secret".toByteArray(), "public", "user_auth")

    private suspend fun ApplicationTestBuilder.download(): HttpResponse =
        client.get("/api/v1/vault/wallet?version=0") { header("X-Device-Id", deviceId) }

    @Test
    fun `under enforce a key registered without a passing attestation is not sealed for until it shows one`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        putWallet()
        // On file from before enforce: accepted then on first use.
        val key = rsa()
        keys.userAuthKeys().register(deviceId, scope, pem(key.public), timestamp = "2026-01-01T00:00:00Z",
            attestation = KeyAttestation(false, null, "chain_missing"))
        val refused = download()
        assertEquals(HttpStatusCode.PreconditionFailed, refused.status)
        assertEquals("user_auth_key_required", refused.json()["error"]!!.jsonPrimitive.content)
        assertEquals("key_not_attested", refused.reason())

        // The same key again without a chain: refused, it stays unusable.
        assertEquals("attestation_required", register(key).json()["error"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.PreconditionFailed, download().status)
        // With its chain: attested, and the file is sealed for it.
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key)).status)
        assertEquals(true, stored()!!.attestation!!.attested)
        assertEquals(HttpStatusCode.OK, download().status)
    }

    @Test
    fun `a time-bound key on Android 11 or later is root's key and is refused`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE)
        val key = rsa()
        val refused = register(key, chainFor(key, Description(deviceId, authTimeout = 10, osVersion = 110000)))
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("attestation_invalid", refused.json()["error"]!!.jsonPrimitive.content)
        assertEquals("time_bound_key", refused.reason())
        assertNull(stored())
        // Android 10 and the library's 10 s window: accepted, and recorded as time-bound.
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key, Description(deviceId, authTimeout = 10, osVersion = 100000))).status)
        assertEquals(KeyAttestation(true, "tee", "ok", keyKind = "time_bound", authTimeoutSeconds = 10, biometricOnly = true), stored()!!.attestation)
    }

    @Test
    fun `USER_AUTH_REQUIRE_PER_USE refuses time-bound keys and asks keys of unknown kind again`() = testApplication {
        configureApp(UserAuthAttestationMode.ENFORCE, verifier = pki.verifier(requirePerUse = true))
        putWallet()
        val key = rsa()
        assertEquals("time_bound_key", register(key, chainFor(key, Description(deviceId, authTimeout = 10, osVersion = 90000))).reason())

        // Attested before kinds were recorded (V19): asked again once.
        keys.userAuthKeys().register(deviceId, scope, pem(key.public), timestamp = "2026-01-01T00:00:00Z",
            attestation = KeyAttestation(true, "tee", "ok"))
        assertEquals("key_kind_unknown", download().reason())
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key)).status)
        assertEquals("per_use", stored()!!.attestation!!.keyKind)
        assertEquals(HttpStatusCode.OK, download().status)

        // A time-bound key on file (accepted before the switch) is not sealed for.
        keys.userAuthKeys().register(deviceId, scope, pem(key.public), timestamp = "2026-01-01T00:00:00Z",
            attestation = KeyAttestation(true, "tee", "ok", keyKind = "time_bound", authTimeoutSeconds = 10))
        assertEquals("time_bound_key", download().reason())
    }

    @Test
    fun `under warn a time-bound key on Android 11 is accepted on first use and recorded as failing`() = testApplication {
        configureApp(UserAuthAttestationMode.WARN)
        putWallet()
        val key = rsa()
        assertEquals(HttpStatusCode.OK, register(key, chainFor(key, Description(deviceId, authTimeout = 5, osVersion = 120000))).status)
        assertEquals(KeyAttestation(false, "tee", "time_bound_key"), stored()!!.attestation)
        // warn seals for it (trust on first use) — enforce would not.
        assertEquals(HttpStatusCode.OK, download().status)
    }
}
