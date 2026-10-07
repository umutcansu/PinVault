package com.example.pinvault.server.service.attestation

import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.AttestationTokenSecretStore
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.KeyAttestation
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Attestation rounds made by the iOS library itself (`pinvault-ios`,
 * `AttestationInteropFixtureTests.swift`), fed to [AttestationService]: the
 * exact POST body its attestation manager sent — the report its probe built,
 * signed by the device key — with a nonce made under a fixed key at a fixed
 * time, so this server's nonce check accepts it. An iOS report is judged by
 * the iOS rules and never trips an Android-only flag; the App Attest tokens
 * the library's providers make are the ones [AppAttestVerifier] reads, bound
 * by the client data hashes it computes.
 *
 * Fixtures: `src/test/resources/ios-interop/` (regenerate with the Swift test).
 */
class IosClientInteropTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private val androidPki = TestAttestationChains.Pki()
    private val apple = AppAttestFixtures.Pki()

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-ios-interop-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        policies = AttestationPolicyStore(db)
        devices = AttestedDeviceStore(db)
        secrets = AttestationTokenSecretStore(db)
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun fixture(name: String): JsonObject {
        val resource = javaClass.getResource("/ios-interop/$name.json") ?: error("missing fixture ios-interop/$name.json")
        return Json.parseToJsonElement(resource.readText()).jsonObject
    }

    private fun JsonObject.str(name: String) = this[name]!!.jsonPrimitive.content

    private fun body(fixture: JsonObject) = Json.parseToJsonElement(fixture.str("body")).jsonObject

    private fun report(fixture: JsonObject) = Json.parseToJsonElement(body(fixture).str("report")).jsonObject

    /**
     * A server as a production one is set up for a mixed fleet: the Android
     * checks configured (package, signer, patch level), the iOS ones too
     * (team id, minimum iOS version), strict policy with the reasons shown.
     */
    private fun service(
        fixture: JsonObject,
        appAttest: AppAttestVerifier? = null,
        ios: IosAttestationRules = IosAttestationRules(minOsVersion = listOf(17, 0), teamIds = setOf(AppAttestFixtures.TEAM_ID)),
        packageNames: Set<String> = setOf(TestAttestationChains.PACKAGE),
        playIntegrity: PlayIntegrityVerifier? = null
    ): AttestationService {
        val time = fixture["time"]!!.jsonPrimitive.long
        val nonceKey = MessageDigest.getInstance("SHA-256").digest(fixture.str("nonceKey").toByteArray())
        return AttestationService(
            policies, devices, secrets,
            nonces = AttestationNonces(ttlSeconds = 120, key = nonceKey, clock = { time + 1_000 }),
            defaults = AttestationPolicyDefaults(revealReasons = true),
            keyPolicy = AttestationKeyPolicy.WARN,
            verifier = { androidPki.verifier(packageNames = packageNames, minPatchLevel = 202601) },
            clock = { Instant.ofEpochMilli(time + 1_000) },
            playIntegrity = playIntegrity,
            appAttest = appAttest,
            ios = ios
        )
    }

    private fun decide(service: AttestationService, fixture: JsonObject): AttestationService.Outcome.Decided {
        val outcome = service.attest(fixture.str("configApiId"), body(fixture), "127.0.0.1")
        assertTrue(outcome is AttestationService.Outcome.Decided, (outcome as? AttestationService.Outcome.Refused)?.let { "${it.status} ${it.body()}" })
        return outcome
    }

    /** Signals the report raised itself. */
    private fun raised(report: JsonObject): Set<String> =
        report["signals"]!!.jsonObject.filter { (_, value) -> value.jsonObject["flag"]!!.jsonPrimitive.boolean }.keys

    // ── The report, judged ──────────────────────────────────────────────

    @Test
    fun `the library's report has the iOS shape the server reads`() {
        for (name in listOf("iphone-app-attest", "iphone-plain", "iphone-jailbroken", "simulator", "macos-live")) {
            val fixture = fixture(name)
            val report = report(fixture)
            assertEquals(AttestationService.PLATFORM_IOS, AttestationService.platformOf(report), name)
            assertEquals(
                listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
                    "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level"),
                report["signals"]!!.jsonObject.keys.toList(), name
            )
            for (androidOnly in listOf("cloner", "adb_enabled")) {
                val signal = report["signals"]!!.jsonObject[androidOnly]!!.jsonObject
                assertFalse(signal["flag"]!!.jsonPrimitive.boolean, "$name $androidOnly")
                assertEquals(listOf("n/a:ios"), signal["evidence"]!!.jsonArray.map { it.jsonPrimitive.content }, "$name $androidOnly")
            }
            val device = report["device"]!!.jsonObject
            assertEquals(JsonNull, device["securityPatch"], name)
            assertTrue(IosAttestationRules.parseVersion(device.str("osVersion")) != null, "$name: a dotted version")
            // The signature covers the report string exactly as it travelled.
            val body = body(fixture)
            val key = AttestationService.parseEcKey(body.str("publicKey"))
            assertNotNull(key, name)
            assertTrue(AttestationService.verifySignature(key, AttestationService.canonical(body.str("nonce"), body.str("deviceId"), body.str("report")), body.str("signature")), name)
        }
    }

    @Test
    fun `a genuine iPhone with App Attest passes with nothing raised`() {
        val fixture = fixture("iphone-app-attest")
        val body = body(fixture)
        val deviceId = body.str("deviceId")
        val scope = fixture.str("configApiId")
        val appAttest = fixture["appAttest"]!!.jsonObject
        assertEquals(AppAttestFixtures.APP_ID, appAttest.str("appId"))
        // An earlier round registered the device and its App Attest key (counter 0).
        val now = Instant.ofEpochMilli(fixture["time"]!!.jsonPrimitive.long)
        val spki = Base64.getDecoder().decode(body.str("publicKey"))
        devices.register(scope, deviceId, AttestationService.sha256Hex(spki), body.str("publicKey"), KeyAttestation(false, null, "chain_missing"), now)
        devices.registerAppAttestKey(scope, deviceId, appAttest.str("keyId"), appAttest.str("publicKey"), "{}", now)

        val decided = decide(service(fixture, appAttest = apple.verifier(appIds = setOf(appAttest.str("appId")))), fixture)

        assertTrue(decided.passed, "${decided.rejectionReasons} ${decided.warnings}")
        assertEquals(emptyList(), decided.rejectionReasons)
        assertEquals(emptyList(), decided.warnings, "App Attest verified: key_unattested lifted; secure_enclave, App Store, team and bundle as expected")
        assertNotNull(decided.token)
        val device = devices.get(scope, deviceId)!!
        assertEquals("ios", device.platform)
        assertEquals("pass", device.appAttestResult)
        assertEquals(1L, device.appAttestCounter, "the assertion's counter")
        assertEquals("app-attest", device.verdictProvider)
    }

    @Test
    fun `a genuine iPhone without App Attest is only unattested, and never missing a Play Integrity verdict`() {
        val fixture = fixture("iphone-plain")
        val plain = decide(service(fixture), fixture)
        assertTrue(plain.passed)
        assertEquals(listOf("key_unattested"), plain.warnings, "no Android-only flag: no signer, patch date or Play Integrity on an iPhone")

        // With App Attest and Play Integrity configured: missing App Attest, never missing Play Integrity.
        val google = PlayIntegrityTokens()
        val judged = decide(service(fixture, appAttest = apple.verifier(), playIntegrity = google.verifier()), fixture)
        assertTrue(judged.passed)
        assertEquals(listOf("app_attest_missing", "key_unattested"), judged.warnings.sorted())
    }

    @Test
    fun `a jailbroken, hooked, debugged iPhone is rejected for exactly that`() {
        val fixture = fixture("iphone-jailbroken")
        assertEquals(setOf("rooted", "debugger", "debuggable", "hooking_framework", "unknown_installer", "software_key"), raised(report(fixture)))
        val decided = decide(service(fixture), fixture)
        assertFalse(decided.passed)
        assertNull(decided.token)
        assertEquals(listOf("debuggable", "debugger", "hooking_framework", "rooted"), decided.rejectionReasons.sorted())
        assertEquals(listOf("key_unattested", "software_key", "unknown_installer"), decided.warnings.sorted())
    }

    @Test
    fun `the simulator is an emulator without a team id`() {
        val fixture = fixture("simulator")
        val decided = decide(service(fixture), fixture)
        assertFalse(decided.passed)
        assertEquals(listOf("app_integrity", "debuggable", "emulator"), decided.rejectionReasons.sorted(), "no team id to match ATTESTATION_IOS_TEAM_IDS")
        assertEquals(listOf("key_unattested", "unknown_installer"), decided.warnings.sorted())
        // Without a team list the simulator is rejected for being one, and a debug build.
        val noTeams = decide(service(fixture, ios = IosAttestationRules()), fixture)
        assertEquals(listOf("debuggable", "emulator"), noTeams.rejectionReasons.sorted())
    }

    @Test
    fun `the live probe of a real host raises nothing the server does not derive from it`() {
        for (name in listOf("macos-live", "simulator-live")) {
            val resource = javaClass.getResource("/ios-interop/$name.json") ?: continue
            val fixture = Json.parseToJsonElement(resource.readText()).jsonObject
            val report = report(fixture)
            val app = report["app"]!!.jsonObject
            // Judged with the host's own bundle id expected: what remains is what the probe saw.
            val decided = decide(service(fixture, ios = IosAttestationRules(minOsVersion = listOf(17, 0)), packageNames = setOf(app.str("bundleId"))), fixture)
            val expected = raised(report) + "key_unattested" +
                (if (report["device"]!!.jsonObject.str("keySecurityLevel") in setOf("software", "unknown")) setOf("software_key") else emptySet())
            assertEquals(expected.sorted(), (decided.rejectionReasons + decided.warnings).sorted(), name)
            for (androidOnly in listOf("cloner", "adb_enabled", "play_integrity", "play_integrity_missing", "old_patch_level", "app_attest", "app_attest_missing")) {
                assertFalse(androidOnly in decided.rejectionReasons + decided.warnings, "$name: $androidOnly")
            }
            // The fixtures share a device id; each host made its own key.
            devices.forget(fixture.str("configApiId"), body(fixture).str("deviceId"))
        }
    }

    // ── App Attest tokens ───────────────────────────────────────────────

    @Test
    fun `the library's App Attest tokens are what the verifier parses, bound by the hashes it computes`() {
        val tokens = fixture("app-attest-tokens")
        val nonce = tokens.str("nonce")
        val deviceId = tokens.str("deviceId")
        val keyId = Base64.getDecoder().decode(tokens.str("keyId"))
        val decode = { name: String -> Base64.getDecoder().decode(tokens.str(name)) }

        val attestation = AppAttestVerifier.parseToken(tokens.str("attestationToken"))
        assertNotNull(attestation)
        assertTrue(attestation.wellFormed)
        assertContentEquals(keyId, attestation.keyId)
        assertNotNull(attestation.attestation)
        assertNull(attestation.assertion)
        assertContentEquals(AppAttestVerifier.roundClientDataHash(nonce, deviceId), decode("attestationClientDataHash"))

        val assertion = AppAttestVerifier.parseToken(tokens.str("assertionToken"))
        assertNotNull(assertion)
        assertTrue(assertion.wellFormed)
        assertContentEquals(keyId, assertion.keyId)
        assertNull(assertion.attestation)
        assertContentEquals(AppAttestVerifier.roundClientDataHash(nonce, deviceId), decode("assertionClientDataHash"))
        // The assertion verifies with the key, over the round's client data hash, for the app.
        val verified = apple.verifier(appIds = setOf(tokens.str("appId")))
            .verifyAssertion(assertion.assertion!!, AppAttestVerifier.roundClientDataHash(nonce, deviceId), decode("publicKey"), storedCounter = 0)
        assertTrue(verified.passed, verified.reason)
        assertEquals(1L, verified.counter)

        val enrollment = AppAttestVerifier.parseToken(tokens.str("enrollmentToken"))
        assertNotNull(enrollment)
        assertTrue(enrollment.wellFormed)
        assertNotNull(enrollment.attestation)
        assertFalse(enrollment.keyId.contentEquals(keyId), "a fresh key per enrollment")
        assertEquals(43, tokens.str("requestHash").length)
        assertContentEquals(AppAttestVerifier.enrollmentClientDataHash(tokens.str("requestHash")), decode("enrollmentClientDataHash"))
    }
}
