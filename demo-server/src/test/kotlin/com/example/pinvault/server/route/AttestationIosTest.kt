package com.example.pinvault.server.route

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.attestation.AppAttestFixtures
import com.example.pinvault.server.service.attestation.AppAttestVerifier
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
import com.example.pinvault.server.service.attestation.AttestationNonces
import com.example.pinvault.server.service.attestation.AttestationPolicy
import com.example.pinvault.server.service.attestation.AttestationPolicyDefaults
import com.example.pinvault.server.service.attestation.AttestationService
import com.example.pinvault.server.service.attestation.IosAttestationRules
import com.example.pinvault.server.service.attestation.PlayIntegrityTokens
import com.example.pinvault.server.service.attestation.PlayIntegrityVerifier
import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.AttestationTokenSecretStore
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DeviceHostAclStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * iOS reports end to end (ATTESTATION.md §3, §12): `platform: ios` is held to
 * its own rules — bundle id and team id for `app_integrity`, the iOS version
 * for `old_patch_level`, `secure_enclave` as hardware, App Attest in place of
 * an Android chain for `key_unattested` — and App Attest verdicts are verified,
 * stored and turned into `app_attest` / `app_attest_missing`, only when the
 * server is configured for it. Android reports keep their old verdicts.
 */
class AttestationIosTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var pins: PinConfigStore
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private lateinit var envelopes: SignedConfigService
    private val androidPki = TestAttestationChains.Pki()
    private val apple = AppAttestFixtures.Pki()
    private var now = Instant.now().toEpochMilli()
    private val scope = "default-tls"

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-attest-ios-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        pins = PinConfigStore(db)
        policies = AttestationPolicyStore(db)
        devices = AttestedDeviceStore(db)
        secrets = AttestationTokenSecretStore(db)
        envelopes = SignedConfigService(ConfigSigningService(File(dir, "k.pem")))
        pins.ensureConfigExists(scope)
        pins.save(scope, PinConfig(pins = listOf(HostPin("api.example.com", listOf("a".repeat(43) + "=", "b".repeat(43) + "="), version = 1))))
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun service(
        appAttest: AppAttestVerifier? = null,
        ios: IosAttestationRules = IosAttestationRules(),
        minPatchLevel: Int? = null,
        playIntegrity: PlayIntegrityVerifier? = null
    ) = AttestationService(
        policies, devices, secrets, nonces = AttestationNonces(ttlSeconds = 120, clock = { now }),
        defaults = AttestationPolicyDefaults(), keyPolicy = AttestationKeyPolicy.WARN, verifier = { androidPki.verifier(minPatchLevel = minPatchLevel) },
        audit = AuditLog(AuditLogStore(db), null), rejections = null, clock = { Instant.ofEpochMilli(now) },
        playIntegrity = playIntegrity, appAttest = appAttest, ios = ios
    )

    private fun ApplicationTestBuilder.app(service: AttestationService) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing { attestationRoutes(scope, service, pins, envelopes, deviceHostAclStore = DeviceHostAclStore(db), limits = null, clock = { now }) }
    }

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(key: PrivateKey, text: String): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(text.toByteArray()); sign() }
    )

    private val signalKeys = listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
        "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level")

    /** An iOS report as PORTING.md §4 shapes it; every signal clean, `cloner` / `adb_enabled` n/a. */
    private fun iosReport(
        provider: JsonObject? = null,
        bundleId: String = TestAttestationChains.PACKAGE,
        teamId: String? = AppAttestFixtures.TEAM_ID,
        osVersion: String = "26.5",
        keySecurityLevel: String = "secure_enclave"
    ): String = buildJsonObject {
        put("sdkVersion", "2.3.0"); put("reportTime", now)
        put("app", buildJsonObject {
            put("packageName", bundleId); put("bundleId", bundleId)
            if (teamId == null) put("teamId", JsonNull) else put("teamId", teamId)
            put("versionCode", 1); put("versionName", "1.0")
            putJsonArray("signerSha256") {}
            put("installer", "testflight"); put("debuggable", false)
        })
        put("device", buildJsonObject {
            put("platform", "ios"); put("osVersion", osVersion); put("manufacturer", "Apple"); put("brand", "Apple")
            put("model", "iPhone17,1"); put("device", "iPhone"); put("sdkInt", osVersion.substringBefore('.').toInt())
            put("securityPatch", JsonNull); put("verifiedBootState", JsonNull)
            put("keySecurityLevel", keySecurityLevel); put("keyAttested", false)
        })
        put("signals", buildJsonObject {
            for (flag in signalKeys) put(flag, buildJsonObject {
                put("flag", false)
                putJsonArray("evidence") { if (flag == "cloner" || flag == "adb_enabled") add(JsonPrimitive("n/a:ios")) }
            })
        })
        provider?.let { put("verdictProvider", it) }
    }.toString()

    /** The Android report of the existing tests: attested-style values, no platform field. */
    private fun androidReport(provider: JsonObject? = null): String = buildJsonObject {
        put("sdkVersion", "2.2.0"); put("reportTime", now)
        put("app", buildJsonObject {
            put("packageName", TestAttestationChains.PACKAGE); put("versionCode", 1); put("versionName", "1")
            putJsonArray("signerSha256") { add(JsonPrimitive(TestAttestationChains.SIGNER_HEX.chunked(2).joinToString(":"))) }
            put("installer", "com.android.vending"); put("debuggable", false)
        })
        put("device", buildJsonObject {
            put("manufacturer", "Google"); put("model", "Pixel 8"); put("sdkInt", 35); put("securityPatch", "2026-09-05")
            put("verifiedBootState", "green"); put("keySecurityLevel", "strongbox"); put("keyAttested", true)
        })
        put("signals", buildJsonObject { for (flag in signalKeys) put(flag, buildJsonObject { put("flag", false); putJsonArray("evidence") {} }) })
        provider?.let { put("verdictProvider", it) }
    }.toString()

    private fun appAttestProvider(token: String) = buildJsonObject { put("name", "app-attest"); put("token", token) }

    private suspend fun ApplicationTestBuilder.challenge(): String {
        val response = client.get("/api/v1/attest/challenge")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return Json.parseToJsonElement(response.bodyAsText()).jsonObject["nonce"]!!.jsonPrimitive.content
    }

    /** One round: challenge, the report [reportFor] builds for that nonce, the signed body. */
    private suspend fun ApplicationTestBuilder.attest(deviceId: String, key: KeyPair, reportFor: (nonce: String) -> String): HttpResponse {
        val nonce = challenge()
        val report = reportFor(nonce)
        val body = buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", deviceId)
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            put("report", report)
            put("signature", sign(key.private, AttestationService.canonical(nonce, deviceId, report)))
        }.toString()
        return client.post("/api/v1/attest") { contentType(ContentType.Application.Json); setBody(body) }
    }

    private suspend fun HttpResponse.json(): JsonObject {
        assertEquals(HttpStatusCode.OK, status, bodyAsText())
        return Json.parseToJsonElement(bodyAsText()).jsonObject
    }

    private fun strings(a: Any?) = (a as? JsonArray)?.map { (it as JsonPrimitive).content }.orEmpty()
    private fun JsonObject.warnings() = strings(this["warnings"])
    private fun summaryReason(deviceId: String) =
        Json.parseToJsonElement(devices.get(scope, deviceId)!!.appAttest!!).jsonObject["reason"]!!.jsonPrimitive.content

    /** A round whose report carries an attestation of [aaKey] made for that round. */
    private fun attested(deviceId: String, aaKey: AppAttestFixtures.Key, pki: AppAttestFixtures.Pki = apple): (String) -> String = { nonce ->
        val hash = AppAttestVerifier.roundClientDataHash(nonce, deviceId)
        iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, aaKey, hash))))
    }

    /** A round whose report carries an assertion by [aaKey] with authenticator [counter]. */
    private fun asserted(deviceId: String, aaKey: AppAttestFixtures.Key, counter: Long): (String) -> String = { nonce ->
        val hash = AppAttestVerifier.roundClientDataHash(nonce, deviceId)
        iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, hash, counter))))
    }

    // ── without App Attest configured ────────────────────────────────────

    @Test
    fun `an iOS report without App Attest configured raises only what is true of it`() = testApplication {
        // A server that checks Android patch dates and signers: neither applies to an iPhone.
        app(service(minPatchLevel = 202401))
        val json = attest("ios-1", ecKey()) { iosReport() }.json()
        assertEquals("pass", json["result"]!!.jsonPrimitive.content)
        // No chain and no App Attest: key_unattested, as for an Android key without a chain. Nothing else.
        assertEquals(listOf("key_unattested"), json.warnings())
        val device = devices.get(scope, "ios-1")!!
        assertEquals("ios", device.platform)
        assertNull(device.appAttestResult)
        // Without ATTESTATION_IOS_TEAM_IDS any team id passes.
        assertEquals("pass", attest("ios-5", ecKey()) { iosReport(teamId = "ZZZZZ99999") }.json()["result"]!!.jsonPrimitive.content)
        // secure_enclave is hardware; a software key is not.
        assertTrue("software_key" in attest("ios-2", ecKey()) { iosReport(keySecurityLevel = "software") }.json().warnings())
        assertTrue("software_key" in attest("ios-3", ecKey()) { iosReport(keySecurityLevel = "unknown") }.json().warnings())
        // A token is stored, not judged, and no app_attest* flag without APP_ATTEST_APP_IDS.
        val withToken = attest("ios-4", ecKey(), attested("ios-4", AppAttestFixtures.Key())).json()
        assertEquals(listOf("key_unattested"), withToken.warnings())
        assertEquals("app-attest", devices.get(scope, "ios-4")!!.verdictProvider)
    }

    @Test
    fun `app_integrity on iOS compares the bundle id and the team id, never the signer`() = testApplication {
        val service = service(ios = IosAttestationRules(teamIds = setOf(AppAttestFixtures.TEAM_ID)))
        app(service)
        // The Android verifier names a signer digest; an iOS report has none and is not held to it.
        val genuine = attest("ios-1", ecKey()) { iosReport() }.json()
        assertEquals("pass", genuine["result"]!!.jsonPrimitive.content)
        assertFalse("app_integrity" in genuine.warnings())
        // strict: app_integrity rejects; the reasons are shown here to see which flag did.
        policies.put(scope, AttestationPolicy.parse(buildJsonObject { put("revealReasons", true) }, service.defaultPolicy).getOrThrow(), "test")
        for ((device, report) in listOf(
            "ios-2" to iosReport(bundleId = "com.evil.clone"),
            "ios-3" to iosReport(teamId = "ZZZZZ99999"),
            "ios-4" to iosReport(teamId = null)
        )) {
            val json = attest(device, ecKey()) { report }.json()
            assertEquals("reject", json["result"]!!.jsonPrimitive.content, device)
            assertEquals(listOf("app_integrity"), strings(json["rejectionReasons"]), device)
        }
    }

    @Test
    fun `old_patch_level on iOS compares the iOS version, only when one is configured`() = testApplication {
        app(service(ios = IosAttestationRules(minOsVersion = listOf(26, 0)), minPatchLevel = 202401))
        assertFalse("old_patch_level" in attest("ios-1", ecKey()) { iosReport(osVersion = "26.5") }.json().warnings())
        assertFalse("old_patch_level" in attest("ios-2", ecKey()) { iosReport(osVersion = "26.0") }.json().warnings())
        assertTrue("old_patch_level" in attest("ios-3", ecKey()) { iosReport(osVersion = "18.6") }.json().warnings())
    }

    // ── with App Attest ──────────────────────────────────────────────────

    @Test
    fun `an attestation registers the key, assertions keep the device verified, a replayed counter fails`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val key = ecKey()
        val aaKey = AppAttestFixtures.Key()
        val first = attest("ios-1", key, attested("ios-1", aaKey)).json()
        assertEquals("pass", first["result"]!!.jsonPrimitive.content)
        assertEquals(emptyList(), first.warnings(), "App Attest verified: key_unattested lifted, nothing missing")
        var device = devices.get(scope, "ios-1")!!
        assertEquals("pass", device.appAttestResult)
        assertEquals(aaKey.keyIdBase64, device.appAttestKeyId)
        assertEquals(0L, device.appAttestCounter)
        assertEquals("attestation", Json.parseToJsonElement(device.appAttest!!).jsonObject["kind"]!!.jsonPrimitive.content)

        now += 60_000
        assertEquals(emptyList(), attest("ios-1", key, asserted("ios-1", aaKey, 1)).json().warnings())
        assertEquals(1L, devices.get(scope, "ios-1")!!.appAttestCounter)

        // The same counter again: a replay or a clone. app_attest, and it sticks until a fresh pass.
        now += 60_000
        val replay = attest("ios-1", key, asserted("ios-1", aaKey, 1)).json()
        assertEquals(listOf("app_attest", "key_unattested"), replay.warnings().sorted())
        assertEquals("counter_replay", summaryReason("ios-1"))
        device = devices.get(scope, "ios-1")!!
        assertEquals("fail", device.appAttestResult)
        assertEquals(1L, device.appAttestCounter, "the counter stays")
        assertTrue("app_attest" in attest("ios-1", key) { iosReport() }.json().warnings())
        assertEquals(emptyList(), attest("ios-1", key, asserted("ios-1", aaKey, 5)).json().warnings())
        assertEquals(5L, devices.get(scope, "ios-1")!!.appAttestCounter)

        // An assertion made for another round's challenge does not verify.
        val stale = attest("ios-1", key) { _ ->
            val hash = AppAttestVerifier.roundClientDataHash("another-nonce", "ios-1")
            iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, hash, 6))))
        }.json()
        assertTrue("app_attest" in stale.warnings())
        assertEquals("signature_invalid", summaryReason("ios-1"))
    }

    @Test
    fun `an assertion for a key the server has no record of tells the app to attest again`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val key = ecKey()
        val unknown = attest("ios-1", key, asserted("ios-1", AppAttestFixtures.Key(), 3)).json()
        assertEquals("pass", unknown["result"]!!.jsonPrimitive.content, "strict: app_attest warns")
        assertTrue("app_attest" in unknown.warnings())
        assertTrue(AttestationService.APP_ATTEST_UNKNOWN_KEY in unknown.warnings())
        assertEquals("app_attest_unknown_key", summaryReason("ios-1"))

        // The app attests a new key and is verified again; the hint is gone.
        val aaKey = AppAttestFixtures.Key()
        assertEquals(emptyList(), attest("ios-1", key, attested("ios-1", aaKey)).json().warnings())
        // Another key's assertion is as unknown as a never-seen one.
        val other = attest("ios-1", key, asserted("ios-1", AppAttestFixtures.Key(), 1)).json()
        assertTrue(AttestationService.APP_ATTEST_UNKNOWN_KEY in other.warnings())

        // Under a policy that rejects app_attest the hint still reaches the app.
        policies.put(scope, AttestationPolicy.parse(buildJsonObject {
            put("flags", buildJsonObject { put("app_attest", "reject") }); put("revealReasons", true)
        }, AttestationPolicy.strict()).getOrThrow(), "test")
        val rejected = attest("ios-1", key, asserted("ios-1", AppAttestFixtures.Key(), 1)).json()
        assertEquals("reject", rejected["result"]!!.jsonPrimitive.content)
        assertEquals(listOf("app_attest"), strings(rejected["rejectionReasons"]))
        assertTrue(AttestationService.APP_ATTEST_UNKNOWN_KEY in rejected.warnings())
        assertNull(rejected["token"])
    }

    @Test
    fun `a failing attestation raises app_attest with its reason`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val key = ecKey()
        val stranger = AppAttestFixtures.Pki("CN=Not Apple")
        val json = attest("ios-1", key, attested("ios-1", AppAttestFixtures.Key(), pki = stranger)).json()
        assertTrue("app_attest" in json.warnings())
        assertTrue("key_unattested" in json.warnings())
        assertEquals("chain_invalid", summaryReason("ios-1"))
        assertNull(devices.get(scope, "ios-1")!!.appAttestKeyId, "no key registered from a failed attestation")
        // An attestation of another round (its nonce) fails nonce_mismatch.
        val aaKey = AppAttestFixtures.Key()
        attest("ios-1", key) { _ ->
            val hash = AppAttestVerifier.roundClientDataHash("someone-elses-nonce", "ios-1")
            iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(apple, aaKey, hash))))
        }.json()
        assertEquals("nonce_mismatch", summaryReason("ios-1"))
        // A token that is not App Attest JSON at all.
        assertTrue("app_attest" in attest("ios-1", key) { iosReport(appAttestProvider("garbage")) }.json().warnings())
        assertEquals("malformed", summaryReason("ios-1"))
    }

    @Test
    fun `app_attest_missing is raised for an iPhone without a fresh verdict, only when configured`() = testApplication {
        app(service(appAttest = apple.verifier(verdictMaxAgeSeconds = 3600)))
        val key = ecKey()
        // A simulator: no provider at all.
        assertEquals(listOf("app_attest_missing", "key_unattested"), attest("ios-sim", ecKey()) { iosReport() }.json().warnings().sorted())

        val aaKey = AppAttestFixtures.Key()
        attest("ios-1", key, attested("ios-1", aaKey)).json()
        now += 30 * 60_000L
        assertEquals(emptyList(), attest("ios-1", key) { iosReport() }.json().warnings(), "a fresh stored verdict covers a round without one")
        now += 60 * 60_000L
        assertEquals(listOf("app_attest_missing", "key_unattested"), attest("ios-1", key) { iosReport() }.json().warnings().sorted())
        assertEquals(emptyList(), attest("ios-1", key, asserted("ios-1", aaKey, 1)).json().warnings())
    }

    @Test
    fun `Android reports keep their verdicts with App Attest configured`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val json = attest("android-1", ecKey()) { androidReport() }.json()
        // The test key sends no chain: key_unattested, as before; never app_attest_missing.
        assertEquals(listOf("key_unattested"), json.warnings())
        assertEquals("android", devices.get(scope, "android-1")!!.platform)
        assertNull(devices.get(scope, "android-1")!!.appAttestResult)
    }

    @Test
    fun `an iPhone is not missing a Play Integrity verdict`() = testApplication {
        val google = PlayIntegrityTokens()
        app(service(playIntegrity = google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE))))
        assertFalse("play_integrity_missing" in attest("ios-1", ecKey()) { iosReport() }.json().warnings())
        assertTrue("play_integrity_missing" in attest("android-1", ecKey()) { androidReport() }.json().warnings(), "Android: unchanged")
    }

    @Test
    fun `the policy decides what app_attest_missing does`() = testApplication {
        val service = service(appAttest = apple.verifier())
        app(service)
        policies.put(scope, AttestationPolicy.parse(buildJsonObject {
            put("flags", buildJsonObject { put("app_attest_missing", "reject"); put("key_unattested", "ignore") })
            put("revealReasons", true)
        }, service.defaultPolicy).getOrThrow(), "test")
        val missing = attest("ios-1", ecKey()) { iosReport() }.json()
        assertEquals("reject", missing["result"]!!.jsonPrimitive.content)
        assertEquals(listOf("app_attest_missing"), strings(missing["rejectionReasons"]))
        val key = ecKey()
        val verified = attest("ios-2", key, attested("ios-2", AppAttestFixtures.Key())).json()
        assertEquals("pass", verified["result"]!!.jsonPrimitive.content)
        assertNotNull(verified["token"])
        // The defaults: both warn, in both profiles.
        for (profile in listOf(AttestationPolicy.strict(), AttestationPolicy.lenient())) {
            assertEquals("warn", profile.flags["app_attest"])
            assertEquals("warn", profile.flags["app_attest_missing"])
        }
    }
}
