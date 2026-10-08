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
        playIntegrity: PlayIntegrityVerifier? = null,
        keyPolicy: AttestationKeyPolicy = AttestationKeyPolicy.WARN
    ) = AttestationService(
        policies, devices, secrets, nonces = AttestationNonces(ttlSeconds = 120, clock = { now }),
        defaults = AttestationPolicyDefaults(), keyPolicy = keyPolicy, verifier = { androidPki.verifier(minPatchLevel = minPatchLevel) },
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
            // No chain is sent here: the genuine library says keyAttested only for a key it sends a chain for.
            put("verifiedBootState", "green"); put("keySecurityLevel", "strongbox"); put("keyAttested", false)
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
    private suspend fun ApplicationTestBuilder.attest(deviceId: String, key: KeyPair, reportFor: (nonce: String) -> String): HttpResponse =
        attestWithChain(deviceId, key, null, reportFor)

    /** [attest] with an Android Key Attestation [chain]. */
    private suspend fun ApplicationTestBuilder.attestWithChain(
        deviceId: String, key: KeyPair, chain: List<String>?, reportFor: (nonce: String) -> String
    ): HttpResponse {
        val nonce = challenge()
        val report = reportFor(nonce)
        val canonical = AttestationService.canonical(nonce, deviceId, report)
        val body = buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", deviceId)
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            chain?.let { putJsonArray("attestationChain") { it.forEach { c -> add(JsonPrimitive(c)) } } }
            put("report", report)
            put("signature", sign(key.private, canonical))
            // A v2 round: the token, made over the canonical string, beside the report (§12).
            (reportFor as? V2Round)?.let { put("verdictProvider", it.provider(canonical)) }
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

    /**
     * A round as the current library sends it (§12, v2): the report carries no
     * provider; the App Attest token — an attestation of [aaKey] or, with a
     * [counter], an assertion — is made over the canonical string and travels
     * in the body's own `verdictProvider` ([attestWithChain] adds it).
     */
    private inner class V2Round(
        private val aaKey: AppAttestFixtures.Key, private val counter: Long?, private val pki: AppAttestFixtures.Pki,
        private val report: () -> String
    ) : (String) -> String {
        override fun invoke(nonce: String): String = report()

        fun provider(canonical: String): JsonObject {
            val hash = AppAttestVerifier.roundClientDataHashV2(canonical)
            return appAttestProvider(
                if (counter == null) AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, aaKey, hash))
                else AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, hash, counter))
            )
        }
    }

    /** A round that carries an attestation of [aaKey] made for that round (v2). */
    @Suppress("UNUSED_PARAMETER")
    private fun attested(deviceId: String, aaKey: AppAttestFixtures.Key, pki: AppAttestFixtures.Pki = apple): (String) -> String =
        V2Round(aaKey, null, pki) { iosReport() }

    /** A round that carries an assertion by [aaKey] with authenticator [counter] (v2). */
    @Suppress("UNUSED_PARAMETER")
    private fun asserted(deviceId: String, aaKey: AppAttestFixtures.Key, counter: Long): (String) -> String =
        V2Round(aaKey, counter, apple) { iosReport() }

    /** An older app's round (v1): the report carries the attestation, client data hash of the nonce and the device id. */
    private fun attestedV1(deviceId: String, aaKey: AppAttestFixtures.Key, pki: AppAttestFixtures.Pki = apple): (String) -> String = { nonce ->
        val hash = AppAttestVerifier.roundClientDataHash(nonce, deviceId)
        iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, aaKey, hash))))
    }

    /** An older app's assertion round (v1). */
    private fun assertedV1(deviceId: String, aaKey: AppAttestFixtures.Key, counter: Long): (String) -> String = { nonce ->
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
        now += 5 * 60_000L
        assertEquals(emptyList(), attest("ios-1", key) { iosReport() }.json().warnings(), "a fresh stored verdict covers a round without one")
        // With its key on record the device can assert every round: a stored pass covers a
        // round without a token for APP_ATTEST_ROUND_GRACE_SECONDS only, not verdictMaxAgeSeconds.
        now += 25 * 60_000L
        assertEquals(listOf("app_attest_missing", "key_unattested"), attest("ios-1", key) { iosReport() }.json().warnings().sorted())
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
    fun `an iPhone is not missing a Play Integrity verdict while App Attest judges it`() = testApplication {
        val google = PlayIntegrityTokens()
        app(service(playIntegrity = google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE)), appAttest = apple.verifier()))
        val ios = attest("ios-1", ecKey()) { iosReport() }.json().warnings()
        assertFalse("play_integrity_missing" in ios)
        assertTrue("app_attest_missing" in ios, "App Attest is its counterpart")
        assertTrue("play_integrity_missing" in attest("android-1", ecKey()) { androidReport() }.json().warnings(), "Android: unchanged")
    }

    @Test
    fun `without App Attest configured an iOS claim is no way out of play_integrity_missing`() = testApplication {
        val google = PlayIntegrityTokens()
        app(service(playIntegrity = google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE))))
        // Nothing would judge an "iPhone" here; the claim alone must not skip the Android check.
        assertTrue("play_integrity_missing" in attest("ios-1", ecKey()) { iosReport() }.json().warnings())
    }

    @Test
    fun `a device cannot switch platforms to pick easier checks`() = testApplication {
        val service = service(appAttest = apple.verifier())
        app(service)
        policies.put(scope, AttestationPolicy.parse(buildJsonObject { put("revealReasons", true) }, service.defaultPolicy).getOrThrow(), "test")
        // An Android device on record (its first verdict) that then claims to be an iPhone.
        val androidKey = ecKey()
        assertEquals("pass", attest("android-1", androidKey) { androidReport() }.json()["result"]!!.jsonPrimitive.content)
        val switched = attest("android-1", androidKey) { iosReport() }.json()
        assertEquals("reject", switched["result"]!!.jsonPrimitive.content)
        assertTrue("app_integrity" in strings(switched["rejectionReasons"]))
        assertFalse("app_attest_missing" in switched.warnings(), "judged as the Android device it is on record as")
        assertEquals("android", devices.get(scope, "android-1")!!.platform, "the record keeps its platform")

        // An iPhone whose App Attest key is on record that then claims to be Android.
        val iosKey = ecKey()
        assertEquals(emptyList(), attest("ios-1", iosKey, attested("ios-1", AppAttestFixtures.Key())).json().warnings())
        val androidClaim = attest("ios-1", iosKey) { androidReport() }.json()
        assertEquals("reject", androidClaim["result"]!!.jsonPrimitive.content)
        assertTrue("app_integrity" in strings(androidClaim["rejectionReasons"]))
        assertEquals("ios", devices.get(scope, "ios-1")!!.platform)
    }

    @Test
    fun `the platform a device is on record as is what its report is judged by`() {
        val base = devices.run {
            register(scope, "d", "00", "AA==", null, Instant.ofEpochMilli(now))
            get(scope, "d")!!
        }
        assertEquals("ios", AttestationService.effectivePlatform("ios", base), "nothing on record: the claim")
        assertEquals("android", AttestationService.effectivePlatform("ios", base.copy(platform = "android")))
        assertEquals("ios", AttestationService.effectivePlatform("android", base.copy(appAttestKeyId = "k")))
        assertEquals("android", AttestationService.effectivePlatform("ios",
            base.copy(keyAttestation = com.example.pinvault.server.store.KeyAttestation(true, "strongbox", "ok"))),
            "a verified Android Key Attestation chain fixes the platform")
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

    // ── ATTESTATION_KEY_POLICY=enforce: App Attest in place of the chain ─

    /** A 403 refusal's body, after checking [error] and [reason]. */
    private suspend fun HttpResponse.refusal(error: String, reason: String? = null): JsonObject {
        assertEquals(HttpStatusCode.Forbidden, status, bodyAsText())
        val json = Json.parseToJsonElement(bodyAsText()).jsonObject
        assertEquals(error, json["error"]!!.jsonPrimitive.content, bodyAsText())
        assertEquals(reason, json["reason"]?.jsonPrimitive?.content, bodyAsText())
        return json
    }

    /** A round whose report carries an attestation of a fresh key made with [clientDataHash] (whatever it binds). */
    private fun attestedWith(clientDataHash: ByteArray, pki: AppAttestFixtures.Pki = apple, appId: String = AppAttestFixtures.APP_ID): String {
        val aaKey = AppAttestFixtures.Key()
        return iosReport(appAttestProvider(AppAttestFixtures.token(aaKey.keyIdBase64,
            attestation = AppAttestFixtures.attestation(pki, aaKey, clientDataHash, appId = appId))))
    }

    @Test
    fun `under enforce an iPhone registers with its first round's App Attest attestation and is held to iOS`() = testApplication {
        val service = service(appAttest = apple.verifier(), keyPolicy = AttestationKeyPolicy.ENFORCE)
        app(service)
        val key = ecKey()
        val aaKey = AppAttestFixtures.Key()
        val first = attest("ios-1", key, attested("ios-1", aaKey)).json()
        assertEquals("pass", first["result"]!!.jsonPrimitive.content)
        assertEquals(emptyList(), first.warnings(), "verified once, in place of the chain: key_unattested lifted")
        assertTrue(first["device"]!!.jsonObject["firstSeen"]!!.jsonPrimitive.content.toBoolean())
        val ka = first["device"]!!.jsonObject["keyAttestation"]!!.jsonObject
        assertEquals("true", ka["attested"]!!.jsonPrimitive.content)
        assertEquals("app_attest", ka["reason"]!!.jsonPrimitive.content)
        assertEquals("app_attest", ka["attestedBy"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, ka["securityLevel"], "App Attest says nothing about where the key lives")

        val device = devices.get(scope, "ios-1")!!
        assertTrue(device.registered)
        assertTrue(com.example.pinvault.server.service.attestation.AppAttestAdmission.admitted(device.keyAttestation))
        assertEquals(aaKey.keyIdBase64, device.appAttestKeyId, "the App Attest key is on record")
        assertEquals(0L, device.appAttestCounter)
        assertEquals("pass", device.appAttestResult)
        assertEquals("ios", device.platform)
        val registered = AuditLogStore(db).page(50, 0).first { it.action == "attestation_device_registered" }
        assertTrue(registered.summary.contains("admitted by App Attest, ${AppAttestFixtures.APP_ID}"), registered.summary)
        assertTrue(registered.detail.contains("\"attestedBy\":\"app_attest\""), registered.detail)

        // Later rounds are any iPhone's: assertions with the key on record.
        now += 60_000
        assertEquals(emptyList(), attest("ios-1", key, asserted("ios-1", aaKey, 1)).json().warnings())
        assertEquals(1L, devices.get(scope, "ios-1")!!.appAttestCounter)

        // Held to iOS: a report claiming Android is judged as the iPhone on record and raises app_integrity.
        policies.put(scope, AttestationPolicy.parse(buildJsonObject { put("revealReasons", true) }, service.defaultPolicy).getOrThrow(), "test")
        val claim = attest("ios-1", key) { androidReport() }.json()
        assertEquals("reject", claim["result"]!!.jsonPrimitive.content)
        assertTrue("app_integrity" in strings(claim["rejectionReasons"]))
        assertEquals("ios", devices.get(scope, "ios-1")!!.platform)
        // The admission alone fixes the platform, App Attest key or not.
        assertEquals("ios", AttestationService.effectivePlatform("android", devices.get(scope, "ios-1")!!.copy(appAttestKeyId = null, platform = null)))
    }

    @Test
    fun `under enforce an App Attest attestation made for another round, device, app, root or place is refused`() = testApplication {
        app(service(appAttest = apple.verifier(), keyPolicy = AttestationKeyPolicy.ENFORCE))
        val key = ecKey()
        // Another round's nonce, another device id: the client data hash does not match.
        attest("ios-1", key) { attestedWith(AppAttestVerifier.roundClientDataHash("another-nonce", "ios-1")) }
            .refusal("attestation_invalid", "app_attest_nonce_mismatch")
        attest("ios-1", key) { nonce -> attestedWith(AppAttestVerifier.roundClientDataHash(nonce, "ios-2")) }
            .refusal("attestation_invalid", "app_attest_nonce_mismatch")
        // Another developer's app, a root that is not Apple's.
        attest("ios-1", key) { nonce -> attestedWith(AppAttestVerifier.roundClientDataHash(nonce, "ios-1"), appId = "ZZZZZ99999.com.evil") }
            .refusal("attestation_invalid", "app_attest_app_id_mismatch")
        attest("ios-1", key) { nonce -> attestedWith(AppAttestVerifier.roundClientDataHash(nonce, "ios-1"), pki = AppAttestFixtures.Pki("CN=Not Apple")) }
            .refusal("attestation_invalid", "app_attest_chain_invalid")
        // Each place needs its own attestation: one made for an enrollment or a screen-lock key does not register a device here.
        val csr = ByteArray(64) { 3 }
        attest("ios-1", key) { attestedWith(AppAttestVerifier.enrollmentClientDataHash(com.example.pinvault.server.service.IntegrityRequestHash.of("ios-1", csr))) }
            .refusal("attestation_invalid", "app_attest_nonce_mismatch")
        attest("ios-1", key) { attestedWith(com.example.pinvault.server.service.attestation.AppAttestAdmission.userAuthClientDataHash("ios-1", key.public.encoded)) }
            .refusal("attestation_invalid", "app_attest_nonce_mismatch")
        assertNull(devices.get(scope, "ios-1"), "nothing registered, no verdict stored")
    }

    @Test
    fun `under enforce an iPhone without an App Attest attestation is refused as before`() = testApplication {
        app(service(appAttest = apple.verifier(), keyPolicy = AttestationKeyPolicy.ENFORCE))
        // A simulator: no verdict provider at all.
        val missing = attest("ios-sim", ecKey()) { iosReport() }.refusal("attestation_required")
        assertTrue(missing["message"]!!.jsonPrimitive.content.contains("App Attest"), "the refusal names the way in")
        // An assertion: this server has no App Attest key for an unknown device — the app attests a new one.
        attest("ios-2", ecKey(), asserted("ios-2", AppAttestFixtures.Key(), 3)).refusal("attestation_required", AttestationService.APP_ATTEST_UNKNOWN_KEY)
        // A token that is not App Attest JSON.
        attest("ios-3", ecKey()) { iosReport(appAttestProvider("garbage")) }.refusal("attestation_invalid", "app_attest_malformed")
        // Another provider's token is no App Attest.
        attest("ios-4", ecKey()) { iosReport(buildJsonObject { put("name", "play-integrity"); put("token", "eyJ") }) }.refusal("attestation_required")
        for (id in listOf("ios-sim", "ios-2", "ios-3", "ios-4")) assertNull(devices.get(scope, id), id)
    }

    @Test
    fun `without App Attest configured enforce refuses every iPhone, attestation or not`() = testApplication {
        app(service(keyPolicy = AttestationKeyPolicy.ENFORCE))
        val refused = attest("ios-1", ecKey(), attested("ios-1", AppAttestFixtures.Key())).refusal("attestation_required")
        assertFalse(refused["message"]!!.jsonPrimitive.content.contains("App Attest"), "the message is the old one")
        assertNull(devices.get(scope, "ios-1"))
    }

    @Test
    fun `under enforce an Android device still needs its chain, App Attest configured or not`() = testApplication {
        app(service(appAttest = apple.verifier(), keyPolicy = AttestationKeyPolicy.ENFORCE))
        val key = ecKey()
        attest("android-1", key) { androidReport() }.refusal("attestation_required")
        val good = TestAttestationChains.chain(androidPki, key.public, TestAttestationChains.identityDescription("android-1"))
        val json = attestWithChain("android-1", key, good) { androidReport() }.json()
        assertEquals("pass", json["result"]!!.jsonPrimitive.content)
        val ka = json["device"]!!.jsonObject["keyAttestation"]!!.jsonObject
        assertEquals("ok", ka["reason"]!!.jsonPrimitive.content)
        assertNull(ka["attestedBy"])
        assertEquals("android", devices.get(scope, "android-1")!!.platform)
        // A chain decides when there is one: a failing chain is not rescued by an App Attest verdict next to it.
        val other = ecKey()
        val wrong = TestAttestationChains.chain(androidPki, other.public, TestAttestationChains.identityDescription("someone-else"))
        attestWithChain("android-2", other, wrong, attested("android-2", AppAttestFixtures.Key())).refusal("attestation_invalid", "challenge_mismatch")
        assertNull(devices.get(scope, "android-2"))
    }

    // ── Client data hash v2 (bound to the report) ─────────────────────────

    @Test
    fun `the v2 client data hash is the canonical string the device key signs, prefixed`() {
        val canonical = AttestationService.canonical("NONCE", "ios-1", "{\"sdkVersion\":\"2.4.0\"}")
        assertEquals("pinvault-attest:v1:NONCE:ios-1:" + AttestationService.sha256Hex("{\"sdkVersion\":\"2.4.0\"}".toByteArray()), canonical)
        assertTrue(AppAttestVerifier.roundClientDataHashV2(canonical).contentEquals(
            java.security.MessageDigest.getInstance("SHA-256").digest("pinvault-app-attest:v2:$canonical".toByteArray(Charsets.UTF_8))),
            "the wire string the iOS client must match")
    }

    @Test
    fun `a v1 verdict in the report still passes with app_attest_v1, a v2 one beside the report without it`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val key = ecKey()
        val aaKey = AppAttestFixtures.Key()
        val v1 = attest("ios-1", key, attestedV1("ios-1", aaKey)).json()
        assertEquals("pass", v1["result"]!!.jsonPrimitive.content)
        assertEquals(listOf(AttestationService.APP_ATTEST_V1), v1.warnings(), "an older app: verified, with the note")
        now += 60_000
        assertEquals(listOf(AttestationService.APP_ATTEST_V1), attest("ios-1", key, assertedV1("ios-1", aaKey, 1)).json().warnings())
        now += 60_000
        // The same key, updated app: v2, nothing to note.
        assertEquals(emptyList(), attest("ios-1", key, asserted("ios-1", aaKey, 2)).json().warnings())
        assertEquals(2L, devices.get(scope, "ios-1")!!.appAttestCounter)
        assertEquals("v2", Json.parseToJsonElement(devices.get(scope, "ios-1")!!.appAttest!!).jsonObject["clientData"]!!.jsonPrimitive.content)
    }

    @Test
    fun `APP_ATTEST_REQUIRE_V2 refuses a v1 verdict, at registration and on later rounds`() = testApplication {
        app(service(appAttest = apple.verifier(requireV2 = true)))
        policies.put(scope, AttestationPolicy.parse(buildJsonObject { put("revealReasons", true) }, service(appAttest = apple.verifier()).defaultPolicy).getOrThrow(), "test")
        val key = ecKey()
        val aaKey = AppAttestFixtures.Key()
        val v1 = attest("ios-1", key, attestedV1("ios-1", aaKey)).json()
        assertTrue("app_attest" in v1.warnings(), v1.toString())
        assertEquals(AttestationService.CLIENT_DATA_V1, summaryReason("ios-1"))
        assertNull(devices.get(scope, "ios-1")!!.appAttestKeyId, "a refused attestation registers no key")
        assertEquals(emptyList(), attest("ios-1", key, attested("ios-1", aaKey)).json().warnings(), "v2 passes")

        // Under enforce, the registration's attestation in place of the chain too.
        val enforce = service(appAttest = apple.verifier(requireV2 = true), keyPolicy = AttestationKeyPolicy.ENFORCE)
        val nonce = enforce.nonces.issue()
        val k2 = ecKey()
        val report = attestedV1("ios-2", AppAttestFixtures.Key())(nonce)
        val body = buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", "ios-2")
            put("publicKey", Base64.getEncoder().encodeToString(k2.public.encoded))
            put("report", report); put("signature", sign(k2.private, AttestationService.canonical(nonce, "ios-2", report)))
        }
        val refused = enforce.attest(scope, body, "test")
        val outcome = refused as AttestationService.Outcome.Refused
        assertEquals("attestation_invalid", outcome.error)
        assertEquals("app_attest_client_data_v1", outcome.reason)
    }

    @Test
    fun `a v2 verdict made for one report does not pass with another - an out-of-app signer cannot reuse it`() = testApplication {
        app(service(appAttest = apple.verifier()))
        val key = ecKey()
        val aaKey = AppAttestFixtures.Key()
        assertEquals(emptyList(), attest("ios-1", key, attested("ios-1", aaKey)).json().warnings())
        now += 60_000
        // The genuine app's assertion is over its own report; the request carries another one, signed with the identity key.
        val nonce = challenge()
        val genuine = iosReport()
        val forged = iosReport(osVersion = "26.6")
        val hash = AppAttestVerifier.roundClientDataHashV2(AttestationService.canonical(nonce, "ios-1", genuine))
        val token = AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, hash, 1))
        val body = buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", "ios-1")
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            put("report", forged); put("signature", sign(key.private, AttestationService.canonical(nonce, "ios-1", forged)))
            put("verdictProvider", appAttestProvider(token))
        }.toString()
        val answer = client.post("/api/v1/attest") { contentType(ContentType.Application.Json); setBody(body) }.json()
        assertTrue("app_attest" in answer.warnings(), answer.toString())
        assertEquals("signature_invalid", summaryReason("ios-1"))
        // A v1-hash token beside the report is not accepted either: outside the report a verdict must be v2.
        now += 60_000
        val nonce2 = challenge()
        val report2 = iosReport()
        val v1Token = AppAttestFixtures.token(aaKey.keyIdBase64,
            assertion = AppAttestFixtures.assertion(aaKey, AppAttestVerifier.roundClientDataHash(nonce2, "ios-1"), 2))
        val outside = buildJsonObject {
            put("v", 1); put("nonce", nonce2); put("deviceId", "ios-1")
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            put("report", report2); put("signature", sign(key.private, AttestationService.canonical(nonce2, "ios-1", report2)))
            put("verdictProvider", appAttestProvider(v1Token))
        }.toString()
        assertTrue("app_attest" in client.post("/api/v1/attest") { contentType(ContentType.Application.Json); setBody(outside) }.json().warnings())
    }
}
