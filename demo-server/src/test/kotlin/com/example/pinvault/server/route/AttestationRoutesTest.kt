package com.example.pinvault.server.route

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.service.AndroidKeyAttestation
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
import com.example.pinvault.server.service.attestation.AttestationNonces
import com.example.pinvault.server.service.attestation.AttestationPolicy
import com.example.pinvault.server.service.attestation.AttestationPolicyDefaults
import com.example.pinvault.server.service.attestation.AttestationService
import com.example.pinvault.server.service.attestation.PinVaultToken
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `GET /api/v1/attest/challenge` and `POST /api/v1/attest` (ATTESTATION.md §2). */
class AttestationRoutesTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var pins: PinConfigStore
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var envelopes: SignedConfigService
    private val pki = TestAttestationChains.Pki()

    /** The test clock: nonces, verdicts and the challenge's serverTime read it. */
    private var now = System.currentTimeMillis()
    private val scope = "default-tls"

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-attest-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        pins = PinConfigStore(db)
        policies = AttestationPolicyStore(db)
        devices = AttestedDeviceStore(db)
        secrets = AttestationTokenSecretStore(db)
        auditStore = AuditLogStore(db)
        envelopes = SignedConfigService(ConfigSigningService(File(dir, "k.pem")))
        pins.ensureConfigExists(scope)
        pins.save(scope, PinConfig(pins = listOf(
            HostPin("api.example.com", listOf("a".repeat(43) + "=", "b".repeat(43) + "="), version = 1),
            HostPin("cdn.example.com", listOf("c".repeat(43) + "=", "d".repeat(43) + "="), version = 1)
        )))
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun service(
        keyPolicy: AttestationKeyPolicy = AttestationKeyPolicy.WARN,
        verifier: AndroidKeyAttestation = pki.verifier(),
        defaults: AttestationPolicyDefaults = AttestationPolicyDefaults(),
        revoked: Set<String> = emptySet(),
        nonceTtl: Int = 120
    ) = AttestationService(
        policies, devices, secrets,
        nonces = AttestationNonces(ttlSeconds = nonceTtl, clock = { now }),
        defaults = defaults, keyPolicy = keyPolicy, verifier = { verifier },
        isDeviceRevoked = { it in revoked }, audit = AuditLog(auditStore, null), rejections = null,
        clock = { Instant.ofEpochMilli(now) }
    )

    private fun ApplicationTestBuilder.app(service: AttestationService, limits: AttestationLimits? = null) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing {
            attestationRoutes(scope, service, pins, envelopes, deviceHostAclStore = DeviceHostAclStore(db), limits = limits, clock = { now })
        }
    }

    // ── A device ────────────────────────────────────────────────────────

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(key: PrivateKey, text: String): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(text.toByteArray()); sign() }
    )

    /** A clean report of the sample app, with the given flags raised. */
    private fun report(
        vararg raised: String,
        packageName: String = TestAttestationChains.PACKAGE,
        signer: String = TestAttestationChains.SIGNER_HEX.chunked(2).joinToString(":"),
        keySecurityLevel: String = "strongbox",
        securityPatch: String = "2026-09-05"
    ): String = buildJsonObject {
        put("sdkVersion", "2.2.0")
        put("reportTime", now)
        put("app", buildJsonObject {
            put("packageName", packageName); put("versionCode", 412); put("versionName", "4.1.2")
            putJsonArray("signerSha256") { add(JsonPrimitive(signer)) }
            put("installer", "com.android.vending"); put("debuggable", false)
        })
        put("device", buildJsonObject {
            put("manufacturer", "Google"); put("model", "Pixel 8"); put("sdkInt", 35)
            put("securityPatch", securityPatch); put("verifiedBootState", "green")
            put("keySecurityLevel", keySecurityLevel); put("keyAttested", true)
        })
        put("signals", buildJsonObject {
            for (flag in listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
                "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level")) {
                put(flag, buildJsonObject {
                    put("flag", flag in raised)
                    putJsonArray("evidence") { if (flag in raised) add(JsonPrimitive("test:$flag")) }
                })
            }
        })
        put("verdictProvider", buildJsonObject { put("name", "play-integrity"); put("token", "eyJ.test") })
    }.toString()

    private suspend fun ApplicationTestBuilder.challenge(): String {
        val response = client.get("/api/v1/attest/challenge")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(120, json["expiresIn"]!!.jsonPrimitive.int)
        assertEquals(now, json["serverTime"]!!.jsonPrimitive.long)
        return json["nonce"]!!.jsonPrimitive.content
    }

    private fun body(
        nonce: String, deviceId: String, key: KeyPair, report: String,
        chain: List<String>? = null, currentConfigVersion: Int? = null, currentIssuedAt: Long? = null,
        hosts: List<String>? = null, v: Int = 1, signer: PrivateKey = key.private, publicKey: String = Base64.getEncoder().encodeToString(key.public.encoded)
    ): String = buildJsonObject {
        put("v", v)
        put("nonce", nonce)
        put("deviceId", deviceId)
        put("publicKey", publicKey)
        chain?.let { put("attestationChain", buildJsonArray { it.forEach { c -> add(JsonPrimitive(c)) } }) }
        put("report", report)
        put("signature", sign(signer, AttestationService.canonical(nonce, deviceId, report)))
        currentConfigVersion?.let { put("currentConfigVersion", it) }
        currentIssuedAt?.let { put("currentIssuedAt", it) }
        hosts?.let { put("hosts", buildJsonArray { it.forEach { h -> add(JsonPrimitive(h)) } }) }
    }.toString()

    private suspend fun ApplicationTestBuilder.attest(body: String): HttpResponse = client.post("/api/v1/attest") {
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun ApplicationTestBuilder.attestJson(body: String): JsonObject {
        val response = attest(body)
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return Json.parseToJsonElement(response.bodyAsText()).jsonObject
    }

    private suspend fun ApplicationTestBuilder.refused(body: String, status: HttpStatusCode, error: String): JsonObject {
        val response = attest(body)
        assertEquals(status, response.status, response.bodyAsText())
        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(error, json["error"]!!.jsonPrimitive.content, response.bodyAsText())
        return json
    }

    private fun JsonObject.strings(name: String): List<String> = (this[name] as? JsonArray)?.map { it.jsonPrimitive.content } ?: emptyList()

    // ── Tests ───────────────────────────────────────────────────────────

    @Test
    fun `challenge then attest - a clean device passes, gets a token that verifies and the config it lacks`() = testApplication {
        val service = service()
        app(service)
        val key = ecKey()
        val answer = attestJson(body(challenge(), "pixel-01", key, report()))

        assertEquals("pass", answer["result"]!!.jsonPrimitive.content)
        assertTrue(Regex("^[0-9a-f]{8}$").matches(answer["arc"]!!.jsonPrimitive.content), answer["arc"].toString())
        assertNull(answer["rejectionReasons"], "reasons are hidden by default")
        // WARN without a chain: the key is registered unattested, and the strict policy warns about it.
        assertEquals(setOf("key_unattested"), answer.strings("warnings").toSet())
        assertEquals(300, answer["tokenTtlSeconds"]!!.jsonPrimitive.int)
        assertEquals(300, answer["nextAttestIn"]!!.jsonPrimitive.int)
        assertEquals(0, answer["policyVersion"]!!.jsonPrimitive.int)
        assertEquals((now / 1000 + 300) * 1000, answer["tokenExpiresAt"]!!.jsonPrimitive.long, "exp in seconds, as the token's")

        val token = answer["token"]!!.jsonPrimitive.content
        val verified = assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(token, secrets.secretsByKid(), scope, now / 1000))
        assertEquals("pixel-01", verified.claims.deviceId)
        assertEquals(answer["arc"]!!.jsonPrimitive.content, verified.claims.arc)
        assertEquals(0, verified.claims.policyVersion)
        assertEquals(secrets.active().kid, verified.claims.kid)

        val device = answer["device"]!!.jsonObject
        assertTrue(device["registered"]!!.jsonPrimitive.boolean)
        assertTrue(device["firstSeen"]!!.jsonPrimitive.boolean)
        assertFalse(device["keyAttestation"]!!.jsonObject["attested"]!!.jsonPrimitive.boolean)
        assertEquals("chain_missing", device["keyAttestation"]!!.jsonObject["reason"]!!.jsonPrimitive.content)

        // No current config named: the signed envelope is embedded, scoped like the config GET.
        assertTrue(answer["configChanged"]!!.jsonPrimitive.boolean)
        val config = answer["config"]!!.jsonObject
        val payload = Json.parseToJsonElement(config["payload"]!!.jsonPrimitive.content).jsonObject
        assertEquals(scope, payload["configApiId"]!!.jsonPrimitive.content)
        assertEquals(setOf("api.example.com", "cdn.example.com"), payload["pins"]!!.jsonArray.map { it.jsonObject["hostname"]!!.jsonPrimitive.content }.toSet())
        assertNotNull(config["signature"])
        val issuedAt = payload["issuedAt"]!!.jsonPrimitive.long
        val version = payload["version"]!!.jsonPrimitive.int

        // The device record and the audit trail.
        val stored = devices.get(scope, "pixel-01", withReport = true)!!
        assertEquals("pass", stored.lastResult)
        assertEquals(1, stored.attestCount)
        assertEquals("2.2.0", stored.lastSdkVersion)
        assertEquals("play-integrity", stored.verdictProvider)
        assertTrue(stored.lastReport!!.contains("\"signals\"") && !stored.lastReport!!.contains("eyJ.test"), "trimmed: no provider token")
        assertEquals(listOf("attestation_device_registered"), auditStore.page(10, 0).map { it.action })

        // Up to date: no config, not the first time any more.
        val again = attestJson(body(challenge(), "pixel-01", key, report(), currentConfigVersion = version, currentIssuedAt = issuedAt))
        assertEquals("pass", again["result"]!!.jsonPrimitive.content)
        assertFalse(again["configChanged"]!!.jsonPrimitive.boolean)
        assertNull(again["config"])
        assertFalse(again["device"]!!.jsonObject["firstSeen"]!!.jsonPrimitive.boolean)
        assertEquals(2, devices.get(scope, "pixel-01")!!.attestCount)

        // Behind by a version and scoped (`hosts`, as a wantPinsFor block sends): the
        // GET's rule — requested ∩ the device's ACL. No ACL: nothing, as on the GET.
        val unscoped = attestJson(body(challenge(), "pixel-01", key, report(), currentConfigVersion = version - 1, currentIssuedAt = issuedAt - 5, hosts = listOf("api.example.com")))
        assertTrue(unscoped["configChanged"]!!.jsonPrimitive.boolean)
        assertTrue(Json.parseToJsonElement(unscoped["config"]!!.jsonObject["payload"]!!.jsonPrimitive.content).jsonObject["pins"]!!.jsonArray.isEmpty())
        DeviceHostAclStore(db).grant(scope, "pixel-01", "api.example.com", Instant.ofEpochMilli(now).toString())
        val behind = attestJson(body(challenge(), "pixel-01", key, report(), currentConfigVersion = version - 1, currentIssuedAt = issuedAt - 5, hosts = listOf("api.example.com", "cdn.example.com")))
        assertTrue(behind["configChanged"]!!.jsonPrimitive.boolean)
        val scoped = Json.parseToJsonElement(behind["config"]!!.jsonObject["payload"]!!.jsonPrimitive.content).jsonObject
        assertEquals(listOf("api.example.com"), scoped["pins"]!!.jsonArray.map { it.jsonObject["hostname"]!!.jsonPrimitive.content })
        // Without `hosts` the device id alone does not switch scoping on (the legacy GET).
        val legacy = attestJson(body(challenge(), "pixel-01", key, report(), currentConfigVersion = version - 1))
        assertEquals(2, Json.parseToJsonElement(legacy["config"]!!.jsonObject["payload"]!!.jsonPrimitive.content).jsonObject["pins"]!!.jsonArray.size)

        // The stats counted it all.
        val stats = devices.windowStats(scope, 24, Instant.ofEpochMilli(now))
        assertEquals(5, stats.passes)
        assertEquals(0, stats.rejects)
        assertEquals(5, stats.byWarning["key_unattested"])
    }

    @Test
    fun `a raised reject flag rejects without a token or config, and the policy decides what is told`() = testApplication {
        val service = service()
        app(service)
        val key = ecKey()
        val rejected = attestJson(body(challenge(), "rooted-01", key, report("rooted", "adb_enabled", "unknown_installer")))
        assertEquals("reject", rejected["result"]!!.jsonPrimitive.content)
        assertNull(rejected["token"])
        assertNull(rejected["tokenExpiresAt"])
        assertNull(rejected["config"])
        assertFalse(rejected["configChanged"]!!.jsonPrimitive.boolean)
        assertNull(rejected["rejectionReasons"], "revealReasons is off")
        // adb_enabled is ignored by the strict policy; unknown_installer and the unattested key are warnings.
        assertEquals(setOf("unknown_installer", "key_unattested"), rejected.strings("warnings").toSet())
        val arc = rejected["arc"]!!.jsonPrimitive.content
        val stored = devices.get(scope, "rooted-01")!!
        assertEquals("reject", stored.lastResult)
        assertEquals(arc, stored.lastArc)
        assertEquals(listOf("rooted"), stored.lastReasons, "the dashboard resolves the ARC from here")
        assertEquals(1, auditStore.count("attestation_rejected"))

        // Reveal the reasons and warn on root: the same device passes with warnings.
        policies.put(scope, AttestationPolicy.strict(revealReasons = true), "test")
        val revealed = attestJson(body(challenge(), "rooted-01", key, report("rooted", "hooking_framework")))
        assertEquals("reject", revealed["result"]!!.jsonPrimitive.content)
        assertEquals(setOf("rooted", "hooking_framework"), revealed.strings("rejectionReasons").toSet())
        assertEquals(1, revealed["policyVersion"]!!.jsonPrimitive.int)
        assertTrue(revealed["arc"]!!.jsonPrimitive.content != arc, "another set of reasons, another ARC")

        policies.put(scope, AttestationPolicy.lenient(), "test")
        val lenient = attestJson(body(challenge(), "rooted-01", key, report("rooted")))
        assertEquals("pass", lenient["result"]!!.jsonPrimitive.content)
        assertTrue("rooted" in lenient.strings("warnings"))
        assertNotNull(lenient["token"])
        assertEquals(2, lenient["policyVersion"]!!.jsonPrimitive.int)
        assertEquals(2, assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(lenient["token"]!!.jsonPrimitive.content, secrets.secretsByKid(), scope, now / 1000)).claims.policyVersion)

        val stats = devices.windowStats(scope, 24, Instant.ofEpochMilli(now))
        assertEquals(2, stats.rejects)
        assertEquals(1, stats.passes)
        assertEquals(2, stats.byReason["rooted"])
        assertEquals(1, stats.byReason["hooking_framework"])
    }

    @Test
    fun `server-side signals - app integrity, software key, old patch level`() = testApplication {
        val service = service(verifier = pki.verifier(minPatchLevel = 202401))
        app(service)
        // Another package than ATTESTATION_PACKAGE_NAMES: app_integrity, whatever the client said.
        val foreign = attestJson(body(challenge(), "clone-01", ecKey(), report(packageName = "com.evil.clone")))
        assertEquals("reject", foreign["result"]!!.jsonPrimitive.content)
        assertEquals(listOf("app_integrity"), devices.get(scope, "clone-01")!!.lastReasons)
        // Another signer.
        val resigned = attestJson(body(challenge(), "resigned-01", ecKey(), report(signer = "00".repeat(32))))
        assertEquals(listOf("app_integrity"), devices.get(scope, "resigned-01")!!.lastReasons)
        assertEquals("reject", resigned["result"]!!.jsonPrimitive.content)
        // A software key and an old patch: warnings under strict.
        val soft = attestJson(body(challenge(), "soft-01", ecKey(), report(keySecurityLevel = "software", securityPatch = "2023-05-01")))
        assertEquals("pass", soft["result"]!!.jsonPrimitive.content)
        assertEquals(setOf("software_key", "key_unattested", "old_patch_level"), soft.strings("warnings").toSet())
    }

    @Test
    fun `nonces - invalid, expired, replayed`() = testApplication {
        app(service())
        val key = ecKey()
        refused(body("not-a-nonce", "dev-1", key, report()), HttpStatusCode.BadRequest, "nonce_invalid")
        // A nonce of another server (another key): a correct shape, a wrong MAC.
        refused(body(AttestationNonces(clock = { now }).issue(), "dev-1", key, report()), HttpStatusCode.BadRequest, "nonce_invalid")

        val stale = challenge()
        now += 121_000
        refused(body(stale, "dev-1", key, report()), HttpStatusCode.BadRequest, "nonce_expired")

        val nonce = challenge()
        val signed = body(nonce, "dev-1", key, report())
        assertEquals("pass", attestJson(signed)["result"]!!.jsonPrimitive.content)
        refused(signed, HttpStatusCode.BadRequest, "nonce_replayed")
        // A fresh signature over a used nonce is a replay too.
        refused(body(nonce, "dev-1", key, report("rooted")), HttpStatusCode.BadRequest, "nonce_replayed")
        assertNull(devices.get(scope, "dev-1")!!.lastReasons.firstOrNull(), "the replay changed nothing")
    }

    @Test
    fun `the signature must be the device key's over the canonical string`() = testApplication {
        app(service())
        val key = ecKey()
        val other = ecKey()
        // Signed by another key.
        refused(body(challenge(), "dev-1", key, report(), signer = other.private), HttpStatusCode.Unauthorized, "signature_invalid")
        // The report changed after signing.
        val nonce = challenge()
        val json = Json.parseToJsonElement(body(nonce, "dev-1", key, report())).jsonObject
        val tampered = JsonObject(json + ("report" to JsonPrimitive(report("rooted")))).toString()
        refused(tampered, HttpStatusCode.Unauthorized, "signature_invalid")
        // Not an EC P-256 key.
        val rsa = TestAttestationChains.rsa()
        refused(body(challenge(), "dev-1", key, report(), publicKey = Base64.getEncoder().encodeToString(rsa.public.encoded)), HttpStatusCode.Unauthorized, "signature_invalid")
        assertNull(devices.get(scope, "dev-1"), "nothing was registered")
    }

    @Test
    fun `shape refusals - version, device id, report size, body`() = testApplication {
        app(service())
        val key = ecKey()
        refused(body(challenge(), "dev-1", key, report(), v = 2), HttpStatusCode.BadRequest, "unsupported_version")
        refused(body(challenge(), "dev 1", key, report()), HttpStatusCode.BadRequest, "invalid_json")
        refused(body(challenge(), "x".repeat(65), key, report()), HttpStatusCode.BadRequest, "invalid_json")
        refused(body(challenge(), "dev-1", key, """{"sdkVersion":"2.2.0","pad":"${"p".repeat(17 * 1024)}"}"""), HttpStatusCode.BadRequest, "report_too_large")
        refused(body(challenge(), "dev-1", key, "not json"), HttpStatusCode.BadRequest, "invalid_json")
        val notJson = attest("[1,2]")
        assertEquals(HttpStatusCode.BadRequest, notJson.status)
        assertTrue(notJson.bodyAsText().contains("invalid_json"))
        val huge = attest("{\"v\":1,\"pad\":\"" + "x".repeat(70 * 1024) + "\"}")
        assertEquals(HttpStatusCode.PayloadTooLarge, huge.status)
    }

    @Test
    fun `a revoked device and a device with another key are refused`() = testApplication {
        app(service(revoked = setOf("revoked-1")))
        refused(body(challenge(), "revoked-1", ecKey(), report()), HttpStatusCode.Forbidden, "device_revoked")

        val first = ecKey()
        assertEquals("pass", attestJson(body(challenge(), "phone-1", first, report()))["result"]!!.jsonPrimitive.content)
        val reinstalled = ecKey()
        refused(body(challenge(), "phone-1", reinstalled, report()), HttpStatusCode.Forbidden, "key_mismatch")
        refused(body(challenge(), "phone-1", reinstalled, report()), HttpStatusCode.Forbidden, "key_mismatch")
        val stored = devices.get(scope, "phone-1")!!
        assertEquals(2, stored.keyMismatches)
        assertNotNull(stored.lastKeyMismatchAt)
        assertEquals(1, auditStore.count("attestation_key_mismatch"), "one entry a minute per device")
        assertEquals(1, stored.attestCount, "the mismatches were not verdicts")
        // The original key still works.
        assertEquals("pass", attestJson(body(challenge(), "phone-1", first, report()))["result"]!!.jsonPrimitive.content)

        // Forgotten by an operator: the new key registers.
        assertTrue(devices.forget(scope, "phone-1"))
        val fresh = attestJson(body(challenge(), "phone-1", reinstalled, report()))
        assertEquals("pass", fresh["result"]!!.jsonPrimitive.content)
        assertTrue(fresh["device"]!!.jsonObject["firstSeen"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `ATTESTATION_KEY_POLICY enforce - a chain is required for the first registration, then never looked at again`() = testApplication {
        app(service(keyPolicy = AttestationKeyPolicy.ENFORCE))
        val key = ecKey()
        refused(body(challenge(), "hw-1", key, report()), HttpStatusCode.Forbidden, "attestation_required")
        assertNull(devices.get(scope, "hw-1"))

        // A chain for another device id (the challenge binds the key to the id).
        val wrong = TestAttestationChains.chain(pki, key.public, TestAttestationChains.identityDescription("hw-2"))
        val invalid = refused(body(challenge(), "hw-1", key, report(), chain = wrong), HttpStatusCode.Forbidden, "attestation_invalid")
        assertEquals("challenge_mismatch", invalid["reason"]!!.jsonPrimitive.content)

        // A software-level chain.
        val software = TestAttestationChains.chain(pki, key.public, TestAttestationChains.identityDescription("hw-1").copy(attestationLevel = 0, keyMintLevel = 0))
        assertEquals("software_attestation", refused(body(challenge(), "hw-1", key, report(), chain = software), HttpStatusCode.Forbidden, "attestation_invalid")["reason"]!!.jsonPrimitive.content)

        val good = TestAttestationChains.chain(pki, key.public, TestAttestationChains.identityDescription("hw-1").copy(attestationLevel = 2, keyMintLevel = 2))
        val answer = attestJson(body(challenge(), "hw-1", key, report(), chain = good))
        assertEquals("pass", answer["result"]!!.jsonPrimitive.content)
        val ka = answer["device"]!!.jsonObject["keyAttestation"]!!.jsonObject
        assertTrue(ka["attested"]!!.jsonPrimitive.boolean)
        assertEquals("strongbox", ka["securityLevel"]!!.jsonPrimitive.content)
        assertEquals("ok", ka["reason"]!!.jsonPrimitive.content)
        assertTrue(answer.strings("warnings").isEmpty(), "an attested hardware key raises neither key_unattested nor software_key: ${answer["warnings"]}")
        val stored = devices.get(scope, "hw-1")!!
        assertEquals(true, stored.keyAttestation?.attested)
        assertEquals("strongbox", stored.keyAttestation?.securityLevel)

        // Registered: a later attestation without a chain (or with a bad one) is fine — a key cannot be re-attested.
        assertEquals("pass", attestJson(body(challenge(), "hw-1", key, report()))["result"]!!.jsonPrimitive.content)
        assertEquals("pass", attestJson(body(challenge(), "hw-1", key, report(), chain = wrong))["result"]!!.jsonPrimitive.content)
    }

    @Test
    fun `ATTESTATION_KEY_POLICY warn records the verdict, off checks nothing`() = testApplication {
        app(service(keyPolicy = AttestationKeyPolicy.WARN))
        val key = ecKey()
        val bad = TestAttestationChains.chain(pki, key.public, TestAttestationChains.identityDescription("warn-1").copy(deviceLocked = false))
        val answer = attestJson(body(challenge(), "warn-1", key, report(), chain = bad))
        assertEquals("pass", answer["result"]!!.jsonPrimitive.content)
        assertEquals("device_unlocked", answer["device"]!!.jsonObject["keyAttestation"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertTrue("key_unattested" in answer.strings("warnings"))
        val good = ecKey()
        val ok = attestJson(body(challenge(), "warn-2", good, report(), chain = TestAttestationChains.chain(pki, good.public, TestAttestationChains.identityDescription("warn-2"))))
        assertEquals("tee", ok["device"]!!.jsonObject["keyAttestation"]!!.jsonObject["securityLevel"]!!.jsonPrimitive.content)
        assertTrue(ok.strings("warnings").isEmpty(), ok["warnings"].toString())
    }

    @Test
    fun `off trusts on first use and does not read the chain`() = testApplication {
        app(service(keyPolicy = AttestationKeyPolicy.OFF, verifier = pki.verifier(packageNames = emptySet(), signerDigests = emptySet())))
        val key = ecKey()
        val answer = attestJson(body(challenge(), "off-1", key, report(packageName = "any.package"), chain = listOf("garbage")))
        assertEquals("pass", answer["result"]!!.jsonPrimitive.content)
        assertEquals("not_checked", answer["device"]!!.jsonObject["keyAttestation"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertEquals(setOf("key_unattested"), answer.strings("warnings").toSet(), "no app binding: app_integrity is not judged")
    }

    @Test
    fun `forceFail and forcePass override the policy`() = testApplication {
        app(service())
        val key = ecKey()
        devices.annotate(scope, "vip-1", forcePass = true, forceFail = false, annotations = listOf("staff", "canary"))
        val passed = attestJson(body(challenge(), "vip-1", key, report("rooted", "debugger")))
        assertEquals("pass", passed["result"]!!.jsonPrimitive.content)
        assertEquals(setOf("rooted", "debugger", "key_unattested"), passed.strings("warnings").toSet(), "every raised flag is demoted to a warning")
        val claims = assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(passed["token"]!!.jsonPrimitive.content, secrets.secretsByKid(), scope, now / 1000)).claims
        assertEquals(listOf("staff", "canary"), claims.annotations)
        assertTrue(passed["device"]!!.jsonObject["firstSeen"]!!.jsonPrimitive.boolean, "annotated before it ever attested: the key registers now")
        assertTrue(devices.get(scope, "vip-1")!!.registered)

        policies.put(scope, AttestationPolicy.strict(revealReasons = true), "test")
        devices.annotate(scope, "vip-1", forcePass = false, forceFail = true, annotations = emptyList())
        val failed = attestJson(body(challenge(), "vip-1", key, report()))
        assertEquals("reject", failed["result"]!!.jsonPrimitive.content)
        assertEquals(listOf("force_fail"), failed.strings("rejectionReasons"))
        assertNull(failed["token"])
    }

    @Test
    fun `rate limits per address and per device`() = testApplication {
        app(service(), limits = AttestationLimits.of(perAddress = 3, perDevice = 2))
        val key = ecKey()
        // The per-device quota first: the third attestation of one device is refused...
        val nonces = List(4) { challenge() }
        assertEquals("pass", attestJson(body(nonces[0], "busy-1", key, report()))["result"]!!.jsonPrimitive.content)
        assertEquals("pass", attestJson(body(nonces[1], "busy-1", key, report()))["result"]!!.jsonPrimitive.content)
        val device = attest(body(nonces[2], "busy-1", key, report()))
        assertEquals(HttpStatusCode.TooManyRequests, device.status)
        assertTrue(device.bodyAsText().contains("rate_limited"))
        // ...and that one used the address's third slot: a fourth request from the address is cut off too.
        assertEquals(HttpStatusCode.TooManyRequests, attest(body(nonces[3], "other-1", ecKey(), report())).status)
        assertNull(devices.get(scope, "other-1"))
        // The challenge has twice the address quota.
        repeat(2) { challenge() }
        assertEquals(HttpStatusCode.TooManyRequests, client.get("/api/v1/attest/challenge").status)
    }

    @Test
    fun `a signer failure leaves the config out but keeps the verdict`() = testApplication {
        val away = object : com.example.pinvault.server.service.signing.ConfigSigner {
            override val name = "command:kms"
            override val type = "command"
            override val description = "a signer that is away"
            override val publicKeyBase64 = Base64.getEncoder().encodeToString(ecKey().public.encoded)
            override fun sign(data: ByteArray): ByteArray = error("HSM away")
        }
        val broken = SignedConfigService(ConfigSigningService(listOf(away)), cacheEnabled = true)
        val service = service()
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing { attestationRoutes(scope, service, pins, broken, clock = { now }) }
        val answer = attestJson(body(challenge(), "dev-1", ecKey(), report()))
        assertEquals("pass", answer["result"]!!.jsonPrimitive.content)
        assertNotNull(answer["token"])
        assertFalse(answer["configChanged"]!!.jsonPrimitive.boolean)
        assertNull(answer["config"])
    }
}
