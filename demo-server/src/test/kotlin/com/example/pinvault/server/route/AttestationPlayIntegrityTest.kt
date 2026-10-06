package com.example.pinvault.server.route

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
import com.example.pinvault.server.service.attestation.AttestationNonces
import com.example.pinvault.server.service.attestation.AttestationPolicy
import com.example.pinvault.server.service.attestation.AttestationPolicyDefaults
import com.example.pinvault.server.service.attestation.AttestationService
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * ATTESTATION.md §11 end to end: a report that carries a Play Integrity
 * token has it verified against the round's nonce; the verdict is stored
 * with the device, `play_integrity` / `play_integrity_missing` follow the
 * policy, and a server without the keys judges nothing.
 */
class AttestationPlayIntegrityTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var pins: PinConfigStore
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private lateinit var envelopes: SignedConfigService
    private val pki = TestAttestationChains.Pki()
    private val google = PlayIntegrityTokens()
    private var now = Instant.parse("2026-10-06T10:00:00Z").toEpochMilli()
    private val scope = "default-tls"

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-attest-pi-").toFile()
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

    private fun service(verifier: PlayIntegrityVerifier?) = AttestationService(
        policies, devices, secrets, nonces = AttestationNonces(ttlSeconds = 120, clock = { now }),
        defaults = AttestationPolicyDefaults(), keyPolicy = AttestationKeyPolicy.WARN, verifier = { pki.verifier() },
        audit = AuditLog(AuditLogStore(db), null), rejections = null, clock = { Instant.ofEpochMilli(now) }, playIntegrity = verifier
    )

    private fun ApplicationTestBuilder.app(service: AttestationService) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing { attestationRoutes(scope, service, pins, envelopes, deviceHostAclStore = DeviceHostAclStore(db), limits = null, clock = { now }) }
    }

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(key: PrivateKey, text: String): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(text.toByteArray()); sign() }
    )

    private fun report(playIntegrityToken: String?): String = buildJsonObject {
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
        put("signals", buildJsonObject {
            for (flag in listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
                "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level")) {
                put(flag, buildJsonObject { put("flag", false); putJsonArray("evidence") {} })
            }
        })
        if (playIntegrityToken != null) put("verdictProvider", buildJsonObject { put("name", "play-integrity"); put("token", playIntegrityToken) })
    }.toString()

    private suspend fun ApplicationTestBuilder.challenge(): String {
        val response = client.get("/api/v1/attest/challenge")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return Json.parseToJsonElement(response.bodyAsText()).jsonObject["nonce"]!!.jsonPrimitive.content
    }

    /** One full round: challenge, a report with [token] for that nonce (built by [tokenFor]), the signed body. */
    private suspend fun ApplicationTestBuilder.attest(deviceId: String, key: KeyPair, tokenFor: ((nonce: String) -> String)?): HttpResponse {
        val nonce = challenge()
        val report = report(tokenFor?.invoke(nonce))
        val body = buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", deviceId)
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            put("report", report)
            put("signature", sign(key.private, AttestationService.canonical(nonce, deviceId, report)))
        }.toString()
        return client.post("/api/v1/attest") { contentType(ContentType.Application.Json); setBody(body) }
    }

    private suspend fun HttpResponse.json() = Json.parseToJsonElement(bodyAsText()).jsonObject
    private fun strings(a: Any?) = (a as? JsonArray)?.map { (it as JsonPrimitive).content }.orEmpty()
    /** The §11 flags of a warnings / reasons array (the test key sends no chain, so `key_unattested` is always among the warnings). */
    private fun piFlags(a: Any?) = strings(a).filter { it.startsWith("play_integrity") }

    private fun genuine(nonce: String) = google.token(google.payload(nonce, now, packageName = TestAttestationChains.PACKAGE))
    private fun basicOnly(nonce: String) = google.token(google.payload(nonce, now, packageName = TestAttestationChains.PACKAGE, deviceVerdicts = listOf("MEETS_BASIC_INTEGRITY")))

    @Test
    fun `without the Play Console keys nothing is judged and the token is only stored`() = testApplication {
        app(service(verifier = null))
        val answer = attest("dev-1", ecKey(), ::genuine)
        assertEquals(HttpStatusCode.OK, answer.status, answer.bodyAsText())
        val json = answer.json()
        assertEquals("pass", json["result"]!!.jsonPrimitive.content)
        assertEquals(emptyList(), piFlags(json["warnings"]))
        val device = devices.get(scope, "dev-1")!!
        assertEquals("play-integrity", device.verdictProvider)
        assertNull(device.playIntegrityResult)
        val bare = attest("dev-2", ecKey(), null)
        assertEquals(emptyList(), piFlags(bare.json()["warnings"]), "no play_integrity_missing without a verifier")
    }

    @Test
    fun `a genuine verdict passes, is stored, and covers the following rounds until it ages out`() = testApplication {
        app(service(google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE), verdictMaxAgeSeconds = 3600)))
        val key = ecKey()
        val first = attest("dev-1", key, ::genuine)
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())
        assertEquals(emptyList(), piFlags(first.json()["warnings"]))
        val device = devices.get(scope, "dev-1")!!
        assertEquals("pass", device.playIntegrityResult)
        assertEquals(Instant.ofEpochMilli(now).toString(), device.playIntegrityAt)
        val summary = Json.parseToJsonElement(device.playIntegrity!!).jsonObject
        assertEquals("ok", summary["reason"]!!.jsonPrimitive.content)
        assertEquals("PLAY_RECOGNIZED", summary["appVerdict"]!!.jsonPrimitive.content)

        // The provider skips Google for a few hours (quota): the stored verdict stands.
        now += 30 * 60_000L
        val second = attest("dev-1", key, null)
        assertEquals(emptyList(), piFlags(second.json()["warnings"]), "a fresh stored verdict is enough")

        // Past the max age the device must send a new token.
        now += 60 * 60_000L
        val third = attest("dev-1", key, null)
        assertEquals(listOf("play_integrity_missing"), piFlags(third.json()["warnings"]))
        assertEquals("pass", third.json()["result"]!!.jsonPrimitive.content, "strict default: warn")
        val fourth = attest("dev-1", key, ::genuine)
        assertEquals(emptyList(), piFlags(fourth.json()["warnings"]))
    }

    @Test
    fun `a device without any verdict raises play_integrity_missing, a failing verdict raises play_integrity`() = testApplication {
        app(service(google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE))))
        val key = ecKey()
        assertEquals(listOf("play_integrity_missing"), piFlags(attest("dev-1", key, null).json()["warnings"]))

        val failing = attest("dev-1", key, ::basicOnly)
        assertEquals(listOf("play_integrity"), piFlags(failing.json()["warnings"]))
        val device = devices.get(scope, "dev-1")!!
        assertEquals("fail", device.playIntegrityResult)
        assertEquals("device_integrity", Json.parseToJsonElement(device.playIntegrity!!).jsonObject["reason"]!!.jsonPrimitive.content)

        // A failed verdict sticks to the device until a fresh pass — not forgotten on the next bare round.
        now += 60_000L
        assertEquals(listOf("play_integrity"), piFlags(attest("dev-1", key, null).json()["warnings"]))
        assertEquals(emptyList(), piFlags(attest("dev-1", key, ::genuine).json()["warnings"]))

        // A token minted for another round's nonce (a replay) fails too.
        val stale = attest("dev-1", key) { _ -> genuine("some-other-nonce-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") }
        assertEquals(listOf("play_integrity"), piFlags(stale.json()["warnings"]))
        assertEquals("nonce_mismatch", Json.parseToJsonElement(devices.get(scope, "dev-1")!!.playIntegrity!!).jsonObject["reason"]!!.jsonPrimitive.content)
    }

    @Test
    fun `the policy decides - reject makes it a rejection reason, ignore drops it`() = testApplication {
        val service = service(google.verifier(packageNames = setOf(TestAttestationChains.PACKAGE)))
        app(service)
        policies.put(scope, AttestationPolicy.parse(buildJsonObject {
            put("flags", buildJsonObject { put("play_integrity", "reject"); put("play_integrity_missing", "reject") })
            put("revealReasons", true)
        }, service.defaultPolicy).getOrThrow(), "test")
        val key = ecKey()
        val missing = attest("dev-1", key, null).json()
        assertEquals("reject", missing["result"]!!.jsonPrimitive.content)
        assertEquals(listOf("play_integrity_missing"), piFlags(missing["rejectionReasons"]))
        assertNull(missing["token"])
        val failing = attest("dev-1", key, ::basicOnly).json()
        assertEquals(listOf("play_integrity"), piFlags(failing["rejectionReasons"]))
        val passing = attest("dev-1", key, ::genuine).json()
        assertEquals("pass", passing["result"]!!.jsonPrimitive.content)
        assertNotNull(passing["token"])

        policies.put(scope, AttestationPolicy.parse(buildJsonObject {
            put("flags", buildJsonObject { put("play_integrity", "ignore"); put("play_integrity_missing", "ignore") })
        }, service.policyFor(scope)).getOrThrow(), "test")
        val ignored = attest("dev-2", ecKey(), ::basicOnly).json()
        assertEquals("pass", ignored["result"]!!.jsonPrimitive.content)
        assertTrue(piFlags(ignored["warnings"]).isEmpty())
        assertEquals("fail", devices.get(scope, "dev-2")!!.playIntegrityResult, "still recorded for the dashboard")
    }
}
