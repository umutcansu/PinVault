package com.example.pinvault.server.route

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
import com.example.pinvault.server.service.attestation.AttestationNonces
import com.example.pinvault.server.service.attestation.AttestationPolicyDefaults
import com.example.pinvault.server.service.attestation.AttestationService
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
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Abuse limits of the attestation endpoint: the accepted-nonce cache fails
 * closed when full (never evicts a nonce that could still be presented) and
 * a Config API holds at most `ATTESTATION_DEVICE_LIMIT` registered devices.
 */
class AttestationLimitsTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var pins: PinConfigStore
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var envelopes: SignedConfigService
    private val pki = TestAttestationChains.Pki()
    private var now = System.currentTimeMillis()
    private val scope = "default-tls"

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-attest-limits-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        pins = PinConfigStore(db)
        policies = AttestationPolicyStore(db)
        devices = AttestedDeviceStore(db)
        secrets = AttestationTokenSecretStore(db)
        auditStore = AuditLogStore(db)
        envelopes = SignedConfigService(ConfigSigningService(File(dir, "k.pem")))
        pins.ensureConfigExists(scope)
        pins.save(scope, PinConfig(pins = listOf(HostPin("api.example.com", listOf("a".repeat(43) + "=", "b".repeat(43) + "="), version = 1))))
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun service(nonces: AttestationNonces = AttestationNonces(ttlSeconds = 120, clock = { now }), deviceLimit: Int = 100_000) = AttestationService(
        policies, devices, secrets, nonces = nonces,
        defaults = AttestationPolicyDefaults(), keyPolicy = AttestationKeyPolicy.WARN, verifier = { pki.verifier() },
        audit = AuditLog(auditStore, null), rejections = null, clock = { Instant.ofEpochMilli(now) }, deviceLimit = deviceLimit
    )

    private fun ApplicationTestBuilder.app(service: AttestationService) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing { attestationRoutes(scope, service, pins, envelopes, deviceHostAclStore = DeviceHostAclStore(db), limits = null, clock = { now }) }
    }

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(key: PrivateKey, text: String): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(text.toByteArray()); sign() }
    )

    private fun report(): String = buildJsonObject {
        put("sdkVersion", "2.2.0"); put("reportTime", now)
        put("app", buildJsonObject {
            put("packageName", TestAttestationChains.PACKAGE); put("versionCode", 1); put("versionName", "1")
            putJsonArray("signerSha256") { add(JsonPrimitive(TestAttestationChains.SIGNER_HEX.chunked(2).joinToString(":"))) }
            put("installer", "com.android.vending"); put("debuggable", false)
        })
        put("device", buildJsonObject {
            put("manufacturer", "Google"); put("model", "Pixel 8"); put("sdkInt", 35); put("securityPatch", "2026-09-05")
            put("verifiedBootState", "green"); put("keySecurityLevel", "strongbox"); put("keyAttested", false)
        })
        put("signals", buildJsonObject {
            for (flag in listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
                "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level")) {
                put(flag, buildJsonObject { put("flag", false); putJsonArray("evidence") {} })
            }
        })
    }.toString()

    private suspend fun ApplicationTestBuilder.challenge(): String {
        val response = client.get("/api/v1/attest/challenge")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return Json.parseToJsonElement(response.bodyAsText()).jsonObject["nonce"]!!.jsonPrimitive.content
    }

    private fun body(nonce: String, deviceId: String, key: KeyPair): String {
        val report = report()
        return buildJsonObject {
            put("v", 1); put("nonce", nonce); put("deviceId", deviceId)
            put("publicKey", Base64.getEncoder().encodeToString(key.public.encoded))
            put("report", report)
            put("signature", sign(key.private, AttestationService.canonical(nonce, deviceId, report)))
        }.toString()
    }

    private suspend fun ApplicationTestBuilder.attest(body: String): HttpResponse = client.post("/api/v1/attest") {
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun HttpResponse.error(): String = Json.parseToJsonElement(bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content

    // ── Nonce cache ─────────────────────────────────────────────────────

    @Test
    fun `a full nonce cache refuses instead of forgetting a presentable nonce`() {
        val nonces = AttestationNonces(ttlSeconds = 120, clock = { now }, maxCached = 2)
        val (n1, n2, n3) = Triple(nonces.issue(), nonces.issue(), nonces.issue())
        assertIs<AttestationNonces.Check.Ok>(nonces.consume(n1))
        assertIs<AttestationNonces.Check.Ok>(nonces.consume(n2))
        assertIs<AttestationNonces.Check.Overloaded>(nonces.consume(n3), "the third fresh nonce is refused, not an older one evicted")
        assertIs<AttestationNonces.Check.Replayed>(nonces.consume(n1), "the first one is still remembered")
        assertIs<AttestationNonces.Check.Replayed>(nonces.consume(n2))
        assertEquals(2, nonces.cached)

        now += 121_000
        assertIs<AttestationNonces.Check.Expired>(nonces.consume(n3), "too old by now")
        val n4 = nonces.issue()
        assertIs<AttestationNonces.Check.Ok>(nonces.consume(n4), "the expired entries made room")
        assertEquals(1, nonces.cached)
    }

    @Test
    fun `the route answers 503 attestation_busy when the nonce cache is full`() = testApplication {
        val service = service(nonces = AttestationNonces(ttlSeconds = 120, clock = { now }, maxCached = 1))
        app(service)
        val first = attest(body(challenge(), "dev-1", ecKey()))
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())
        val second = attest(body(challenge(), "dev-2", ecKey()))
        assertEquals(HttpStatusCode.ServiceUnavailable, second.status, second.bodyAsText())
        assertEquals("attestation_busy", second.error())
        assertEquals(1, devices.counts(scope).registered, "the refused device was not registered")
    }

    // ── Device limit ────────────────────────────────────────────────────

    @Test
    fun `a Config API holds at most ATTESTATION_DEVICE_LIMIT registered devices`() = testApplication {
        app(service(deviceLimit = 1))
        val known = ecKey()
        val first = attest(body(challenge(), "dev-1", known))
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())

        val second = attest(body(challenge(), "dev-2", ecKey()))
        assertEquals(HttpStatusCode.ServiceUnavailable, second.status, second.bodyAsText())
        assertEquals("device_limit_reached", second.error())
        assertEquals(1, devices.counts(scope).registered)

        val again = attest(body(challenge(), "dev-1", known))
        assertEquals(HttpStatusCode.OK, again.status, "a known device keeps attesting")

        assertTrue(devices.forget(scope, "dev-1"))
        val afterForget = attest(body(challenge(), "dev-2", ecKey()))
        assertEquals(HttpStatusCode.OK, afterForget.status, "room again once a device is forgotten")
    }

    @Test
    fun `zero means unlimited`() = testApplication {
        app(service(deviceLimit = 0))
        for (i in 1..3) {
            val response = attest(body(challenge(), "dev-$i", ecKey()))
            assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        }
        assertEquals(3, devices.counts(scope).registered)
    }
}
