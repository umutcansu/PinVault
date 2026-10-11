package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.ApprovedReplayKey
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.attestation.AttestationPolicy
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
import com.example.pinvault.server.service.attestation.AttestationNonces
import com.example.pinvault.server.service.attestation.AttestationPolicyDefaults
import com.example.pinvault.server.service.attestation.AttestationService
import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.AttestationTokenSecretStore
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.KeyAttestation
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.time.Instant
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The admin API of ATTESTATION.md §6. */
class AttestationAdminRoutesTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var policies: AttestationPolicyStore
    private lateinit var devices: AttestedDeviceStore
    private lateinit var secrets: AttestationTokenSecretStore
    private lateinit var auditStore: AuditLogStore
    private val scope = "default-tls"
    private val base = "/api/v1/config-apis/default-tls/attestation"

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-attest-admin-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        policies = AttestationPolicyStore(db)
        devices = AttestedDeviceStore(db)
        secrets = AttestationTokenSecretStore(db)
        auditStore = AuditLogStore(db)
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun ApplicationTestBuilder.app(defaults: AttestationPolicyDefaults = AttestationPolicyDefaults()) {
        val service = AttestationService(policies, devices, secrets, AttestationNonces(), defaults,
            AttestationKeyPolicy.WARN, verifier = { error("not used") }, audit = AuditLog(auditStore, null))
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        // What ApiKeyAuth does for the replay of an approved change request (its one-time token).
        install(io.ktor.server.application.createApplicationPlugin("TestApprovedReplay") {
            onCall { call -> if (call.request.headers["X-Test-Approved-Replay"] != null) call.attributes.put(ApprovedReplayKey, 7L) }
        })
        routing { attestationAdminRoutes(service, policies, devices, secrets, AuditLog(auditStore, null)) }
    }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    private fun actions() = auditStore.page(100, 0).map { it.action }

    @Test
    fun `policy - defaults until a PUT, which bumps the version only when something changed`() = testApplication {
        app()
        val defaults = client.get("$base/policy").json()
        assertEquals(0, defaults["version"]!!.jsonPrimitive.int)
        assertEquals("reject", defaults["flags"]!!.jsonObject["rooted"]!!.jsonPrimitive.content)
        assertEquals("ignore", defaults["flags"]!!.jsonObject["adb_enabled"]!!.jsonPrimitive.content)
        assertFalse(defaults["revealReasons"]!!.jsonPrimitive.boolean)

        val put = client.put("$base/policy") { contentType(ContentType.Application.Json); setBody("""{"flags":{"rooted":"warn"},"revealReasons":true}""") }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())
        val v1 = put.json()
        assertEquals(1, v1["version"]!!.jsonPrimitive.int)
        assertEquals("warn", v1["flags"]!!.jsonObject["rooted"]!!.jsonPrimitive.content)
        assertEquals("reject", v1["flags"]!!.jsonObject["emulator"]!!.jsonPrimitive.content)
        assertTrue(v1["revealReasons"]!!.jsonPrimitive.boolean)
        assertEquals(v1, client.get("$base/policy").json())

        // The same policy again: no new version, no audit entry.
        val same = client.put("$base/policy") { contentType(ContentType.Application.Json); setBody(v1.toString()) }.json()
        assertEquals(1, same["version"]!!.jsonPrimitive.int)
        assertEquals(1, auditStore.count("attestation_policy_updated"))

        val v2 = client.put("$base/policy") { contentType(ContentType.Application.Json); setBody("""{"tokenTtlSeconds":120,"attestIntervalSeconds":600}""") }.json()
        assertEquals(2, v2["version"]!!.jsonPrimitive.int)
        assertEquals(120, v2["tokenTtlSeconds"]!!.jsonPrimitive.int)
        assertEquals("warn", v2["flags"]!!.jsonObject["rooted"]!!.jsonPrimitive.content, "flags not named keep their action")
        assertEquals(2, auditStore.count("attestation_policy_updated"))
        val entry = auditStore.page(1, 0, "attestation_policy_updated").single()
        assertEquals(scope, entry.configApiId)
        assertTrue(entry.summary.contains("v2") && entry.summary.contains("tokenTtl=120s"), entry.summary)

        for (bad in listOf("""{"flags":{"rooted":"nope"}}""", """{"flags":{"unknown":"reject"}}""", """{"tokenTtlSeconds":1}""", "nope")) {
            val response = client.put("$base/policy") { contentType(ContentType.Application.Json); setBody(bad) }
            assertEquals(HttpStatusCode.BadRequest, response.status, bad)
            assertTrue(response.bodyAsText().contains("invalid_policy"), response.bodyAsText())
        }
        // Another scope has its own.
        assertEquals(0, client.get("/api/v1/config-apis/other/attestation/policy").json()["version"]!!.jsonPrimitive.int)
    }

    @Test
    fun `production - the floor is held in code and lowered only by an approved replay`() = testApplication {
        // A policy stored before (v138 of the review): root, emulator and debuggable ignored.
        policies.put(scope, AttestationPolicy.strict().let { it.copy(flags = it.flags + mapOf("rooted" to "ignore", "emulator" to "ignore", "debuggable" to "ignore")) }, "old-admin")
        app(AttestationPolicyDefaults(profile = "production"))
        suspend fun put(body: String, replay: Boolean = false) = client.put("$base/policy") {
            contentType(ContentType.Application.Json); setBody(body)
            if (replay) headers.append("X-Test-Approved-Replay", "1")
        }
        fun JsonObject.flag(name: String) = this["flags"]!!.jsonObject[name]!!.jsonPrimitive.content

        val read = client.get("$base/policy").json()
        for (flag in AttestationPolicy.PRODUCTION_FLOOR) assertEquals("reject", read.flag(flag), "$flag is read as reject whatever was stored")
        assertEquals(0, read["approvedRelaxations"]!!.jsonArray.size)

        // Lowering a floor flag without an approved replay: refused, nothing stored, audited.
        val refused = put("""{"flags":{"rooted":"warn"}}""")
        assertEquals(HttpStatusCode.Forbidden, refused.status, refused.bodyAsText())
        val refusal = refused.json()
        assertEquals("two_person_approval_required", refusal["error"]!!.jsonPrimitive.content)
        assertEquals(listOf("rooted"), refusal["flags"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(1, auditStore.count("attestation_policy_floor_refused"))
        assertEquals("reject", client.get("$base/policy").json().flag("rooted"))

        // Anything else is a plain PUT.
        assertEquals(HttpStatusCode.OK, put("""{"tokenTtlSeconds":120,"flags":{"adb_enabled":"warn"}}""").status)

        // The replay of an approved change lowers it, and says so.
        val approved = put("""{"flags":{"rooted":"warn"}}""", replay = true)
        assertEquals(HttpStatusCode.OK, approved.status, approved.bodyAsText())
        val approvedJson = approved.json()
        assertEquals("warn", approvedJson.flag("rooted"))
        assertEquals(listOf("rooted"), approvedJson["approvedRelaxations"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("warn", client.get("$base/policy").json().flag("rooted"))
        // A later edit keeps an approved relaxation without asking again…
        val later = put("""{"tokenTtlSeconds":60}""")
        assertEquals(HttpStatusCode.OK, later.status)
        assertEquals("warn", later.json().flag("rooted"))
        // …but not a new one.
        assertEquals(HttpStatusCode.Forbidden, put("""{"flags":{"emulator":"ignore"}}""").status)

        // Back to reject: the approval is spent; lowering it again needs a new one.
        val restored = put("""{"flags":{"rooted":"reject"}}""")
        assertEquals(0, restored.json()["approvedRelaxations"]!!.jsonArray.size)
        assertEquals(HttpStatusCode.Forbidden, put("""{"flags":{"rooted":"warn"}}""").status)
    }

    @Test
    fun `strict and lenient have no floor`() = testApplication {
        app()
        val response = client.put("$base/policy") { contentType(ContentType.Application.Json); setBody("""{"flags":{"rooted":"ignore"}}""") }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `devices - list, one, annotate, forget`() = testApplication {
        app()
        val now = Instant.now()
        devices.register(scope, "pixel-01", "ab".repeat(32), Base64.getEncoder().encodeToString(ByteArray(8)), KeyAttestation(true, "tee", "ok"), now)
        devices.recordVerdict(scope, "pixel-01", "pass", "11111111", emptyList(), listOf("unknown_installer"), 1, """{"signals":{"rooted":{"flag":false}}}""", "2.2.0", "play-integrity", "tok", now)
        devices.register(scope, "rooted-01", "cd".repeat(32), Base64.getEncoder().encodeToString(ByteArray(8)), KeyAttestation(false, null, "chain_missing"), now)
        devices.recordVerdict(scope, "rooted-01", "reject", "22222222", listOf("rooted"), listOf("key_unattested"), 1, "{}", "2.2.0", null, null, now)
        devices.register("other", "pixel-01", "ef".repeat(32), "x", null, now)

        val all = client.get("$base/devices").json()
        assertEquals(2, all["total"]!!.jsonPrimitive.int)
        assertEquals(1, all["page"]!!.jsonPrimitive.int)
        val ids = all["items"]!!.jsonArray.map { it.jsonObject["deviceId"]!!.jsonPrimitive.content }.toSet()
        assertEquals(setOf("pixel-01", "rooted-01"), ids)
        val rooted = all["items"]!!.jsonArray.map { it.jsonObject }.first { it["deviceId"]!!.jsonPrimitive.content == "rooted-01" }
        assertEquals("reject", rooted["lastResult"]!!.jsonPrimitive.content)
        assertEquals("22222222", rooted["lastArc"]!!.jsonPrimitive.content)
        assertEquals(listOf("rooted"), rooted["lastReasons"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("chain_missing", rooted["keyAttestation"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertTrue(rooted["lastReport"] == null || rooted["lastReport"] is JsonNull, "the list carries no report")

        assertEquals(listOf("rooted-01"), client.get("$base/devices?result=reject").json()["items"]!!.jsonArray.map { it.jsonObject["deviceId"]!!.jsonPrimitive.content })
        assertEquals(listOf("pixel-01"), client.get("$base/devices?q=pix").json()["items"]!!.jsonArray.map { it.jsonObject["deviceId"]!!.jsonPrimitive.content })
        assertEquals(1, client.get("$base/devices?q=22222222").json()["total"]!!.jsonPrimitive.int, "an ARC resolves to its device")
        assertEquals(1, client.get("$base/devices?page=2&pageSize=1").json()["items"]!!.jsonArray.size)

        val one = client.get("$base/devices/pixel-01").json()
        assertEquals("pixel-01", one["deviceId"]!!.jsonPrimitive.content)
        assertEquals(false, one["lastReport"]!!.jsonObject["signals"]!!.jsonObject["rooted"]!!.jsonObject["flag"]!!.jsonPrimitive.boolean)
        assertEquals("tee", one["keyAttestation"]!!.jsonObject["securityLevel"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.NotFound, client.get("$base/devices/nobody").status)

        // Annotate: overrides and the strings the token will carry.
        val annotated = client.put("$base/devices/pixel-01") { contentType(ContentType.Application.Json); setBody("""{"forcePass":true,"annotations":["staff","canary"]}""") }
        assertEquals(HttpStatusCode.OK, annotated.status, annotated.bodyAsText())
        assertTrue(annotated.json()["forcePass"]!!.jsonPrimitive.boolean)
        assertEquals(listOf("staff", "canary"), devices.get(scope, "pixel-01")!!.annotations)
        // An unknown device can be annotated ahead of its first attestation (unregistered row).
        val early = client.put("$base/devices/new-01") { contentType(ContentType.Application.Json); setBody("""{"forceFail":true}""") }.json()
        assertFalse(early["registered"]!!.jsonPrimitive.boolean)
        assertTrue(early["forceFail"]!!.jsonPrimitive.boolean)
        for ((body, error) in listOf(
            """{"forcePass":true,"forceFail":true}""" to "conflicting_overrides",
            """{"annotations":["bad\"quote"]}""" to "invalid_annotation",
            """{"annotations":"staff"}""" to "invalid_annotation"
        )) {
            val response = client.put("$base/devices/pixel-01") { contentType(ContentType.Application.Json); setBody(body) }
            assertEquals(HttpStatusCode.BadRequest, response.status, body)
            assertTrue(response.bodyAsText().contains(error), response.bodyAsText())
        }
        assertEquals(HttpStatusCode.BadRequest, client.put("$base/devices/bad%20id") { contentType(ContentType.Application.Json); setBody("{}") }.status)

        // Forget.
        val forgotten = client.delete("$base/devices/rooted-01")
        assertEquals(HttpStatusCode.OK, forgotten.status, forgotten.bodyAsText())
        assertTrue(forgotten.json()["forgotten"]!!.jsonPrimitive.boolean)
        assertEquals(HttpStatusCode.NotFound, client.delete("$base/devices/rooted-01").status)
        assertEquals(2, client.get("$base/devices").json()["total"]!!.jsonPrimitive.int, "pixel-01 and the annotated new-01")

        val stats = client.get("$base/stats").json()
        assertEquals(1, stats["last24h"]!!.jsonObject["passes"]!!.jsonPrimitive.int)
        assertEquals(1, stats["last24h"]!!.jsonObject["rejects"]!!.jsonPrimitive.int)
        assertEquals(1, stats["last7d"]!!.jsonObject["byReason"]!!.jsonObject["rooted"]!!.jsonPrimitive.int)
        assertEquals(1, stats["last7d"]!!.jsonObject["byWarning"]!!.jsonObject["unknown_installer"]!!.jsonPrimitive.int)
        assertEquals(2, stats["devices"]!!.jsonObject["total"]!!.jsonPrimitive.int)
        assertEquals(1, stats["devices"]!!.jsonObject["registered"]!!.jsonPrimitive.int)
        assertEquals(1, stats["devices"]!!.jsonObject["forcePass"]!!.jsonPrimitive.int)

        val recorded = actions()
        assertEquals(2, recorded.count { it == "attestation_device_annotated" })
        assertEquals(1, recorded.count { it == "attestation_device_forgotten" })
    }

    @Test
    fun `token secrets - made on first read, rotated, previous ones deleted, never the active one`() = testApplication {
        app()
        val first = client.get("/api/v1/attestation/token-secrets")
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())
        assertEquals("no-store", first.headers["Cache-Control"])
        val listing = first.json()
        val active = listing["active"]!!.jsonPrimitive.content
        assertTrue(Regex("^\\d{4}-\\d{2}-\\d{2}-\\d{2}$").matches(active), active)
        val entries = listing["secrets"]!!.jsonArray.map { it.jsonObject }
        assertEquals(1, entries.size)
        // ES256 by default: the public half only, never the private key.
        assertEquals("ES256", listing["alg"]!!.jsonPrimitive.content)
        assertEquals("ES256", entries[0]["alg"]!!.jsonPrimitive.content)
        assertTrue("secret" !in entries[0], entries[0].toString())
        val publicKey = entries[0]["publicKey"]!!.jsonPrimitive.content
        java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)))
        assertEquals(active, entries[0]["jwk"]!!.jsonObject["kid"]!!.jsonPrimitive.content)
        assertTrue(entries[0]["active"]!!.jsonPrimitive.boolean)
        val privateKey = Base64.getEncoder().encodeToString(secrets.active().secret)
        assertFalse(first.bodyAsText().contains(privateKey), "the private key never leaves the server")

        val rotated = client.post("/api/v1/attestation/token-secrets/rotate")
        assertEquals(HttpStatusCode.OK, rotated.status, rotated.bodyAsText())
        val fresh = rotated.json()["kid"]!!.jsonPrimitive.content
        assertNotEquals(active, fresh)
        assertTrue(rotated.bodyAsText().contains("\"active\":true") && !rotated.bodyAsText().contains("\"secret\""), "rotate names the kid only: ${rotated.bodyAsText()}")

        val after = client.get("/api/v1/attestation/token-secrets").json()
        assertEquals(fresh, after["active"]!!.jsonPrimitive.content)
        assertEquals(setOf(active, fresh), after["secrets"]!!.jsonArray.map { it.jsonObject["kid"]!!.jsonPrimitive.content }.toSet())
        assertEquals(setOf(active, fresh), secrets.verificationKeys().keys, "both verify tokens")
        // The JWK Set lists both public keys, without an API key (ApiKeyAuth allowlists it).
        val jwks = client.get("/api/v1/attestation/jwks")
        assertEquals(HttpStatusCode.OK, jwks.status)
        assertEquals(setOf(active, fresh), jwks.json()["keys"]!!.jsonArray.map { it.jsonObject["kid"]!!.jsonPrimitive.content }.toSet())
        assertTrue(com.example.pinvault.server.plugin.isPublicEndpoint("/api/v1/attestation/jwks", io.ktor.http.HttpMethod.Get))

        val refused = client.delete("/api/v1/attestation/token-secrets/$fresh")
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertTrue(refused.bodyAsText().contains("secret_active"))
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/attestation/token-secrets/$active").status)
        assertEquals(HttpStatusCode.NotFound, client.delete("/api/v1/attestation/token-secrets/$active").status)
        assertEquals(setOf(fresh), secrets.verificationKeys().keys)

        val recorded = actions()
        assertTrue("attestation_token_secret_rotated" in recorded && "attestation_token_secret_deleted" in recorded, recorded.toString())
        // No private key in the audit log.
        assertFalse(auditStore.page(100, 0).any { privateKey in it.summary || privateKey in it.detail })
    }

    @Test
    fun `token secrets - with PINVAULT_TOKEN_ALG=HS256 the shared secret is listed, and a switch rotates once`() = testApplication {
        secrets = AttestationTokenSecretStore(db, alg = com.example.pinvault.server.service.attestation.PinVaultToken.ALG_HS256)
        app()
        val listing = client.get("/api/v1/attestation/token-secrets").json()
        val entry = listing["secrets"]!!.jsonArray.single().jsonObject
        assertEquals("HS256", entry["alg"]!!.jsonPrimitive.content)
        assertEquals(32, Base64.getDecoder().decode(entry["secret"]!!.jsonPrimitive.content).size)
        assertTrue("publicKey" !in entry)
        assertEquals(0, client.get("/api/v1/attestation/jwks").json()["keys"]!!.jsonArray.size, "no public key for HS256")
        val hsKid = entry["kid"]!!.jsonPrimitive.content

        // The same database under ES256: the next token is signed by a new ES256 key; the HS256 one keeps verifying.
        val es = AttestationTokenSecretStore(db)
        val active = es.active()
        assertEquals("ES256", active.alg)
        assertTrue(active.kid != hsKid)
        assertEquals(setOf(hsKid, active.kid), es.verificationKeys().keys)
    }
}
