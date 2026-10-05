package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.GovernanceHarness.Companion.BOB
import com.example.pinvault.server.GovernanceHarness.Companion.SHARED
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertAdminRoutes
import com.example.pinvault.server.route.clientCertRevocationRoutes
import com.example.pinvault.server.route.configApiAdminRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertChangePlanner
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ChangeDescriber
import com.example.pinvault.server.service.ConfigApiManager
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.EgressFilter
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.PinConfigRules
import com.example.pinvault.server.service.PlanRefused
import com.example.pinvault.server.service.VaultAtRestCipher
import com.example.pinvault.server.store.*
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
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
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.time.Duration
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The admin-surface findings of the 2026-10-05 review: pin rules as strict
 * as the library's (A4), the client CA's alias reserved (A2/A3), the
 * two-person rule for letting a device in (A5), probes through the egress
 * filter (A6), Config API start/stop validated and described (A9), one key
 * per host P12 (A10), and change-request bodies encrypted at rest.
 */
class AdminSurfaceHardeningTest {

    private val dir: File = Files.createTempDirectory("admin-surface").toFile()
    private val db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
    private val pins = PinConfigStore(db)
    private val hosts = HostStore(db)
    private val audit = AuditLog(AuditLogStore(db), null)
    private val certService = CertificateService(File(dir, "certs").also { it.mkdirs() }, egress = EgressFilter(allowPrivate = true))
    private val clientCerts = ClientCertStore(db)
    private val identities = ClientIdentityStore(db)
    private val scope = "default-tls"

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun pin(seed: Int): String = Base64.getEncoder().encodeToString(ByteArray(32) { (seed * 31 + it).toByte() })

    // ── A4: pin rules ─────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.pinApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(scope, pins, PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(dir, "k.pem")), ClientDeviceStore(db))
        }
    }

    private suspend fun ApplicationTestBuilder.putPins(config: PinConfig) = client.put("/api/v1/certificate-config") {
        contentType(ContentType.Application.Json)
        setBody(Json.encodeToString(PinConfig.serializer(), config))
    }

    @Test
    fun `the pin editor applies the library's rules`() = testApplication {
        pinApp()
        // Names differing only in case are one host to the library.
        val twice = putPins(PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), pin(2))), HostPin("API.example.com", listOf(pin(3), pin(4))))))
        assertEquals(HttpStatusCode.Conflict, twice.status)
        // At most 32 pins a host.
        val many = putPins(PinConfig(pins = listOf(HostPin("api.example.com", (1..33).map(::pin)))))
        assertEquals(HttpStatusCode.BadRequest, many.status)
        assertContains(many.bodyAsText(), "en fazla 32")
        // Each pin the Base64 of a SHA-256 (43 characters and '=').
        val malformed = putPins(PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), "A".repeat(44))))))
        assertEquals(HttpStatusCode.BadRequest, malformed.status)
        // At most 2000 hosts.
        val huge = putPins(PinConfig(pins = (1..2001).map { HostPin("h$it.example.com", listOf(pin(1), pin(2))) }))
        assertEquals(HttpStatusCode.BadRequest, huge.status)
        assertContains(huge.bodyAsText(), "at most 2000")
        assertTrue(pins.load(scope).pins.isEmpty(), "nothing was stored")
        // A config with no host at all stays accepted: removing the last host is the operator's call.
        assertEquals(HttpStatusCode.OK, putPins(PinConfig(pins = emptyList())).status)
        assertEquals(HttpStatusCode.OK, putPins(PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), pin(2)))))).status)
    }

    @Test
    fun `a host that is added is compared with the pinned ones ignoring case`() {
        pins.save(scope, PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), pin(2))))))
        val planner = CertChangePlanner(certService, pins, hosts)
        val refused = assertFailsWith<PlanRefused> { planner.checkNew(scope, "API.Example.com") }
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertTrue(PinConfigRules.hostErrors("x.example.com", listOf(pin(1), pin(1))).isNotEmpty(), "one pin twice is not a backup")
        assertTrue(PinConfigRules.hostErrors("x.example.com", emptyList()).isNotEmpty())
    }

    @Test
    fun `an approval is never asked for a pin config devices would refuse`() {
        GovernanceHarness(File(dir, "gov").also { it.mkdirs() }).use { h ->
            val body = Json.encodeToString(PinConfig.serializer(), PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), "not-a-pin")))))
            val answer = h.call("PUT", "/api/v1/certificate-config", ALICE, body)
            assertEquals(400, answer.status, answer.body)
            assertTrue(h.changeRequests.list(null).isEmpty())
        }
    }

    // ── A2/A3: the client CA is nobody's client id ────────────────────────

    private fun ApplicationTestBuilder.clientCertApp() {
        install(ContentNegotiation) { json() }
        routing {
            clientCertAdminRoutes(certService, clientCerts, identities, EnrollmentTokenStore(db), audit, { })
            clientCertRevocationRoutes(clientCerts, identities, certService, audit) { _, _ -> }
        }
    }

    private suspend fun ApplicationTestBuilder.upload(id: String, bytes: ByteArray = "x".toByteArray()) =
        GovernanceHarness.multipart(mapOf("clientId" to id), bytes, "cert.pem").let { (type, body) ->
            client.post("/api/v1/client-certs/upload") { header("Content-Type", type); setBody(body) }
        }

    @Test
    fun `revoke, forget, upload and tokens never touch the client CA's entry`() = testApplication {
        clientCertApp()
        val ca = certService.ensureClientCa()
        fun anchor() = certService.getTrustStore()!!.getCertificate(CertificateService.CLIENT_CA_ALIAS)

        for (id in listOf("client-ca", "Client-CA", "server-ca")) {
            assertEquals(HttpStatusCode.BadRequest, client.delete("/api/v1/client-certs/$id").status, id)
            assertEquals(HttpStatusCode.BadRequest, client.post("/api/v1/client-certs/$id/forget").status, id)
            val uploaded = upload(id)
            assertEquals(HttpStatusCode.BadRequest, uploaded.status, id)
            assertContains(uploaded.bodyAsText(), "reserved_client_id")
            assertEquals(HttpStatusCode.BadRequest, client.post("/api/v1/enrollment-tokens/generate") {
                contentType(ContentType.Application.Json); setBody("""{"clientId":"$id"}""")
            }.status, id)
        }
        // The service refuses too, whoever calls it.
        certService.removeFromTrustStore("client-ca")
        assertFailsWith<IllegalArgumentException> { certService.importClientCertificate("CLIENT-CA", "x".toByteArray()) }
        assertEquals(ca, anchor(), "the CA every CSR identity chains to is still trusted")
    }

    @Test
    fun `the token list shows the device a token is bound to`() = testApplication {
        clientCertApp()
        for (body in listOf("""{"clientId":"tablet-bound","deviceUid":"9774d56d682e549c"}""", """{"clientId":"tablet-any"}""")) {
            val res = client.post("/api/v1/enrollment-tokens/generate") {
                contentType(ContentType.Application.Json); setBody(body)
            }
            assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        }
        // A device id the server would refuse at enrollment is refused when minting.
        val bad = client.post("/api/v1/enrollment-tokens/generate") {
            contentType(ContentType.Application.Json); setBody("""{"clientId":"tablet-bad","deviceUid":"<b>x</b>"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, bad.status)
        assertContains(bad.bodyAsText(), "invalid_device_uid")

        val list = Json.parseToJsonElement(client.get("/api/v1/enrollment-tokens").bodyAsText()).jsonArray
            .associateBy { it.jsonObject["clientId"]!!.jsonPrimitive.content }
        assertEquals(setOf("tablet-bound", "tablet-any"), list.keys)
        assertEquals("9774d56d682e549c", list["tablet-bound"]!!.jsonObject["deviceUid"]!!.jsonPrimitive.content)
        assertTrue(list["tablet-any"]!!.jsonObject["deviceUid"].let { it == null || it is JsonNull }, "unbound: no device id")
        // Still only the masked prefix, never the plaintext.
        assertTrue(list.values.all { it.jsonObject["masked"]!!.jsonPrimitive.content == "true" })
    }

    @Test
    fun `an upload never replaces an active identity or another truststore entry`() = testApplication {
        clientCertApp()
        clientCerts.add("dev-1", "PinVault Client: dev-1", "fp", "2026-10-01T00:00:00Z")
        val active = upload("dev-1")
        assertEquals(HttpStatusCode.Conflict, active.status)
        assertContains(active.bodyAsText(), "client_id_in_use")
        // A truststore alias with no row (JKS aliases ignore case).
        val key = TestPki.keys()
        val cert = TestPki.build("CN=legacy", key.public, "CN=legacy", key.private, eku = listOf("1.3.6.1.5.5.7.3.2"))
        certService.importClientCertificate("legacy-anchor", TestPki.pem(cert))
        assertEquals(HttpStatusCode.Conflict, upload("Legacy-Anchor").status)
        // A fresh id is uploaded.
        val fresh = TestPki.build("CN=fresh", key.public, "CN=fresh", key.private, eku = listOf("1.3.6.1.5.5.7.3.2"))
        assertEquals(HttpStatusCode.OK, upload("fresh-1", TestPki.pem(fresh)).status)
    }

    // ── A5: letting a device in is the second person's act ────────────────

    @Test
    fun `with approvals on, a device is let in by a personal key that did not make the code`() {
        GovernanceHarness(File(dir, "gov5").also { it.mkdirs() }).use { h ->
            val policy = h.policies.create("fleet", 5, Duration.ofDays(1), requireApproval = true, createdBy = "alice").policy
            fun request(n: Int) = h.policies.createRequest(policy, "spki-$n", EnrollmentRequest.PENDING, h.scope, null, "android-$n", "10.0.0.$n").request

            val own = h.call("POST", "/api/v1/enrollment-requests/${request(1).id}/approve", ALICE)
            assertEquals(409, own.status, own.body)
            assertContains(own.body, "own_enrollment_code")
            val shared = h.call("POST", "/api/v1/enrollment-requests/${request(1).id}/approve", SHARED)
            assertEquals(409, shared.status, shared.body)
            assertContains(shared.body, "named_admin_required")
            val bob = h.call("POST", "/api/v1/enrollment-requests/${request(1).id}/approve", BOB)
            assertEquals(200, bob.status, bob.body)
            val entry = h.auditStore.page(50, 0).first { it.action == "enrollment_request_approved" }
            assertContains(entry.detail ?: "", "\"approvedBy\":\"bob\"")

            // Code-less applications have no creator: any personal key, recorded.
            val open = h.policies.openApplications(true, "bob")!!
            val applicant = h.policies.createRequest(open, "spki-open", EnrollmentRequest.PENDING, h.scope, null, "android-open", "10.0.0.9").request
            assertEquals(409, h.call("POST", "/api/v1/enrollment-requests/${applicant.id}/approve", SHARED).status)
            assertEquals(200, h.call("POST", "/api/v1/enrollment-requests/${applicant.id}/approve", BOB).status)
        }
    }

    @Test
    fun `with approvals off the shared key still lets devices in`() {
        GovernanceHarness(File(dir, "gov1").also { it.mkdirs() }, required = 1).use { h ->
            val policy = h.policies.create("fleet", 5, Duration.ofDays(1), requireApproval = true, createdBy = "admin").policy
            val request = h.policies.createRequest(policy, "spki-1", EnrollmentRequest.PENDING, h.scope, null, "android-1", "10.0.0.1").request
            assertEquals(200, h.call("POST", "/api/v1/enrollment-requests/${request.id}/approve", SHARED).status)
        }
    }

    // ── A6: probes go where the egress filter lets them ───────────────────

    @Test
    fun `the live gate connects to the checked address and never to metadata`() {
        var connected: Pair<String, String?>? = null
        val lab = LiveCertificateGate(LiveCertificateGate.Mode.ENFORCE,
            egress = EgressFilter(allowPrivate = true) { arrayOf(InetAddress.getByName("10.0.0.5")) },
            probe = { host, _, sni, _ -> connected = host to sni; throw java.io.IOException("refused") })
        lab.checkPins(listOf(HostPin("api.example.com", listOf(pin(1), pin(2)))))
        assertEquals("10.0.0.5" to "api.example.com", connected, "the address that was checked, the name as SNI")

        val metadata = LiveCertificateGate(LiveCertificateGate.Mode.ENFORCE,
            egress = EgressFilter(allowPrivate = true) { arrayOf(InetAddress.getByName("169.254.169.254")) },
            probe = { _, _, _, _ -> error("never probed") })
        val check = metadata.checkPins(listOf(HostPin("api.example.com", listOf(pin(1), pin(2))))).checks.single()
        assertFalse(check.reachable)
        assertContains(check.error ?: "", "metadata")
        // Not a host name at all: not a connection target.
        val bad = metadata.checkPins(listOf(HostPin("127.0.0.1/admin", listOf(pin(1), pin(2))))).checks.single()
        assertNull(bad.probed)
        assertNotNull(LiveCertificateGate.fromEnv(emptyMap()), "fromEnv wires the filter")
    }

    private fun ApplicationTestBuilder.hostApp(egress: EgressFilter) {
        install(ContentNegotiation) { json() }
        routing { hostRoutes(scope, pins, hosts, PinConfigHistoryStore(db), certService, MockServerManager(), egress = egress) }
    }

    @Test
    fun `ping-remote probes only known hosts, on their ports, through the egress filter, never cross-site`() = testApplication {
        pins.save(scope, PinConfig(pins = listOf(HostPin("api.example.com", listOf(pin(1), pin(2))))))
        hostApp(EgressFilter(allowPrivate = false) { arrayOf(InetAddress.getByName("169.254.169.254")) })
        suspend fun ping(path: String, vararg headers: Pair<String, String>) =
            client.get(path) { headers.forEach { (n, v) -> header(n, v) } }
        val marked = "X-PinVault-Admin" to "1"

        assertEquals(HttpStatusCode.Forbidden, ping("/api/v1/hosts/api.example.com/ping-remote").status, "an <img> on another page sends no marker")
        assertEquals(HttpStatusCode.Forbidden, ping("/api/v1/hosts/api.example.com/ping-remote", marked, "Sec-Fetch-Site" to "cross-site").status)
        assertEquals(HttpStatusCode.NotFound, ping("/api/v1/hosts/internal.example.com/ping-remote", marked).status, "not pinned or registered")
        assertEquals(HttpStatusCode.BadRequest, ping("/api/v1/hosts/api.example.com/ping-remote?port=22", marked).status, "not one of its ports")
        val metadata = ping("/api/v1/hosts/api.example.com/ping-remote?port=443", marked)
        assertEquals(HttpStatusCode.BadRequest, metadata.status)
        assertContains(metadata.bodyAsText(), "metadata")
    }

    // ── A9: Config API start/stop ─────────────────────────────────────────

    @Test
    fun `Config API start and stop take an identifier and a known mode, and answer real JSON`() = testApplication {
        install(ContentNegotiation) { json() }
        routing {
            configApiAdminRoutes(ConfigApiManager(), pins, certService, ConfigApiRegistry(db), hosts, MockServerManager(), audit,
                File(dir, "server.jks"), moduleFor = { _, _ -> {} })
        }
        suspend fun post(path: String, body: String) = client.post(path) { contentType(ContentType.Application.Json); setBody(body) }
        for (body in listOf("""{"id":"x\",\"mode\":\"tls","port":9001}""", """{"id":"ok","port":9001,"mode":"plain"}""",
                """{"id":"ok","port":70000}""", """{"id":"ok"}""")) {
            assertEquals(HttpStatusCode.BadRequest, post("/api/v1/config-apis/start", body).status, body)
        }
        assertEquals(HttpStatusCode.BadRequest, post("/api/v1/config-apis/stop", """{"id":"a b"}""").status)
        assertEquals(HttpStatusCode.BadRequest, post("/api/v1/config-apis/delete", """{"id":"<x>"}""").status)
        assertEquals(HttpStatusCode.OK, post("/api/v1/config-apis/stop", """{"id":"not-running"}""").status)
        assertEquals(0, Json.parseToJsonElement(client.get("/api/v1/config-apis").bodyAsText()).jsonArray.size)
    }

    @Test
    fun `the approval card says the mode and which API a start would stop`() {
        val planner = CertChangePlanner(certService, pins, hosts)
        val describer = ChangeDescriber(pins, planner, LiveCertificateGate(LiveCertificateGate.Mode.OFF), { "" },
            portHolder = { port -> if (port == 8092) "prod-mtls" else null })
        fun describe(path: String, body: String) = describer.describe(ApprovalService.ChangeInput("config_api_lifecycle", path, "", "application/json", body.toByteArray()))

        val takeover = describe("/api/v1/config-apis/start", """{"id":"other","port":8092,"mode":"tls"}""")
        assertContains(takeover.summary, "as TLS")
        assertContains(takeover.summary, "STOPS Config API prod-mtls")
        val fresh = describe("/api/v1/config-apis/start", """{"id":"new-mtls","port":9100,"mode":"mtls"}""")
        assertContains(fresh.summary, "as MTLS")
        assertFailsWith<IllegalArgumentException> { describe("/api/v1/config-apis/start", """{"id":"x","port":9100,"mode":"ftp"}""") }
        assertFailsWith<IllegalArgumentException> { describe("/api/v1/config-apis/stop", """{"id":"a\"b"}""") }
    }

    // ── A10: a host P12 holds one key ────────────────────────────────────

    private fun p12(vararg names: String): ByteArray {
        val ks = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null) }
        for (name in names) {
            val key = TestPki.keys()
            ks.setKeyEntry(name, key.private, "pw".toCharArray(), arrayOf(TestPki.build("CN=$name", key.public, "CN=$name", key.private)))
        }
        return java.io.ByteArrayOutputStream().also { ks.store(it, "pw".toCharArray()) }.toByteArray()
    }

    @Test
    fun `a host client P12 must hold exactly one key, and that entry is what is shown and stored`() {
        val (alias, cert) = certService.hostClientKeyEntry(p12("only"), "pw")
        assertEquals("CN=only", cert.subjectX500Principal.name)
        assertEquals("only", alias)
        val two = assertFailsWith<IllegalArgumentException> { certService.hostClientKeyEntry(p12("shown", "hidden"), "pw") }
        assertContains(two.message ?: "", "exactly one private key")
        assertFailsWith<IllegalArgumentException> { certService.rewrapP12(p12("a", "b"), "pw", "new", keyEntryOnly = true) }
        val stored = certService.rewrapP12(p12("one"), "pw", "new", keyEntryOnly = true)
        assertEquals(1, java.security.KeyStore.getInstance("PKCS12", "BC").apply { load(stored.inputStream(), "new".toCharArray()) }.size())
        // The approval card reads the same entry, and refuses the same files.
        val planner = CertChangePlanner(certService, pins, hosts)
        assertFailsWith<IllegalArgumentException> { planner.hostClientCertificate(p12("x", "y"), "pw") }
    }

    // ── Change requests wait encrypted ────────────────────────────────────

    @Test
    fun `a change request's body and plan are stored encrypted and read back as sent`() {
        val store = ChangeRequestStore(db, VaultAtRestCipher("test-at-rest-password"))
        val body = "P12 and its password".toByteArray()
        val id = store.create("2026-10-05T00:00:00Z", "2026-10-06T00:00:00Z", "alice", "POST", "/api/v1/client-certs/upload", "",
            "multipart/form-data", body, "", "summary", "{}", prepared = "plan".toByteArray())
        val raw = db.connection().use { conn ->
            conn.prepareStatement("SELECT body, prepared FROM change_requests WHERE id = ?").use { s ->
                s.setLong(1, id); val rs = s.executeQuery(); rs.next(); rs.getBytes(1) to rs.getBytes(2)
            }
        }
        assertTrue(VaultAtRestCipher.isEncrypted(raw.first) && VaultAtRestCipher.isEncrypted(raw.second))
        assertFalse(String(raw.first).contains("password"))
        assertEquals(body.toList(), store.body(id)!!.toList())
        assertEquals("plan", String(store.prepared(id)!!))
        // A row stored before (plaintext) is read as it is.
        val plain = ChangeRequestStore(db).create("2026-10-05T00:00:00Z", "2026-10-06T00:00:00Z", "alice", "POST", "/x", "", "", "old".toByteArray(), "", "s", "{}")
        assertEquals("old", String(store.body(plain)!!))
    }
}
