package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.plugin.AdminAudit
import com.example.pinvault.server.plugin.AdminRegistry
import com.example.pinvault.server.plugin.ApiKeyAuth
import com.example.pinvault.server.plugin.ApprovalGate
import com.example.pinvault.server.plugin.ApprovalReplay
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.governanceRoutes
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.LiveCertificateGate
import com.example.pinvault.server.service.PinDiff
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.WebhookNotifier
import com.example.pinvault.server.store.*
import com.sun.net.httpserver.HttpServer
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.*

/**
 * Admin identities, the hash-chained audit log, webhook notifications, the
 * live certificate gate and two-person approval.
 */
class GovernanceTest {

    private val scope = "default-tls"
    private val pinA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val pinB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
    private val pinC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var history: PinConfigHistoryStore
    private lateinit var auditStore: AuditLogStore

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-governance-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        store = PinConfigStore(db)
        history = PinConfigHistoryStore(db)
        auditStore = AuditLogStore(db)
        store.save(scope, PinConfig(pins = listOf(HostPin("api.example.com", listOf(pinA, pinB), version = 1))))
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun sha256Hex(text: String) =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun testRegistry() = AdminRegistry.fromEnv(
        mapOf(
            "API_KEY" to "shared-key",
            "ADMIN_KEYS" to "alice:${sha256Hex("alice-key")},bob:${sha256Hex("bob-key")}"
        )
    )

    // ── Identities ──────────────────────────────────────────────────────

    @Test
    fun `admin keys identify their holders and only their holders`() {
        val registry = testRegistry()
        assertEquals(listOf("admin", "alice", "bob"), registry.names)
        assertEquals("alice", registry.identify("alice-key"))
        assertEquals("bob", registry.identify("bob-key"))
        assertEquals("admin", registry.identify("shared-key"))
        assertNull(registry.identify("alice-key "))
        assertNull(registry.identify(sha256Hex("alice-key")), "the configured hash is not itself a key")
    }

    @Test
    fun `ADMIN_KEYS refuses malformed entries and the name admin next to API_KEY`() {
        assertFailsWith<IllegalArgumentException> { AdminRegistry.fromEnv(mapOf("ADMIN_KEYS" to "alice:not-a-hash")) }
        assertFailsWith<IllegalArgumentException> { AdminRegistry.fromEnv(mapOf("ADMIN_KEYS" to "al ice:${sha256Hex("k")}")) }
        assertFailsWith<IllegalArgumentException> {
            AdminRegistry.fromEnv(mapOf("API_KEY" to "k", "ADMIN_KEYS" to "admin:${sha256Hex("x")}"))
        }
    }

    // ── Audit log ───────────────────────────────────────────────────────

    @Test
    fun `the audit chain verifies, refuses edits and exposes the first tampered row`() {
        val first = auditStore.append("t1", "alice", "pins_changed", summary = "one")
        auditStore.append("t2", "bob", "change_approved", summary = "two")
        auditStore.append("t3", "alice", "http", summary = "three")
        assertEquals(AuditLogStore.GENESIS, first.prevHash)
        assertEquals(AuditChainCheck(ok = true, entries = 3), auditStore.verify())

        // The triggers keep even a direct UPDATE/DELETE from rewriting history…
        db.connection().use { conn ->
            assertFails { conn.createStatement().executeUpdate("UPDATE audit_log SET summary = 'x' WHERE id = 2") }
            assertFails { conn.createStatement().executeUpdate("DELETE FROM audit_log WHERE id = 1") }
        }
        // …and someone who drops them first still leaves a broken chain.
        db.connection().use { conn ->
            conn.createStatement().executeUpdate("DROP TRIGGER audit_log_no_update")
            conn.createStatement().executeUpdate("UPDATE audit_log SET summary = 'rewritten' WHERE id = 2")
        }
        val check = auditStore.verify()
        assertFalse(check.ok)
        assertEquals(2L, check.firstBrokenId)
    }

    @Test
    fun `pin diffs name what changed`() {
        val before = PinConfig(
            pins = listOf(
                HostPin("a.example.com", listOf(pinA, pinB), version = 3),
                HostPin("gone.example.com", listOf(pinA, pinB), version = 1)
            )
        )
        val after = PinConfig(
            pins = listOf(
                HostPin("a.example.com", listOf(pinA, pinC), version = 4, forceUpdate = true),
                HostPin("new.example.com", listOf(pinB, pinC), version = 1)
            )
        )
        val summary = PinDiff.of(before, after).summary()
        assertTrue(summary.contains("new.example.com added"), summary)
        assertTrue(summary.contains("gone.example.com removed"), summary)
        assertTrue(summary.contains("a.example.com: pins v3→v4, force on"), summary)
        assertTrue(PinDiff.of(after, after).isEmpty)
    }

    // ── Webhook ─────────────────────────────────────────────────────────

    @Test
    fun `webhook deliveries carry an HMAC signature and are retried`() {
        val calls = AtomicInteger()
        val bodies = CopyOnWriteArrayList<Pair<String, String?>>()
        val receiver = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/hook") { exchange ->
                val body = exchange.requestBody.readBytes().decodeToString()
                bodies += body to exchange.requestHeaders.getFirst("X-PinVault-Signature")
                // First attempt fails: the notifier must retry.
                val status = if (calls.incrementAndGet() == 1) 500 else 204
                exchange.sendResponseHeaders(status, -1)
                exchange.close()
            }
            start()
        }
        try {
            val notifier = WebhookNotifier("http://127.0.0.1:${receiver.address.port}/hook", "s3cret", setOf("*"))
            val audit = AuditLog(auditStore, notifier)
            val entry = audit.record("pins_changed", "api.example.com: pins v1→v2", scope, actor = "alice")

            val deadline = System.currentTimeMillis() + 15_000
            while (notifier.status().recent.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(100)
            val delivery = notifier.status().recent.single()
            assertEquals(204, delivery.status)
            assertEquals(2, delivery.attempts)
            assertEquals(entry.id, delivery.auditId)

            val (body, signature) = bodies.last()
            val json = Json.parseToJsonElement(body).jsonObject
            assertEquals("pins_changed", json["event"]!!.jsonPrimitive.content)
            assertEquals("alice", json["actor"]!!.jsonPrimitive.content)
            assertTrue(json["text"]!!.jsonPrimitive.content.contains("pins_changed by alice"))
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec("s3cret".toByteArray(), "HmacSHA256")) }
            val expected = "sha256=" + mac.doFinal(body.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            assertEquals(expected, signature)
        } finally {
            receiver.stop(0)
        }
    }

    private fun ApplicationTestBuilder.governanceApp(audit: AuditLog) {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = audit, required = 1, managementPort = 1,
            describe = { _, _, _, _ -> ApprovalService.Description(scope, "x", buildJsonObject { }) }
        )
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            governanceRoutes(testRegistry(), audit, auditStore, approvals, LiveCertificateGate(LiveCertificateGate.Mode.OFF), SignedConfigService(signing))
        }
    }

    @Test
    fun `the dashboard's test notification is audited and answered with its audit id`() {
        val receiver = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/hook") { exchange ->
                exchange.requestBody.readBytes()
                exchange.sendResponseHeaders(204, -1)
                exchange.close()
            }
            start()
        }
        try {
            val notifier = WebhookNotifier("http://127.0.0.1:${receiver.address.port}/hook", null, setOf("*"))
            testApplication {
                governanceApp(AuditLog(auditStore, notifier))
                // Used to be a 500: the body mixed a Boolean and a Long in one map.
                val response = client.post("/api/v1/notifications/test")
                assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
                val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
                assertTrue(body["sent"]!!.jsonPrimitive.boolean)
                val entry = auditStore.page(1, 0).single()
                assertEquals("notification_test", entry.action)
                assertEquals(entry.id, body["auditId"]!!.jsonPrimitive.long)
            }
            testApplication {
                governanceApp(AuditLog(auditStore, null))
                assertEquals(HttpStatusCode.Conflict, client.post("/api/v1/notifications/test").status)
            }
        } finally {
            receiver.stop(0)
        }
    }

    // ── Live certificate gate ───────────────────────────────────────────

    private fun cert(): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val holder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            org.bouncycastle.asn1.x500.X500Name("CN=test"), BigInteger.ONE, Date(), Date(System.currentTimeMillis() + 86_400_000),
            org.bouncycastle.asn1.x500.X500Name("CN=test"), pair.public
        ).build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder)
    }

    private val leaf = cert()
    private val intermediate = cert()
    private val leafPin = LiveCertificateGate.spkiPin(leaf)
    private val intermediatePin = LiveCertificateGate.spkiPin(intermediate)

    private fun gate(mode: LiveCertificateGate.Mode, map: Map<String, String> = emptyMap(), probed: MutableList<String> = mutableListOf()) =
        LiveCertificateGate(mode, map, probe = { host, port, sni, _ ->
            probed += "$host:$port sni=$sni"
            if (host == "down.example.com") throw java.net.ConnectException("Connection refused")
            listOf(leaf, intermediate)
        })

    @Test
    fun `the live gate passes when the served leaf or an issuer it chains to is pinned`() {
        val probed = mutableListOf<String>()
        val g = gate(LiveCertificateGate.Mode.ENFORCE, mapOf("*.example.org" to "www.example.org:8443"), probed)

        assertTrue(g.checkPins(listOf(HostPin("api.example.com", listOf(leafPin, pinA)))).passed)
        val notTheIssuer = g.checkPins(listOf(HostPin("api.example.com", listOf(intermediatePin, pinA))))
        assertFalse(notTheIssuer.passed, "the served leaf does not chain to that certificate — devices would refuse it")

        val wildcard = g.checkPins(listOf(HostPin("*.example.com", listOf(leafPin, pinA))))
        assertFalse(wildcard.passed)
        assertTrue(wildcard.checks.single().error!!.contains("LIVE_CHECK_HOST_MAP"))
        assertTrue(g.checkPins(listOf(HostPin("*.example.org", listOf(leafPin, pinA)))).passed, "a mapped wildcard is probed")

        val down = g.checkPins(listOf(HostPin("down.example.com", listOf(leafPin, pinA)))).checks.single()
        assertFalse(down.reachable)
        assertFalse(down.matched)

        g.checkPins(listOf(HostPin("10.0.0.5:9443", listOf(leafPin, pinA))))
        assertTrue(probed.contains("api.example.com:443 sni=api.example.com"))
        assertTrue(probed.contains("www.example.org:8443 sni=www.example.org"))
        assertTrue(probed.contains("10.0.0.5:9443 sni=null"), "an IP address carries no SNI")
    }

    private fun issued(subject: String, subjectKey: java.security.PublicKey, issuer: String, signingKey: java.security.PrivateKey, ca: Boolean): X509Certificate {
        val builder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            org.bouncycastle.asn1.x500.X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(System.currentTimeMillis() - 60_000),
            Date(System.currentTimeMillis() + 86_400_000), org.bouncycastle.asn1.x500.X500Name(subject), subjectKey
        )
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(ca))
        if (ca) builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
            org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign))
        val holder = builder.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(signingKey))
        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder)
    }

    @Test
    fun `the live gate accepts the pin of the CA that issued the served leaf, not of one appended to a forged leaf`() {
        val ec = { KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair() }
        val caKeys = ec()
        val ca = issued("CN=Gate Test CA", caKeys.public, "CN=Gate Test CA", caKeys.private, ca = true)
        val leafKeys = ec()
        val servedLeaf = issued("CN=api.example.com", leafKeys.public, "CN=Gate Test CA", caKeys.private, ca = false)
        val caPins = listOf(LiveCertificateGate.spkiPin(ca), pinA)

        val genuine = LiveCertificateGate(LiveCertificateGate.Mode.ENFORCE, probe = { _, _, _, _ -> listOf(servedLeaf, ca) })
        assertTrue(genuine.checkPins(listOf(HostPin("api.example.com", caPins))).passed, "devices accept a leaf that chains to the pinned CA")

        val forgedLeaf = issued("CN=api.example.com", leafKeys.public, "CN=Gate Test CA", ec().private, ca = false)
        val forged = LiveCertificateGate(LiveCertificateGate.Mode.ENFORCE, probe = { _, _, _, _ -> listOf(forgedLeaf, ca) })
        assertFalse(forged.checkPins(listOf(HostPin("api.example.com", caPins))).passed, "the CA did not sign that leaf")
    }

    private fun ApplicationTestBuilder.pinApp(gate: LiveCertificateGate, audit: AuditLog) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                scope, store, history, ConnectionHistoryStore(db), ConfigSigningService(File(dir, "k.pem")),
                ClientDeviceStore(db), liveGate = gate, audit = audit
            )
        }
    }

    private suspend fun ApplicationTestBuilder.putPins(pins: List<String>, query: String = ""): HttpResponse =
        client.put("/api/v1/certificate-config$query") {
            contentType(ContentType.Application.Json)
            setBody("""{"version":0,"forceUpdate":false,"pins":[{"hostname":"api.example.com","sha256":${pins.joinToString(",", "[", "]") { "\"$it\"" }}}]}""")
        }

    @Test
    fun `enforce refuses a pin set the live host fails, and an override is audited`() = testApplication {
        val audit = AuditLog(auditStore, null)
        pinApp(gate(LiveCertificateGate.Mode.ENFORCE), audit)

        val refused = putPins(listOf(pinA, pinC))
        assertEquals(HttpStatusCode.UnprocessableEntity, refused.status)
        val body = Json.parseToJsonElement(refused.bodyAsText()).jsonObject
        assertEquals(leafPin, body["liveCheck"]!!.jsonObject["checks"]!!.jsonArray.single().jsonObject["livePins"]!!.jsonArray.first().jsonPrimitive.content)
        assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256, "nothing was stored")
        assertEquals("live_check_blocked", auditStore.page(1, 0).single().action)

        assertEquals(HttpStatusCode.OK, putPins(listOf(leafPin, pinC)).status, "the served leaf plus a backup passes")

        val overridden = putPins(listOf(pinA, pinC), "?liveCheckOverride=host%20switches%20at%2018:00")
        assertEquals(HttpStatusCode.OK, overridden.status)
        val entry = auditStore.page(10, 0).first { it.action == "live_check_overridden" }
        assertTrue(entry.summary.contains("host switches at 18:00"), entry.summary)
    }

    @Test
    fun `warn stores the change and flags it`() = testApplication {
        val audit = AuditLog(auditStore, null)
        pinApp(gate(LiveCertificateGate.Mode.WARN), audit)

        val response = putPins(listOf(pinA, pinC))
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("warn", response.headers["X-PinVault-Live-Check"])
        assertEquals(listOf(pinA, pinC), store.load(scope).pins.single().sha256)
        assertTrue(auditStore.page(10, 0).any { it.action == "live_check_warning" })
    }

    // ── Two-person approval, on a real socket (the approval replays the
    //    request through the server's own port) ──────────────────────────

    private val http = HttpClient.newHttpClient()

    private fun call(port: Int, method: String, path: String, key: String, body: String? = null): Pair<Int, String> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$port$path"))
            .header("X-API-Key", key)
            .header("Content-Type", "application/json")
            .method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = http.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
        return response.statusCode() to response.body()
    }

    private fun pinsBody(vararg pins: String) =
        """{"version":0,"forceUpdate":false,"pins":[{"hostname":"api.example.com","sha256":${pins.joinToString(",", "[", "]") { "\"$it\"" }}}]}"""

    @Test
    fun `a pin change waits for a second admin and is applied as the requester`() {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val audit = AuditLog(auditStore, null)
        store.onSaved = { s, before, after -> audit.recordPinChange(s, before, after) }
        val approvals = ApprovalService(
            store = ChangeRequestStore(db),
            audit = audit,
            required = 2,
            managementPort = port,
            describe = { _, _, _, _ -> ApprovalService.Description(scope, "test change", buildJsonObject { }, baseHash = stateOf(scope)) },
            stateHash = { stateOf(it) }
        )
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(ApiKeyAuth) { registry = testRegistry(); allowAnonymous = false }
            install(AdminAudit) { this.audit = audit }
            install(ApprovalGate) { this.approvals = approvals }
            routing {
                certificateConfigRoutes(scope, store, history, ConnectionHistoryStore(db), signing, ClientDeviceStore(db), audit = audit)
                governanceRoutes(testRegistry(), audit, auditStore, approvals, LiveCertificateGate(LiveCertificateGate.Mode.OFF), SignedConfigService(signing))
            }
        }.start(wait = false)
        try {
            val (status, body) = call(port, "PUT", "/api/v1/certificate-config", "alice-key", pinsBody(pinA, pinC))
            assertEquals(202, status, body)
            val id = Json.parseToJsonElement(body).jsonObject["changeRequestId"]!!.jsonPrimitive.long
            assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256, "nothing changes before approval")

            assertEquals(409, call(port, "POST", "/api/v1/change-requests/$id/approve", "alice-key").first, "no self-approval")
            assertEquals(409, call(port, "POST", "/api/v1/change-requests/$id/approve", "shared-key").first, "a shared key names nobody")

            val (approved, approvedBody) = call(port, "POST", "/api/v1/change-requests/$id/approve", "bob-key")
            assertEquals(200, approved, approvedBody)
            val cr = Json.parseToJsonElement(approvedBody).jsonObject
            assertEquals("applied", cr["status"]!!.jsonPrimitive.content)
            assertEquals(listOf(pinA, pinC), store.load(scope).pins.single().sha256)

            val pinChange = auditStore.page(50, 0).first { it.action == "pins_changed" }
            assertEquals("alice (approved by bob)", pinChange.actor)
            val actions = auditStore.page(50, 0).map { it.action }
            assertTrue(actions.containsAll(listOf("change_requested", "change_applied", "pins_changed")), actions.toString())
            assertTrue(auditStore.verify().ok)

            // Two requests made against the same pins: once one is applied,
            // the other is stale and refused instead of undoing it.
            val first = Json.parseToJsonElement(call(port, "PUT", "/api/v1/certificate-config", "alice-key", pinsBody(pinA, pinB)).second)
                .jsonObject["changeRequestId"]!!.jsonPrimitive.long
            val second = Json.parseToJsonElement(call(port, "PUT", "/api/v1/certificate-config", "bob-key", pinsBody(pinB, pinC)).second)
                .jsonObject["changeRequestId"]!!.jsonPrimitive.long
            assertEquals(200, call(port, "POST", "/api/v1/change-requests/$first/approve", "bob-key").first)
            assertEquals(409, call(port, "POST", "/api/v1/change-requests/$second/approve", "alice-key").first)
            assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256)

            // Rejection.
            val third = Json.parseToJsonElement(call(port, "PUT", "/api/v1/certificate-config", "alice-key", pinsBody(pinC, pinA)).second)
                .jsonObject["changeRequestId"]!!.jsonPrimitive.long
            val (rejected, rejectedBody) = call(port, "POST", "/api/v1/change-requests/$third/reject", "bob-key", """{"reason":"wrong host"}""")
            assertEquals(200, rejected)
            assertEquals("rejected", Json.parseToJsonElement(rejectedBody).jsonObject["status"]!!.jsonPrimitive.content)
            assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256)

            // A forged replay token gets nowhere.
            val forged = HttpRequest.newBuilder(URI("http://127.0.0.1:$port/api/v1/certificate-config"))
                .header("X-PinVault-Replay", "not-a-token").header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(pinsBody(pinC, pinB))).build()
            assertEquals(403, http.send(forged, java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode())
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun `with approvals on, the device-facing listeners refuse pin writes`() = testApplication {
        val audit = AuditLog(auditStore, null)
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = audit, required = 2, managementPort = 1,
            describe = { _, _, _, _ -> ApprovalService.Description(scope, "x", buildJsonObject { }) }
        )
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(ApiKeyAuth) { registry = testRegistry(); allowAnonymous = false }
        install(AdminAudit) { this.audit = audit }
        install(ApprovalGate) { this.approvals = approvals; managementListener = false }
        routing {
            certificateConfigRoutes(scope, store, history, ConnectionHistoryStore(db), ConfigSigningService(File(dir, "k.pem")), ClientDeviceStore(db))
        }
        val response = client.put("/api/v1/certificate-config") {
            header("X-API-Key", "alice-key")
            contentType(ContentType.Application.Json)
            setBody(pinsBody(pinA, pinC))
        }
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256)
        // Device reads are untouched.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/certificate-config").status)
    }

    private fun stateOf(scope: String): String =
        store.load(scope).pins.sortedBy { it.hostname }.joinToString("\n") { "${it.hostname}|${it.version}|${it.sha256.sorted()}" }

    // ── Review findings (2026-09-23) ────────────────────────────────────

    /** A real Netty server with the approval gate, as in production. */
    private fun approvalServer(block: (port: Int, approvals: ApprovalService) -> Unit) {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val audit = AuditLog(auditStore, null)
        store.onSaved = { s, before, after -> audit.recordPinChange(s, before, after) }
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = audit, required = 2, managementPort = port,
            describe = { _, path, _, _ -> ApprovalService.Description(scope, "change at $path", buildJsonObject { }, baseHash = stateOf(scope)) },
            stateHash = { stateOf(it) }
        )
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(ApiKeyAuth) { registry = testRegistry(); allowAnonymous = false }
            install(AdminAudit) { this.audit = audit }
            install(ApprovalGate) { this.approvals = approvals }
            routing {
                certificateConfigRoutes(scope, store, history, ConnectionHistoryStore(db), signing, ClientDeviceStore(db), audit = audit)
                governanceRoutes(testRegistry(), audit, auditStore, approvals, LiveCertificateGate(LiveCertificateGate.Mode.OFF), SignedConfigService(signing))
            }
        }.start(wait = false)
        try {
            block(port, approvals)
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun `other spellings of a gated path are still gated, and the approved spelling replays`() = approvalServer { port, _ ->
        // Each of these routes to the pin-write handler; none may skip approval.
        val spellings = listOf(
            "PUT" to "/api//v1/certificate-config",
            "PUT" to "//api/v1/certificate-config",
            "PUT" to "/api/v1/certificate%2Dconfig",
            "POST" to "/api/v1/certificate-config//force-update"
        )
        val ids = spellings.map { (method, path) ->
            val (status, body) = call(port, method, path, "alice-key", if (method == "PUT") pinsBody(pinA, pinC) else null)
            assertEquals(202, status, "$method $path must wait for approval: $body")
            Json.parseToJsonElement(body).jsonObject["changeRequestId"]!!.jsonPrimitive.long
        }
        assertEquals(listOf(pinA, pinB), store.load(scope).pins.single().sha256, "nothing applied without approval")

        val (approved, body) = call(port, "POST", "/api/v1/change-requests/${ids[0]}/approve", "bob-key")
        assertEquals(200, approved, body)
        assertEquals("applied", Json.parseToJsonElement(body).jsonObject["status"]!!.jsonPrimitive.content)
        assertEquals(listOf(pinA, pinC), store.load(scope).pins.single().sha256)
    }

    @Test
    fun `a refused approval is audited under the request's Config API and target`() = approvalServer { port, _ ->
        val (status, body) = call(port, "PUT", "/api/v1/certificate-config", "alice-key", pinsBody(pinA, pinC))
        assertEquals(202, status, body)
        val id = Json.parseToJsonElement(body).jsonObject["changeRequestId"]!!.jsonPrimitive.long
        assertEquals(409, call(port, "POST", "/api/v1/change-requests/$id/approve", "alice-key").first)
        assertEquals(409, call(port, "POST", "/api/v1/change-requests/$id/approve", "shared-key").first)

        // E2E Y03: these rows had no Config API and no target, unlike every
        // other change_* entry — a per-scope view of the log did not show them.
        val refused = auditStore.page(10, 0, "change_approval_refused", scope)
        assertEquals(listOf("admin", "alice"), refused.map { it.actor }, "both refusals, newest first, under $scope")
        refused.forEach { assertEquals("PUT /api/v1/certificate-config", it.target) }

        // An id that does not exist is still recorded, without a scope.
        assertEquals(404, call(port, "POST", "/api/v1/change-requests/999/approve", "bob-key").first)
        val unknown = auditStore.page(1, 0, "change_approval_refused").single()
        assertEquals("bob", unknown.actor)
        assertEquals("", unknown.configApiId)
        assertTrue(auditStore.verify().ok)
    }

    @Test
    fun `with approvals on, the shared key cannot request gated changes`() = approvalServer { port, approvals ->
        val (status, body) = call(port, "PUT", "/api/v1/certificate-config", "shared-key", pinsBody(pinA, pinC))
        assertEquals(409, status, body)
        assertTrue(body.contains("personal admin key"), body)
        assertTrue(approvals.list("pending").isEmpty())
        // Reads with the shared key are unaffected.
        assertEquals(200, call(port, "GET", "/api/v1/audit-log", "shared-key").first)
    }

    @Test
    fun `an approved change is audited with the approver's address, not the loopback replay's`() = testApplication {
        val audit = AuditLog(auditStore, null)
        install(ApiKeyAuth) { registry = testRegistry(); allowAnonymous = false }
        install(AdminAudit) { this.audit = audit }
        routing {
            put("/api/v1/probe") {
                audit.record("probe", "replayed write")
                call.respond(HttpStatusCode.OK)
            }
        }
        // E2E Y03: pins_changed of an approved change said 127.0.0.1 — the
        // server's own replay — instead of where the approval came from.
        val token = ApprovalReplay.issue(7, "alice (approved by bob)", "PUT", "/api/v1/probe", "", ip = "203.0.113.7")
        assertEquals(HttpStatusCode.OK, client.put("/api/v1/probe") { header(ApprovalReplay.HEADER, token) }.status)
        val entry = auditStore.page(10, 0).first { it.action == "probe" }
        assertEquals("alice (approved by bob)", entry.actor)
        assertEquals("203.0.113.7", entry.sourceIp)
    }

    @Test
    fun `an expired request cannot be approved and its body is dropped`() {
        val audit = AuditLog(auditStore, null)
        val requests = ChangeRequestStore(db)
        var replayed = false
        val approvals = ApprovalService(
            store = requests, audit = audit, required = 2, ttlHours = 0, managementPort = 1,
            describe = { _, _, _, _ -> ApprovalService.Description(scope, "x", buildJsonObject { }) },
            replay = { _, _, _ -> replayed = true; 200 to "{}" }
        )
        val pending = approvals.submit("alice", "pins_update", "PUT", "/api/v1/certificate-config", query = "",
            contentType = "application/json", body = "{\"secret\":1}".toByteArray())
        Thread.sleep(5)
        val refused = assertFailsWith<ApprovalService.Refused> { approvals.approve(pending.changeRequestId, "bob") }
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertFalse(replayed)
        assertEquals("expired", requests.get(pending.changeRequestId)!!.status)
        db.connection().use { conn ->
            val rs = conn.createStatement().executeQuery("SELECT body IS NULL FROM change_requests WHERE id = ${pending.changeRequestId}")
            assertTrue(rs.getBoolean(1), "a decided request keeps no body")
        }
    }

    @Test
    fun `a change that cannot be described is refused, never stored blind`() {
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = AuditLog(auditStore, null), required = 2, managementPort = 1,
            describe = { _, _, _, _ -> error("unreadable body") }
        )
        val refused = assertFailsWith<ApprovalService.Refused> {
            approvals.submit("alice", "pins_update", "PUT", "/api/v1/certificate-config", query = "",
                contentType = "application/json", body = ByteArray(0))
        }
        assertEquals(HttpStatusCode.BadRequest, refused.status)
        assertTrue(approvals.list("all").isEmpty())
    }

    @Test
    fun `switching to a backup key needs approval like any certificate change`() {
        val routes = com.example.pinvault.server.service.PinAffectingRoutes
        assertEquals("host_cert", routes.match(HttpMethod.Post, "/api/v1/hosts/api.example.com/rotate-to-backup"))
        assertEquals("bootstrap_pins", routes.match(HttpMethod.Post, "/api/v1/server-tls-pins/rotate-to-backup"))
    }

    @Test
    fun `gate paths are compared the way routing resolves them`() {
        assertEquals("/api/v1/certificate-config", com.example.pinvault.server.service.PinAffectingRoutes.canonicalPath("/api//v1/certificate%2Dconfig/"))
        assertEquals("/api/v1/config/prod/update", com.example.pinvault.server.service.PinAffectingRoutes.canonicalPath("/api/v1/config/pr%6Fd/update"))
        assertEquals("config_api_lifecycle", com.example.pinvault.server.service.PinAffectingRoutes.match(HttpMethod.Post, "/api/v1/config-apis/start"))
        assertEquals("config_api_lifecycle", com.example.pinvault.server.service.PinAffectingRoutes.match(HttpMethod.Post, "/api/v1/config-apis/stop"))
        assertNull(com.example.pinvault.server.service.PinAffectingRoutes.match(HttpMethod.Get, "/api/v1/certificate-config"))
    }

    @Test
    fun `admin names the audit log uses for non-admins are reserved`() {
        for (name in listOf("system", "unknown", "anonymous", "admin")) {
            assertFailsWith<IllegalArgumentException>(name) { AdminRegistry.fromEnv(mapOf("ADMIN_KEYS" to "$name:${sha256Hex("k")}")) }
        }
    }

    @Test
    fun `invalid keys are summarised, not written one row each`() {
        val recorder = com.example.pinvault.server.service.AuthFailureRecorder(AuditLog(auditStore, null), windowMs = 60_000)
        repeat(5) { recorder.report("203.0.113.${it + 1}", "GET", "/api/v1/audit-log") }
        assertEquals(1, auditStore.count("auth_failed"), "the first failure is recorded at once")
        recorder.flush()
        val entries = auditStore.page(10, 0, "auth_failed")
        assertEquals(2, entries.size)
        assertTrue(entries.first().summary.startsWith("4 more invalid X-API-Key attempt(s)"), entries.first().summary)
    }

    @Test
    fun `probe addresses parse IPv6 literals`() {
        assertEquals("::1" to 8443, LiveCertificateGate.splitHostPort("[::1]:8443"))
        assertEquals("::1" to 443, LiveCertificateGate.splitHostPort("[::1]"))
        assertEquals("fe80::1" to 443, LiveCertificateGate.splitHostPort("fe80::1"))
        assertEquals("host.example" to 9443, LiveCertificateGate.splitHostPort("host.example:9443"))
        assertEquals("host.example" to 443, LiveCertificateGate.splitHostPort("host.example"))
    }
}
