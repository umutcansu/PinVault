package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.plugin.AdminAudit
import com.example.pinvault.server.plugin.AdminRegistry
import com.example.pinvault.server.plugin.ApiKeyAuth
import com.example.pinvault.server.plugin.ApprovalGate
import com.example.pinvault.server.plugin.EncodedPathGuard
import com.example.pinvault.server.plugin.isAmbiguousPath
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.route.managementConfigRoutes
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.PinAffectingRoutes
import com.example.pinvault.server.store.*
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
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.security.MessageDigest
import kotlin.test.*

/**
 * K1: `POST /api/v1/config/x%2Fy/update?configApiId=default-tls` reached the
 * `{configApiId}` handler, which read `call.parameters` (query first) and
 * wrote default-tls, while the approval gate decoded `%2F` into a separator,
 * matched no rule and let the write through unapproved.
 *
 * Three fixes, each pinned here: every listener refuses such paths
 * ([EncodedPathGuard]); handlers read path segments with `pathParameters`, so
 * a same-named query parameter changes nothing; and the gate keeps `%2F`
 * inside its segment, so the rule still matches if a path gets past the guard.
 */
class PathParameterIntegrityTest {

    private val pinA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val pinB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
    private val pinC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var history: PinConfigHistoryStore
    private lateinit var hostStore: HostStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var certService: CertificateService

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-path-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        store = PinConfigStore(db)
        history = PinConfigHistoryStore(db)
        hostStore = HostStore(db)
        auditStore = AuditLogStore(db)
        certService = CertificateService(File(dir, "certs").also { it.mkdirs() })
        store.save("default-tls", PinConfig(pins = listOf(
            HostPin("api.example.com", listOf(pinA, pinB), version = 1),
            HostPin("other.example.com", listOf(pinA, pinB), version = 1)
        )))
        store.save("prod", PinConfig(pins = listOf(HostPin("api.example.com", listOf(pinA, pinB), version = 1))))
        for (host in listOf("api.example.com", "other.example.com")) {
            hostStore.save(HostRecord(host, "default-tls", null, null, null, "now"))
        }
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun sha256Hex(text: String) =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun registry() = AdminRegistry.fromEnv(
        mapOf("API_KEY" to "shared-key", "ADMIN_KEYS" to "alice:${sha256Hex("alice-key")},bob:${sha256Hex("bob-key")}")
    )

    private fun pinsBody(vararg pins: String) =
        """{"version":0,"forceUpdate":false,"pins":[{"hostname":"api.example.com","sha256":${pins.joinToString(",", "[", "]") { "\"$it\"" }}}]}"""

    private fun pinsOf(scope: String, host: String = "api.example.com") = store.load(scope).pins.first { it.hostname == host }

    /** One request per [PinAffectingRoutes] rule; `{x}` marks a path parameter. */
    private data class Sample(val method: HttpMethod, val template: String) {
        val plain get() = template.replace(Regex("\\{(\\w+)}"), "$1")
    }

    private val samples = listOf(
        Sample(HttpMethod.Put, "/api/v1/certificate-config"),
        Sample(HttpMethod.Post, "/api/v1/certificate-config/force-update/{host}"),
        Sample(HttpMethod.Post, "/api/v1/certificate-config/clear-force/{host}"),
        Sample(HttpMethod.Post, "/api/v1/config/{scope}/update"),
        Sample(HttpMethod.Post, "/api/v1/management/hosts/{scope}/generate-cert"),
        Sample(HttpMethod.Post, "/api/v1/hosts/generate-cert"),
        Sample(HttpMethod.Post, "/api/v1/hosts/{host}/fetch-cert-url"),
        Sample(HttpMethod.Post, "/api/v1/config-apis/delete"),
        Sample(HttpMethod.Post, "/api/v1/config-apis/start"),
        Sample(HttpMethod.Post, "/api/v1/server-tls-pins/regenerate"),
        Sample(HttpMethod.Post, "/api/v1/signing-key/regenerate"),
        Sample(HttpMethod.Put, "/api/v1/signing-keyset"),
        Sample(HttpMethod.Put, "/api/v1/server-settings"),
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/default-host-acl"),
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/devices/{device}/host-acl"),
        // Trust material and identities
        Sample(HttpMethod.Post, "/api/v1/client-certs/upload"),
        Sample(HttpMethod.Post, "/api/v1/client-certs/generate"),
        Sample(HttpMethod.Post, "/api/v1/enrollment-policies"),
        Sample(HttpMethod.Put, "/api/v1/enrollment-open"),
        Sample(HttpMethod.Post, "/api/v1/enrollment-tokens/generate"),
        // Vault
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/vault/{key}"),
        Sample(HttpMethod.Delete, "/api/v1/config-apis/{scope}/vault/{key}"),
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/vault/{key}/policy"),
        Sample(HttpMethod.Post, "/api/v1/config-apis/{scope}/vault/{key}/tokens"),
        Sample(HttpMethod.Delete, "/api/v1/config-apis/{scope}/vault/tokens/{token}"),
        Sample(HttpMethod.Delete, "/api/v1/config-apis/{scope}/vault/devices/{device}/public-key"),
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/vault-enabled"),
        // Attestation
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/attestation/policy"),
        Sample(HttpMethod.Put, "/api/v1/config-apis/{scope}/attestation/devices/{device}"),
        Sample(HttpMethod.Delete, "/api/v1/config-apis/{scope}/attestation/devices/{device}"),
        Sample(HttpMethod.Get, "/api/v1/attestation/token-secrets"),
        Sample(HttpMethod.Post, "/api/v1/attestation/token-secrets/rotate"),
        Sample(HttpMethod.Delete, "/api/v1/attestation/token-secrets/{kid}")
    )

    /** Every spelling of [sample] that hides a separator in a path segment. */
    private fun encodedSpellings(sample: Sample): List<String> = buildList {
        add(sample.plain.replaceFirst("/api/v1/", "/api%2Fv1/"))
        add(sample.plain.replaceFirst("/api/v1/", "/api%2fv1/"))
        if ('{' in sample.template) add(sample.template.replace(Regex("\\{\\w+}"), "x%2Fy"))
    }

    @Test
    fun `the samples cover every gated rule`() {
        for ((method, pattern, op) in PinAffectingRoutes.rules) {
            assertTrue(samples.any { it.method == method && pattern.matches(it.plain) }, "no sample for $op $pattern")
        }
        samples.forEach { assertNotNull(PinAffectingRoutes.match(it.method, it.plain), it.plain) }
    }

    // ── 1. The guard ────────────────────────────────────────────────────

    @Test
    fun `ambiguous escapes and backslashes are recognised in any case`() {
        for (bad in listOf("/a%2Fb", "/a%2fb", "/a%5Cb", "/a%5cb", "/a%2Eb", "/%2e%2e/x", "/a%252Fb", "/a\\b")) {
            assertTrue(isAmbiguousPath(bad), bad)
        }
        for (ok in listOf("/api/v1/certificate%2Dconfig", "/api/v1/vault/model.bin", "/api/v1/config/pr%6Fd/update", "/a%20b")) {
            assertFalse(isAmbiguousPath(ok), ok)
        }
    }

    /** The management server's plugin stack, approvals off. */
    private fun ApplicationTestBuilder.managementApp(guard: Boolean = true) {
        val audit = AuditLog(auditStore, null)
        if (guard) install(EncodedPathGuard)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(ApiKeyAuth) { registry = registry(); allowAnonymous = false }
        install(AdminAudit) { this.audit = audit }
        routing {
            certificateConfigRoutes("default-tls", store, history, ConnectionHistoryStore(db),
                ConfigSigningService(File(dir, "k.pem")), ClientDeviceStore(db), audit = audit)
            hostRoutes("default-tls", store, hostStore, history, certService, MockServerManager(), HostClientCertStore(db))
            managementConfigRoutes(store, history, hostStore, certService, audit = audit)
        }
    }

    @Test
    fun `every gated route refuses a path segment that hides a slash`() = testApplication {
        managementApp()
        for (sample in samples) {
            for (path in encodedSpellings(sample)) {
                val response = client.request("$path?configApiId=default-tls&hostname=api.example.com") {
                    method = sample.method
                    header("X-API-Key", "alice-key")
                    contentType(ContentType.Application.Json)
                    setBody(pinsBody(pinA, pinC))
                }
                assertEquals(HttpStatusCode.BadRequest, response.status, "${sample.method.value} $path")
                assertTrue(response.bodyAsText().contains("invalid_path"), response.bodyAsText())
            }
        }
        assertEquals(listOf(pinA, pinB), pinsOf("default-tls").sha256)
        assertEquals(listOf(pinA, pinB), pinsOf("prod").sha256)
    }

    // ── 2. A query parameter never stands in for a path parameter ───────

    @Test
    fun `force-update and clear-force act on the host in the path`() = testApplication {
        managementApp()
        val forced = client.post("/api/v1/certificate-config/force-update/api.example.com?hostname=other.example.com") {
            header("X-API-Key", "alice-key")
        }
        assertEquals(HttpStatusCode.OK, forced.status, forced.bodyAsText())
        assertTrue(pinsOf("default-tls").forceUpdate)
        assertFalse(pinsOf("default-tls", "other.example.com").forceUpdate)

        client.post("/api/v1/certificate-config/force-update/other.example.com") { header("X-API-Key", "alice-key") }
        val cleared = client.post("/api/v1/certificate-config/clear-force/api.example.com?hostname=other.example.com") {
            header("X-API-Key", "alice-key")
        }
        assertEquals(HttpStatusCode.OK, cleared.status)
        assertFalse(pinsOf("default-tls").forceUpdate)
        assertTrue(pinsOf("default-tls", "other.example.com").forceUpdate)
    }

    @Test
    fun `config update and read act on the Config API in the path`() = testApplication {
        managementApp()
        val response = client.post("/api/v1/config/prod/update?configApiId=default-tls") {
            header("X-API-Key", "alice-key")
            contentType(ContentType.Application.Json)
            setBody(pinsBody(pinA, pinC))
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals(listOf(pinA, pinC), pinsOf("prod").sha256)
        assertEquals(listOf(pinA, pinB), pinsOf("default-tls").sha256, "the query value must not pick the scope")

        val read = client.get("/api/v1/config/prod?configApiId=default-tls") { header("X-API-Key", "alice-key") }
        assertEquals(1, Json.parseToJsonElement(read.bodyAsText()).jsonObject["pins"]!!.jsonArray.size, "prod has one host")
    }

    @Test
    fun `scoped host generation acts on the Config API in the path`() = testApplication {
        managementApp()
        val response = client.post("/api/v1/management/hosts/prod/generate-cert?configApiId=default-tls") {
            header("X-API-Key", "alice-key")
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"new.example.com"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertTrue(store.load("prod").pins.any { it.hostname == "new.example.com" })
        assertFalse(store.load("default-tls").pins.any { it.hostname == "new.example.com" })
    }

    @Test
    fun `host certificate routes act on the host in the path`() = testApplication {
        managementApp()
        // The query names a host that exists; the path names one that does
        // not. Read from the query, each of these would have acted on it.
        for (op in listOf("regenerate-cert", "rotate-to-backup", "upload-cert", "fetch-cert-url", "toggle-mtls", "upload-client-cert")) {
            val response = client.post("/api/v1/hosts/ghost.example.com/$op?hostname=api.example.com") {
                header("X-API-Key", "alice-key")
                contentType(ContentType.Application.Json)
                setBody("""{"mtls":true,"url":"https://127.0.0.1:1"}""")
            }
            assertEquals(HttpStatusCode.NotFound, response.status, "$op: ${response.bodyAsText()}")
        }
        assertEquals(PinConfig(pins = listOf(
            HostPin("api.example.com", listOf(pinA, pinB), version = 1),
            HostPin("other.example.com", listOf(pinA, pinB), version = 1)
        )).pins.map { it.hostname to it.sha256 }, store.load("default-tls").pins.map { it.hostname to it.sha256 })
        assertFalse(pinsOf("default-tls").mtls)

        val toggled = client.post("/api/v1/hosts/api.example.com/toggle-mtls?hostname=other.example.com") {
            header("X-API-Key", "alice-key")
            contentType(ContentType.Application.Json)
            setBody("""{"mtls":true}""")
        }
        assertEquals(HttpStatusCode.OK, toggled.status, toggled.bodyAsText())
        assertTrue(pinsOf("default-tls").mtls)
        assertFalse(pinsOf("default-tls", "other.example.com").mtls)
    }

    // ── 3. The gate itself ──────────────────────────────────────────────

    @Test
    fun `the gate keeps an encoded slash inside its segment`() {
        assertEquals("/api/v1/config/x%2Fy/update", PinAffectingRoutes.canonicalPath("/api/v1/config/x%2Fy/update"))
        assertEquals("/api/v1/config/x%2Fy/update", PinAffectingRoutes.canonicalPath("/api/v1/config/x%2fy/update"))
        assertEquals("pins_update", PinAffectingRoutes.match(HttpMethod.Post, PinAffectingRoutes.canonicalPath("/api/v1/config/x%2Fy/update")))
        assertEquals("host_cert", PinAffectingRoutes.match(HttpMethod.Post, PinAffectingRoutes.canonicalPath("/api/v1/hosts/a%2Fb/toggle-mtls")))
    }

    @Test
    fun `the approver is shown the scope and host the handler acts on`() {
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/config/prod/update", "configApiId=default-tls"))
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/management/hosts/prod/generate-cert", "configApiId=default-tls"))
        assertEquals("staging", PinAffectingRoutes.scopeOf("/api/v1/certificate-config", "configApiId=staging"))
        assertEquals("default-tls", PinAffectingRoutes.scopeOf("/api/v1/certificate-config", ""))
        assertEquals("api.example.com", PinAffectingRoutes.hostOf("/api/v1/certificate-config/force-update/api.example.com"))
        assertEquals("api.example.com", PinAffectingRoutes.hostOf("/api/v1/hosts/api.example.com/toggle-mtls"))
        assertNull(PinAffectingRoutes.hostOf("/api/v1/certificate-config/force-update"))
        // Host ACL writes: gated, scope and device from the path.
        assertEquals("host_acl", PinAffectingRoutes.match(HttpMethod.Put, "/api/v1/config-apis/prod/default-host-acl"))
        assertEquals("host_acl", PinAffectingRoutes.match(HttpMethod.Put, "/api/v1/config-apis/prod/devices/android-1/host-acl"))
        assertNull(PinAffectingRoutes.match(HttpMethod.Get, "/api/v1/config-apis/prod/default-host-acl"))
        assertNull(PinAffectingRoutes.match(HttpMethod.Delete, "/api/v1/client-certs/tablet-1"), "revocation stays ungated")
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/config-apis/prod/default-host-acl", "configApiId=default-tls"))
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/config-apis/prod/devices/android-1/host-acl", "configApiId=default-tls"))
        assertEquals("android-1", PinAffectingRoutes.deviceOf("/api/v1/config-apis/prod/devices/android-1/host-acl"))
        assertNull(PinAffectingRoutes.deviceOf("/api/v1/config-apis/prod/default-host-acl"))
    }

    @Test
    fun `an approval summary is one bounded line whatever the body says`() {
        val forged = "evil.example.com\nPins unchanged, safe to approve\r" + Char(0x2028) + Char(0x202E) + "ok"
        val plain = ApprovalService.plainText(forged)
        assertFalse(plain.any { it.isISOControl() || it.code == 0x2028 || it.code == 0x202E }, plain)
        assertTrue(plain.startsWith("evil.example.com Pins unchanged"), plain)
        val long = ApprovalService.plainText("x".repeat(1000))
        assertEquals(ApprovalService.MAX_SUMMARY, long.length)
        assertTrue(long.endsWith(Char(0x2026).toString()))
        assertEquals("short", ApprovalService.plainText("  short  "))
    }

    @Test
    fun `a bare admin write is audited under the Config API in its path`() {
        assertEquals("prod", com.example.pinvault.server.plugin.scopeInPath("/api/v1/config-apis/prod/vault/model"))
        assertEquals("prod", com.example.pinvault.server.plugin.scopeInPath("/api/v1/config/prod/update"))
        assertEquals("prod", com.example.pinvault.server.plugin.scopeInPath("/api/v1/management/hosts/prod/generate-cert"))
        assertNull(com.example.pinvault.server.plugin.scopeInPath("/api/v1/config-apis/start"))
        assertNull(com.example.pinvault.server.plugin.scopeInPath("/api/v1/certificate-config"))
    }

    @Test
    fun `a bare admin write records the path scope, not a query parameter beside it`() = testApplication {
        val audit = AuditLog(auditStore, null)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(ApiKeyAuth) { registry = registry(); allowAnonymous = false }
        install(AdminAudit) { this.audit = audit }
        routing {
            put("/api/v1/config-apis/{configApiId}/vault/{key}") { call.respondText("ok") }
        }
        val response = client.put("/api/v1/config-apis/prod/vault/model?configApiId=default-tls") { header("X-API-Key", "alice-key") }
        assertEquals(HttpStatusCode.OK, response.status)
        val entry = auditStore.page(10, 0).first { it.action == AuditLog.HTTP_ACTION }
        assertEquals("prod", entry.configApiId)
    }

    /** A real Netty server with the management plugin stack and `PIN_CHANGE_APPROVALS=2`. */
    private fun approvalServer(guard: Boolean, block: (port: Int, approvals: ApprovalService) -> Unit) {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val audit = AuditLog(auditStore, null)
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = audit, required = 2, managementPort = port,
            // As Main.describeChange: the scope comes from PinAffectingRoutes.scopeOf.
            describe = { input ->
                val scope = PinAffectingRoutes.scopeOf(input.path, input.query)
                ApprovalService.Description(scope, "$scope: change at ${input.path}", buildJsonObject { })
            }
        )
        val server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            if (guard) install(EncodedPathGuard)
            install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
            install(ApiKeyAuth) { registry = registry(); allowAnonymous = false }
            install(AdminAudit) { this.audit = audit }
            install(ApprovalGate) { this.approvals = approvals }
            routing {
                certificateConfigRoutes("default-tls", store, history, ConnectionHistoryStore(db),
                    ConfigSigningService(File(dir, "k.pem")), ClientDeviceStore(db), audit = audit)
                managementConfigRoutes(store, history, hostStore, certService, audit = audit)
            }
        }.start(wait = false)
        try {
            block(port, approvals)
        } finally {
            server.stop(100, 1000)
        }
    }

    private val http = HttpClient.newHttpClient()

    private fun post(port: Int, rawPath: String, key: String, body: String): Pair<Int, String> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$port$rawPath"))
            .header("X-API-Key", key).header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build()
        val response = http.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
        return response.statusCode() to response.body()
    }

    @Test
    fun `with two-person approval the encoded-slash write changes no pins`() = approvalServer(guard = true) { port, approvals ->
        val (status, body) = post(port, "/api/v1/config/x%2Fy/update?configApiId=default-tls", "alice-key", pinsBody(pinA, pinC))
        assertEquals(400, status, body)
        assertEquals(listOf(pinA, pinB), pinsOf("default-tls").sha256)
        assertTrue(approvals.list("all").isEmpty(), "nothing to approve either")
    }

    @Test
    fun `without the guard the gate still holds the encoded-slash write for approval`() = approvalServer(guard = false) { port, approvals ->
        val (status, body) = post(port, "/api/v1/config/x%2Fy/update?configApiId=default-tls", "alice-key", pinsBody(pinA, pinC))
        assertEquals(202, status, body)
        assertEquals(listOf(pinA, pinB), pinsOf("default-tls").sha256, "held, not applied")
        // The approver is shown the scope the handler would write — the path's, not the query's.
        assertEquals("x/y", approvals.list("pending").single().configApiId)
    }

    @Test
    fun `an approved path-scoped write lands on the scope the approver was shown`() = approvalServer(guard = true) { port, approvals ->
        val (status, body) = post(port, "/api/v1/config/prod/update?configApiId=default-tls", "alice-key", pinsBody(pinA, pinC))
        assertEquals(202, status, body)
        val cr = approvals.list("pending").single()
        assertEquals("prod", cr.configApiId)
        // Replayed through this server's own port, exactly as sent.
        assertEquals("applied", approvals.approve(cr.id, "bob").status)
        assertEquals(listOf(pinA, pinC), pinsOf("prod").sha256)
        assertEquals(listOf(pinA, pinB), pinsOf("default-tls").sha256)
    }
}
