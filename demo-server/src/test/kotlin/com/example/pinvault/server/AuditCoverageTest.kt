package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.GovernanceHarness.Companion.multipart
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.WebhookNotifier
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.ClientCertStore
import com.example.pinvault.server.store.ClientDeviceStore
import com.example.pinvault.server.store.ClientIdentityStore
import com.example.pinvault.server.store.ConnectionHistoryStore
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.EnrollmentTokenStore
import com.example.pinvault.server.store.PinConfigHistoryStore
import com.example.pinvault.server.store.PinConfigStore
import io.ktor.client.request.post
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
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What used to leave no specific trace: a private key made for a device, a
 * token minted, a vault file replaced, a host list changed, a key downloaded.
 * And what left too many: refused enrollments, one audit row per request.
 */
class AuditCoverageTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var auditStore: AuditLogStore
    private lateinit var tokens: EnrollmentTokenStore
    private lateinit var clientCerts: ClientCertStore

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-audit-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        auditStore = AuditLogStore(db)
        tokens = EnrollmentTokenStore(db)
        clientCerts = ClientCertStore(db)
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun ApplicationTestBuilder.enrollmentApp(refusals: AuthFailureRecorder?) {
        val audit = AuditLog(auditStore, null)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                "default-tls", PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(dir, "k.pem")), ClientDeviceStore(db),
                certService = CertificateService(File(dir, "certs").also { it.mkdirs() }),
                enrollmentTokenStore = tokens, clientCertStore = clientCerts, audit = audit,
                clientIdentityStore = ClientIdentityStore(db), enrollRefusals = refusals
            )
        }
    }

    private suspend fun ApplicationTestBuilder.enroll(token: String) = client.post("/api/v1/client-certs/enroll") {
        contentType(ContentType.Application.Json)
        setBody("""{"token":"$token","deviceUid":"android-01"}""")
    }

    @Test
    fun `a server-made P12 is audited as an issued certificate, with its format`() = testApplication {
        enrollmentApp(null)
        val response = enroll(tokens.create("dev-1"))
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val entry = auditStore.page(10, 0, "client_cert_issued").single()
        assertEquals("dev-1", entry.target)
        assertEquals("default-tls", entry.configApiId)
        assertEquals("p12", Json.parseToJsonElement(entry.detail).jsonObject["format"]!!.jsonPrimitive.content)
        assertTrue(entry.summary.contains("server-made P12"), entry.summary)
    }

    @Test
    fun `refused enrollments are summarised, not written one row per request`() = testApplication {
        val recorder = AuthFailureRecorder(AuditLog(auditStore, null), windowMs = 60_000,
            action = "client_cert_enroll_refused", what = "Enrollment refused", attemptsLabel = "refused enrollment")
        enrollmentApp(recorder)
        // A token is not spent by a refusal: its holder can repeat the request at will.
        val token = tokens.create("dev-1")
        clientCerts.add("dev-1", "PinVault Client: dev-1", "fp", "2026-01-01T00:00:00Z")
        clientCerts.revoke("dev-1")

        repeat(30) { assertEquals(HttpStatusCode.Forbidden, enroll(token).status) }
        assertEquals(1, auditStore.count("client_cert_enroll_refused"), "the first refusal of a minute is recorded at once")
        val first = auditStore.page(1, 0, "client_cert_enroll_refused").single()
        assertTrue(first.summary.contains("revoked client id dev-1"), first.summary)
        assertEquals("dev-1", first.actor)

        recorder.flush()
        val entries = auditStore.page(10, 0, "client_cert_enroll_refused")
        assertEquals(2, entries.size)
        assertTrue(entries.first().summary.startsWith("29 more refused enrollment attempt(s)"), entries.first().summary)
        assertTrue(auditStore.verify().ok)
    }

    @Test
    fun `admin writes that change what devices get are audited under their own actions`() {
        GovernanceHarness(dir, required = 1).use { h ->
            val base = "/api/v1/config-apis/${h.scope}"
            h.registry.ensureRegistered(h.scope, 8443, "tls")
            assertEquals(200, h.call("PUT", "$base/vault/flags?policy=token", ALICE, "v1".toByteArray(), "application/octet-stream").status)
            assertEquals(200, h.call("PUT", "$base/vault/flags/policy", ALICE, """{"access_policy":"public","encryption":"plain"}""").status)
            val token = h.call("POST", "$base/vault/flags/tokens", ALICE, """{"deviceId":"dev-1"}""")
            assertEquals(200, token.status, token.body)
            val tokenId = token.json["id"]!!.jsonPrimitive.content
            assertEquals(200, h.call("DELETE", "$base/vault/tokens/$tokenId", ALICE).status)
            assertEquals(200, h.call("DELETE", "$base/vault/flags", ALICE).status)
            assertEquals(200, h.call("PUT", "$base/vault-enabled", ALICE, """{"enabled":false}""").status)
            assertEquals(200, h.call("PUT", "$base/default-host-acl", ALICE, """{"hostnames":["a.example.com","b.example.com"]}""").status)
            assertEquals(200, h.call("PUT", "$base/devices/dev-1/host-acl", ALICE, """{"hostnames":["c.example.com"]}""").status)
            assertEquals(200, h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, """{"clientId":"dev-2"}""").status)
            assertEquals(200, h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"dev-3"}""").status)

            val expected = listOf(
                "vault_file_uploaded", "vault_policy_changed", "vault_token_issued", "vault_token_revoked", "vault_file_deleted",
                "vault_enabled_changed", "host_acl_changed", "enrollment_token_created", "client_cert_generated"
            )
            val actions = h.actions()
            for (action in expected) assertTrue(action in actions, "$action missing from $actions")
            assertEquals(2, actions.count { it == "host_acl_changed" }, "the default list and the device's own")
            // A call with a specific entry is not also logged as a bare "http" one.
            assertFalse("http" in actions, actions.toString())
            // The token itself is in neither the summary nor the detail.
            val secret = token.json["token"]!!.jsonPrimitive.content
            assertFalse(h.auditStore.page(100, 0).any { secret in it.summary || secret in it.detail })
            val acl = h.auditStore.page(100, 0, "host_acl_changed").first()
            assertEquals("dev-1", acl.target)
            assertTrue(acl.summary.contains("c.example.com"), acl.summary)

            // Unchanged values write nothing more.
            val before = h.auditStore.count()
            assertEquals(200, h.call("PUT", "$base/vault-enabled", ALICE, """{"enabled":false}""").status)
            assertEquals(200, h.call("PUT", "$base/default-host-acl", ALICE, """{"hostnames":["a.example.com","b.example.com"]}""").status)
            assertEquals(before + 2, h.auditStore.count(), "two generic http entries, no false \"changed\"")
        }
    }

    @Test
    fun `downloading a host's client certificate with its private key is audited`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.seedHost("mtls.example.com")
            val p12 = h.certService.generateClientCertificate("host-client", "pw").p12Bytes
            val (type, body) = multipart(mapOf("password" to "pw"), p12, "client.p12")
            val uploaded = h.call("POST", "/api/v1/hosts/mtls.example.com/upload-client-cert", ALICE, body, type)
            assertEquals(200, uploaded.status, uploaded.body)
            assertFalse("private_key_downloaded" in h.actions())

            val download = h.call("GET", "/api/v1/hosts/mtls.example.com/client-cert/download", ALICE)
            assertEquals(200, download.status)
            val entry = h.auditStore.page(10, 0, "private_key_downloaded").single()
            assertEquals("alice", entry.actor)
            assertEquals("mtls.example.com", entry.target)
            assertEquals(404, h.call("GET", "/api/v1/hosts/other.example.com/client-cert/download", ALICE).status)
            assertEquals(1, h.auditStore.count("private_key_downloaded"), "a download that found nothing is not one")
        }
    }

    @Test
    fun `every new audit action reaches the webhook under the wildcard`() {
        val notifier = WebhookNotifier("http://127.0.0.1:1/hook", "secret", setOf("*"))
        for (action in listOf(
            "client_cert_issued", "client_cert_generated", "client_cert_uploaded", "enrollment_token_created",
            "vault_file_uploaded", "vault_file_deleted", "vault_policy_changed", "vault_token_issued", "vault_token_revoked",
            "vault_enabled_changed", "host_acl_changed", "private_key_downloaded", "bootstrap_pins_changed", "admin_request_refused"
        )) assertTrue(notifier.wants(action), action)

        // What a receiver recomputes: HMAC-SHA256 of "<timestamp>.<body>".
        val a = WebhookNotifier.signature("secret", "1790000000", """{"event":"x"}""")
        assertEquals(64, a.length)
        assertFalse(a == WebhookNotifier.signature("secret", "1790000001", """{"event":"x"}"""), "another timestamp, another signature")
        assertFalse(a == WebhookNotifier.signature("other", "1790000000", """{"event":"x"}"""))
        assertEquals(a, WebhookNotifier.signature("secret", "1790000000", """{"event":"x"}"""))
    }
}
