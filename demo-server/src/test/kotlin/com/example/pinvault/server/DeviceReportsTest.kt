package com.example.pinvault.server

import com.example.pinvault.server.route.ReportLimits
import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import kotlin.test.*

/**
 * Device reports are claims, not facts (O15): every field is checked or cut
 * to size, the time is the server's, reports are rate limited per address and
 * per device, on mTLS a device reports for itself only — and a flood of
 * made-up reports can no longer erase another Config API's history or push
 * the failures out of its own.
 */
class DeviceReportsTest {

    private val scopeA = "api-a"
    private val scopeB = "api-b"
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var dist: VaultDistributionStore
    private lateinit var connections: ConnectionHistoryStore
    private lateinit var clientCerts: ClientCertStore
    private lateinit var signingFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-reports-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        dist = VaultDistributionStore(db)
        connections = ConnectionHistoryStore(db)
        clientCerts = ClientCertStore(db)
        signingFile = File.createTempFile("pinvault-reports-signing-", ".pem").also { it.delete(); it.deleteOnExit() }
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); signingFile.delete() }

    // ── helpers ──────────────────────────────────────────────────────────

    /** Both scopes on one test application: `/a/...` is [scopeA], `/b/...` is [scopeB]. */
    private fun ApplicationTestBuilder.configureApp(limits: ReportLimits? = null, presented: X509Certificate? = null) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        if (presented != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
            })
        }
        val signing = ConfigSigningService(signingFile)
        val vaultTokens = VaultFileTokenStore(db)
        routing {
            for ((prefix, scope) in listOf("/a" to scopeA, "/b" to scopeB)) {
                route(prefix) {
                    vaultRoutes(scope, VaultFileStore(db), dist, vaultTokens, DevicePublicKeyStore(db),
                        VaultAccessTokenService(vaultTokens), VaultEncryptionService(),
                        clientCertStore = clientCerts, reportLimits = limits)
                    certificateConfigRoutes(scope, PinConfigStore(db), PinConfigHistoryStore(db), connections,
                        signing, ClientDeviceStore(db), reportLimits = limits)
                }
            }
        }
    }

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private suspend fun ApplicationTestBuilder.post(path: String, body: String): HttpResponse =
        client.post(path) { contentType(ContentType.Application.Json); setBody(body) }

    private suspend fun ApplicationTestBuilder.vaultReport(prefix: String, body: String) = post("$prefix/api/v1/vault/report", body)
    private suspend fun ApplicationTestBuilder.clientReport(prefix: String, body: String) =
        post("$prefix/api/v1/connection-history/client-report", body)
    private suspend fun ApplicationTestBuilder.configReport(prefix: String, body: String) =
        post("$prefix/api/v1/connection-history/config-update-report", body)

    // ── vault report: every field ────────────────────────────────────────

    @Test
    fun `a vault report with a field out of shape is a 400 and nothing is stored`() = testApplication {
        configureApp()
        val refused = listOf(
            "key" to """{"key":"../../etc","version":1,"deviceId":"d1","status":"downloaded"}""",
            "key" to """{"version":1,"deviceId":"d1","status":"downloaded"}""",
            "deviceId" to """{"key":"model","version":1,"deviceId":"<img src=x onerror=alert(1)>","status":"downloaded"}""",
            "deviceId" to """{"key":"model","version":1,"deviceId":"${"d".repeat(65)}","status":"downloaded"}""",
            "status" to """{"key":"model","version":1,"deviceId":"d1","status":"pwned"}""",
            "version" to """{"key":"model","version":-4,"deviceId":"d1","status":"downloaded"}""",
            "authMethod" to """{"key":"model","version":1,"deviceId":"d1","status":"downloaded","authMethod":"<b>root</b>"}"""
        )
        for ((field, body) in refused) {
            val response = vaultReport("/a", body)
            assertEquals(HttpStatusCode.BadRequest, response.status, body)
            assertTrue(response.bodyAsText().contains("\"field\":\"$field\""), "${response.bodyAsText()} for $body")
        }
        // Not JSON, or JSON of another shape: a 400, never a 500.
        for (body in listOf("not json", "[1,2]", """{"key":{"a":1},"deviceId":["x"],"status":7}""")) {
            assertEquals(HttpStatusCode.BadRequest, vaultReport("/a", body).status, body)
        }
        assertTrue(dist.getAll(scopeA).isEmpty())
    }

    @Test
    fun `free text is cut to a printable line and the time is the server's`() = testApplication {
        configureApp()
        val before = Instant.now().minusSeconds(5)
        val response = vaultReport("/a", buildJsonObject {
            put("key", "model"); put("version", 3); put("deviceId", "android-1"); put("status", "failed")
            put("deviceManufacturer", "<script>Acme</script> Corp"); put("deviceModel", "moto g(7) power")
            put("enrollmentLabel", "x".repeat(500)); put("deviceAlias", "Ali's phone\u0000\n")
            put("failureReason", "HTTP 401\nline two\u0007" + "z".repeat(5_000))
            put("authMethod", "token")
            put("timestamp", "1999-01-01T00:00:00Z")
        }.toString())
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())

        val row = dist.getAll(scopeA).single()
        assertEquals("scriptAcmescript Corp", row.deviceManufacturer)
        assertEquals("moto g(7) power", row.deviceModel, "a real model name is kept")
        assertEquals(64, row.enrollmentLabel!!.length)
        assertEquals("Ali's phone", row.deviceAlias)
        assertEquals(300, row.failureReason!!.length)
        assertTrue(row.failureReason!!.startsWith("HTTP 401 line two"))
        assertTrue(row.failureReason!!.none { it.isISOControl() })
        assertEquals("token", row.authMethod)
        assertTrue(Instant.parse(row.timestamp).isAfter(before), "the reported time was not taken: ${row.timestamp}")
    }

    @Test
    fun `an Apple model identifier keeps its comma and nothing else is let through`() = testApplication {
        configureApp()
        val response = vaultReport("/a", buildJsonObject {
            put("key", "model"); put("version", 1); put("deviceId", "ios-1"); put("status", "downloaded")
            put("deviceManufacturer", "Apple"); put("deviceModel", "iPhone17,1")
            put("enrollmentLabel", "iPad16,3 <img src=x onerror=alert(1)>"); put("deviceAlias", "Ali's iPhone,\"x\";\n")
        }.toString())
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())

        val row = dist.getAll(scopeA).single()
        assertEquals("iPhone17,1", row.deviceModel, "iPhone17,1 and iPhone1,71 must not read the same")
        assertEquals("iPad16,3 img srcx onerroralert(1)", row.enrollmentLabel)
        assertEquals("Ali's iPhone,x", row.deviceAlias)
        for (shown in listOf(row.deviceModel!!, row.enrollmentLabel!!, row.deviceAlias!!)) {
            assertTrue(shown.none { it in "<>\"&;=\n" || it.isISOControl() }, shown)
        }
        assertEquals("iPhone17,1", com.example.pinvault.server.route.displayAlias(" iPhone17,1 "))
    }

    // ── the eviction attack ──────────────────────────────────────────────

    @Test
    fun `a flood of made-up downloads erases neither another scope's history nor its own failures`() = testApplication {
        configureApp()
        // Real history: scope A, and one failure in scope B.
        vaultReport("/a", """{"key":"model","version":1,"deviceId":"real-a1","status":"downloaded"}""")
        vaultReport("/a", """{"key":"model","version":0,"deviceId":"real-a2","status":"failed","failureReason":"HTTP 401"}""")
        vaultReport("/b", """{"key":"model","version":0,"deviceId":"real-b1","status":"failed","failureReason":"signature mismatch"}""")

        // 600 forged "downloaded" reports for scope B — more than the whole table used to keep.
        repeat(600) {
            assertEquals(HttpStatusCode.OK, vaultReport("/b", """{"key":"model","version":9,"deviceId":"fake-$it","status":"downloaded"}""").status)
        }

        // Scope A is untouched.
        assertEquals(setOf("real-a1", "real-a2"), dist.getByKey(scopeA, "model").map { it.deviceId }.toSet())
        // Scope B's failure is still there, and its healthy rows are capped on their own.
        assertEquals(listOf("real-b1"), dist.getByDevice(scopeB, "real-b1").map { it.deviceId })
        val statsB = dist.getStats(scopeB)
        assertEquals(1, statsB.failed)
        assertEquals(VaultDistributionStore.MAX_OK_ROWS, statsB.downloaded)
        assertEquals(1, dist.getStats(scopeA).failed)
    }

    @Test
    fun `healthy noise cannot push a pin mismatch out of the connection history`() = testApplication {
        configureApp()
        clientReport("/a", """{"hostname":"api.bank.example","status":"pin_mismatch","pinMatched":false,"pinVersion":4,"deviceManufacturer":"Google","deviceModel":"Pixel 8","serverCertPin":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","storedPin":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}""")
        configReport("/a", """{"status":"config_update_failed","pinVersion":4,"deviceManufacturer":"Google","deviceModel":"Pixel 8","failureReason":"signature invalid"}""")
        clientReport("/b", """{"hostname":"api.shop.example","status":"healthy","pinMatched":true,"pinVersion":2,"deviceManufacturer":"Google","deviceModel":"Pixel 8"}""")

        // The attack the review describes, and then some: 450 forged "healthy" reports to scope A.
        repeat(450) {
            assertEquals(HttpStatusCode.OK, clientReport("/a",
                """{"hostname":"api.bank.example","status":"healthy","pinMatched":true,"pinVersion":4,"deviceManufacturer":"Fake","deviceModel":"Fake $it"}""").status)
        }

        val all = connections.getAll()
        assertEquals(1, all.count { it.status == "pin_mismatch" }, "the real mismatch is still on the dashboard")
        assertEquals(1, all.count { it.status == "config_update_failed" })
        assertEquals(1, all.count { it.hostname == "api.shop.example" }, "another Config API's history is untouched")
        assertEquals(ConnectionHistoryStore.MAX_OK_ROWS + 1, all.count { it.status == "healthy" }, "scope A's healthy rows are capped; scope B keeps its one")
    }

    // ── connection reports: every field ──────────────────────────────────

    @Test
    fun `connection reports take only the library's statuses, well-formed pins and the server's time`() = testApplication {
        configureApp()
        val ok = """"hostname":"api.example.com","deviceManufacturer":"Google","deviceModel":"Pixel 8""""
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{$ok,"status":"all good, nothing to see"}""").status)
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{$ok}""").status, "no status")
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{$ok,"status":"healthy","pinVersion":-1}""").status)
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{$ok,"status":"pin_mismatch","serverCertPin":"<svg onload=x>"}""").status)
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{$ok,"status":"pin_mismatch","storedPin":"${"A".repeat(200)}"}""").status)
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{"hostname":"<b>x</b>","status":"healthy"}""").status)
        assertEquals(HttpStatusCode.BadRequest, clientReport("/a", """{"hostname":{"a":1},"status":["healthy"]}""").status)
        assertEquals(HttpStatusCode.BadRequest, configReport("/a", """{"status":"healthy"}""").status, "a connection status is not a config-update status")
        assertEquals(HttpStatusCode.BadRequest, configReport("/a", """{"status":"config_updated","pinVersion":-2}""").status)
        assertEquals(HttpStatusCode.BadRequest, configReport("/a", "nope").status)
        assertTrue(connections.getAll().isEmpty())

        val before = Instant.now().minusSeconds(5)
        assertEquals(HttpStatusCode.OK, clientReport("/a",
            """{$ok,"status":"pin_mismatch","responseTimeMs":99999999999,"timestamp":"1999-01-01T00:00:00Z","errorMessage":"${"e".repeat(2_000)}"}""").status)
        assertEquals(HttpStatusCode.OK, configReport("/a",
            """{"status":"config_update_failed","timestamp":"2999-01-01T00:00:00Z","failureReason":"${"r".repeat(2_000)}"}""").status)
        val rows = connections.getAll()
        assertEquals(2, rows.size)
        for (row in rows) {
            assertTrue(Instant.parse(row.timestamp).isAfter(before) && Instant.parse(row.timestamp).isBefore(Instant.now().plusSeconds(5)), row.timestamp)
            assertEquals(300, row.errorMessage!!.length)
        }
        assertEquals(600_000, rows.first { it.status == "pin_mismatch" }.responseTimeMs)
    }

    // ── rate limits ──────────────────────────────────────────────────────

    @Test
    fun `reports are limited per source address, whatever device they name`() = testApplication {
        configureApp(ReportLimits(perAddress = RateLimiter(maxAttempts = 4, windowMs = 60_000)))
        val statuses = listOf(
            vaultReport("/a", """{"key":"model","version":1,"deviceId":"d1","status":"downloaded"}""").status,
            vaultReport("/b", """{"key":"model","version":1,"deviceId":"d2","status":"downloaded"}""").status,
            clientReport("/a", """{"hostname":"h","status":"healthy"}""").status,
            configReport("/a", """{"status":"config_updated"}""").status,
            vaultReport("/a", """{"key":"model","version":1,"deviceId":"d3","status":"downloaded"}""").status,
            clientReport("/b", """{"hostname":"h","status":"pin_mismatch"}""").status,
            configReport("/b", """{"status":"config_update_failed"}""").status
        )
        assertEquals(List(4) { HttpStatusCode.OK } + List(3) { HttpStatusCode.TooManyRequests }, statuses)
        assertEquals(2, dist.getAll().size)
        assertEquals(2, connections.getAll().size)
    }

    @Test
    fun `on TLS a claimed device id is not a quota anyone can use up`() = testApplication {
        // Counted per device, a stranger naming a victim's id used up its quota and
        // its real reports were refused. On TLS only the address counts.
        configureApp(ReportLimits(perDevice = RateLimiter(maxAttempts = 2, windowMs = 60_000)))
        fun body(device: String) = """{"key":"model","version":1,"deviceId":"$device","status":"downloaded"}"""
        repeat(5) { assertEquals(HttpStatusCode.OK, vaultReport("/a", body("d1")).status) }
        assertEquals(5, dist.getByDevice(scopeA, "d1").size)
    }

    @Test
    fun `over mTLS reports are limited per certificate within a scope`() = testApplication {
        clientCerts.add("tablet-r", "PinVault Client: tablet-r", "fp", Instant.now().toString(), deviceUid = "android-r")
        configureApp(ReportLimits(perDevice = RateLimiter(maxAttempts = 2, windowMs = 60_000)), presented = clientCert("tablet-r"))
        fun body() = """{"key":"model","version":1,"deviceId":"android-r","status":"downloaded"}"""
        assertEquals(HttpStatusCode.OK, vaultReport("/a", body()).status)
        assertEquals(HttpStatusCode.OK, vaultReport("/a", body()).status)
        val third = vaultReport("/a", body())
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertTrue(third.bodyAsText().contains("rate_limited"))
        assertEquals(HttpStatusCode.OK, vaultReport("/b", body()).status, "the same certificate in another scope")
    }

    // ── mTLS: a device reports for itself ────────────────────────────────

    @Test
    fun `on an mTLS listener a report must be about the certificate's own device`() = testApplication {
        clientCerts.add("tablet-1", "PinVault Client: tablet-1", "fp", Instant.now().toString(), deviceUid = "android-1")
        configureApp(presented = clientCert("tablet-1"))

        val forged = vaultReport("/a", """{"key":"model","version":9,"deviceId":"victim-phone","status":"downloaded"}""")
        assertEquals(HttpStatusCode.Forbidden, forged.status)
        assertTrue(forged.bodyAsText().contains("device_identity_mismatch"))
        assertEquals(HttpStatusCode.Forbidden, vaultReport("/a", """{"key":"model","version":9,"deviceId":"unknown","status":"downloaded"}""").status)
        assertTrue(dist.getAll(scopeA).isEmpty())

        // Its device id, its client id, or none at all (filed under its device).
        assertEquals(HttpStatusCode.OK, vaultReport("/a", """{"key":"model","version":1,"deviceId":"android-1","status":"downloaded"}""").status)
        assertEquals(HttpStatusCode.OK, vaultReport("/a", """{"key":"model","version":1,"deviceId":"tablet-1","status":"cached"}""").status)
        assertEquals(HttpStatusCode.OK, vaultReport("/a", """{"key":"model","version":1,"status":"cached"}""").status)
        assertEquals(listOf("android-1", "tablet-1", "android-1"), dist.getAll(scopeA).map { it.deviceId })
    }

    @Test
    fun `on a TLS listener a report without a device id is filed under unknown`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, vaultReport("/a", """{"key":"model","version":1}""").status)
        val row = dist.getAll(scopeA).single()
        assertEquals("unknown", row.deviceId)
        assertEquals("downloaded", row.status)
    }
}
