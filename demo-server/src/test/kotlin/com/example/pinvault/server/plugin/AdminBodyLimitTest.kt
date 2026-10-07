package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.OutgoingContent
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.*

/**
 * Admin JSON routes read their body with `call.receive<JsonObject>()`, which
 * has no cap of its own: a leaked admin key could make the server buffer
 * anything. [installAdminBodyLimit] puts `ADMIN_UPLOAD_MAX_BYTES` on them,
 * keeps the vault upload at `VAULT_MAX_FILE_BYTES`, and leaves the device
 * endpoints to [ClientBodyLimit].
 */
class AdminBodyLimitTest {

    private val scope = "cap-admin"
    private val adminMax = 4_096L
    private val vaultMax = 16_384L
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var pins: PinConfigStore
    private lateinit var vaultFiles: VaultFileStore
    private var handlerRuns = 0

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-admin-cap-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        pins = PinConfigStore(db).also { it.ensureConfigExists(scope) }
        vaultFiles = VaultFileStore(db)
        handlerRuns = 0
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    /** A body of [bytes] bytes written to the channel: no Content-Length, no Transfer-Encoding. */
    private class Streamed(private val bytes: Int) : OutgoingContent.WriteChannelContent() {
        override val contentType = ContentType.Application.Json
        override suspend fun writeTo(channel: ByteWriteChannel) {
            val chunk = ByteArray(8 * 1024) { ' '.code.toByte() }
            var left = bytes
            while (left > 0) {
                val n = minOf(left, chunk.size)
                channel.writeFully(chunk, 0, n)
                left -= n
            }
        }
    }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(StatusPages) { genericErrors { "e1d2c3b4" } }
        install(ClientBodyLimit)
        application { installAdminBodyLimit(adminMax, vaultMax) }
        val tokens = VaultFileTokenStore(db)
        routing {
            certificateConfigRoutes(scope, pins, PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(dbFile.parentFile, "cap-admin-${System.nanoTime()}.pem")), ClientDeviceStore(db))
            vaultRoutes(scope, vaultFiles, VaultDistributionStore(db), tokens, DevicePublicKeyStore(db),
                VaultAccessTokenService(tokens), VaultEncryptionService(), maxFileBytes = vaultMax)
            scopedVaultAdminRoutes(vaultFiles, VaultDistributionStore(db), tokens, VaultAccessTokenService(tokens), maxFileBytes = vaultMax)
            // An admin route that reads without any cap of its own.
            post("/api/v1/unbounded") { handlerRuns++; call.receiveText(); call.respondText("ok") }
        }
    }

    /** A valid config body padded with whitespace to [size] bytes. */
    private fun paddedConfig(size: Int): String {
        val body = """{"version":0,"forceUpdate":false,"pins":[{"hostname":"a.example.com","sha256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="]}]}"""
        return body + " ".repeat(size - body.length)
    }

    @Test
    fun `an admin PUT above the cap is answered 413 and the handler never runs`() = testApplication {
        configureApp()
        val declared = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json); setBody(paddedConfig(adminMax.toInt() + 1))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, declared.status, declared.bodyAsText())
        assertTrue(declared.bodyAsText().contains("body_too_large"), declared.bodyAsText())
        assertTrue(pins.load(scope).pins.isEmpty(), "nothing was stored")

        val streamed = client.put("/api/v1/certificate-config") { setBody(Streamed(adminMax.toInt() + 1)) }
        assertEquals(HttpStatusCode.PayloadTooLarge, streamed.status, "cut off while it is read, without a length")
        assertTrue(pins.load(scope).pins.isEmpty())

        // A route with no cap of its own has this one.
        val big = client.post("/api/v1/unbounded") { setBody(ByteArray(adminMax.toInt() + 1)) }
        assertEquals(HttpStatusCode.PayloadTooLarge, big.status)
        assertEquals(0, handlerRuns, "refused before the handler, from the declared length")
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/unbounded") { setBody(ByteArray(adminMax.toInt())) }.status)
        assertEquals(1, handlerRuns)

        // ...and a body at the cap goes through to the handler.
        val fits = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json); setBody(paddedConfig(adminMax.toInt()))
        }
        assertEquals(HttpStatusCode.OK, fits.status, fits.bodyAsText())
        assertEquals(1, pins.load(scope).pins.size)
    }

    @Test
    fun `a vault upload keeps its own, larger cap`() = testApplication {
        configureApp()
        val base = "/api/v1/config-apis/$scope/vault"
        val under = client.put("$base/model.bin") {
            contentType(ContentType.Application.OctetStream); setBody(ByteArray(vaultMax.toInt() - 1) { 7 })
        }
        assertEquals(HttpStatusCode.OK, under.status, under.bodyAsText())
        assertEquals(vaultMax.toInt() - 1, vaultFiles.get(scope, "model.bin")!!.content.size)

        val over = client.put("$base/model.bin") {
            contentType(ContentType.Application.OctetStream); setBody(ByteArray(vaultMax.toInt() + 1))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, over.status)
        assertEquals(vaultMax.toInt() - 1, vaultFiles.get(scope, "model.bin")!!.content.size, "the stored file is the one under the cap")
    }

    @Test
    fun `device endpoints stay under ClientBodyLimit, not the admin cap`() = testApplication {
        configureApp()
        // Above the admin cap, under the device cap: not this plugin's refusal.
        val report = client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json); setBody(" ".repeat(adminMax.toInt() + 1) + "{}")
        }
        assertNotEquals(HttpStatusCode.PayloadTooLarge, report.status, report.bodyAsText())
        // Above the device cap: ClientBodyLimit's 413.
        val huge = client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json); setBody(ByteArray(DEFAULT_CLIENT_BODY_MAX_BYTES.toInt() + 1))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, huge.status)
    }

    @Test
    fun `the cap per route`() {
        fun limit(method: HttpMethod, path: String) = adminBodyLimit(method, path, 1_000, 5_000)
        assertEquals(1_000, limit(HttpMethod.Put, "/api/v1/certificate-config"))
        assertEquals(1_000, limit(HttpMethod.Post, "/api/v1/hosts/a.example.com/toggle-mtls"))
        assertEquals(1_000, limit(HttpMethod.Put, "/api/v1/signing-keyset"))
        assertEquals(5_000, limit(HttpMethod.Put, "/api/v1/config-apis/default-tls/vault/model.bin"))
        assertEquals(5_000, limit(HttpMethod.Put, "/api//v1/config-apis/default-tls/vault/model.bin"), "the path as routing sees it")
        assertEquals(Long.MAX_VALUE, limit(HttpMethod.Post, "/api/v1/client-certs/enroll"))
        assertEquals(Long.MAX_VALUE, limit(HttpMethod.Post, "/api/v1/vault/report"))
        assertEquals(Long.MAX_VALUE, limit(HttpMethod.Post, "/api/v1/attest"))
    }
}
