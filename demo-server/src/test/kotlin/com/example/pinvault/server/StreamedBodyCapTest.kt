package com.example.pinvault.server

import com.example.pinvault.server.plugin.ClientBodyLimit
import com.example.pinvault.server.plugin.DEFAULT_CLIENT_BODY_MAX_BYTES
import com.example.pinvault.server.plugin.receiveLimitedText
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertRenewalRoute
import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.RecoveryListener
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
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.serialization.json.Json
import java.io.File
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.cert.X509Certificate
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * The body cap on device endpoints holds for a body that declares no length
 * (O2). `Content-Length` and `Transfer-Encoding` were all that was looked at;
 * over HTTP/2 a request needs neither, and its body was read whole. Every
 * device route now reads through the cap, and so does anything else on a
 * capped path.
 */
class StreamedBodyCapTest {

    private val scope = "cap-api"
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private var listener: RecoveryListener? = null

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-cap-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-cap-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() {
        listener?.stop()
        dbFile.delete()
        certsDir.deleteRecursively()
    }

    /** A body of [bytes] bytes written to the channel: no Content-Length, no Transfer-Encoding. */
    private class Streamed(private val bytes: Int) : OutgoingContent.WriteChannelContent() {
        override val contentType = ContentType.Application.Json
        override suspend fun writeTo(channel: ByteWriteChannel) {
            val chunk = ByteArray(8 * 1024) { 'x'.code.toByte() }
            var left = bytes
            while (left > 0) {
                val n = minOf(left, chunk.size)
                channel.writeFully(chunk, 0, n)
                left -= n
            }
        }
    }

    private val deviceEndpoints = listOf(
        "/api/v1/client-certs/enroll",
        "/api/v1/client-certs/renew",
        "/api/v1/vault/devices/android-1/public-key",
        "/api/v1/vault/report",
        "/api/v1/connection-history/client-report",
        "/api/v1/connection-history/config-update-report"
    )

    private fun Route.deviceRoutes() {
        val identities = ClientIdentityStore(db)
        val vaultTokens = VaultFileTokenStore(db)
        certificateConfigRoutes(
            scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
            ConfigSigningService(File(certsDir, "signing.pem")), ClientDeviceStore(db), certService,
            EnrollmentTokenStore(db), ClientCertStore(db), clientIdentityStore = identities
        )
        vaultRoutes(scope, VaultFileStore(db), VaultDistributionStore(db), vaultTokens, DevicePublicKeyStore(db),
            VaultAccessTokenService(vaultTokens), VaultEncryptionService(), maxFileBytes = 1_000)
        scopedVaultAdminRoutes(VaultFileStore(db), VaultDistributionStore(db), vaultTokens,
            VaultAccessTokenService(vaultTokens), maxFileBytes = 1_000)
    }

    @Test
    fun `every device route answers 413 to a streamed body beyond the cap`() = testApplication {
        // Without the plugin: each route's own bounded read must hold by itself.
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { deviceRoutes() }

        for (path in deviceEndpoints) {
            val response = client.post(path) { setBody(Streamed(300 * 1024)) }
            assertEquals(HttpStatusCode.PayloadTooLarge, response.status, path)
            assertTrue(response.bodyAsText().contains("body_too_large"), path)
            assertNull(response.call.request.headers[HttpHeaders.ContentLength], "the request declared no length")
        }
    }

    @Test
    fun `a streamed body within the cap is read as before`() = testApplication {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(ClientBodyLimit)
        routing { deviceRoutes() }

        // Garbage of a permitted size reaches the handlers, which refuse it for what it is.
        for (path in deviceEndpoints) {
            val response = client.post(path) { setBody(Streamed(2_000)) }
            assertEquals(HttpStatusCode.BadRequest, response.status, path)
        }
    }

    @Test
    fun `whatever reads a capped path gets at most one byte more than the cap`() = testApplication {
        install(ClientBodyLimit)
        routing {
            // A handler that forgot the bounded read.
            post("/api/v1/client-certs/enroll") { call.respondText("read ${call.receiveText().length}") }
            post("/api/v1/client-certs/renew") {
                val text = call.receiveLimitedText() ?: return@post
                call.respondText("read ${text.length}")
            }
        }
        val unbounded = client.post("/api/v1/client-certs/enroll") { setBody(Streamed(5 * 1024 * 1024)) }
        assertEquals("read ${DEFAULT_CLIENT_BODY_MAX_BYTES + 1}", unbounded.bodyAsText())

        assertEquals(HttpStatusCode.PayloadTooLarge, client.post("/api/v1/client-certs/renew") { setBody(Streamed(5 * 1024 * 1024)) }.status)
        val exact = client.post("/api/v1/client-certs/renew") { setBody(Streamed(DEFAULT_CLIENT_BODY_MAX_BYTES.toInt())) }
        assertEquals("read $DEFAULT_CLIENT_BODY_MAX_BYTES", exact.bodyAsText(), "exactly the cap is allowed")
    }

    @Test
    fun `a vault upload beyond VAULT_MAX_FILE_BYTES is refused, declared or streamed`() = testApplication {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { deviceRoutes() }

        // The device listener no longer has an upload route at all.
        assertEquals(HttpStatusCode.NotFound, client.put("/api/v1/vault/model?policy=public") { setBody(ByteArray(10)) }.status)
        assertNull(VaultFileStore(db).meta(scope, "model"))
        for (path in listOf("/api/v1/config-apis/$scope/vault/model?policy=public")) {
            val declared = client.put(path) { setBody(ByteArray(1_001)) }
            assertEquals(HttpStatusCode.PayloadTooLarge, declared.status, path)
            assertEquals(HttpStatusCode.PayloadTooLarge, client.put(path) { setBody(Streamed(50_000)) }.status, path)
            assertNull(VaultFileStore(db).meta(scope, "model"), "nothing was stored")

            assertEquals(HttpStatusCode.OK, client.put(path) { setBody(ByteArray(1_000)) }.status, path)
            assertEquals(1_000, VaultFileStore(db).get(scope, "model")!!.content.size)
            VaultFileStore(db).delete(scope, "model")
        }
    }

    // ── a real HTTP/2 connection ─────────────────────────────────────────

    private class TrustAll : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    }

    /** Bytes that are produced as they are read: the client cannot know (or declare) the length. */
    private fun endless(total: Long) = object : InputStream() {
        var left = total
        override fun read(): Int = if (left-- > 0) 'x'.code else -1
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (left <= 0) return -1
            val n = minOf(len.toLong(), left).toInt()
            java.util.Arrays.fill(b, off, off + n, 'x'.code.toByte())
            left -= n
            return n
        }
    }

    @Test
    fun `over HTTP 2 without Content-Length the recovery door reads no more than the cap`() {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val identities = ClientIdentityStore(db)
        listener = RecoveryListener(certService, port, host = "127.0.0.1") {
            clientCertRenewalRoute("recovery", certService, identities, { Duration.ofDays(90) })
            post("/forgot-the-bounded-read") { call.respondText("read ${call.receiveText().length}") }
        }.also { it.start() }

        val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(TrustAll()), null) }
        val http = HttpClient.newBuilder().sslContext(ctx).version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(5)).build()
        fun post(path: String, bytes: Long): HttpResponse<String> = http.send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port$path"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofInputStream { endless(bytes) })
                .timeout(Duration.ofSeconds(30)).build(),
            HttpResponse.BodyHandlers.ofString()
        )

        val renewal = post("/api/v1/client-certs/renew", 8L * 1024 * 1024)
        assertEquals(HttpClient.Version.HTTP_2, renewal.version(), "the test must really speak HTTP/2")
        assertNull(renewal.request().headers().firstValue("Content-Length").orElse(null))
        assertEquals(413, renewal.statusCode(), renewal.body())

        // Even a handler that reads the body whole sees one byte more than the cap, not 8 MB.
        val unbounded = post("/forgot-the-bounded-read", 8L * 1024 * 1024)
        assertEquals(200, unbounded.statusCode(), unbounded.body())
        assertEquals("read ${DEFAULT_CLIENT_BODY_MAX_BYTES + 1}", unbounded.body())

        // A small streamed body still gets through to the route (which refuses it as a request).
        assertEquals(400, post("/api/v1/client-certs/renew", 100).statusCode())
    }
}
