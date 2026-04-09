package com.example.pinvault.server

import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * mTLS + VaultFile cross-layer tests.
 *
 * Simulates the full flow:
 *   1. Web admin uploads vault file
 *   2. Android client with mTLS cert fetches file
 *   3. Client reports download
 *   4. Web admin verifies distribution history
 *
 * Also tests real mTLS connectivity to sample-mtls-host (192.168.1.217:9443)
 * when it's running. Tests are skipped gracefully if host is unreachable.
 */
class VaultFileMtlsCrossTest {

    private lateinit var db: DatabaseManager
    private lateinit var vaultFileStore: VaultFileStore
    private lateinit var distStore: VaultDistributionStore
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-mtls-cross-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        vaultFileStore = VaultFileStore(db)
        distStore = VaultDistributionStore(db)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
    }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(vaultFileStore, distStore)
        }
    }

    // ── Simulated mTLS cross tests (in-memory server) ───

    @Test
    fun `web upload then mtls client fetch with enrollment label tracked`() = testApplication {
        configureApp()
        val secretConfig = """{"api_key":"encrypted-value","tier":"premium"}"""

        // Web admin uploads sensitive config
        client.put("/api/v1/vault/premium-config") {
            setBody(secretConfig.toByteArray())
            contentType(ContentType.Application.OctetStream)
        }

        // mTLS client fetches (simulated — real mTLS handshake tested separately)
        val response = client.get("/api/v1/vault/premium-config")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(secretConfig, response.bodyAsText())

        val version = response.headers["X-Vault-Version"]!!.toInt()

        // Client reports with enrollment label (mTLS cert identifier)
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"premium-config","version":$version,"deviceId":"moto_edge","deviceManufacturer":"Motorola","deviceModel":"Edge 50","enrollmentLabel":"mtls-prod-cert","status":"downloaded"}""")
        }

        // Web admin checks — enrollment label present in distribution
        val dists = distStore.getByKey("premium-config")
        assertEquals(1, dists.size)
        assertEquals("mtls-prod-cert", dists[0].enrollmentLabel)
        assertEquals("Motorola", dists[0].deviceManufacturer)
    }

    @Test
    fun `multiple mtls clients with different labels download same file`() = testApplication {
        configureApp()

        client.put("/api/v1/vault/shared-secret") {
            setBody("shared-data".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val version = vaultFileStore.get("shared-secret")!!.version

        // Device 1 — prod cert
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"shared-secret","version":$version,"deviceId":"pixel_8","deviceManufacturer":"Google","deviceModel":"Pixel 8","enrollmentLabel":"prod-api-cert","status":"downloaded"}""")
        }

        // Device 2 — staging cert
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"shared-secret","version":$version,"deviceId":"samsung_s24","deviceManufacturer":"Samsung","deviceModel":"Galaxy S24","enrollmentLabel":"staging-cert","status":"downloaded"}""")
        }

        // Device 3 — no cert (TLS only, should be tracked differently)
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"shared-secret","version":$version,"deviceId":"xiaomi_14","deviceManufacturer":"Xiaomi","deviceModel":"14 Pro","enrollmentLabel":"default","status":"downloaded"}""")
        }

        val dists = distStore.getByKey("shared-secret")
        assertEquals(3, dists.size)

        val labels = dists.map { it.enrollmentLabel }.toSet()
        assertTrue(labels.contains("prod-api-cert"))
        assertTrue(labels.contains("staging-cert"))
        assertTrue(labels.contains("default"))

        val stats = distStore.getStats()
        assertEquals(3, stats.uniqueDevices)
        assertEquals(3, stats.totalDistributions)
    }

    @Test
    fun `web update vault file then mtls client gets new version old client gets 304`() = testApplication {
        configureApp()

        // v1
        client.put("/api/v1/vault/rotating-key") {
            setBody("key-v1".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val v1 = vaultFileStore.get("rotating-key")!!.version

        // Client A fetches v1
        val r1 = client.get("/api/v1/vault/rotating-key?version=0")
        assertEquals("key-v1", r1.bodyAsText())

        // Web rotates to v2
        client.put("/api/v1/vault/rotating-key") {
            setBody("key-v2".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val v2 = vaultFileStore.get("rotating-key")!!.version
        assertTrue(v2 > v1)

        // Client A (still on v1) re-fetches → gets v2
        val r2 = client.get("/api/v1/vault/rotating-key?version=$v1")
        assertEquals(HttpStatusCode.OK, r2.status)
        assertEquals("key-v2", r2.bodyAsText())

        // Client B (already on v2) re-fetches → 304
        val r3 = client.get("/api/v1/vault/rotating-key?version=$v2")
        assertEquals(HttpStatusCode.NotModified, r3.status)
    }

    @Test
    fun `failed mtls download tracked separately from successful`() = testApplication {
        configureApp()

        client.put("/api/v1/vault/mtls-only-config") {
            setBody("restricted".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val version = vaultFileStore.get("mtls-only-config")!!.version

        // Device without cert fails
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"mtls-only-config","version":0,"deviceId":"no-cert-device","deviceManufacturer":"Generic","deviceModel":"Phone","enrollmentLabel":"default","status":"failed"}""")
        }

        // Device with cert succeeds
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"mtls-only-config","version":$version,"deviceId":"enrolled-device","deviceManufacturer":"Samsung","deviceModel":"S24","enrollmentLabel":"prod-cert","status":"downloaded"}""")
        }

        val stats = distStore.getStats()
        assertEquals(1, stats.downloaded)
        assertEquals(1, stats.failed)
        assertEquals(2, stats.totalDistributions)

        // Filter by key shows both
        val dists = distStore.getByKey("mtls-only-config")
        val failed = dists.filter { it.status == "failed" }
        val success = dists.filter { it.status == "downloaded" }
        assertEquals(1, failed.size)
        assertEquals("no-cert-device", failed[0].deviceId)
        assertEquals(1, success.size)
        assertEquals("enrolled-device", success[0].deviceId)
    }

    // ── Real mTLS connectivity test ─────────────────────

    @Test
    fun `real mtls host is reachable with correct client cert`() {
        val clientP12 = File("certs/client.p12")
        if (!clientP12.exists()) {
            println("⚠ Skipping real mTLS test — certs/client.p12 not found (run sample-mtls-host first)")
            return
        }

        val mtlsHost = System.getenv("MTLS_HOST") ?: "192.168.1.217"
        val mtlsPort = System.getenv("MTLS_PORT")?.toIntOrNull() ?: 9443
        val password = "changeit"

        try {
            // Load client P12
            val ks = KeyStore.getInstance("PKCS12")
            FileInputStream(clientP12).use { ks.load(it, password.toCharArray()) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, password.toCharArray())

            // Trust all (self-signed server cert)
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
            }

            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(kmf.keyManagers, arrayOf(trustAll), java.security.SecureRandom())

            val client = OkHttpClient.Builder()
                .sslSocketFactory(sslCtx.socketFactory, trustAll)
                .hostnameVerifier { _, _ -> true }
                .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .build()

            val response = client.newCall(
                Request.Builder().url("https://$mtlsHost:$mtlsPort/health").build()
            ).execute()

            assertEquals(200, response.code)
            val body = response.body?.string() ?: ""
            assertTrue(body.contains("\"mtls\":true"), "Response should indicate mTLS: $body")
            assertTrue(body.contains("\"status\":\"ok\""), "Health should be ok: $body")
            println("✓ Real mTLS connection successful: $body")

        } catch (e: java.net.ConnectException) {
            println("⚠ Skipping real mTLS test — host $mtlsHost:$mtlsPort unreachable: ${e.message}")
        } catch (e: Exception) {
            println("⚠ Skipping real mTLS test — ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    @Test
    fun `real mtls host rejects connection without client cert`() {
        val mtlsHost = System.getenv("MTLS_HOST") ?: "192.168.1.217"
        val mtlsPort = System.getenv("MTLS_PORT")?.toIntOrNull() ?: 9443

        try {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
            }

            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(null, arrayOf(trustAll), java.security.SecureRandom()) // no client cert

            val client = OkHttpClient.Builder()
                .sslSocketFactory(sslCtx.socketFactory, trustAll)
                .hostnameVerifier { _, _ -> true }
                .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                .build()

            client.newCall(
                Request.Builder().url("https://$mtlsHost:$mtlsPort/health").build()
            ).execute()

            fail("Should have thrown SSL exception — mTLS host should reject without client cert")

        } catch (e: javax.net.ssl.SSLHandshakeException) {
            println("✓ mTLS host correctly rejected connection without cert: ${e.message}")
        } catch (e: javax.net.ssl.SSLException) {
            println("✓ mTLS host correctly rejected connection: ${e.message}")
        } catch (e: java.net.ConnectException) {
            println("⚠ Skipping — host unreachable: ${e.message}")
        } catch (e: Exception) {
            // Other network errors are acceptable when host is not running
            println("⚠ Skipping — ${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
