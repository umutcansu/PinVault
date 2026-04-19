package com.example.pinvault.server

import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DevicePublicKeyStore
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.*

/**
 * Cross-layer E2E tests: Web UI actions + Android client actions on the same server.
 *
 * "Web" = PUT/DELETE/GET via management API (browser)
 * "Android" = GET file download + POST report (mobile client)
 *
 * These tests verify that actions on one side are visible on the other.
 *
 * V2 note: all fixtures run under a single configApiId = "cross-test". Web
 * uploads explicitly set policy=public via `?policy=public` so Android
 * fetches don't require tokens.
 */
class VaultFileCrossTest {

    private val testApi = "cross-test"

    private lateinit var db: DatabaseManager
    private lateinit var vaultFileStore: VaultFileStore
    private lateinit var distStore: VaultDistributionStore
    private lateinit var tokenStore: VaultFileTokenStore
    private lateinit var publicKeyStore: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var encryptionService: VaultEncryptionService
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-cross-test-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        vaultFileStore = VaultFileStore(db)
        distStore = VaultDistributionStore(db)
        tokenStore = VaultFileTokenStore(db)
        publicKeyStore = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokenStore)
        encryptionService = VaultEncryptionService()
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
    }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService)
        }
    }

    // ── Helpers ──────────────────────────────────────────

    /** Web admin uploads a file with access_policy=public (default for these tests). */
    private suspend fun io.ktor.client.HttpClient.webUpload(key: String, content: ByteArray) {
        put("/api/v1/vault/$key?policy=public") {
            setBody(content)
            contentType(ContentType.Application.OctetStream)
        }
    }

    /** Android client downloads a file */
    private suspend fun io.ktor.client.HttpClient.androidFetch(key: String, currentVersion: Int = 0) =
        get("/api/v1/vault/$key?version=$currentVersion")

    /** Android client reports a download */
    private suspend fun io.ktor.client.HttpClient.androidReport(
        key: String,
        version: Int,
        deviceId: String = "samsung_s24",
        manufacturer: String = "Samsung",
        model: String = "Galaxy S24",
        label: String = "default",
        status: String = "downloaded"
    ) {
        post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"$key","version":$version,"deviceId":"$deviceId","deviceManufacturer":"$manufacturer","deviceModel":"$model","enrollmentLabel":"$label","status":"$status"}""")
        }
    }

    // ── Cross Tests ─────────────────────────────────────

    @Test
    fun `web upload then android fetch returns correct content`() = testApplication {
        configureApp()
        val content = """{"feature":"dark_mode","enabled":true}"""

        // Web admin uploads
        client.webUpload("feature-flags", content.toByteArray())

        // Android client fetches
        val response = client.androidFetch("feature-flags")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(content, response.bodyAsText())

        val version = response.headers["X-Vault-Version"]!!.toInt()
        assertTrue(version > 0)
    }

    @Test
    fun `android fetch and report appears in distribution history`() = testApplication {
        configureApp()

        // Web uploads file
        client.webUpload("ml-model", "model-binary-data".toByteArray())
        val entry = vaultFileStore.get(testApi, "ml-model")!!

        // Android fetches and reports
        client.androidFetch("ml-model")
        client.androidReport("ml-model", entry.version)

        // Web checks distribution history
        val distResponse = client.get("/api/v1/vault/distributions")
        val body = distResponse.bodyAsText()
        assertTrue(body.contains("ml-model"))
        assertTrue(body.contains("Samsung"))
        assertTrue(body.contains("Galaxy S24"))
        assertTrue(body.contains("downloaded"))

        // Web checks stats
        val statsResponse = client.get("/api/v1/vault/stats")
        val stats = statsResponse.bodyAsText()
        assertTrue(stats.contains("\"totalDistributions\":1"))
        assertTrue(stats.contains("\"uniqueDevices\":1"))
    }

    @Test
    fun `web update file then android re-fetch gets new version`() = testApplication {
        configureApp()

        // Web uploads v1
        client.webUpload("config", "v1-data".toByteArray())
        val v1 = vaultFileStore.get(testApi, "config")!!.version

        // Android fetches v1
        val r1 = client.androidFetch("config")
        assertEquals("v1-data", r1.bodyAsText())
        client.androidReport("config", v1, status = "downloaded")

        // Web updates to v2
        client.webUpload("config", "v2-data".toByteArray())
        val v2 = vaultFileStore.get(testApi, "config")!!.version
        assertTrue(v2 > v1)

        // Android re-fetches with old version → gets new content
        val r2 = client.androidFetch("config", currentVersion = v1)
        assertEquals(HttpStatusCode.OK, r2.status)
        assertEquals("v2-data", r2.bodyAsText())
        assertEquals(v2.toString(), r2.headers["X-Vault-Version"])

        client.androidReport("config", v2, status = "downloaded")

        // Distribution history shows both downloads
        val dists = distStore.getAll()
        assertEquals(2, dists.size)
    }

    @Test
    fun `android fetch with current version returns 304`() = testApplication {
        configureApp()

        client.webUpload("flags", "data".toByteArray())
        val version = vaultFileStore.get(testApi, "flags")!!.version

        // Android fetches with current version → 304
        val response = client.androidFetch("flags", currentVersion = version)
        assertEquals(HttpStatusCode.NotModified, response.status)
    }

    @Test
    fun `web delete then android fetch returns 404`() = testApplication {
        configureApp()

        // Web uploads
        client.webUpload("temp-file", "temporary".toByteArray())

        // Android can fetch
        val r1 = client.androidFetch("temp-file")
        assertEquals(HttpStatusCode.OK, r1.status)

        // Web deletes
        client.delete("/api/v1/vault/temp-file")

        // Android fetch → 404
        val r2 = client.androidFetch("temp-file")
        assertEquals(HttpStatusCode.NotFound, r2.status)
    }

    @Test
    fun `multiple devices download same file tracked separately`() = testApplication {
        configureApp()

        client.webUpload("shared-config", "shared-data".toByteArray())
        val version = vaultFileStore.get(testApi, "shared-config")!!.version

        // Device 1 reports
        client.androidReport("shared-config", version, deviceId = "pixel_8", manufacturer = "Google", model = "Pixel 8")
        // Device 2 reports
        client.androidReport("shared-config", version, deviceId = "samsung_s24", manufacturer = "Samsung", model = "Galaxy S24")
        // Device 3 reports
        client.androidReport("shared-config", version, deviceId = "xiaomi_14", manufacturer = "Xiaomi", model = "14 Pro")

        // Stats show 3 unique devices
        val statsResponse = client.get("/api/v1/vault/stats")
        val stats = statsResponse.bodyAsText()
        assertTrue(stats.contains("\"uniqueDevices\":3"))
        assertTrue(stats.contains("\"totalDistributions\":3"))
        assertTrue(stats.contains("\"uniqueKeys\":1"))

        // Distribution by key shows all 3
        val distResponse = client.get("/api/v1/vault/distributions/shared-config")
        val body = distResponse.bodyAsText()
        assertTrue(body.contains("Google"))
        assertTrue(body.contains("Samsung"))
        assertTrue(body.contains("Xiaomi"))
    }

    @Test
    fun `android failed report appears in stats`() = testApplication {
        configureApp()

        // Device reports a failed download
        client.androidReport("missing-file", 0, status = "failed")

        val statsResponse = client.get("/api/v1/vault/stats")
        val stats = statsResponse.bodyAsText()
        assertTrue(stats.contains("\"failed\":1"))
        assertTrue(stats.contains("\"downloaded\":0"))
    }

    @Test
    fun `web upload multiple files then android fetches each independently`() = testApplication {
        configureApp()

        client.webUpload("file-a", "aaa".toByteArray())
        client.webUpload("file-b", "bbb".toByteArray())
        client.webUpload("file-c", "ccc".toByteArray())

        // Android fetches only file-b
        val response = client.androidFetch("file-b")
        assertEquals("bbb", response.bodyAsText())

        val vB = vaultFileStore.get(testApi, "file-b")!!.version
        client.androidReport("file-b", vB)

        // Stats: 1 distribution, 1 device, 1 key (not 3)
        val stats = client.get("/api/v1/vault/stats").bodyAsText()
        assertTrue(stats.contains("\"totalDistributions\":1"))
        assertTrue(stats.contains("\"uniqueKeys\":1"))

        // File list shows all 3
        val listResponse = client.get("/api/v1/vault")
        val list = listResponse.bodyAsText()
        assertTrue(list.contains("file-a"))
        assertTrue(list.contains("file-b"))
        assertTrue(list.contains("file-c"))
    }

    @Test
    fun `distribution by device shows all files downloaded by one device`() = testApplication {
        configureApp()

        client.webUpload("flags", "f".toByteArray())
        client.webUpload("model", "m".toByteArray())

        val vFlags = vaultFileStore.get(testApi, "flags")!!.version
        val vModel = vaultFileStore.get(testApi, "model")!!.version

        // Same device downloads both
        client.androidReport("flags", vFlags, deviceId = "my-phone")
        client.androidReport("model", vModel, deviceId = "my-phone")

        // Query by device
        val response = client.get("/api/v1/vault/distributions/device/my-phone")
        val body = response.bodyAsText()
        assertTrue(body.contains("flags"))
        assertTrue(body.contains("model"))

        // Different device only downloaded one
        client.androidReport("flags", vFlags, deviceId = "other-phone")
        val otherResponse = client.get("/api/v1/vault/distributions/device/other-phone")
        val otherBody = otherResponse.bodyAsText()
        assertTrue(otherBody.contains("flags"))
        assertFalse(otherBody.contains("model"))
    }

    @Test
    fun `enrollment label tracked in distribution`() = testApplication {
        configureApp()

        client.webUpload("secure-config", "secret".toByteArray())
        val version = vaultFileStore.get(testApi, "secure-config")!!.version

        // Device with custom enrollment label
        client.androidReport("secure-config", version, label = "prod-api-cert")

        val dists = distStore.getByKey(testApi, "secure-config")
        assertEquals(1, dists.size)
        assertEquals("prod-api-cert", dists[0].enrollmentLabel)
    }

    @Test
    fun `full lifecycle web upload - android fetch - web update - android refetch - stats correct`() = testApplication {
        configureApp()

        // 1. Web uploads initial version
        client.webUpload("lifecycle", """{"v":1}""".toByteArray())
        val v1 = vaultFileStore.get(testApi, "lifecycle")!!.version

        // 2. Android fetches
        val r1 = client.androidFetch("lifecycle")
        assertEquals("""{"v":1}""", r1.bodyAsText())
        client.androidReport("lifecycle", v1, deviceId = "phone-1")

        // 3. Web updates
        client.webUpload("lifecycle", """{"v":2}""".toByteArray())
        val v2 = vaultFileStore.get(testApi, "lifecycle")!!.version

        // 4. Same device re-fetches
        val r2 = client.androidFetch("lifecycle", currentVersion = v1)
        assertEquals("""{"v":2}""", r2.bodyAsText())
        client.androidReport("lifecycle", v2, deviceId = "phone-1")

        // 5. Different device also fetches v2
        client.androidReport("lifecycle", v2, deviceId = "phone-2")

        // 6. Verify full state
        val stats = Json.parseToJsonElement(client.get("/api/v1/vault/stats").bodyAsText()).jsonObject
        assertEquals(3, stats["totalDistributions"]?.jsonPrimitive?.int)
        assertEquals(2, stats["uniqueDevices"]?.jsonPrimitive?.int)
        assertEquals(1, stats["uniqueKeys"]?.jsonPrimitive?.int)
        assertEquals(3, stats["downloaded"]?.jsonPrimitive?.int)
        assertEquals(0, stats["failed"]?.jsonPrimitive?.int)

        // 7. Distribution history for this key has 3 entries
        val dists = distStore.getByKey(testApi, "lifecycle")
        assertEquals(3, dists.size)

        // 8. phone-1 has 2 entries (v1 + v2), phone-2 has 1
        val phone1 = distStore.getByDevice(testApi, "phone-1")
        assertEquals(2, phone1.size)
        val phone2 = distStore.getByDevice(testApi, "phone-2")
        assertEquals(1, phone2.size)
    }
}
