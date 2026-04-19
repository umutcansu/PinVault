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
 * Route-level tests for /api/v1/vault. All tests use a fixed
 * configApiId of "test-api" — V2 vault is scoped per Config API, so each
 * test's data is isolated from every other Config API.
 *
 * These tests default to access_policy = "public" (via PUT without ?policy=),
 * so no tokens are required. Policy-specific tests live in
 * VaultRoutesAccessPolicyTest.
 */
class VaultRoutesTest {

    private val testApi = "test-api"

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
        dbFile = File.createTempFile("pinvault-vault-test-", ".db")
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

    /** Uploads a file with access_policy=public so GET needs no token. */
    private suspend fun io.ktor.client.HttpClient.putPublic(key: String, content: ByteArray) {
        put("/api/v1/vault/$key?policy=public") {
            setBody(content); contentType(ContentType.Application.OctetStream)
        }
    }

    @Test
    fun `PUT and GET vault file round-trip`() = testApplication {
        configureApp()
        val content = "hello vault world".toByteArray()

        val putResponse = client.put("/api/v1/vault/test-file?policy=public") {
            setBody(content)
            contentType(ContentType.Application.OctetStream)
        }
        assertEquals(HttpStatusCode.OK, putResponse.status)

        val getResponse = client.get("/api/v1/vault/test-file")
        assertEquals(HttpStatusCode.OK, getResponse.status)
        assertContentEquals(content, getResponse.bodyAsBytes())
        assertNotNull(getResponse.headers["X-Vault-Version"])
    }

    @Test
    fun `GET nonexistent file returns 404`() = testApplication {
        configureApp()
        val response = client.get("/api/v1/vault/nonexistent")
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `GET with current version returns 304`() = testApplication {
        configureApp()
        val content = "version check".toByteArray()
        client.putPublic("versioned", content)

        val entry = vaultFileStore.get(testApi, "versioned")!!

        val response = client.get("/api/v1/vault/versioned?version=${entry.version}")
        assertEquals(HttpStatusCode.NotModified, response.status)
    }

    @Test
    fun `GET with old version returns 200 with new content`() = testApplication {
        configureApp()
        client.putPublic("updated", "v1 content".toByteArray())

        val response = client.get("/api/v1/vault/updated?version=0")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("v1 content", response.bodyAsText())
    }

    @Test
    fun `PUT overwrites and increments version`() = testApplication {
        configureApp()
        client.putPublic("overwrite", "first".toByteArray())
        val v1 = vaultFileStore.get(testApi, "overwrite")!!.version

        client.putPublic("overwrite", "second".toByteArray())
        val v2 = vaultFileStore.get(testApi, "overwrite")!!.version

        assertTrue(v2 > v1)
        assertEquals("second", String(vaultFileStore.get(testApi, "overwrite")!!.content))
    }

    @Test
    fun `X-Vault-Version header is present in response`() = testApplication {
        configureApp()
        client.putPublic("header-test", "test".toByteArray())

        val response = client.get("/api/v1/vault/header-test")
        assertEquals(HttpStatusCode.OK, response.status)
        val versionHeader = response.headers["X-Vault-Version"]
        assertNotNull(versionHeader)
        assertTrue(versionHeader!!.toInt() > 0)
    }

    /**
     * Scenario: v1 → v2 → v3 version bump lifecycle.
     *
     * Simulates the full update flow a real device goes through:
     *  1. Upload v1, client fetches, stores content+version locally.
     *  2. Admin uploads v2 with new content → client re-fetches (with currentVersion=1)
     *     and must receive 200 + new content + X-Vault-Version: 2.
     *  3. Same content uploaded again → version bumps to v3 anyway (every PUT = new version).
     *  4. Client that already has v3 re-fetches → must get 304 Not Modified.
     *  5. Client that has v1 re-fetches directly to v3 (skip) → must get 200 + v3 content.
     *
     * This catches regressions where version isn't persisted, content isn't replaced,
     * 304 shortcut fires incorrectly, or headers drop.
     */
    @Test
    fun `v1 to v2 to v3 bump - content replaced, version persisted, 304 for current`() = testApplication {
        configureApp()

        val key = "feature-flags"
        val v1 = """{"feature":"off","rollout":0}""".toByteArray()
        val v2 = """{"feature":"beta","rollout":10}""".toByteArray()
        val v3 = """{"feature":"on","rollout":100}""".toByteArray()

        // ── PUT v1
        val putV1 = client.put("/api/v1/vault/$key?policy=public") {
            setBody(v1); contentType(ContentType.Application.OctetStream)
        }
        assertEquals(HttpStatusCode.OK, putV1.status)
        assertEquals(1, vaultFileStore.get(testApi, key)!!.version)

        // Client (with currentVersion=0) fetches v1
        val getV1 = client.get("/api/v1/vault/$key?version=0")
        assertEquals(HttpStatusCode.OK, getV1.status)
        assertEquals("1", getV1.headers["X-Vault-Version"])
        assertContentEquals(v1, getV1.readRawBytes())

        // ── PUT v2 (new content, increments version)
        val putV2 = client.put("/api/v1/vault/$key?policy=public") {
            setBody(v2); contentType(ContentType.Application.OctetStream)
        }
        assertEquals(HttpStatusCode.OK, putV2.status)
        assertEquals(2, vaultFileStore.get(testApi, key)!!.version)
        assertContentEquals(v2, vaultFileStore.get(testApi, key)!!.content)

        // Client that has v1 re-fetches → must get 200 + v2 bytes (not 304)
        val reFetchFromV1 = client.get("/api/v1/vault/$key?version=1")
        assertEquals(HttpStatusCode.OK, reFetchFromV1.status)
        assertEquals("2", reFetchFromV1.headers["X-Vault-Version"])
        assertContentEquals(v2, reFetchFromV1.readRawBytes())

        // ── PUT v3
        val putV3 = client.put("/api/v1/vault/$key?policy=public") {
            setBody(v3); contentType(ContentType.Application.OctetStream)
        }
        assertEquals(HttpStatusCode.OK, putV3.status)
        assertEquals(3, vaultFileStore.get(testApi, key)!!.version)

        // Client that has v3 already → 304 (no body)
        val currentClient = client.get("/api/v1/vault/$key?version=3")
        assertEquals(HttpStatusCode.NotModified, currentClient.status)
        assertEquals("3", currentClient.headers["X-Vault-Version"])
        assertEquals(0, currentClient.readRawBytes().size)

        // Client that skipped v2 (still has v1) → 200 + v3 bytes directly
        val skipClient = client.get("/api/v1/vault/$key?version=1")
        assertEquals(HttpStatusCode.OK, skipClient.status)
        assertEquals("3", skipClient.headers["X-Vault-Version"])
        assertContentEquals(v3, skipClient.readRawBytes())

        // Uploading identical content still bumps version (no content-dedup by design)
        val putV3Again = client.put("/api/v1/vault/$key?policy=public") {
            setBody(v3); contentType(ContentType.Application.OctetStream)
        }
        assertEquals(HttpStatusCode.OK, putV3Again.status)
        assertEquals(4, vaultFileStore.get(testApi, key)!!.version)
    }

    /**
     * Full observability: after v1→v2 bump + client reports for each,
     * the distribution table must show both versions with correct counts.
     * This is the data that drives the web UI's "Version Timeline" section.
     */
    @Test
    fun `version bump produces correct distribution stats per version`() = testApplication {
        configureApp()

        val key = "ml-model"
        client.putPublic(key, "v1-bytes".toByteArray())

        // Two devices download v1
        repeat(2) { i ->
            client.post("/api/v1/vault/report") {
                contentType(ContentType.Application.Json)
                setBody("""{"key":"$key","version":1,"deviceId":"dev-$i","status":"downloaded"}""")
            }
        }

        client.putPublic(key, "v2-bytes-bigger".toByteArray())

        // Three devices download v2 (including one repeat)
        listOf("dev-0", "dev-1", "dev-2").forEach { dev ->
            client.post("/api/v1/vault/report") {
                contentType(ContentType.Application.Json)
                setBody("""{"key":"$key","version":2,"deviceId":"$dev","status":"downloaded"}""")
            }
        }
        // One failed v2 attempt on a new device
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"$key","version":2,"deviceId":"dev-3","status":"failed"}""")
        }

        val allDists = distStore.getByKey(testApi, key)
        val v1Count = allDists.count { it.version == 1 }
        val v2Ok = allDists.count { it.version == 2 && it.status == "downloaded" }
        val v2Failed = allDists.count { it.version == 2 && it.status == "failed" }

        assertEquals(2, v1Count, "v1 must have 2 download records")
        assertEquals(3, v2Ok, "v2 must have 3 successful downloads")
        assertEquals(1, v2Failed, "v2 must have 1 failed download")

        // Current file version is v2 (latest PUT)
        assertEquals(2, vaultFileStore.get(testApi, key)!!.version)
    }

    // ── Distribution tracking tests ─────────────────────

    @Test
    fun `POST report stores distribution`() = testApplication {
        configureApp()

        val response = client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"ml-model","version":3,"deviceId":"test-device-1","deviceManufacturer":"Samsung","deviceModel":"Galaxy S24","enrollmentLabel":"default","status":"downloaded"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val dists = distStore.getAll(testApi)
        assertEquals(1, dists.size)
        assertEquals("ml-model", dists[0].vaultKey)
        assertEquals(3, dists[0].version)
        assertEquals("test-device-1", dists[0].deviceId)
        assertEquals("Samsung", dists[0].deviceManufacturer)
        assertEquals("downloaded", dists[0].status)
    }

    @Test
    fun `GET distributions returns all`() = testApplication {
        configureApp()

        // Add two reports
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"file-a","version":1,"deviceId":"d1","status":"downloaded"}""")
        }
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"file-b","version":2,"deviceId":"d2","status":"cached"}""")
        }

        val response = client.get("/api/v1/vault/distributions")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("file-a"))
        assertTrue(body.contains("file-b"))
    }

    @Test
    fun `GET distributions by key filters correctly`() = testApplication {
        configureApp()

        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"target","version":1,"deviceId":"d1","status":"downloaded"}""")
        }
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"other","version":1,"deviceId":"d2","status":"downloaded"}""")
        }

        val response = client.get("/api/v1/vault/distributions/target")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("target"))
        assertFalse(body.contains("other"))
    }

    @Test
    fun `GET stats returns correct counts`() = testApplication {
        configureApp()

        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"f1","version":1,"deviceId":"d1","status":"downloaded"}""")
        }
        client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"f2","version":1,"deviceId":"d2","status":"failed"}""")
        }

        val response = client.get("/api/v1/vault/stats")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("\"totalDistributions\":2"))
        assertTrue(body.contains("\"uniqueDevices\":2"))
        assertTrue(body.contains("\"uniqueKeys\":2"))
        assertTrue(body.contains("\"downloaded\":1"))
        assertTrue(body.contains("\"failed\":1"))
    }
}
