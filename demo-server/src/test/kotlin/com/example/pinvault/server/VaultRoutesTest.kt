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
import java.io.File
import kotlin.test.*

class VaultRoutesTest {

    private lateinit var db: DatabaseManager
    private lateinit var vaultFileStore: VaultFileStore
    private lateinit var distStore: VaultDistributionStore
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-vault-test-", ".db")
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

    @Test
    fun `PUT and GET vault file round-trip`() = testApplication {
        configureApp()
        val content = "hello vault world".toByteArray()

        val putResponse = client.put("/api/v1/vault/test-file") {
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

        client.put("/api/v1/vault/versioned") {
            setBody(content)
            contentType(ContentType.Application.OctetStream)
        }

        // Get version from the stored entry
        val entry = vaultFileStore.get("versioned")!!

        val response = client.get("/api/v1/vault/versioned?version=${entry.version}")
        assertEquals(HttpStatusCode.NotModified, response.status)
    }

    @Test
    fun `GET with old version returns 200 with new content`() = testApplication {
        configureApp()

        client.put("/api/v1/vault/updated") {
            setBody("v1 content".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }

        val response = client.get("/api/v1/vault/updated?version=0")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("v1 content", response.bodyAsText())
    }

    @Test
    fun `PUT overwrites and increments version`() = testApplication {
        configureApp()

        client.put("/api/v1/vault/overwrite") {
            setBody("first".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val v1 = vaultFileStore.get("overwrite")!!.version

        client.put("/api/v1/vault/overwrite") {
            setBody("second".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
        val v2 = vaultFileStore.get("overwrite")!!.version

        assertTrue(v2 > v1)
        assertEquals("second", String(vaultFileStore.get("overwrite")!!.content))
    }

    @Test
    fun `X-Vault-Version header is present in response`() = testApplication {
        configureApp()

        client.put("/api/v1/vault/header-test") {
            setBody("test".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }

        val response = client.get("/api/v1/vault/header-test")
        assertEquals(HttpStatusCode.OK, response.status)
        val versionHeader = response.headers["X-Vault-Version"]
        assertNotNull(versionHeader)
        assertTrue(versionHeader!!.toInt() > 0)
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

        val dists = distStore.getAll()
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
