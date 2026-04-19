package com.example.pinvault.server

import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DeviceHostAclStore
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
 * Smoke-level coverage for the V2 admin endpoints that back the web UI.
 * Each endpoint gets at least one happy-path test and one validation/404
 * test. Policy enforcement of the token/vault routes themselves lives in
 * VaultRoutesAccessPolicyTest.
 */
class AdminVaultRoutesTest {

    private val testApi = "admin-test-api"

    private lateinit var db: DatabaseManager
    private lateinit var aclStore: DeviceHostAclStore
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-admin-test-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        aclStore = DeviceHostAclStore(db)

        // Seed a config_apis row so vault-enabled PUT can find something.
        db.connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO config_apis (id, port, mode, auto_start, created_at, vault_enabled) " +
                        "VALUES (?, 8091, 'tls', 1, datetime('now'), 1)"
            ).use { stmt ->
                stmt.setString(1, testApi)
                stmt.executeUpdate()
            }
        }
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { adminVaultRoutes(db, aclStore) }
    }

    // ── vault-enabled toggle ──────────────────────────────────────────

    @Test
    fun `GET vault-enabled returns current value`() = testApplication {
        configureApp()
        val res = client.get("/api/v1/config-apis/$testApi/vault-enabled")
        assertEquals(HttpStatusCode.OK, res.status)
        assertTrue(res.bodyAsText().contains("\"vault_enabled\""))
    }

    @Test
    fun `PUT vault-enabled false then GET reflects it`() = testApplication {
        configureApp()

        val put = client.put("/api/v1/config-apis/$testApi/vault-enabled") {
            contentType(ContentType.Application.Json)
            setBody("""{"enabled":false}""")
        }
        assertEquals(HttpStatusCode.OK, put.status)

        val get = client.get("/api/v1/config-apis/$testApi/vault-enabled")
        assertTrue(get.bodyAsText().contains("\"vault_enabled\" : \"false\"")
            || get.bodyAsText().contains("\"vault_enabled\":\"false\""))
    }

    @Test
    fun `PUT vault-enabled on unknown config API returns 404`() = testApplication {
        configureApp()
        val res = client.put("/api/v1/config-apis/doesnt-exist/vault-enabled") {
            contentType(ContentType.Application.Json)
            setBody("""{"enabled":true}""")
        }
        assertEquals(HttpStatusCode.NotFound, res.status)
    }

    @Test
    fun `PUT vault-enabled without enabled field returns 400`() = testApplication {
        configureApp()
        val res = client.put("/api/v1/config-apis/$testApi/vault-enabled") {
            contentType(ContentType.Application.Json)
            setBody("""{}""")
        }
        assertEquals(HttpStatusCode.BadRequest, res.status)
    }

    // ── Per-device host ACL ───────────────────────────────────────────

    @Test
    fun `PUT device host-acl adds listed hostnames and removes missing ones`() = testApplication {
        configureApp()

        val put1 = client.put("/api/v1/config-apis/$testApi/devices/dev-a/host-acl") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostnames":["a.com","b.com"]}""")
        }
        assertEquals(HttpStatusCode.OK, put1.status)
        assertEquals(setOf("a.com", "b.com"),
            aclStore.listForDevice(testApi, "dev-a").toSet())

        // Replace with a different set — a.com removed, c.com added
        val put2 = client.put("/api/v1/config-apis/$testApi/devices/dev-a/host-acl") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostnames":["b.com","c.com"]}""")
        }
        assertEquals(HttpStatusCode.OK, put2.status)
        assertEquals(setOf("b.com", "c.com"),
            aclStore.listForDevice(testApi, "dev-a").toSet())
    }

    @Test
    fun `GET device host-acl returns empty list for unknown device`() = testApplication {
        configureApp()
        val res = client.get("/api/v1/config-apis/$testApi/devices/never-seen/host-acl")
        assertEquals(HttpStatusCode.OK, res.status)
        val normalized = res.bodyAsText().trim().replace(" ", "")
        assertEquals("[]", normalized)
    }

    @Test
    fun `GET effective ACL unions device ACL with default ACL`() = testApplication {
        configureApp()
        aclStore.grant(testApi, "dev-a", "device-only.com", java.time.Instant.now().toString())
        aclStore.addDefault(testApi, "default-only.com")

        val res = client.get("/api/v1/config-apis/$testApi/devices/dev-a/host-acl/effective")
        val body = res.bodyAsText()
        assertTrue(body.contains("device-only.com"))
        assertTrue(body.contains("default-only.com"))
    }

    // ── Default host ACL ───────────────────────────────────────────────

    @Test
    fun `PUT default host-acl replaces the full set`() = testApplication {
        configureApp()

        val put = client.put("/api/v1/config-apis/$testApi/default-host-acl") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostnames":["cdn.example.com","api.example.com"]}""")
        }
        assertEquals(HttpStatusCode.OK, put.status)
        assertEquals(setOf("cdn.example.com", "api.example.com"),
            aclStore.listDefault(testApi).toSet())

        // Replace with smaller set — cdn is removed
        client.put("/api/v1/config-apis/$testApi/default-host-acl") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostnames":["api.example.com"]}""")
        }
        assertEquals(listOf("api.example.com"), aclStore.listDefault(testApi))
    }

    @Test
    fun `GET default host-acl returns empty list when unset`() = testApplication {
        configureApp()
        val res = client.get("/api/v1/config-apis/$testApi/default-host-acl")
        assertEquals(HttpStatusCode.OK, res.status)
        val normalized = res.bodyAsText().trim().replace(" ", "")
        assertEquals("[]", normalized)
    }

    @Test
    fun `PUT default host-acl without hostnames array returns 400`() = testApplication {
        configureApp()
        val res = client.put("/api/v1/config-apis/$testApi/default-host-acl") {
            contentType(ContentType.Application.Json)
            setBody("""{"wrong":"field"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, res.status)
    }
}
