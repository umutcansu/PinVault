package com.example.pinvault.server

import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.*

/**
 * Cross-layer: two Config APIs registered on the same process + one DB,
 * both routing to the same vaultRoutes() but with different scope ids.
 * Verifies that a vault key uploaded under api-A is invisible to
 * api-B's endpoint and vice versa.
 *
 * This nails the V2 promise that pre-existing single-URL integrations are
 * unaffected by a newly-registered second Config API — no hostname
 * collisions, no leaked keys across scopes, no cross-tenant pollution.
 */
class VaultScopingCrossTest {

    private lateinit var db: DatabaseManager
    private lateinit var vfs: VaultFileStore
    private lateinit var dist: VaultDistributionStore
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var pks: DevicePublicKeyStore
    private lateinit var tokenSvc: VaultAccessTokenService
    private lateinit var encSvc: VaultEncryptionService
    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("cross-scoping-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        vfs = VaultFileStore(db)
        dist = VaultDistributionStore(db)
        tokens = VaultFileTokenStore(db)
        pks = DevicePublicKeyStore(db)
        tokenSvc = VaultAccessTokenService(tokens)
        encSvc = VaultEncryptionService()
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    /** Mount two independent vaultRoutes instances under scope-specific URL prefixes. */
    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            route("/scope-a") { vaultRoutes("api-a", vfs, dist, tokens, pks, tokenSvc, encSvc) }
            route("/scope-b") { vaultRoutes("api-b", vfs, dist, tokens, pks, tokenSvc, encSvc) }
        }
    }

    @Test
    fun `same key uploaded on both scopes stays independent`() = testApplication {
        configureApp()
        client.put("/scope-a/api/v1/vault/shared-name?policy=public") {
            setBody("content-A".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        client.put("/scope-b/api/v1/vault/shared-name?policy=public") {
            setBody("content-B".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        val a = client.get("/scope-a/api/v1/vault/shared-name")
        val b = client.get("/scope-b/api/v1/vault/shared-name")

        assertEquals("content-A", a.bodyAsText())
        assertEquals("content-B", b.bodyAsText())
    }

    @Test
    fun `key uploaded on scope A is 404 on scope B`() = testApplication {
        configureApp()
        client.put("/scope-a/api/v1/vault/only-in-a?policy=public") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        val b = client.get("/scope-b/api/v1/vault/only-in-a")
        assertEquals(HttpStatusCode.NotFound, b.status)
    }

    @Test
    fun `token issued on scope A does not authorize scope B`() = testApplication {
        configureApp()
        client.put("/scope-a/api/v1/vault/guarded?policy=token") {
            setBody("a-secret".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        client.put("/scope-b/api/v1/vault/guarded?policy=token") {
            setBody("b-secret".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        // Admin issues a token under scope A only.
        val tokenA = tokenSvc.generate("api-a", "guarded", "dev-1")

        // Token valid on scope A
        val a = client.get("/scope-a/api/v1/vault/guarded") {
            header("X-Device-Id", "dev-1")
            header("X-Vault-Token", tokenA.plaintext)
        }
        assertEquals(HttpStatusCode.OK, a.status)
        assertEquals("a-secret", a.bodyAsText())

        // Same token rejected on scope B (wrong scope, even if same key/device/token)
        val b = client.get("/scope-b/api/v1/vault/guarded") {
            header("X-Device-Id", "dev-1")
            header("X-Vault-Token", tokenA.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, b.status)
    }

    @Test
    fun `file list for scope A does not include scope B files`() = testApplication {
        configureApp()
        client.put("/scope-a/api/v1/vault/only-a?policy=public") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        client.put("/scope-b/api/v1/vault/only-b?policy=public") {
            setBody("y".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        val listA = client.get("/scope-a/api/v1/vault").bodyAsText()
        val listB = client.get("/scope-b/api/v1/vault").bodyAsText()

        assertTrue(listA.contains("only-a"))
        assertFalse(listA.contains("only-b"))
        assertTrue(listB.contains("only-b"))
        assertFalse(listB.contains("only-a"))
    }

    @Test
    fun `distribution report lands in the scope it was reported from`() = testApplication {
        configureApp()
        client.put("/scope-a/api/v1/vault/tracked?policy=public") {
            setBody("v".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        client.post("/scope-a/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"tracked","version":1,"deviceId":"d-1","status":"downloaded"}""")
        }

        assertEquals(1, dist.getByKey("api-a", "tracked").size)
        assertEquals(0, dist.getByKey("api-b", "tracked").size)
    }
}
