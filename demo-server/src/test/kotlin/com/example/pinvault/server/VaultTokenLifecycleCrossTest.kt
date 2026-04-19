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
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.io.File
import kotlin.test.*

/**
 * Admin-side token issuance + client-side fetch + admin-side revocation,
 * all through HTTP. This is the full token lifecycle as a human admin and
 * a real device would experience it.
 */
class VaultTokenLifecycleCrossTest {

    private val testApi = "token-lifecycle-api"

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
        dbFile = File.createTempFile("cross-token-", ".db")
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

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { vaultRoutes(testApi, vfs, dist, tokens, pks, tokenSvc, encSvc) }
    }

    @Test
    fun `full lifecycle — upload, issue token, fetch, revoke, fetch fails`() = testApplication {
        configureApp()

        // Admin uploads
        client.put("/api/v1/vault/license-key?policy=token") {
            setBody("license-payload-xyz".toByteArray())
            contentType(ContentType.Application.OctetStream)
        }

        // Admin issues a token via HTTP (not the service directly)
        val genResponse = client.post("/api/v1/vault/license-key/tokens") {
            contentType(ContentType.Application.Json)
            setBody("""{"deviceId":"dev-ops-1"}""")
        }
        assertEquals(HttpStatusCode.OK, genResponse.status)
        val gen = Json.parseToJsonElement(genResponse.bodyAsText()).jsonObject
        val plaintextToken = gen["token"]!!.jsonPrimitive.content
        val tokenId = gen["id"]!!.jsonPrimitive.content.toLong()

        // Device fetches — should succeed
        val ok = client.get("/api/v1/vault/license-key") {
            header("X-Device-Id", "dev-ops-1"); header("X-Vault-Token", plaintextToken)
        }
        assertEquals(HttpStatusCode.OK, ok.status)
        assertEquals("license-payload-xyz", ok.bodyAsText())

        // Token list reflects the newly-created row
        val listBefore = client.get("/api/v1/vault/license-key/tokens").bodyAsText()
        assertTrue(listBefore.contains("dev-ops-1"))
        assertTrue(listBefore.contains("\"revoked\" : false") || listBefore.contains("\"revoked\":false"))

        // Admin revokes via HTTP DELETE
        val revoke = client.delete("/api/v1/vault/tokens/$tokenId")
        assertEquals(HttpStatusCode.OK, revoke.status)

        // Device fetches — must fail now
        val denied = client.get("/api/v1/vault/license-key") {
            header("X-Device-Id", "dev-ops-1"); header("X-Vault-Token", plaintextToken)
        }
        assertEquals(HttpStatusCode.Unauthorized, denied.status)

        // Token list still shows the row, marked revoked
        val listAfter = client.get("/api/v1/vault/license-key/tokens").bodyAsText()
        assertTrue(listAfter.contains("\"revoked\" : true") || listAfter.contains("\"revoked\":true"))
    }

    @Test
    fun `re-issuing a token invalidates the old one (end-to-end)`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/rotating?policy=token") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }

        // First issue
        val gen1 = Json.parseToJsonElement(client.post("/api/v1/vault/rotating/tokens") {
            contentType(ContentType.Application.Json); setBody("""{"deviceId":"d"}""")
        }.bodyAsText()).jsonObject
        val oldToken = gen1["token"]!!.jsonPrimitive.content

        // Re-issue (replaces the old hash on the UNIQUE(configApiId, key, deviceId) row)
        val gen2 = Json.parseToJsonElement(client.post("/api/v1/vault/rotating/tokens") {
            contentType(ContentType.Application.Json); setBody("""{"deviceId":"d"}""")
        }.bodyAsText()).jsonObject
        val newToken = gen2["token"]!!.jsonPrimitive.content

        assertNotEquals(oldToken, newToken)

        // Old token rejected
        val oldResp = client.get("/api/v1/vault/rotating") {
            header("X-Device-Id", "d"); header("X-Vault-Token", oldToken)
        }
        assertEquals(HttpStatusCode.Unauthorized, oldResp.status)

        // New token accepted
        val newResp = client.get("/api/v1/vault/rotating") {
            header("X-Device-Id", "d"); header("X-Vault-Token", newToken)
        }
        assertEquals(HttpStatusCode.OK, newResp.status)
    }

    @Test
    fun `token plaintext is never returned in list endpoint`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/hidden?policy=token") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        val gen = Json.parseToJsonElement(client.post("/api/v1/vault/hidden/tokens") {
            contentType(ContentType.Application.Json); setBody("""{"deviceId":"d"}""")
        }.bodyAsText()).jsonObject
        val plaintext = gen["token"]!!.jsonPrimitive.content

        val listBody = client.get("/api/v1/vault/hidden/tokens").bodyAsText()
        assertFalse(listBody.contains(plaintext), "Token plaintext must not appear in list response")
    }

    @Test
    fun `revoking unknown token id returns 404`() = testApplication {
        configureApp()
        val r = client.delete("/api/v1/vault/tokens/99999999")
        assertEquals(HttpStatusCode.NotFound, r.status)
    }

    @Test
    fun `issuing token without deviceId returns 400`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/x?policy=token") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        val r = client.post("/api/v1/vault/x/tokens") {
            contentType(ContentType.Application.Json); setBody("""{}""")
        }
        assertEquals(HttpStatusCode.BadRequest, r.status)
    }
}
