package com.example.pinvault.server

import com.example.pinvault.server.route.scopedVaultAdminRoutes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.store.DatabaseManager
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
 * A vault file may carry the date it stops being valid: set on upload
 * (`?expiresAt=`), changed or cleared with the policy (`expires_at`), shown in
 * the listing, and never a reason for a new version.
 */
class VaultExpiryRouteTest {

    private val scope = "test-api"
    private lateinit var dbFile: File
    private lateinit var files: VaultFileStore
    private lateinit var db: DatabaseManager

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-vault-expiry-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.app() {
        val tokens = VaultFileTokenStore(db)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing { scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, VaultAccessTokenService(tokens)) }
    }

    private suspend fun ApplicationTestBuilder.upload(key: String, query: String = ""): HttpResponse =
        client.put("/api/v1/config-apis/$scope/vault/$key$query") {
            contentType(ContentType.Application.OctetStream)
            setBody("content".toByteArray())
        }

    private suspend fun ApplicationTestBuilder.listed(key: String): JsonObject =
        Json.parseToJsonElement(client.get("/api/v1/config-apis/$scope/vault").bodyAsText()).jsonArray
            .map { it.jsonObject }.first { it["key"]!!.jsonPrimitive.content == key }

    @Test
    fun `upload sets the expiry, a replacement without the parameter keeps it, an empty one clears it`() = testApplication {
        app()
        val first = upload("licence", "?expiresAt=2027-06-30")
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())
        assertEquals("2027-06-30T23:59:59Z", Json.parseToJsonElement(first.bodyAsText()).jsonObject["expires_at"]!!.jsonPrimitive.content)
        assertEquals("2027-06-30T23:59:59Z", listed("licence")["expires_at"]!!.jsonPrimitive.content)

        upload("licence")
        assertEquals("2027-06-30T23:59:59Z", listed("licence")["expires_at"]!!.jsonPrimitive.content, "kept across a replacement")
        assertEquals("2", listed("licence")["version"]!!.jsonPrimitive.content)

        upload("licence", "?expiresAt=")
        assertEquals("", listed("licence")["expires_at"]!!.jsonPrimitive.content, "cleared")
        assertEquals("", files.meta(scope, "licence")!!.expiresAt ?: "")
    }

    @Test
    fun `the policy route changes the expiry without a new version`() = testApplication {
        app()
        upload("model", "?expiresAt=2027-01-01")
        val changed = client.put("/api/v1/config-apis/$scope/vault/model/policy") {
            contentType(ContentType.Application.Json)
            setBody("""{"access_policy":"token","encryption":"plain","expires_at":"2028-01-01"}""")
        }
        assertEquals(HttpStatusCode.OK, changed.status, changed.bodyAsText())
        assertEquals("2028-01-01T23:59:59Z", listed("model")["expires_at"]!!.jsonPrimitive.content)
        assertEquals("1", listed("model")["version"]!!.jsonPrimitive.content, "an expiry change is metadata: devices keep what they hold")

        val kept = client.put("/api/v1/config-apis/$scope/vault/model/policy") {
            contentType(ContentType.Application.Json)
            setBody("""{"access_policy":"public","encryption":"plain"}""")
        }
        assertEquals(HttpStatusCode.OK, kept.status)
        assertEquals("2028-01-01T23:59:59Z", listed("model")["expires_at"]!!.jsonPrimitive.content, "a body without the field keeps it")

        val cleared = client.put("/api/v1/config-apis/$scope/vault/model/policy") {
            contentType(ContentType.Application.Json)
            setBody("""{"access_policy":"public","encryption":"plain","expires_at":null}""")
        }
        assertEquals(HttpStatusCode.OK, cleared.status)
        assertEquals("", listed("model")["expires_at"]!!.jsonPrimitive.content)
        assertTrue(files.expiring().none { it.key == "model" })
    }

    @Test
    fun `an invalid date is refused and nothing is stored`() = testApplication {
        app()
        val bad = upload("bad", "?expiresAt=2027-02-31")
        assertEquals(HttpStatusCode.BadRequest, bad.status)
        assertNull(files.meta(scope, "bad"))
        upload("ok", "?expiresAt=2027-01-01")
        val badPolicy = client.put("/api/v1/config-apis/$scope/vault/ok/policy") {
            contentType(ContentType.Application.Json)
            setBody("""{"access_policy":"token","encryption":"plain","expires_at":"soon"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, badPolicy.status)
        assertEquals("2027-01-01T23:59:59Z", files.meta(scope, "ok")!!.expiresAt)
    }

    @Test
    fun `the monitor sees expiring files across scopes`() = testApplication {
        app()
        upload("soon", "?expiresAt=2027-01-01")
        files.put("other-scope", "later", "x".toByteArray(), expiresAt = com.example.pinvault.server.store.ExpirySetting("2030-01-01T00:00:00Z"))
        files.put("other-scope", "never", "x".toByteArray())
        assertEquals(listOf("test-api/soon", "other-scope/later"), files.expiring().map { "${it.configApiId}/${it.key}" })
    }
}
