package com.example.pinvault.server

import com.example.pinvault.server.route.scopedVaultAdminRoutes
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
 * Y2: `?policy=` and `?encryption=` were stored as sent on both upload routes,
 * so markup in them reached the dashboard and an unknown encryption was
 * served as plaintext. Both routes now take only known values (including the
 * `user_auth` mode), and a stored row with an unknown encryption is not served.
 */
class VaultUploadValidationTest {

    private val scope = "test-api"
    private val payload = """<button data-action="approveChange" data-arg0="17" style="position:fixed;inset:0;opacity:0;z-index:9999">"""

    private lateinit var dbFile: File
    private lateinit var files: VaultFileStore
    private lateinit var db: DatabaseManager

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-vault-upload-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        files = VaultFileStore(db)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
    }

    private fun ApplicationTestBuilder.app() {
        val tokens = VaultFileTokenStore(db)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            // The Config API listeners' upload…
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, DevicePublicKeyStore(db),
                VaultAccessTokenService(tokens), VaultEncryptionService())
            // …and the management server's.
            scopedVaultAdminRoutes(files, VaultDistributionStore(db), tokens, VaultAccessTokenService(tokens))
        }
    }

    // One upload route: the management listener's. The device listener has none (see the last test).
    private val uploadPaths = listOf("/api/v1/config-apis/$scope/vault/%s")

    private suspend fun ApplicationTestBuilder.upload(path: String, key: String, query: String): HttpResponse =
        client.put(path.format(key) + query) {
            contentType(ContentType.Application.OctetStream)
            setBody("content".toByteArray())
        }

    private fun q(name: String, value: String) = "$name=${value.encodeURLParameter()}"

    @Test
    fun `an unknown policy or encryption is refused on upload and nothing is stored`() = testApplication {
        app()
        for (path in uploadPaths) {
            for (query in listOf(
                "?" + q("policy", payload),
                "?" + q("encryption", payload),
                "?policy=public&encryption=rot13",
                "?policy=PUBLIC",
                "?" + q("policy", "token ") + "&encryption=plain"
            )) {
                val response = upload(path, "model", query)
                assertEquals(HttpStatusCode.BadRequest, response.status, "$path$query: ${response.bodyAsText()}")
                assertNull(files.get(scope, "model"), "$path$query stored something")
            }
        }
    }

    @Test
    fun `the management upload applies the key rules of the device route`() = testApplication {
        app()
        for (key in listOf("stats", "distributions", "a%20b", "x".repeat(65))) {
            val response = upload(uploadPaths[0], key, "?policy=public")
            assertEquals(HttpStatusCode.BadRequest, response.status, "key '$key': ${response.bodyAsText()}")
        }
        assertTrue(files.summaries(scope).isEmpty())
    }

    @Test
    fun `every known policy and encryption, user_auth included, is accepted`() = testApplication {
        app()
        for ((i, path) in uploadPaths.withIndex()) {
            for (policy in listOf("public", "api_key", "token", "token_mtls")) {
                for (encryption in listOf("plain", "at_rest", "end_to_end", "user_auth")) {
                    val key = "f$i-$policy-$encryption".replace('_', '-')
                    val response = upload(path, key, "?policy=$policy&encryption=$encryption")
                    assertEquals(HttpStatusCode.OK, response.status, "$path $policy/$encryption: ${response.bodyAsText()}")
                    val stored = files.get(scope, key)!!
                    assertEquals(policy, stored.accessPolicy)
                    assertEquals(encryption, stored.encryption)
                }
            }
        }
        // Without the parameters the file keeps its values (or the defaults).
        assertEquals(HttpStatusCode.OK, upload(uploadPaths[0], "f0-token-user-auth", "").status)
        assertEquals("user_auth", files.get(scope, "f0-token-user-auth")!!.encryption)
    }

    @Test
    fun `the device listener serves no vault administration`() = testApplication {
        app()
        files.put(scope, "model", "content".toByteArray(), "public", "plain")
        // No such route (404), or only the device's own method on that path (405): never served.
        fun gone(response: HttpResponse, what: String) =
            assertTrue(response.status == HttpStatusCode.NotFound || response.status == HttpStatusCode.MethodNotAllowed, "$what: ${response.status}")

        gone(upload("/api/v1/vault/%s", "other", "?policy=public"), "upload")
        gone(client.put("/api/v1/vault/model/policy") { contentType(ContentType.Application.Json); setBody("""{"access_policy":"token","encryption":"plain"}""") }, "policy")
        gone(client.delete("/api/v1/vault/model"), "delete")
        gone(client.post("/api/v1/vault/model/tokens") { contentType(ContentType.Application.Json); setBody("""{"deviceId":"d1"}""") }, "token issue")
        gone(client.get("/api/v1/vault/model/tokens"), "token list")
        gone(client.delete("/api/v1/vault/tokens/1"), "token revoke")
        gone(client.delete("/api/v1/vault/devices/d1/public-key"), "device key reset")
        for (path in listOf("/api/v1/vault", "/api/v1/vault/distributions/model", "/api/v1/vault/distributions/device/d1")) {
            gone(client.get(path), path)
        }
        // "distributions" and "stats" are reserved names, never files: a stranger is answered as for any missing file.
        for (path in listOf("/api/v1/vault/distributions", "/api/v1/vault/stats")) {
            assertEquals(HttpStatusCode.Unauthorized, client.get(path).status, path)
        }
        // The file is untouched and the device download still works.
        assertEquals("public", files.meta(scope, "model")!!.accessPolicy)
        assertEquals(1, files.meta(scope, "model")!!.version)
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/vault/model").status)
        assertNull(files.meta(scope, "other"))
    }

    @Test
    fun `a stored row with an unknown encryption is never served as plaintext`() = testApplication {
        app()
        // Written some other way than the upload routes (an older server, the database).
        files.put(scope, "legacy", "top secret".toByteArray(), "public", "rot13")
        val response = client.get("/api/v1/vault/legacy")
        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertFalse(response.bodyAsText().contains("top secret"), response.bodyAsText())
        assertTrue(response.bodyAsText().contains("Misconfigured encryption"), response.bodyAsText())
    }
}
