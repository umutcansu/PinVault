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
 * V2 policy enforcement tests. Covers the security-critical promise that a
 * `token` file cannot be read without a matching (deviceId, key, plaintext)
 * triple — this is the core guarantee of the per-device access model.
 *
 * Each scenario uploads a file with a specific access_policy, then tries the
 * fetch under several conditions to verify the route:
 *   - enforces the right headers
 *   - binds tokens to exactly one device
 *   - binds tokens to exactly one file key
 *   - invalidates tokens on revoke
 */
class VaultRoutesAccessPolicyTest {

    private val testApi = "policy-test-api"

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
        dbFile = File.createTempFile("pinvault-policy-test-", ".db")
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
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService)
        }
    }

    private suspend fun io.ktor.client.HttpClient.uploadWithPolicy(key: String, content: String, policy: String) {
        put("/api/v1/vault/$key?policy=$policy") {
            setBody(content.toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
    }

    // ── Scenario 1: public policy is entirely unauthenticated ──────────

    @Test
    fun `public policy allows anyone to fetch without any headers`() = testApplication {
        configureApp()
        client.uploadWithPolicy("anon-public", "{}", "public")

        val response = client.get("/api/v1/vault/anon-public")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("{}", response.bodyAsText())
    }

    // ── Scenario 2: token policy — all four header combinations ────────

    @Test
    fun `token policy rejects request without X-Device-Id`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file", "secret", "token")

        val response = client.get("/api/v1/vault/tok-file") {
            // No headers at all
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token policy rejects request without X-Vault-Token`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file2", "secret", "token")

        val response = client.get("/api/v1/vault/tok-file2") {
            header("X-Device-Id", "dev-a")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token policy accepts the exact matching triple`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file3", "payload-3", "token")

        val gen = tokenService.generate(testApi, "tok-file3", "dev-a")

        val response = client.get("/api/v1/vault/tok-file3") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("payload-3", response.bodyAsText())
    }

    @Test
    fun `token policy rejects token bound to a different device`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file4", "payload-4", "token")
        val gen = tokenService.generate(testApi, "tok-file4", "dev-a")

        val response = client.get("/api/v1/vault/tok-file4") {
            header("X-Device-Id", "dev-b")               // different device!
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token policy rejects token bound to a different file`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file5a", "payload-a", "token")
        client.uploadWithPolicy("tok-file5b", "payload-b", "token")
        val gen = tokenService.generate(testApi, "tok-file5a", "dev-a")

        val response = client.get("/api/v1/vault/tok-file5b") {   // fetching b with a's token
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token policy rejects arbitrary random token`() = testApplication {
        configureApp()
        client.uploadWithPolicy("tok-file6", "payload-6", "token")
        tokenService.generate(testApi, "tok-file6", "dev-a")

        val response = client.get("/api/v1/vault/tok-file6") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", "obviously-not-the-real-token-12345678901234")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    // ── Scenario 3: revocation + replacement ──────────────────────────

    @Test
    fun `revoked token fails the next fetch`() = testApplication {
        configureApp()
        client.uploadWithPolicy("revoke-test", "payload", "token")
        val gen = tokenService.generate(testApi, "revoke-test", "dev-a")

        val ok = client.get("/api/v1/vault/revoke-test") {
            header("X-Device-Id", "dev-a"); header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, ok.status)

        tokenService.revoke(gen.id)

        val denied = client.get("/api/v1/vault/revoke-test") {
            header("X-Device-Id", "dev-a"); header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, denied.status)
    }

    @Test
    fun `reissuing a token invalidates the previous one`() = testApplication {
        configureApp()
        client.uploadWithPolicy("reissue-test", "payload", "token")
        val first = tokenService.generate(testApi, "reissue-test", "dev-a")
        val second = tokenService.generate(testApi, "reissue-test", "dev-a")  // replaces first

        // old token rejected
        val old = client.get("/api/v1/vault/reissue-test") {
            header("X-Device-Id", "dev-a"); header("X-Vault-Token", first.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, old.status)

        // new token accepted
        val new = client.get("/api/v1/vault/reissue-test") {
            header("X-Device-Id", "dev-a"); header("X-Vault-Token", second.plaintext)
        }
        assertEquals(HttpStatusCode.OK, new.status)
    }

    // ── Scenario 4: 304 flow under policy ──────────────────────────────

    @Test
    fun `304 still returned when client has current version + valid token`() = testApplication {
        configureApp()
        client.uploadWithPolicy("ver-test", "v1-body", "token")
        val gen = tokenService.generate(testApi, "ver-test", "dev-a")
        val current = vaultFileStore.get(testApi, "ver-test")!!.version

        val r = client.get("/api/v1/vault/ver-test?version=$current") {
            header("X-Device-Id", "dev-a"); header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.NotModified, r.status)
    }

    // ── Scenario 5: policy change via PUT /policy ──────────────────────

    @Test
    fun `PUT policy endpoint switches file from token to public`() = testApplication {
        configureApp()
        client.uploadWithPolicy("switch-file", "content", "token")

        // Token needed first
        val denied = client.get("/api/v1/vault/switch-file")
        assertEquals(HttpStatusCode.Unauthorized, denied.status)

        // Admin relaxes to public
        val put = client.put("/api/v1/vault/switch-file/policy") {
            contentType(ContentType.Application.Json)
            setBody("""{"access_policy":"public","encryption":"plain"}""")
        }
        assertEquals(HttpStatusCode.OK, put.status)

        // Now open
        val ok = client.get("/api/v1/vault/switch-file")
        assertEquals(HttpStatusCode.OK, ok.status)
    }

    // ── Scenario 6: api_key policy ─────────────────────────────────────
    //
    // Note: The ApiKeyAuth plugin enforces X-API-Key at plugin level for
    // non-public paths. In test harness the plugin isn't installed, so the
    // VaultRoutes code path for `api_key` is effectively a no-op (comment
    // in VaultRoutes.kt line 91-96). These tests pin the behavior as-is:
    // the route itself neither demands nor rejects based on X-API-Key,
    // relying on the ApiKeyAuth plugin when present.

    @Test
    fun `api_key policy allows fetch in test harness (no plugin)`() = testApplication {
        configureApp()
        client.uploadWithPolicy("apikey-file", "admin-content", "api_key")

        // In real deployment the ApiKeyAuth plugin would have blocked this if
        // no X-API-Key header was set; in testApplication the plugin isn't
        // installed so the call passes through.
        val response = client.get("/api/v1/vault/apikey-file")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("admin-content", response.bodyAsText())
    }

    // ── Scenario 7: token_mtls policy ──────────────────────────────────
    //
    // token_mtls requires BOTH:
    //   1. A valid per-device token (same check as TOKEN policy)
    //   2. An mTLS cert whose CN equals the claimed X-Device-Id header
    //
    // testApplication doesn't carry the X500Principal attribute, so without
    // mock mTLS plumbing the extractClientCertCn() returns null → 401
    // "mTLS client certificate required" regardless of token. This is the
    // desired behavior: plaintext HTTP requests to a token_mtls file must
    // fail closed.

    @Test
    fun `token_mtls policy rejects plain HTTP even with valid token`() = testApplication {
        configureApp()
        client.uploadWithPolicy("mtls-file", "top-secret", "token_mtls")
        val gen = tokenService.generate(testApi, "mtls-file", "dev-a")

        val response = client.get("/api/v1/vault/mtls-file") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        // No mTLS cert on the call → rejected with 401
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("mTLS", ignoreCase = true))
    }

    @Test
    fun `token_mtls policy also rejects requests with no token`() = testApplication {
        configureApp()
        client.uploadWithPolicy("mtls-file2", "secret", "token_mtls")

        val response = client.get("/api/v1/vault/mtls-file2") {
            header("X-Device-Id", "dev-a")
            // No X-Vault-Token
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token_mtls policy also rejects requests with no deviceId`() = testApplication {
        configureApp()
        client.uploadWithPolicy("mtls-file3", "secret", "token_mtls")

        val response = client.get("/api/v1/vault/mtls-file3") {
            // No X-Device-Id, no X-Vault-Token, no cert
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }
}
