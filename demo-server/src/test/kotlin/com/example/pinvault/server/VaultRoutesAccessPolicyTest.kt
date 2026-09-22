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
import io.ktor.server.application.*
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

    /** Admin key injected into the routes; `null` simulates an unset API_KEY. */
    private val testAdminKey = "test-admin-key"

    private fun ApplicationTestBuilder.configureApp(apiKey: String? = testAdminKey) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService,
                apiKeyProvider = { apiKey })
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
    // The ApiKeyAuth plugin allowlists GET /api/v1/vault/{key} for every key
    // (devices fetch public/token files without an admin key), so the plugin
    // never sees this request. The route itself must enforce the key for
    // `api_key` files — and fail closed when no key is configured at all.

    @Test
    fun `api_key policy rejects fetch without X-API-Key`() = testApplication {
        configureApp()
        client.uploadWithPolicy("apikey-file", "admin-content", "api_key")

        val response = client.get("/api/v1/vault/apikey-file")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertFalse(response.bodyAsText().contains("admin-content"))
    }

    @Test
    fun `api_key policy rejects a wrong key`() = testApplication {
        configureApp()
        client.uploadWithPolicy("apikey-file", "admin-content", "api_key")

        val response = client.get("/api/v1/vault/apikey-file") { header("X-API-Key", "nope") }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertFalse(response.bodyAsText().contains("admin-content"))
    }

    @Test
    fun `api_key policy allows fetch with the configured key`() = testApplication {
        configureApp()
        client.uploadWithPolicy("apikey-file", "admin-content", "api_key")

        val response = client.get("/api/v1/vault/apikey-file") { header("X-API-Key", testAdminKey) }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("admin-content", response.bodyAsText())
    }

    @Test
    fun `api_key policy fails closed when no API_KEY is configured`() = testApplication {
        configureApp(apiKey = null)
        client.uploadWithPolicy("apikey-file", "admin-content", "api_key")

        val response = client.get("/api/v1/vault/apikey-file") { header("X-API-Key", "anything") }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertFalse(response.bodyAsText().contains("admin-content"))
    }

    // ── Scenario 6b: reserved names cannot become file keys ────────────

    @Test
    fun `upload rejects keys that collide with admin route segments`() = testApplication {
        configureApp()
        for (reserved in listOf("distributions", "stats", "devices", "report", "tokens")) {
            val put = client.put("/api/v1/vault/$reserved?policy=public") {
                setBody("x".toByteArray())
                contentType(ContentType.Application.OctetStream)
            }
            assertEquals(HttpStatusCode.BadRequest, put.status, "key '$reserved' must be rejected")
        }
    }

    // ── Scenario 7: token_mtls policy ──────────────────────────────────
    //
    // token_mtls requires BOTH:
    //   1. A valid per-device token (same check as TOKEN policy)
    //   2. A verified mTLS client cert bound to the claimed X-Device-Id
    //
    // On a real Netty connector the peer certificate is read off the channel's
    // SslHandler (see ClientCertIdentity.kt). testApplication has no TLS, so
    // these tests drive the same code path through the `TLSPeerPrincipal`
    // attribute the helper also honours — that isolates the *matching rule*
    // from the transport. The transport half is covered end-to-end by a curl
    // against the running mTLS Config API.

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

    // ── token_mtls WITH a client certificate (audit N-7) ───────────────
    //
    // Before the fix these paths were unreachable: the CN lookup always
    // returned null, so a token_mtls file 401'd even for a correctly
    // authenticated device. The policy was advertised but dead.

    /**
     * Simulates a client-authenticated connection by publishing the peer
     * principal the Netty extraction would have produced.
     */
    private fun ApplicationTestBuilder.configureAppWithClientCert(
        cn: String?,
        clientCertStore: com.example.pinvault.server.store.ClientCertStore? = null
    ) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        if (cn != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call ->
                    call.attributes.put(
                        io.ktor.util.AttributeKey<javax.security.auth.x500.X500Principal>("TLSPeerPrincipal"),
                        javax.security.auth.x500.X500Principal("CN=$cn, O=PinVault Client, C=TR")
                    )
                }
            })
        }
        routing {
            vaultRoutes(testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService,
                clientCertStore = clientCertStore,
                apiKeyProvider = { testAdminKey })
        }
    }

    @Test
    fun `token_mtls accepts a cert whose client id equals the device id`() = testApplication {
        // Auto-enrollment shape: the device enrolls with its own ANDROID_ID,
        // so the issued CN is "PinVault Client: <ANDROID_ID>".
        configureAppWithClientCert(cn = "PinVault Client: dev-a")
        client.uploadWithPolicy("mtls-ok", "top-secret", "token_mtls")
        val gen = tokenService.generate(testApi, "mtls-ok", "dev-a")

        val response = client.get("/api/v1/vault/mtls-ok") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("top-secret", response.bodyAsText())
    }

    @Test
    fun `token_mtls rejects a valid token presented with another devices cert`() = testApplication {
        // The token is valid for dev-a, but the TLS peer is dev-b: a stolen
        // token must be useless without the matching private key.
        configureAppWithClientCert(cn = "PinVault Client: dev-b")
        client.uploadWithPolicy("mtls-wrong-cert", "top-secret", "token_mtls")
        val gen = tokenService.generate(testApi, "mtls-wrong-cert", "dev-a")

        val response = client.get("/api/v1/vault/mtls-wrong-cert") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("mismatch", ignoreCase = true))
    }

    @Test
    fun `token_mtls accepts a token-enrolled cert bound to the device at enrollment`() = testApplication {
        // Token enrollment: the client id is admin-chosen and never equals an
        // ANDROID_ID, so the binding comes from client_certs.device_uid.
        val certStore = com.example.pinvault.server.store.ClientCertStore(db)
        certStore.add("qa-laptop", "PinVault Client: qa-laptop", "fp", "2026-01-01T00:00:00Z",
            deviceAlias = "QA", deviceUid = "androidid-42")

        configureAppWithClientCert(cn = "PinVault Client: qa-laptop", clientCertStore = certStore)
        client.uploadWithPolicy("mtls-bound", "top-secret", "token_mtls")
        val gen = tokenService.generate(testApi, "mtls-bound", "androidid-42")

        val response = client.get("/api/v1/vault/mtls-bound") {
            header("X-Device-Id", "androidid-42")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `token_mtls rejects a revoked certificate even when ids match`() = testApplication {
        val certStore = com.example.pinvault.server.store.ClientCertStore(db)
        certStore.add("dev-a", "PinVault Client: dev-a", "fp", "2026-01-01T00:00:00Z")
        certStore.revoke("dev-a")

        configureAppWithClientCert(cn = "PinVault Client: dev-a", clientCertStore = certStore)
        client.uploadWithPolicy("mtls-revoked", "top-secret", "token_mtls")
        val gen = tokenService.generate(testApi, "mtls-revoked", "dev-a")

        val response = client.get("/api/v1/vault/mtls-revoked") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `token_mtls still requires a valid token even with a good cert`() = testApplication {
        configureAppWithClientCert(cn = "PinVault Client: dev-a")
        client.uploadWithPolicy("mtls-no-token", "top-secret", "token_mtls")

        val response = client.get("/api/v1/vault/mtls-no-token") {
            header("X-Device-Id", "dev-a")
            header("X-Vault-Token", "not-a-real-token")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }
}
