package com.example.pinvault.server

import com.example.pinvault.server.route.adminVaultRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.ConfigApiRegistry
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DeviceHostAclStore
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
 * The "vault enabled" switch, end to end inside the server.
 *
 * E2E scenario C09 found it inert in two independent ways, and both are
 * covered here:
 *
 *  1. The Config API the sample app actually uses (`default-tls`) had no
 *     `config_apis` row, because Main.kt mounts that listener directly instead
 *     of going through `POST /api/v1/config-apis/start`. The toggle's
 *     `UPDATE … WHERE id = ?` matched nothing and answered 404, so the switch
 *     could not even be stored — see [ConfigApiRegistry.ensureRegistered].
 *  2. Nothing ever read the flag back: the download route served files with
 *     the switch off.
 */
class VaultEnabledSwitchTest {

    private val testApi = "switch-test-api"

    private lateinit var db: DatabaseManager
    private lateinit var dbFile: File
    private lateinit var registry: ConfigApiRegistry
    private lateinit var vaultFileStore: VaultFileStore
    private lateinit var distStore: VaultDistributionStore
    private lateinit var tokenStore: VaultFileTokenStore
    private lateinit var publicKeyStore: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var encryptionService: VaultEncryptionService
    private lateinit var aclStore: DeviceHostAclStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-vault-switch-test-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        registry = ConfigApiRegistry(db)
        vaultFileStore = VaultFileStore(db)
        distStore = VaultDistributionStore(db)
        tokenStore = VaultFileTokenStore(db)
        publicKeyStore = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokenStore)
        encryptionService = VaultEncryptionService()
        aclStore = DeviceHostAclStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    /** Config API listener (the port devices talk to) plus the admin toggle. */
    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(
                testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService,
                apiKeyProvider = { "test-admin-key" },
                vaultEnabledProvider = { registry.isVaultEnabled(testApi) }
            )
            adminVaultRoutes(db, aclStore, registry)
        }
    }

    private suspend fun io.ktor.client.HttpClient.upload(key: String, content: String) {
        put("/api/v1/vault/$key?policy=public") {
            setBody(content.toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
    }

    private suspend fun io.ktor.client.HttpClient.toggle(enabled: Boolean) =
        put("/api/v1/config-apis/$testApi/vault-enabled") {
            contentType(ContentType.Application.Json)
            setBody("""{"enabled":$enabled}""")
        }

    // ── The switch is reachable on a directly-mounted Config API ────────

    @Test
    fun `ensureRegistered makes the toggle reachable on a directly mounted Config API`() = testApplication {
        // No row yet: this is the state default-tls was permanently stuck in.
        assertNull(registry.vaultEnabledOrNull(testApi))
        configureApp()
        assertEquals(HttpStatusCode.NotFound, client.toggle(false).status)

        registry.ensureRegistered(testApi, 8091, "tls")

        assertEquals(HttpStatusCode.OK, client.toggle(false).status)
        assertEquals(false, registry.isVaultEnabled(testApi))
    }

    @Test
    fun `ensureRegistered is idempotent and preserves a disabled vault`() {
        registry.ensureRegistered(testApi, 8091, "tls")
        assertTrue(registry.isVaultEnabled(testApi))

        registry.setVaultEnabled(testApi, false)
        // A server restart (or an API restart through the start route) must not
        // silently re-open a vault the operator closed.
        registry.ensureRegistered(testApi, 8091, "tls")

        assertEquals(false, registry.isVaultEnabled(testApi))
    }

    @Test
    fun `unknown Config API still answers true so unregistered listeners keep working`() {
        // A missing row means "not registered", not "disabled": embedded and
        // test listeners mount vaultRoutes without touching config_apis.
        assertTrue(registry.isVaultEnabled("never-registered"))
    }

    // ── The switch actually stops downloads ────────────────────────────

    @Test
    fun `download is refused with 403 while the vault is disabled`() = testApplication {
        configureApp()
        registry.ensureRegistered(testApi, 8091, "tls")
        client.upload("flags", "bayraklar")

        assertEquals(HttpStatusCode.OK, client.get("/api/v1/vault/flags").status)

        assertEquals(HttpStatusCode.OK, client.toggle(false).status)

        val refused = client.get("/api/v1/vault/flags")
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertTrue(
            refused.bodyAsText().contains("disabled"),
            "the error must say why: ${refused.bodyAsText()}"
        )
    }

    @Test
    fun `a disabled vault does not reveal which keys exist`() = testApplication {
        configureApp()
        registry.ensureRegistered(testApi, 8091, "tls")
        client.upload("flags", "bayraklar")
        client.toggle(false)

        // Present and absent keys must be indistinguishable — 403 for both,
        // not 403 vs 404.
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/vault/flags").status)
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/vault/no-such-key").status)
    }

    @Test
    fun `re-enabling restores downloads`() = testApplication {
        configureApp()
        registry.ensureRegistered(testApi, 8091, "tls")
        client.upload("flags", "bayraklar")
        client.toggle(false)
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/vault/flags").status)

        assertEquals(HttpStatusCode.OK, client.toggle(true).status)

        val res = client.get("/api/v1/vault/flags")
        assertEquals(HttpStatusCode.OK, res.status)
        assertEquals("bayraklar", res.bodyAsText())
    }

    // ── Administration stays available so the operator can clean up ────

    @Test
    fun `admin routes keep working while the vault is disabled`() = testApplication {
        configureApp()
        registry.ensureRegistered(testApi, 8091, "tls")
        client.upload("flags", "bayraklar")
        client.toggle(false)

        // Upload / list / delete must survive: flipping the switch is what an
        // operator does *before* removing a file that went out by mistake.
        client.upload("flags", "duzeltilmis")
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/vault").status)
        assertTrue(client.get("/api/v1/vault").bodyAsText().contains("flags"))
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/vault/flags").status)
        assertNull(vaultFileStore.get(testApi, "flags"))
    }

    @Test
    fun `report and distribution history keep working while the vault is disabled`() = testApplication {
        configureApp()
        registry.ensureRegistered(testApi, 8091, "tls")
        client.toggle(false)

        val report = client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"flags","version":0,"deviceId":"dev-1","status":"failed"}""")
        }
        assertEquals(HttpStatusCode.OK, report.status)
        assertTrue(client.get("/api/v1/vault/distributions").bodyAsText().contains("dev-1"))
    }

    // ── Default: a listener with no provider behaves exactly as before ──

    @Test
    fun `vaultEnabledProvider defaults to enabled`() = testApplication {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(
                testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService,
                apiKeyProvider = { "test-admin-key" }
            )
        }
        client.upload("flags", "bayraklar")
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/vault/flags").status)
    }
}
