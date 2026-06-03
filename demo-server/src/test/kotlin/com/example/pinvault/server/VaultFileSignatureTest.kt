package com.example.pinvault.server

import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.ConfigSigningService
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
import java.security.MessageDigest
import kotlin.test.*

/**
 * Proves vault file CONTENT signing (integrity). A device that distributes a
 * trust anchor (truststore/CA) must be able to reject a tampered file even if
 * the server/DB/mirror is compromised — the signature, verified client-side
 * against the Config API's ECDSA key, is what guarantees that.
 *
 * Asserts:
 *  - a 200 download carries an X-Vault-Signature valid over key+version+hash
 *  - that same signature does NOT verify against tampered content
 *  - a 304 carries NO signature (nothing new to trust)
 *  - with no signer wired, no signature header is emitted (back-compat)
 */
class VaultFileSignatureTest {

    private val testApi = "sign-api"
    private lateinit var db: DatabaseManager
    private lateinit var vaultFileStore: VaultFileStore
    private lateinit var distStore: VaultDistributionStore
    private lateinit var tokenStore: VaultFileTokenStore
    private lateinit var publicKeyStore: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private lateinit var encryptionService: VaultEncryptionService
    private lateinit var signingService: ConfigSigningService
    private lateinit var dbFile: File
    private lateinit var keyFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-vaultsig-", ".db").apply { deleteOnExit() }
        // delete() so ConfigSigningService generates a fresh keypair into it
        keyFile = File.createTempFile("pinvault-vaultsig-key-", ".pem").apply { delete(); deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        vaultFileStore = VaultFileStore(db)
        distStore = VaultDistributionStore(db)
        tokenStore = VaultFileTokenStore(db)
        publicKeyStore = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokenStore)
        encryptionService = VaultEncryptionService()
        signingService = ConfigSigningService(keyFile)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        keyFile.delete()
    }

    /** Same canonical the server/client build — kept in lock-step here on purpose. */
    private fun canonical(key: String, version: Int, content: ByteArray): String {
        val hex = MessageDigest.getInstance("SHA-256").digest(content)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return "pinvault-vault-file:v1:$key:$version:$hex"
    }

    private fun ApplicationTestBuilder.configureApp(withSigner: Boolean = true) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(testApi, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService,
                if (withSigner) signingService else null)
        }
    }

    @Test
    fun `200 download carries a signature valid over key+version+hash`() = testApplication {
        configureApp()
        val content = "trust-anchor-bytes".toByteArray()
        client.put("/api/v1/vault/ts?policy=public") {
            setBody(content); contentType(ContentType.Application.OctetStream)
        }

        val resp = client.get("/api/v1/vault/ts?version=0")
        assertEquals(HttpStatusCode.OK, resp.status)
        val version = resp.headers["X-Vault-Version"]!!.toInt()
        val sig = resp.headers["X-Vault-Signature"]
        assertNotNull(sig, "a 200 download must carry X-Vault-Signature")
        assertTrue(
            signingService.verify(canonical("ts", version, content), sig!!),
            "signature must verify over the canonical key+version+hash"
        )
    }

    @Test
    fun `signature does not verify against tampered content`() = testApplication {
        configureApp()
        val content = "real".toByteArray()
        client.put("/api/v1/vault/ts2?policy=public") {
            setBody(content); contentType(ContentType.Application.OctetStream)
        }

        val resp = client.get("/api/v1/vault/ts2?version=0")
        val version = resp.headers["X-Vault-Version"]!!.toInt()
        val sig = resp.headers["X-Vault-Signature"]!!
        assertFalse(
            signingService.verify(canonical("ts2", version, "TAMPERED".toByteArray()), sig),
            "the signature must NOT verify once content is altered"
        )
    }

    @Test
    fun `304 not modified carries no signature`() = testApplication {
        configureApp()
        client.put("/api/v1/vault/ts3?policy=public") {
            setBody("v".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        val current = vaultFileStore.get(testApi, "ts3")!!.version

        val resp = client.get("/api/v1/vault/ts3?version=$current")
        assertEquals(HttpStatusCode.NotModified, resp.status)
        assertNull(resp.headers["X-Vault-Signature"], "304 must not carry a signature")
    }

    @Test
    fun `no signer wired means no signature header`() = testApplication {
        configureApp(withSigner = false)
        client.put("/api/v1/vault/ts4?policy=public") {
            setBody("x".toByteArray()); contentType(ContentType.Application.OctetStream)
        }
        val resp = client.get("/api/v1/vault/ts4?version=0")
        assertEquals(HttpStatusCode.OK, resp.status)
        assertNull(resp.headers["X-Vault-Signature"])
    }
}
