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
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.*

/**
 * Cross-layer test for the `mtls-secure` Config API scope.
 *
 * Web UI'da mtls-secure scope'una yüklenen 4 örnek dosya (app-config /
 * feature-flags / ml-model / secrets — her biri farklı access_policy +
 * encryption kombinasyonunda) için uçtan uca erişim matrisini doğrular:
 *
 *   app-config     public      plain         → header'sız erişim
 *   feature-flags  token       plain         → cihaz başına token
 *   ml-model       token       end_to_end    → token + RSA-OAEP sarmal
 *   secrets        token_mtls  end_to_end    → token + mTLS cert CN eşleşmesi
 *
 * Aynı senaryoları `default-tls` scope'unda da yürüten policy testleri zaten
 * `VaultRoutesAccessPolicyTest`'te var; bu test scope izolasyonunu ve mtls-
 * secure özelindeki davranışı kanıtlar — bir scope'ta üretilen token diğer
 * scope'ta çalışmamalı, dosyalar da scope'a bağlı olmalı.
 */
class MtlsSecureVaultPolicyCrossTest {

    private val mtlsSecure = "mtls-secure"
    private val defaultTls = "default-tls"

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
        dbFile = File.createTempFile("pinvault-mtls-secure-test-", ".db")
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

    /** Vault routes mounted for mtls-secure scope. */
    private fun ApplicationTestBuilder.mountMtlsSecure() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes(mtlsSecure, vaultFileStore, distStore, tokenStore,
                publicKeyStore, tokenService, encryptionService)
        }
    }

    private suspend fun io.ktor.client.HttpClient.upload(
        key: String, content: String, policy: String, encryption: String = "plain"
    ) {
        put("/api/v1/vault/$key?policy=$policy&encryption=$encryption") {
            setBody(content.toByteArray())
            contentType(ContentType.Application.OctetStream)
        }
    }

    // ── 1. Public policy (app-config eşdeğeri) ─────────────────────────

    @Test
    fun `app-config public fetch needs no headers under mtls-secure`() = testApplication {
        mountMtlsSecure()
        client.upload("app-config", """{"appVersion":"2.0.0"}""", "public")

        val resp = client.get("/api/v1/vault/app-config")
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals("""{"appVersion":"2.0.0"}""", resp.bodyAsText())
    }

    // ── 2. Token policy (feature-flags eşdeğeri) ───────────────────────

    @Test
    fun `feature-flags token fetch succeeds with valid device+token triple`() = testApplication {
        mountMtlsSecure()
        client.upload("feature-flags", """{"newCheckout":true}""", "token")

        val gen = tokenService.generate(mtlsSecure, "feature-flags", "device-prod-1")

        val resp = client.get("/api/v1/vault/feature-flags") {
            header("X-Device-Id", "device-prod-1")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals("""{"newCheckout":true}""", resp.bodyAsText())
    }

    @Test
    fun `feature-flags token rejects another device even with valid plaintext`() = testApplication {
        mountMtlsSecure()
        client.upload("feature-flags", "payload", "token")
        val gen = tokenService.generate(mtlsSecure, "feature-flags", "device-prod-1")

        val resp = client.get("/api/v1/vault/feature-flags") {
            header("X-Device-Id", "device-prod-2")          // farklı cihaz
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── 3. End-to-end encryption (ml-model eşdeğeri) ───────────────────

    @Test
    fun `ml-model e2e returns encrypted envelope when device has a registered RSA key`() = testApplication {
        mountMtlsSecure()

        // Cihaz RSA key'ini kayıt et — e2e için gerekli
        val kp = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val pem = "-----BEGIN PUBLIC KEY-----\n" +
            java.util.Base64.getEncoder().encodeToString(kp.public.encoded) +
            "\n-----END PUBLIC KEY-----"
        publicKeyStore.register(
            deviceId = "device-e2e-1",
            configApiId = mtlsSecure,
            publicKeyPem = pem,
            algorithm = "RSA-OAEP-SHA256",
            timestamp = java.time.Instant.now().toString()
        )

        val plaintext = "mlmodel-binary-bytes".repeat(20)  // ~400 bytes
        client.upload("ml-model", plaintext, "token", "end_to_end")

        val gen = tokenService.generate(mtlsSecure, "ml-model", "device-e2e-1")

        val resp = client.get("/api/v1/vault/ml-model") {
            header("X-Device-Id", "device-e2e-1")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals("end_to_end", resp.headers["X-Vault-Encryption"])

        // Envelope: cihazın private key'iyle açılmalı, plaintext geri gelmeli
        val envelope = resp.readRawBytes()
        val decrypted = com.example.pinvault.server.service.VaultEncryptionRoundtripTestHelper
            .decrypt(envelope, kp.private)
        assertEquals(plaintext, String(decrypted))
    }

    @Test
    fun `ml-model e2e rejects when device has no registered public key`() = testApplication {
        mountMtlsSecure()
        client.upload("ml-model", "content", "token", "end_to_end")
        val gen = tokenService.generate(mtlsSecure, "ml-model", "unknown-device")

        val resp = client.get("/api/v1/vault/ml-model") {
            header("X-Device-Id", "unknown-device")
            header("X-Vault-Token", gen.plaintext)
        }
        // Server cihaz pub key bulamadığı için 500 vs 412 atabilir; işin kalbi:
        // 200 OK ile şifresiz içerik dönmesin.
        assertNotEquals(HttpStatusCode.OK, resp.status)
    }

    // ── 4. token_mtls policy (secrets eşdeğeri) ────────────────────────

    @Test
    fun `secrets token_mtls rejects plain HTTP even with valid token under mtls-secure`() = testApplication {
        mountMtlsSecure()
        client.upload("secrets", "topsecret", "token_mtls")
        val gen = tokenService.generate(mtlsSecure, "secrets", "device-tls-1")

        val resp = client.get("/api/v1/vault/secrets") {
            header("X-Device-Id", "device-tls-1")
            header("X-Vault-Token", gen.plaintext)
            // X-MTLS-Client-Cn header YOK → test harness'te mTLS sim yok
        }
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    // ── 5. Scope izolasyonu: cross-scope token taşması yok ────────────

    @Test
    fun `token issued for mtls-secure does not validate under default-tls scope`() = testApplication {
        mountMtlsSecure()

        // Her iki scope'a aynı key + content + policy yükle (store doğrudan)
        vaultFileStore.put(mtlsSecure, "feature-flags", "MTLS_PAYLOAD".toByteArray(), "token", "plain")
        vaultFileStore.put(defaultTls, "feature-flags", "TLS_PAYLOAD".toByteArray(), "token", "plain")

        val genMtls = tokenService.generate(mtlsSecure, "feature-flags", "device-dual-1")

        // mtls-secure scope'tan fetch — başarılı
        val respMtls = client.get("/api/v1/vault/feature-flags") {
            header("X-Device-Id", "device-dual-1")
            header("X-Vault-Token", genMtls.plaintext)
        }
        assertEquals(HttpStatusCode.OK, respMtls.status)
        assertEquals("MTLS_PAYLOAD", respMtls.bodyAsText())

        // default-tls validate: token mtls-secure'e bağlı olmalı, bu scope'ta geçerli olmamalı
        assertFalse(tokenService.validate(defaultTls, "feature-flags", "device-dual-1", genMtls.plaintext),
            "Token cross-scope geçerli olmamalı (mtls-secure → default-tls taşma yok)")
    }

    // ── 6. Token revocation per scope ─────────────────────────────────

    @Test
    fun `revoking token in mtls-secure invalidates next fetch immediately`() = testApplication {
        mountMtlsSecure()
        client.upload("feature-flags", "v1", "token")

        val gen = tokenService.generate(mtlsSecure, "feature-flags", "device-revoke-1")
        // İlk fetch çalışıyor
        val ok = client.get("/api/v1/vault/feature-flags") {
            header("X-Device-Id", "device-revoke-1")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.OK, ok.status)

        // Revoke
        tokenStore.revoke(gen.id)

        // Sonraki fetch reddedilmeli
        val blocked = client.get("/api/v1/vault/feature-flags") {
            header("X-Device-Id", "device-revoke-1")
            header("X-Vault-Token", gen.plaintext)
        }
        assertEquals(HttpStatusCode.Unauthorized, blocked.status)
    }

    // ── 7. Policy reconfigure — UI-driven "policy change" akışı ────────

    @Test
    fun `changing policy from token to public removes auth requirement mid-life`() = testApplication {
        mountMtlsSecure()
        client.upload("app-config", "payload", "token")

        // Başta token lazım
        val unauth = client.get("/api/v1/vault/app-config")
        assertEquals(HttpStatusCode.Unauthorized, unauth.status)

        // Policy'yi public'e çevir (store üzerinden; prod'da PUT .../policy route)
        vaultFileStore.updatePolicy(mtlsSecure, "app-config", "public", "plain")

        // Artık auth'suz başarılı
        val open = client.get("/api/v1/vault/app-config")
        assertEquals(HttpStatusCode.OK, open.status)
        assertEquals("payload", open.bodyAsText())
    }
}
