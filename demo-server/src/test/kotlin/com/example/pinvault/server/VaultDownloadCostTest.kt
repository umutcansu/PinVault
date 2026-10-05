package com.example.pinvault.server

import com.example.pinvault.server.plugin.DeviceRefusalLimit
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultAtRestCipher
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.security.KeyPairGenerator
import java.util.Base64
import kotlin.test.*

/**
 * What a vault request costs before it is authorised (O1): nothing is
 * decrypted — and no at-rest key derived — for a request that is refused or
 * answered without a body, the key is derived once per process and not once
 * per download, and an address that keeps being refused is cut off.
 */
class VaultDownloadCostTest {

    private val scope = "cost-api"
    private val password = "an-operator-password"

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var tokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService

    /** The cipher of the "restarted" server the routes run on: its cache starts empty. */
    private lateinit var cipher: VaultAtRestCipher
    private lateinit var files: VaultFileStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-cost-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        tokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(tokens)
        // Uploaded by an earlier process: the serving one has derived nothing yet.
        VaultFileStore(db, VaultAtRestCipher(password)).apply {
            put(scope, "secret", "the secret".toByteArray(), "token", "at_rest")
            put(scope, "wallet", "the wallet".toByteArray(), "token", "end_to_end")
            put(scope, "sealed", "sealed for all".toByteArray(), "public", "end_to_end")
        }
        cipher = VaultAtRestCipher(password)
        files = VaultFileStore(db, cipher)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun ApplicationTestBuilder.configureApp(refusalLimiter: RateLimiter? = null) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        if (refusalLimiter != null) install(DeviceRefusalLimit) { limiter = refusalLimiter }
        routing {
            vaultRoutes(scope, files, VaultDistributionStore(db), tokens, keys, tokenService, VaultEncryptionService())
        }
    }

    private fun rsaPem(): String {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public
        val body = Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    private suspend fun ApplicationTestBuilder.download(key: String, device: String? = null, token: String? = null, version: Int? = null) =
        client.get("/api/v1/vault/$key" + (version?.let { "?version=$it" } ?: "")) {
            device?.let { header("X-Device-Id", it) }
            token?.let { header("X-Vault-Token", it) }
        }

    @Test
    fun `refused requests for a token file derive no key and open nothing`() = testApplication {
        configureApp()
        repeat(20) { round ->
            assertEquals(HttpStatusCode.Unauthorized, download("secret").status)
            assertEquals(HttpStatusCode.Unauthorized, download("secret", "dev-$round").status)
            assertEquals(HttpStatusCode.Unauthorized, download("secret", "dev-$round", "not-the-token").status)
            assertEquals(HttpStatusCode.Unauthorized, download("wallet", "dev-$round", "not-the-token").status)
            // A missing file answers a stranger exactly as a token file does (no name enumeration).
            assertEquals(HttpStatusCode.Unauthorized, download("no-such-file", "dev-$round").status)
        }
        assertEquals(0, cipher.derivations, "a refusal must not cost a key derivation")
    }

    @Test
    fun `a 304 and a device without a key are answered from the metadata`() = testApplication {
        configureApp()
        val token = tokenService.generate(scope, "secret", "dev-1").plaintext
        val current = download("secret", "dev-1", token, version = 1)
        assertEquals(HttpStatusCode.NotModified, current.status)
        assertEquals("1", current.headers["X-Vault-Version"])
        assertEquals("at_rest", current.headers["X-Vault-Encryption"])
        // An end_to_end file for a device that registered no key: 412 before the file is opened.
        assertEquals(HttpStatusCode.PreconditionFailed, download("sealed", "dev-1").status)
        assertEquals(HttpStatusCode.Unauthorized, download("sealed").status, "no device id")
        assertEquals(0, cipher.derivations)
    }

    @Test
    fun `an authorised download derives the key once, however often it is repeated`() = testApplication {
        configureApp()
        val token = tokenService.generate(scope, "secret", "dev-1").plaintext
        repeat(5) {
            val response = download("secret", "dev-1", token)
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals("the secret", response.bodyAsText())
        }
        assertEquals(1, cipher.derivations, "one derivation per process, not one per download")

        // The other files were written by the same process (one salt): no further derivation.
        keys.register("dev-1", scope, rsaPem(), timestamp = "now")
        assertEquals(HttpStatusCode.OK, download("sealed", "dev-1").status)
        assertEquals(1, cipher.derivations)
    }

    @Test
    fun `a key replacement proof looks at the file's metadata only`() = testApplication {
        configureApp()
        keys.register("dev-1", scope, rsaPem(), timestamp = "now")
        repeat(10) {
            val refused = client.post("/api/v1/vault/devices/dev-1/public-key") {
                contentType(ContentType.Application.Json)
                header("X-Vault-Key", "wallet"); header("X-Vault-Token", "any-token-$it")
                setBody(buildJsonObject { put("publicKeyPem", rsaPem()) }.toString())
            }
            assertEquals(HttpStatusCode.Conflict, refused.status)
        }
        assertEquals(0, cipher.derivations, "the proof path used to open the file for every request")

        // The real token still proves the device, still without opening the file.
        val token = tokenService.generate(scope, "wallet", "dev-1").plaintext
        val replaced = client.post("/api/v1/vault/devices/dev-1/public-key") {
            contentType(ContentType.Application.Json)
            header("X-Vault-Key", "wallet"); header("X-Vault-Token", token)
            setBody(buildJsonObject { put("publicKeyPem", rsaPem()) }.toString())
        }
        assertEquals(HttpStatusCode.OK, replaced.status, replaced.bodyAsText())
        assertEquals(0, cipher.derivations)
    }

    @Test
    fun `an address that keeps being refused is cut off, and served requests are not counted`() = testApplication {
        configureApp(refusalLimiter = RateLimiter(maxAttempts = 3, windowMs = 60_000))
        val token = tokenService.generate(scope, "secret", "dev-1").plaintext
        // Served requests never use up the quota.
        repeat(10) { assertEquals(HttpStatusCode.OK, download("secret", "dev-1", token).status) }

        val statuses = (1..6).map { download("secret", "dev-$it", "guess-$it").status }
        assertEquals(List(3) { HttpStatusCode.Unauthorized } + List(3) { HttpStatusCode.TooManyRequests }, statuses)
        // Cut off before anything is looked at: the valid token too, and the proof path.
        val cutOff = download("secret", "dev-1", token)
        assertEquals(HttpStatusCode.TooManyRequests, cutOff.status)
        assertTrue(cutOff.bodyAsText().contains("rate_limited"))
        assertEquals(HttpStatusCode.TooManyRequests, client.post("/api/v1/vault/devices/dev-9/public-key") {
            contentType(ContentType.Application.Json)
            header("X-Vault-Key", "wallet"); header("X-Vault-Token", "x")
            setBody("""{"publicKeyPem":"x"}""")
        }.status)
        // Reports are not this limiter's business.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/vault/report") {
            contentType(ContentType.Application.Json)
            setBody("""{"key":"secret","version":1,"deviceId":"dev-1","status":"downloaded"}""")
        }.status)
    }

    // ── the cipher itself ────────────────────────────────────────────────

    @Test
    fun `one instance derives once for everything it writes and reads`() {
        val one = VaultAtRestCipher(password)
        val blobs = (1..5).map { one.encrypt("file $it".toByteArray()) }
        blobs.forEachIndexed { i, blob -> assertEquals("file ${i + 1}", one.decrypt(blob).toString(Charsets.UTF_8)) }
        assertEquals(1, one.derivations)
        assertEquals(5, blobs.map { Base64.getEncoder().encodeToString(it.copyOfRange(24, 36)) }.distinct().size, "a fresh IV per blob")
    }

    @Test
    fun `blobs of earlier processes open, one derivation per salt and none when read again`() {
        val earlier = (1..3).map { VaultAtRestCipher(password).encrypt("old $it".toByteArray()) }
        val now = VaultAtRestCipher(password)
        repeat(4) {
            earlier.forEachIndexed { i, blob -> assertEquals("old ${i + 1}", now.decrypt(blob).toString(Charsets.UTF_8)) }
        }
        assertEquals(3, now.derivations)
    }

    @Test
    fun `a previous password still opens a blob for the startup pass, the current one alone for reads`() {
        val old = VaultAtRestCipher("old-password").encrypt("kept".toByteArray())
        val rotated = VaultAtRestCipher(password, previous = listOf("old-password"))
        val opened = rotated.open(old)
        assertTrue(opened is VaultAtRestCipher.Opened.Previous)
        assertEquals("kept", (opened as VaultAtRestCipher.Opened.Previous).plaintext.toString(Charsets.UTF_8))
        assertFailsWith<com.example.pinvault.server.service.VaultKeyMismatchException> { rotated.decrypt(old) }
        // The wrong-password read derived once (cached), not once per attempt.
        val before = rotated.derivations
        repeat(3) { assertFails { rotated.decrypt(old) } }
        assertEquals(before, rotated.derivations)
    }
}
