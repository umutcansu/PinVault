package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.scopedVaultAdminRoutes
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
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.*

/**
 * Review 2026-11-17 (server side):
 *
 *  - a deleted vault file left its tokens behind, and a token could be issued
 *    for a file that did not exist: whatever was uploaded under the same name
 *    later opened with them;
 *  - a vault upload read the version and wrote it as two steps: two uploads at
 *    the same time got the same version with different content;
 *  - a pin save read (first snapshot, one watermark per host) before it wrote,
 *    on a deferred transaction: under WAL a commit by any other connection in
 *    between failed the save with SQLITE_BUSY_SNAPSHOT.
 */
class Review20261117ServerTest {

    private val api = "review-1117"

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var vfs: VaultFileStore
    private lateinit var tokens: VaultFileTokenStore

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-review-1117-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath, DatabaseManager.JournalMode.WAL)
        vfs = VaultFileStore(db)
        tokens = VaultFileTokenStore(db)
    }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun ApplicationTestBuilder.configureApp() {
        val dist = VaultDistributionStore(db)
        val pks = DevicePublicKeyStore(db)
        val tokenSvc = VaultAccessTokenService(tokens)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            scopedVaultAdminRoutes(vfs, dist, tokens, tokenSvc, publicKeyStore = pks)
            vaultRoutes(api, vfs, dist, tokens, pks, tokenSvc, VaultEncryptionService())
        }
    }

    private suspend fun ApplicationTestBuilder.upload(key: String, content: String) =
        client.put("/api/v1/config-apis/$api/vault/$key?policy=token") {
            setBody(content.toByteArray()); contentType(ContentType.Application.OctetStream)
        }

    private suspend fun ApplicationTestBuilder.issue(key: String, device: String) =
        client.post("/api/v1/config-apis/$api/vault/$key/tokens") {
            contentType(ContentType.Application.Json); setBody("""{"deviceId":"$device"}""")
        }

    @Test
    fun `a token of a deleted file does not open the file uploaded under its name later`() = testApplication {
        configureApp()
        upload("secrets", "for devices A to C")
        val token = Json.parseToJsonElement(issue("secrets", "dev-a").bodyAsText()).jsonObject["token"]!!.jsonPrimitive.content
        suspend fun fetch() = client.get("/api/v1/vault/secrets") { header("X-Device-Id", "dev-a"); header("X-Vault-Token", token) }
        assertEquals(HttpStatusCode.OK, fetch().status)

        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/config-apis/$api/vault/secrets").status)
        upload("secrets", "for device D only")

        assertEquals(HttpStatusCode.Unauthorized, fetch().status, "the old file's token must not open the new file")
        assertTrue(tokens.listForFile(api, "secrets").all { it.revoked })
    }

    @Test
    fun `no token is issued for a file that does not exist`() = testApplication {
        configureApp()
        val answer = issue("not-uploaded-yet", "dev-a")
        assertEquals(HttpStatusCode.NotFound, answer.status)
        assertTrue(answer.bodyAsText().contains("vault_file_not_found"))
        assertTrue(tokens.listForFile(api, "not-uploaded-yet").isEmpty())
    }

    @Test
    fun `uploads of one file at the same time each get their own version`() {
        val writers = 8
        val pool = Executors.newFixedThreadPool(writers)
        val start = CountDownLatch(1)
        val done = (1..writers).map { n ->
            pool.submit { start.await(); vfs.put(api, "racing", "content-$n".toByteArray(), "token", "plain") }
        }
        start.countDown()
        done.forEach { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()
        assertEquals(writers, vfs.meta(api, "racing")!!.version, "one version per upload: none shared a number")
    }

    @Test
    fun `a pin save does not fail while other connections keep committing`() {
        val store = PinConfigStore(db)
        db.connection().use { it.createStatement().use { s -> s.executeUpdate("CREATE TABLE IF NOT EXISTS review_noise (n INTEGER)") } }
        val stop = AtomicBoolean(false)
        val noise = Executors.newSingleThreadExecutor()
        noise.submit {
            while (!stop.get()) {
                runCatching { db.connection().use { it.createStatement().use { s -> s.executeUpdate("INSERT INTO review_noise VALUES (1)") } } }
            }
        }
        try {
            val pins = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
            repeat(15) { round ->
                val hosts = (1..300).map { HostPin("h$it.review.example", pins, version = round + 1) }
                store.save(api, PinConfig(pins = hosts))
            }
        } finally {
            stop.set(true)
            noise.shutdown()
            noise.awaitTermination(10, TimeUnit.SECONDS)
        }
        assertEquals(300, store.load(api).pins.size)
    }
}
