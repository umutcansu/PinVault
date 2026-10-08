package com.example.pinvault.server

import com.example.pinvault.server.plugin.MultipartForm
import com.example.pinvault.server.plugin.genericErrors
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.EgressFilter
import com.example.pinvault.server.service.EgressRefusedException
import com.example.pinvault.server.service.StartupSecrets
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.DevicePublicKeyStore
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Deployment defaults and the smaller edges: required secrets, where a
 * certificate fetch may connect, what an error tells its caller, whether a
 * stranger can learn vault file names, and how admin uploads are read.
 */
class DeploymentHardeningTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-deploy-").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    // ── Required secrets ────────────────────────────────────────────────

    private val secrets = mapOf("KEYSTORE_PASSWORD" to "k", "VAULT_AT_REST_PASSWORD" to "v", "SIGNING_KEY_PASSWORD" to "s")

    @Test
    fun `the server refuses to start on the demo secrets unless that was asked for`() {
        assertNull(StartupSecrets.check(secrets))

        for (name in secrets.keys) {
            val error = assertFailsWith<IllegalStateException>(name) { StartupSecrets.check(secrets - name) }
            assertTrue(error.message!!.contains(name) && error.message!!.contains("ALLOW_DEMO_SECRETS"), error.message)
            // Empty or blank is unset (compose passes "${VAR:-}").
            assertFailsWith<IllegalStateException>(name) { StartupSecrets.check(secrets + (name to " ")) }
        }
        assertEquals(listOf("KEYSTORE_PASSWORD", "VAULT_AT_REST_PASSWORD", "SIGNING_KEY_PASSWORD"), StartupSecrets.missing(emptyMap()))
        // Only the exact opt-in counts.
        assertFailsWith<IllegalStateException> { StartupSecrets.check(mapOf("ALLOW_DEMO_SECRETS" to "yes")) }
        assertFailsWith<IllegalStateException> { StartupSecrets.check(mapOf("ALLOW_DEMO_SECRETS" to "TRUE")) }

        val warning = StartupSecrets.check(mapOf("ALLOW_DEMO_SECRETS" to "true", "KEYSTORE_PASSWORD" to "k"))
        assertNotNull(warning)
        assertTrue(warning.contains("VAULT_AT_REST_PASSWORD") && warning.contains("SIGNING_KEY_PASSWORD") && !warning.contains("KEYSTORE_PASSWORD"), warning)
    }

    @Test
    fun `the signing-key password is asked for per local signer only`() {
        val base = secrets - "SIGNING_KEY_PASSWORD"
        // An HSM or KMS key has no key file to encrypt.
        assertNull(StartupSecrets.check(base + ("CONFIG_SIGNERS" to "command")))
        assertNull(StartupSecrets.check(base + ("CONFIG_SIGNERS" to "pkcs11:hsm,command:kms")))
        assertEquals(listOf("SIGNING_KEY_PASSWORD"), StartupSecrets.missing(base + ("CONFIG_SIGNERS" to "local,command:kms")))
        // A named local signer: its own password, or the shared one.
        assertEquals(listOf("SIGNING_KEY_PASSWORD", "SIGNING_KEY_PASSWORD_BACKUP"), StartupSecrets.missing(base + ("CONFIG_SIGNERS" to "local,local:backup")))
        assertNull(StartupSecrets.check(secrets + ("CONFIG_SIGNERS" to "local,local:backup")))
        assertEquals(
            listOf("SIGNING_KEY_PASSWORD"),
            StartupSecrets.missing(base + ("CONFIG_SIGNERS" to "local,local:backup") + ("SIGNING_KEY_PASSWORD_BACKUP" to "b"))
        )
    }

    // ── Where a certificate fetch may connect ───────────────────────────

    private fun address(literal: String): InetAddress = InetAddress.getByName(literal)

    @Test
    fun `link-local and metadata targets are never fetched, private ones only when allowed`() {
        val strict = EgressFilter(allowPrivate = false)
        val lab = EgressFilter(allowPrivate = true)

        for (never in listOf("169.254.169.254", "169.254.0.1", "fe80::1", "100.100.100.200", "fd00:ec2::254", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255")) {
            assertNotNull(strict.refusal(address(never)), never)
            assertNotNull(lab.refusal(address(never)), "$never even with FETCH_ALLOW_PRIVATE_TARGETS=true")
        }
        for (private in listOf("127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.10", "100.64.0.1", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1")) {
            val reason = strict.refusal(address(private))
            assertNotNull(reason, private)
            assertTrue(reason.contains("FETCH_ALLOW_PRIVATE_TARGETS"), reason)
            assertNull(lab.refusal(address(private)), "$private with FETCH_ALLOW_PRIVATE_TARGETS=true")
        }
        for (public in listOf("93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:2800:220:1:248:1893:25c8:1946")) {
            assertNull(strict.refusal(address(public)), public)
        }
        assertFalse(EgressFilter.fromEnv(emptyMap()).allowPrivate)
        assertFalse(EgressFilter.fromEnv(mapOf("FETCH_ALLOW_PRIVATE_TARGETS" to "1")).allowPrivate)
        assertTrue(EgressFilter.fromEnv(mapOf("FETCH_ALLOW_PRIVATE_TARGETS" to "true")).allowPrivate)
    }

    @Test
    fun `a name is resolved once and the checked address is the one connected to`() {
        // DNS rebinding: a public address for the check, a private one for the connection.
        val lookups = AtomicInteger()
        val rebinding = EgressFilter(allowPrivate = false) { _ ->
            if (lookups.incrementAndGet() == 1) arrayOf(address("93.184.216.34")) else arrayOf(address("127.0.0.1"))
        }
        assertEquals("93.184.216.34", rebinding.resolveChecked("rebind.attacker.example").hostAddress)
        assertEquals(1, lookups.get(), "one lookup: the caller connects to what was returned, never to the name")

        val internal = EgressFilter(allowPrivate = false) { arrayOf(address("10.0.0.5"), address("93.184.216.34")) }
        val error = assertFailsWith<EgressRefusedException> { internal.resolveChecked("intranet.example") }
        assertTrue(error.message!!.contains("10.0.0.5"), error.message)
        assertFailsWith<EgressRefusedException> { EgressFilter { throw java.net.UnknownHostException(it) }.resolveChecked("nowhere.invalid") }
    }

    @Test
    fun `a fetch of a refused target is answered without a connection attempt`() {
        GovernanceHarness(dir, required = 1).use { h ->
            // The harness allows private targets (its TLS fixtures are on 127.0.0.1); metadata is refused all the same.
            val metadata = h.call("POST", "/api/v1/hosts/fetch-from-url", GovernanceHarness.ALICE, """{"url":"https://169.254.169.254/latest/meta-data"}""")
            assertEquals(400, metadata.status, metadata.body)
            assertEquals("target_not_allowed", metadata.json["reason"]!!.jsonPrimitive.content)
            assertTrue(h.pins.load(h.scope).pins.isEmpty())
            val plain = h.call("POST", "/api/v1/hosts/fetch-from-url", GovernanceHarness.ALICE, """{"url":"http://example.com"}""")
            assertEquals(400, plain.status, "https only: ${plain.body}")
        }
        val strict = com.example.pinvault.server.service.CertificateService(File(dir, "strict").also { it.mkdirs() }, egress = EgressFilter(allowPrivate = false))
        for (url in listOf("https://127.0.0.1:1", "https://localhost:1", "https://[::1]:1", "https://192.168.1.20:9443", "https://10.0.0.1")) {
            assertFailsWith<EgressRefusedException>(url) { strict.fetchFromUrl(url) }
        }
    }

    // ── What an error tells its caller ──────────────────────────────────

    @Test
    fun `an unhandled error is answered with an id, not with its message`() = testApplication {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(StatusPages) { genericErrors { "e1d2c3b4" } }
        routing {
            get("/boom") { error("jdbc:sqlite:/data/db/pinvault.db: keystore password 'hunter2' rejected") }
            post("/typed") { call.receive<JsonObject>(); call.respondText("ok") }
        }
        val response = client.get("/boom")
        assertEquals(HttpStatusCode.InternalServerError, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("Internal server error", body["error"]!!.jsonPrimitive.content)
        assertEquals("e1d2c3b4", body["errorId"]!!.jsonPrimitive.content)
        assertFalse(response.bodyAsText().contains("hunter2") || response.bodyAsText().contains("sqlite"), response.bodyAsText())

        // A body the server cannot read is the caller's mistake: 400, without the parser's text.
        val malformed = client.post("/typed") { contentType(ContentType.Application.Json); setBody("{not json") }
        assertEquals(HttpStatusCode.BadRequest, malformed.status)
        assertFalse(malformed.bodyAsText().contains("JsonDecodingException"), malformed.bodyAsText())
    }

    // ── Vault file names ────────────────────────────────────────────────

    @Test
    fun `a stranger cannot tell a missing vault file from one behind a token`() = testApplication {
        val db = DatabaseManager(File(dir, "v.sqlite").absolutePath)
        val files = VaultFileStore(db)
        val tokens = VaultFileTokenStore(db)
        files.put("default-tls", "secret", "x".toByteArray(), "token", "plain")
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            vaultRoutes("default-tls", files, VaultDistributionStore(db), tokens, DevicePublicKeyStore(db),
                VaultAccessTokenService(tokens), VaultEncryptionService(), apiKeyProvider = { "admin-key" })
        }

        suspend fun ask(key: String, device: String? = null, token: String? = null, admin: String? = null) =
            client.get("/api/v1/vault/$key") {
                device?.let { header("X-Device-Id", it) }
                token?.let { header("X-Vault-Token", it) }
                admin?.let { header("X-API-Key", it) }
            }.let { it.status to it.bodyAsText() }

        // Whatever a stranger sends, "exists behind a token" and "does not exist" answer alike: status and body.
        for ((device, token) in listOf(null to null, "dev-1" to null, "dev-1" to "guess", null to "guess")) {
            val existing = ask("secret", device, token)
            val missing = ask("no-such-file", device, token)
            assertEquals(HttpStatusCode.Unauthorized, existing.first)
            assertEquals(existing, missing, "device=$device token=$token")
        }
        assertEquals(ask("secret", "dev-1", admin = "wrong-key"), ask("no-such-file", "dev-1", admin = "wrong-key"), "a wrong admin key proves nothing")

        // Someone who showed an admin key is told the truth: the contract tools and admins rely on.
        val admin = ask("no-such-file", admin = "admin-key")
        assertEquals(HttpStatusCode.NotFound, admin.first)
        assertTrue(admin.second.contains("File not found"), admin.second)

        // A malformed name stays a 400 for everyone: it names no file.
        assertEquals(HttpStatusCode.BadRequest, ask("bad%20name").first)
    }

    // ── Admin uploads ───────────────────────────────────────────────────

    @Test
    fun `an uploaded form is parsed from bytes - fields, a binary file, quoted boundaries`() {
        val binary = ByteArray(300) { (it % 256).toByte() } + "\r\n--not-the-boundary\r\n".toByteArray()
        val (type, body) = GovernanceHarness.multipart(mapOf("clientId" to "dev-1", "password" to "päss wörd"), binary, "store.p12")
        val form = MultipartForm.parse(type, body)!!
        assertEquals(mapOf("clientId" to "dev-1", "password" to "päss wörd"), form.fields)
        assertTrue(binary.contentEquals(form.file), "the file part is byte-exact, CRLFs inside it included")

        val quoted = type.replace(Regex("boundary=(.+)$"), "boundary=\"$1\"")
        assertTrue(binary.contentEquals(MultipartForm.parse(quoted, body)!!.file))

        // No file part; not multipart; truncated; wrong boundary.
        val (fieldsOnlyType, fieldsOnly) = GovernanceHarness.multipart(mapOf("a" to "b"), null)
        assertNull(MultipartForm.parse(fieldsOnlyType, fieldsOnly)!!.file)
        assertNull(MultipartForm.parse("application/json", body))
        assertNull(MultipartForm.parse(null, body))
        assertNull(MultipartForm.parse(type, body.copyOf(body.size - 20)), "a body cut short is refused, not half-read")
        assertNull(MultipartForm.parse("multipart/form-data; boundary=other", body))
    }

    @Test
    fun `admin JSON bodies are capped on every route, gated or not`() {
        GovernanceHarness(dir, required = 2, adminBodyMax = 2_000, vaultMax = 3_000).use { h ->
            val pinsBefore = h.pins.load(h.scope)
            val padded = """{"version":0,"forceUpdate":false,"pins":[]}""" + " ".repeat(2_000)
            // Gated: refused before the gate stores a change request.
            val gated = h.call("PUT", "/api/v1/certificate-config", GovernanceHarness.ALICE, padded)
            assertEquals(413, gated.status, gated.body)
            assertTrue(h.changeRequests.list(null).isEmpty(), "no change request for a body that was refused")
            assertEquals(pinsBefore, h.pins.load(h.scope))
            // Not gated, read with a typed receive: the same cap.
            val plain = h.call("POST", "/api/v1/connection-history/web", GovernanceHarness.ALICE, """{"hostname":"a"}""" + " ".repeat(2_000))
            assertEquals(413, plain.status, plain.body)
            assertEquals(200, h.call("POST", "/api/v1/connection-history/web", GovernanceHarness.ALICE, """{"hostname":"a"}""").status)
            // The vault upload keeps VAULT_MAX_FILE_BYTES: just under it is stored as a change request.
            val upload = h.call("PUT", "/api/v1/config-apis/${h.scope}/vault/model.bin", GovernanceHarness.ALICE, ByteArray(2_999), "application/octet-stream")
            assertEquals(202, upload.status, upload.body)
        }
        GovernanceHarness(File(dir, "no-approvals").also { it.mkdirs() }, required = 1, adminBodyMax = 2_000, vaultMax = 3_000).use { h ->
            // Without approvals the upload reaches the store.
            val upload = h.call("PUT", "/api/v1/config-apis/${h.scope}/vault/model.bin", GovernanceHarness.ALICE, ByteArray(2_999), "application/octet-stream")
            assertEquals(200, upload.status, upload.body)
            assertEquals(2_999, h.vaultFiles.get(h.scope, "model.bin")!!.content.size)
            assertEquals(413, h.call("PUT", "/api/v1/config-apis/${h.scope}/vault/model.bin", GovernanceHarness.ALICE, ByteArray(3_001), "application/octet-stream").status)
        }
    }

    @Test
    fun `admin uploads of keystores and certificates are capped`() {
        GovernanceHarness(dir, required = 1, adminBodyMax = 8_000).use { h ->
            val (type, big) = GovernanceHarness.multipart(mapOf("hostname" to "big.example.com", "format" to "jks"), ByteArray(9_000))
            for (path in listOf(
                "/api/v1/hosts/upload-cert", "/api/v1/server-tls-pins/upload", "/api/v1/client-certs/upload"
            )) {
                val answer = h.call("POST", path, GovernanceHarness.ALICE, big, type)
                assertEquals(413, answer.status, "$path: ${answer.body}")
            }
            h.seedHost("mock.example.com")
            assertEquals(413, h.call("POST", "/api/v1/hosts/mock.example.com/upload-cert", GovernanceHarness.ALICE, big, type).status)
            assertEquals(413, h.call("POST", "/api/v1/hosts/mock.example.com/upload-client-cert", GovernanceHarness.ALICE, big, type).status)
            assertEquals(413, h.call("POST", "/api/v1/client-certs/generate", GovernanceHarness.ALICE, ByteArray(8_001) { 'x'.code.toByte() }).status)

            // Within the cap, a body that is not a form is a 400, not a 500.
            val notForm = h.call("POST", "/api/v1/client-certs/upload", GovernanceHarness.ALICE, "hello".toByteArray(), "application/octet-stream")
            assertEquals(400, notForm.status, notForm.body)
        }
    }
}
