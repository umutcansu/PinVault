package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.model.SignatureEntry
import com.example.pinvault.server.model.SignedKeySetWire
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.signingAdminRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.SigningKeySetService
import com.example.pinvault.server.service.signing.CommandSigner
import com.example.pinvault.server.service.signing.LocalFileSigner
import com.example.pinvault.server.service.signing.SigningKeys
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.*

/**
 * The optional signing features of the reference server: several signers
 * (m-of-n), the external command signer, the per-content signature cache and
 * signing-key sets relayed to devices.
 */
class SigningFeaturesTest {

    private val scope = "signing-features"
    private val pins = listOf(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
    )

    private lateinit var dir: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-signing-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
        store = PinConfigStore(db)
        store.save(scope, PinConfig(pins = listOf(HostPin("a.example.com", pins, version = 1))))
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun KeyPair.pub() = Base64.getEncoder().encodeToString(public.encoded)

    private fun KeyPair.sign(text: String): String = Signature.getInstance("SHA256withECDSA").run {
        initSign(private)
        update(text.toByteArray(Charsets.UTF_8))
        Base64.getEncoder().encodeToString(sign())
    }

    private fun verifies(publicKeyBase64: String, payload: String, signature: String) =
        SigningKeys.verify(SigningKeys.decodePublicKey(publicKeyBase64), payload.toByteArray(), Base64.getDecoder().decode(signature))

    private fun twoSigners() = ConfigSigningService.fromEnv(
        File(dir, "signing-key.pem"),
        mapOf("CONFIG_SIGNERS" to "local,local:second")
    )

    // ── Signers ─────────────────────────────────────────────────────────

    @Test
    fun `CONFIG_SIGNERS defaults to one local key file`() {
        val service = ConfigSigningService.fromEnv(File(dir, "signing-key.pem"), emptyMap())
        assertEquals(listOf("local"), service.signers.map { it.name })
        assertTrue(service.canRegenerate)
        assertTrue(File(dir, "signing-key.pem").exists())
    }

    @Test
    fun `two local signers sign every payload twice, primary first`() {
        val service = twoSigners()
        assertEquals(listOf("local", "local:second"), service.signers.map { it.name })
        assertTrue(File(dir, "signing-key-second.pem").exists(), "a named local signer gets its own key file")

        val signatures = service.signAll("payload")
        assertEquals(service.signers.map { it.keyId }, signatures.map { it.keyId })
        service.signers.zip(signatures).forEach { (signer, entry) ->
            assertTrue(verifies(signer.publicKeyBase64, "payload", entry.signature))
        }
        assertEquals(signatures.first().signature.length > 0, true)
    }

    @Test
    fun `the same key listed twice is refused`() {
        val keyFile = File(dir, "shared.pem")
        assertFailsWith<IllegalArgumentException> {
            ConfigSigningService.fromEnv(
                keyFile,
                mapOf("CONFIG_SIGNERS" to "local,local:again", "SIGNING_KEY_PATH_AGAIN" to keyFile.absolutePath)
            )
        }
    }

    @Test
    fun `the command signer accepts DER, Base64 and raw r-s output and checks every signature`() {
        val pair = ecKeyPair()
        val keyFile = File(dir, "kms.pem").apply {
            writeText(
                "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(pair.private.encoded) +
                    "\n-----END PRIVATE KEY-----\n"
            )
        }
        // openssl prints a DER signature; `| base64` turns it into text.
        val der = CommandSigner("command:kms", "openssl dgst -sha256 -sign ${keyFile.absolutePath}", pair.public)
        val b64 = CommandSigner("command:kms", "openssl dgst -sha256 -sign ${keyFile.absolutePath} | base64", pair.public)
        for (signer in listOf(der, b64)) {
            val signature = signer.sign("hello".toByteArray())
            assertTrue(SigningKeys.verify(pair.public, "hello".toByteArray(), signature))
        }

        // A signer that answers with some other key's signature is rejected
        // before anything reaches a device.
        val other = ecKeyPair()
        val wrongKey = CommandSigner("command:kms", "openssl dgst -sha256 -sign ${keyFile.absolutePath}", other.public)
        assertFailsWith<IllegalStateException> { wrongKey.sign("hello".toByteArray()) }

        val failing = CommandSigner("command:kms", "echo nope >&2; exit 3", pair.public)
        val error = assertFailsWith<IllegalStateException> { failing.sign("x".toByteArray()) }
        assertTrue(error.message!!.contains("exited with 3"), error.message)
    }

    @Test
    fun `raw r-s signatures are converted to DER`() {
        val pair = ecKeyPair()
        val p1363 = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(pair.private)
            update("data".toByteArray())
            sign()
        }
        assertEquals(64, p1363.size)
        val der = SigningKeys.normalizeSignature(p1363)
        assertTrue(SigningKeys.verify(pair.public, "data".toByteArray(), der))
    }

    // ── Envelopes and the signature cache ───────────────────────────────

    @Test
    fun `envelopes carry every signature and the primary key id`() {
        val signing = twoSigners()
        val envelope = SignedConfigService(signing, cacheEnabled = false).envelope(scope, store.load(scope))
        assertEquals(signing.primary.keyId, envelope.keyId)
        assertEquals(2, envelope.signatures!!.size)
        assertEquals(envelope.signature, envelope.signatures!!.first().signature)
        signing.signers.zip(envelope.signatures!!).forEach { (signer, entry) ->
            assertTrue(verifies(signer.publicKeyBase64, envelope.payload, entry.signature))
        }
    }

    @Test
    fun `with the cache on, the same content is signed once and served identically`() {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        var now = 1_000_000L
        val envelopes = SignedConfigService(signing, ttlMs = 60_000, cacheEnabled = true, clock = { now })

        val first = envelopes.envelope(scope, store.load(scope))
        now += 10_000
        val second = envelopes.envelope(scope, store.load(scope))
        assertEquals(first, second, "byte-identical envelope within half the TTL")
        assertEquals(1, signing.signaturesProduced.get())

        now += 25_000 // past TTL/2 → re-signed with a newer issuedAt
        val third = envelopes.envelope(scope, store.load(scope))
        assertNotEquals(first.payload, third.payload)
        assertEquals(2, signing.signaturesProduced.get())

        // New content → new signature immediately.
        val changed = store.load(scope).let { it.copy(pins = it.pins.map { p -> p.copy(version = 2) }) }
        assertNotEquals(third.payload, envelopes.envelope(scope, changed).payload)

        envelopes.invalidate()
        assertNotEquals(third, envelopes.envelope(scope, store.load(scope)), "invalidate forces a fresh signature")
    }

    @Test
    fun `pre-signing at publish time means the device poll hits the cache`() = testApplication {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val envelopes = SignedConfigService(signing, cacheEnabled = true)
        store.onSaved = { id, _, _ ->
            envelopes.invalidate()
            envelopes.prewarm(id) { store.load(id).let { it.copy(forceUpdate = it.hasAnyForceUpdate()) } }
        }
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                scope, store, PinConfigHistoryStore(db), ConnectionHistoryStore(db), signing, ClientDeviceStore(db),
                signedConfigService = envelopes
            )
        }

        store.save(scope, PinConfig(pins = listOf(HostPin("a.example.com", pins.reversed(), version = 2))))
        val producedAtPublish = signing.signaturesProduced.get()
        assertEquals(1, producedAtPublish, "the publish itself signed the new config")

        val served = Json.parseToJsonElement(
            client.get("/api/v1/certificate-config") { header("X-PinVault-Features", "redelivery,multisig,keyset") }.bodyAsText()
        ).jsonObject
        assertEquals(producedAtPublish, signing.signaturesProduced.get(), "the poll was served from the cache")
        assertEquals(1, envelopes.cacheHits.get())

        // A client that does not announce `redelivery` (library < 2.1) would
        // reject the repeat as a replay: it gets a signature of its own.
        client.get("/api/v1/certificate-config")
        assertEquals(producedAtPublish + 1, signing.signaturesProduced.get())
        assertTrue(signing.verify(served["payload"]!!.jsonPrimitive.content, served["signature"]!!.jsonPrimitive.content))
    }

    // ── Signing-key sets ────────────────────────────────────────────────

    private fun keySet(version: Int, keys: List<String>, signer: KeyPair, required: Int? = null): SignedKeySetWire {
        val payload = buildJsonObject {
            put("type", "pinvault-signing-keys")
            put("version", version)
            putJsonArray("keys") { keys.forEach { add(it) } }
            required?.let { put("requiredSignatures", it) }
        }.toString()
        return SignedKeySetWire(payload, listOf(SignatureEntry(signature = signer.sign(payload))))
    }

    @Test
    fun `key sets are refused until recovery keys are configured`() {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val service = SigningKeySetService(SigningKeySetStore(db), signing, recoveryKeys = emptyList())
        val error = assertFailsWith<SigningKeySetService.Rejected> {
            service.upload(keySet(1, listOf(signing.publicKeyBase64), ecKeyPair()), "alice")
        }
        assertTrue(error.message!!.contains("RECOVERY_PUBLIC_KEYS"))
    }

    @Test
    fun `key set uploads are checked the way a device will check them`() {
        val signing = twoSigners()
        val recovery = ecKeyPair()
        val service = SigningKeySetService(SigningKeySetStore(db), signing, recoveryKeys = listOf(recovery.pub()))
        val primary = signing.signers[0].publicKeyBase64
        val second = signing.signers[1].publicKeyBase64

        // Signed by the (stolen) signing key instead of the recovery key.
        val forged = assertFailsWith<SigningKeySetService.Rejected> {
            val payload = keySet(1, listOf(second), recovery).payload
            service.upload(SignedKeySetWire(payload, listOf(SignatureEntry(signature = signing.sign(payload)))), "mallory")
        }
        assertTrue(forged.message!!.contains("0 of 1 required recovery signature"))
        assertFailsWith<SigningKeySetService.Rejected> { service.upload(keySet(1, listOf(recovery.pub()), recovery), "alice") }
        assertFailsWith<SigningKeySetService.Rejected> { service.upload(keySet(1, listOf(second), recovery, required = 2), "alice") }

        // A set listing only keys this server does not sign with would leave
        // every device that applies it refusing every config: refused.
        val stranded = assertFailsWith<SigningKeySetService.Rejected> {
            service.upload(keySet(1, listOf(ecKeyPair().pub()), recovery), "alice")
        }
        assertTrue(stranded.conflict)

        val result = service.upload(keySet(1, listOf(primary, second), recovery), "alice")
        assertEquals(1, result.version)
        assertTrue(result.warnings.isEmpty(), "both active keys are listed")

        assertFailsWith<SigningKeySetService.Rejected>("versions only go up") {
            service.upload(keySet(1, listOf(second), recovery), "alice")
        }
        // Revoking the primary: allowed, because the second signer is listed —
        // and the operator is told the primary no longer counts.
        val revoking = service.upload(keySet(2, listOf(second), recovery), "alice")
        assertEquals(1, revoking.warnings.size)
        assertEquals(listOf(signing.primary.keyId), service.status().activeSignersMissing)
        assertEquals("alice", service.status().uploadedBy)
    }

    @Test
    fun `the latest key set rides along with every signed config and the admin routes manage it`() = testApplication {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val recovery = ecKeyPair()
        val keySets = SigningKeySetService(SigningKeySetStore(db), signing, recoveryKeys = listOf(recovery.pub()))
        val envelopes = SignedConfigService(signing, keySets, cacheEnabled = false)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                scope, store, PinConfigHistoryStore(db), ConnectionHistoryStore(db), signing, ClientDeviceStore(db),
                signedConfigService = envelopes, keySetService = keySets
            )
            signingAdminRoutes(signing, envelopes, keySets)
        }

        fun served() = Json.parseToJsonElement(kotlinx.coroutines.runBlocking { client.get("/api/v1/certificate-config").bodyAsText() }).jsonObject
        assertTrue(served()["signingKeys"] == null || served()["signingKeys"] is JsonNull, "no set uploaded yet")

        val set = keySet(1, listOf(signing.publicKeyBase64), recovery)
        val upload = client.put("/api/v1/signing-keyset") {
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(SignedKeySetWire.serializer(), set))
        }
        assertEquals(HttpStatusCode.OK, upload.status, upload.bodyAsText())

        val relayed = served()["signingKeys"]!!.jsonObject
        assertEquals(set.payload, relayed["payload"]!!.jsonPrimitive.content, "relayed byte for byte")

        val bad = client.put("/api/v1/signing-keyset") {
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(SignedKeySetWire.serializer(), keySet(2, listOf(signing.publicKeyBase64), ecKeyPair())))
        }
        assertEquals(HttpStatusCode.UnprocessableEntity, bad.status)

        val status = Json.parseToJsonElement(client.get("/api/v1/signing/status").bodyAsText()).jsonObject
        assertEquals(1, status["keySet"]!!.jsonObject["version"]!!.jsonPrimitive.int)
        assertEquals("local", status["signers"]!!.jsonArray.single().jsonObject["type"]!!.jsonPrimitive.content)

        val info = Json.parseToJsonElement(client.get("/api/v1/signing-key").bodyAsText()).jsonObject
        assertEquals(signing.publicKeyBase64, info["publicKey"]!!.jsonPrimitive.content)
        assertEquals(1, info["keySetVersion"]!!.jsonPrimitive.int)
    }

    @Test
    fun `regenerate is refused for signers that are not a local key file`() = testApplication {
        val pair = ecKeyPair()
        val signing = ConfigSigningService(listOf(CommandSigner("command", "false", pair.public)))
        val keySets = SigningKeySetService(SigningKeySetStore(db), signing, emptyList())
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing { signingAdminRoutes(signing, SignedConfigService(signing, keySets, cacheEnabled = false), keySets) }

        val response = client.post("/api/v1/signing-key/regenerate")
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertFalse(LocalFileSigner::class.isInstance(signing.primary))
    }

    // ── Review findings (2026-09-23) ────────────────────────────────────

    @Test
    fun `a config loaded before a change is never signed after it`() {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        var now = 1_000_000L
        val envelopes = SignedConfigService(signing, ttlMs = 60_000, cacheEnabled = true, clock = { now })
        val old = store.load(scope)
        val loadedAt = envelopes.generation()

        // An admin write commits and pre-signs the new pins...
        val new = old.copy(pins = old.pins.map { it.copy(version = 2) })
        envelopes.invalidate()
        now += 5
        envelopes.prewarm(scope) { new }

        // ...so the request that read the old pins must load again instead of
        // stamping old content with a newer issuedAt.
        now += 5
        assertFailsWith<SignedConfigService.StaleLoad> { envelopes.envelope(scope, old, redeliveryOk = true, loadedAt = loadedAt) }
        val served = envelopes.envelope(scope, new, redeliveryOk = true, loadedAt = envelopes.generation())
        assertEquals(2, Json.parseToJsonElement(served.payload).jsonObject["pins"]!!.jsonArray.single().jsonObject["version"]!!.jsonPrimitive.int)
    }

    @Test
    fun `a command signer that hangs is killed with its children`() {
        val pair = ecKeyPair()
        val marker = "31.${System.nanoTime() % 100000}"
        val signer = CommandSigner("command:hang", "sleep $marker | cat", pair.public, timeoutMs = 500)
        val error = assertFailsWith<IllegalStateException> { signer.sign("x".toByteArray()) }
        assertTrue(error.message!!.contains("timed out"), error.message)
        Thread.sleep(300)
        val left = ProcessBuilder("pgrep", "-f", "sleep $marker").start().inputStream.readBytes().decodeToString().trim()
        assertEquals("", left, "no child left running")
    }

    @Test
    fun `key sets devices would refuse are refused by the server too`() {
        val signing = ConfigSigningService(File(dir, "k.pem"))
        val recovery = ecKeyPair()
        val service = SigningKeySetService(SigningKeySetStore(db), signing, recoveryKeys = listOf(recovery.pub()))
        val tooMany = (1..33).map { ecKeyPair().pub() } + signing.publicKeyBase64
        val error = assertFailsWith<SigningKeySetService.Rejected> { service.upload(keySet(1, tooMany, recovery), "alice") }
        assertTrue(error.message!!.contains("at most 32"), error.message)
    }
}
