package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.signing.CommandSigner
import com.example.pinvault.server.service.signing.ConfigSigner
import com.example.pinvault.server.service.signing.SigningKeys
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * An external signer (a command, an HSM, a KMS) is never run once per
 * unauthenticated request: one signing per distinct content, a bounded number
 * at a time — and the command sees none of the server's secrets.
 */
class SignerLoadTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-signer-").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    /** Signs in-process like a slow remote signer would: counts calls, can be held. */
    private class SlowSigner(private val delayMs: Long = 0) : ConfigSigner {
        private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        override val name = "command:test"
        override val type = "command"
        override val description = "test signer"
        override val publicKeyBase64: String = SigningKeys.base64Of(pair.public)
        val calls = AtomicInteger()
        val running = AtomicInteger()
        val peak = AtomicInteger()
        @Volatile var hold: CountDownLatch? = null

        override fun sign(data: ByteArray): ByteArray {
            calls.incrementAndGet()
            peak.accumulateAndGet(running.incrementAndGet(), ::maxOf)
            try {
                hold?.await(10, TimeUnit.SECONDS)
                if (delayMs > 0) Thread.sleep(delayMs)
                return Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(data); sign() }
            } finally {
                running.decrementAndGet()
            }
        }
    }

    private fun config(host: String = "api.example.com") = PinConfig(
        pins = listOf(HostPin(host, listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="), version = 1))
    )

    private fun <T> together(n: Int, block: (Int) -> T): List<Result<T>> {
        val pool = Executors.newFixedThreadPool(n)
        val start = CountDownLatch(1)
        try {
            val futures = (0 until n).map { i -> pool.submit<Result<T>> { start.await(); runCatching { block(i) } } }
            start.countDown()
            return futures.map { it.get(30, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `an external signer turns the signature cache on whatever was asked for`() {
        val external = ConfigSigningService(listOf(SlowSigner()))
        assertTrue(external.external)
        val forced = SignedConfigService(external, cacheEnabled = false)
        assertTrue(forced.cacheEnabled)
        assertTrue(forced.cacheForced)

        val local = ConfigSigningService(File(dir, "k.pem"))
        assertFalse(local.external)
        assertFalse(SignedConfigService(local, cacheEnabled = false).cacheEnabled, "a local key file keeps signing per request by default")
        assertFalse(SignedConfigService(local, cacheEnabled = true).cacheForced)
    }

    @Test
    fun `config requests never start more than one signing per distinct content`() {
        val signer = SlowSigner(delayMs = 150)
        val envelopes = SignedConfigService(ConfigSigningService(listOf(signer)), cacheEnabled = false)

        // 40 requests at once, half of them from clients that do not announce "redelivery"
        // (anyone can leave the header out: it used to buy a signature per request).
        val results = together(40) { i -> envelopes.envelope("default-tls", config(), redeliveryOk = i % 2 == 0) }
        assertTrue(results.all { it.isSuccess }, results.firstOrNull { it.isFailure }.toString())
        assertEquals(1, signer.calls.get(), "one signing for one content")
        assertEquals(1, results.map { it.getOrThrow().signature }.distinct().size, "everyone is served the same envelope")

        // More of the same later: still that one signature.
        repeat(50) { envelopes.envelope("default-tls", config(), redeliveryOk = false) }
        assertEquals(1, signer.calls.get())

        // Different content (another host list, another scope) is signed once each.
        together(20) { i -> envelopes.envelope("default-tls", config("other.example.com"), redeliveryOk = i % 2 == 0) }
        together(20) { envelopes.envelope("prod", config(), redeliveryOk = true) }
        assertEquals(3, signer.calls.get())

        // A local key file still signs per request for clients that would refuse a repeat.
        val local = SignedConfigService(ConfigSigningService(File(dir, "k.pem")), cacheEnabled = true)
        val first = local.envelope("default-tls", config(), redeliveryOk = false)
        val second = local.envelope("default-tls", config(), redeliveryOk = false)
        assertTrue(first.payload != second.payload, "a fresh issuedAt each time")
    }

    @Test
    fun `vault file signatures are produced once per file version`() {
        val signer = SlowSigner(delayMs = 100)
        val envelopes = SignedConfigService(ConfigSigningService(listOf(signer)), cacheEnabled = false)
        val content = "model".toByteArray()
        val results = together(30) { envelopes.vaultSignatures("default-tls", "model.bin", 3, content) }
        assertTrue(results.all { it.isSuccess })
        // Two signings per version: the v1 canonical and the v2 one, which names the Config API.
        assertEquals(2, signer.calls.get())
        envelopes.vaultSignatures("default-tls", "model.bin", 4, content)
        assertEquals(4, signer.calls.get())
        // The same file of another Config API is another v2 canonical: signed again, never served from this one.
        envelopes.vaultSignatures("other-tls", "model.bin", 4, content)
        assertEquals(6, signer.calls.get())
    }

    @Test
    fun `signer invocations are bounded - a short queue, then refusal`() {
        val signer = SlowSigner()
        val signing = ConfigSigningService(listOf(signer), maxConcurrent = 2, maxQueued = 3, queueWaitMs = 5_000)
        val release = CountDownLatch(1)
        signer.hold = release

        // 12 different documents at once: 2 are signing, 3 wait, 7 are refused at once.
        val pool = Executors.newFixedThreadPool(12)
        try {
            val futures = (0 until 12).map { i -> pool.submit<Result<Any>> { runCatching { signing.signAll("document-$i") } } }
            val deadline = System.currentTimeMillis() + 5_000
            while (futures.count { it.isDone } < 7 && System.currentTimeMillis() < deadline) Thread.sleep(20)
            assertEquals(7, futures.count { it.isDone }, "everything beyond the queue is answered without waiting")
            assertTrue(futures.filter { it.isDone }.all { it.get().exceptionOrNull() is ConfigSigningService.SignerBusyException })
            assertEquals(2, signer.running.get(), "two at the signer")

            release.countDown()
            val results = futures.map { it.get(10, TimeUnit.SECONDS) }
            assertEquals(5, results.count { it.isSuccess })
            assertEquals(5, signer.calls.get())
            assertEquals(2, signer.peak.get(), "never more than SIGNER_MAX_CONCURRENT at once")
        } finally {
            release.countDown()
            pool.shutdownNow()
        }

        // A local key is not throttled: it is cheap, and throttling it would only add a way to stall the server.
        val local = ConfigSigningService(File(dir, "k.pem"))
        assertTrue(together(16) { local.signAll("document-$it") }.all { it.isSuccess })
    }

    @Test
    fun `a queued signing gives up after its wait`() {
        val signer = SlowSigner()
        val signing = ConfigSigningService(listOf(signer), maxConcurrent = 1, maxQueued = 4, queueWaitMs = 200)
        val release = CountDownLatch(1)
        signer.hold = release
        val pool = Executors.newSingleThreadExecutor()
        try {
            val first = pool.submit<Any> { signing.signAll("a") }
            while (signer.running.get() == 0) Thread.sleep(10)
            assertFailsWith<ConfigSigningService.SignerBusyException> { signing.signAll("b") }
            release.countDown()
            first.get(5, TimeUnit.SECONDS)
            assertEquals(1, signer.calls.get())
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `limits and extra variables come from the environment`() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val signing = ConfigSigningService.fromEnv(File(dir, "k.pem"), mapOf(
            "CONFIG_SIGNERS" to "command",
            "SIGNER_COMMAND" to "true",
            "SIGNER_PUBLIC_KEY" to SigningKeys.base64Of(pair.public),
            "SIGNER_MAX_CONCURRENT" to "1", "SIGNER_MAX_QUEUE" to "0",
            "SIGNER_PASS_ENV" to "AWS_PROFILE, AWS_REGION"
        ))
        assertTrue(signing.external)
        assertTrue(signing.primary is CommandSigner)
    }

    // ── The command's environment ───────────────────────────────────────

    @Test
    fun `a signer command is given an allowlist, not the server's environment`() {
        for (passed in listOf("PATH", "HOME", "LANG", "TZ", "SIGNER_COMMAND", "SIGNER_KMS_KEY_ID", "SIGNER_PASS_ENV")) {
            assertTrue(CommandSigner.passesToSigner(passed), passed)
        }
        // What the old denylist missed, what it caught, and anything nobody thought of.
        for (kept in listOf(
            "KEYSTORE_PASSWORD_PREVIOUS", "VAULT_AT_REST_PASSWORD_PREVIOUS", "CLIENT_P12_PASSWORD",
            "NOTIFY_WEBHOOK_URL", "NOTIFY_WEBHOOK_SECRET", "ADMIN_KEYS", "ADMIN_KEYS_FILE",
            "API_KEY", "KEYSTORE_PASSWORD", "VAULT_AT_REST_PASSWORD", "SIGNING_KEY_PASSWORD", "SIGNING_KEY_PASSWORD_BACKUP", "PKCS11_PIN",
            "RECOVERY_PUBLIC_KEYS", "DB_PATH", "JAVA_TOOL_OPTIONS", "SOME_FUTURE_SECRET", "AWS_SECRET_ACCESS_KEY", "USER"
        )) assertFalse(CommandSigner.passesToSigner(kept), kept)

        // SIGNER_PASS_ENV adds names — but never one of the server's own secrets.
        val extra = setOf("AWS_PROFILE", "AWS_SECRET_ACCESS_KEY", "API_KEY", "KEYSTORE_PASSWORD_PREVIOUS", "NOTIFY_WEBHOOK_URL")
        assertTrue(CommandSigner.passesToSigner("AWS_PROFILE", extra))
        assertTrue(CommandSigner.passesToSigner("AWS_SECRET_ACCESS_KEY", extra), "the signer's own credential, named by the operator")
        for (secret in listOf("API_KEY", "KEYSTORE_PASSWORD_PREVIOUS", "NOTIFY_WEBHOOK_URL")) {
            assertFalse(CommandSigner.passesToSigner(secret, extra), secret)
        }
    }

    @Test
    fun `the running command really sees only allowlisted variables`() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val dump = File(dir, "env.txt")
        // Fails on purpose after writing its environment: the signature is not what is tested here.
        val signer = CommandSigner("command:env", "env > '${dump.absolutePath}'; exit 3", pair.public)
        assertFailsWith<IllegalStateException> { signer.sign("x".toByteArray()) }
        val names = dump.readLines().map { it.substringBefore('=') }.toSet()
        // Whatever the shell adds on its own (PWD, SHLVL, _, OLDPWD) is not the server's.
        val shellOwn = setOf("PWD", "SHLVL", "_", "OLDPWD")
        val leaked = names.filter { it !in shellOwn && !CommandSigner.passesToSigner(it) }
        assertEquals(emptyList(), leaked, "variables the command was not meant to see")
        // The test JVM has plenty of other variables: they did not come along.
        val parentOnly = System.getenv().keys.filter { !CommandSigner.passesToSigner(it) && it !in shellOwn }
        assertTrue(parentOnly.isNotEmpty(), "the test needs a parent environment with something to withhold")
        assertTrue(parentOnly.none { it in names })
        assertTrue("PATH" in names)
    }
}
