package com.example.pinvault.server

import com.example.pinvault.server.model.ConfigView
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.ViewSignLimits
import com.example.pinvault.server.service.signing.ConfigSigner
import com.example.pinvault.server.service.signing.SigningKeys
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.mutableOriginConnectionPoint
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.serialization.json.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * Narrowed signed views (`?hosts=`, `X-Device-Id`) are each their own signed
 * content, and on a TLS listener both values are anyone's to make up. A
 * requester gets a budget of narrowed SIGNINGS (cache misses), narrowed
 * signings never take the external signer's last permit, and both values are
 * bounded before anything is signed. The full view is never limited.
 */
class ConfigViewSignLimitTest {

    private val scope = "view-sign-limit-test"

    private lateinit var db: DatabaseManager
    private lateinit var pinConfigStore: PinConfigStore
    private lateinit var localSigning: ConfigSigningService
    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-view-limit-", ".db").also { it.deleteOnExit() }
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        pinConfigStore = PinConfigStore(db)
        localSigning = ConfigSigningService(signingKeyFile)
        pinConfigStore.save(scope, PinConfig(
            pins = listOf(
                HostPin("cdn.example.com", listOf("p1", "p2"), version = 1),
                HostPin("api.example.com", listOf("p3", "p4"), version = 1)
            )
        ))
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
    }

    /** Signs in-process like a remote signer; narrowed views ("view" in the payload) wait for [holdNarrowed]. */
    private class SlowSigner : ConfigSigner {
        private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        override val name = "command:test"
        override val type = "command"
        override val description = "test signer"
        override val publicKeyBase64: String = SigningKeys.base64Of(pair.public)
        val running = AtomicInteger()
        val narrowedCalls = AtomicInteger()
        val fullCalls = AtomicInteger()
        @Volatile var holdNarrowed: CountDownLatch? = null

        override fun sign(data: ByteArray): ByteArray {
            val narrowed = String(data, Charsets.UTF_8).contains("\"view\":")
            (if (narrowed) narrowedCalls else fullCalls).incrementAndGet()
            running.incrementAndGet()
            try {
                if (narrowed) holdNarrowed?.await(10, TimeUnit.SECONDS)
                return Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(data); sign() }
            } finally {
                running.decrementAndGet()
            }
        }
    }

    /**
     * The routes behind two test plugins: `X-Test-Peer` stands for the source
     * address (the test engine has none) and `X-Test-Cn` for a verified client
     * certificate, as the mTLS listener's handshake would publish it.
     */
    private fun ApplicationTestBuilder.app(envelopes: SignedConfigService, signing: ConfigSigningService = localSigning) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(createApplicationPlugin("FakePeer") {
            onCall { call ->
                call.request.headers["X-Test-Peer"]?.let {
                    call.mutableOriginConnectionPoint.remoteAddress = it
                    call.mutableOriginConnectionPoint.remoteHost = it
                }
                call.request.headers["X-Test-Cn"]?.let { cn ->
                    call.attributes.put(
                        io.ktor.util.AttributeKey<javax.security.auth.x500.X500Principal>("TLSPeerPrincipal"),
                        javax.security.auth.x500.X500Principal("CN=PinVault Client: $cn, O=PinVault Client, C=TR")
                    )
                }
            }
        })
        routing {
            certificateConfigRoutes(
                scope, pinConfigStore, PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signing, ClientDeviceStore(db),
                signedConfigService = envelopes
            )
        }
    }

    private suspend fun ApplicationTestBuilder.fetch(
        query: String = "",
        deviceId: String? = null,
        peer: String = "198.51.100.1",
        cn: String? = null
    ): HttpResponse = client.get("/api/v1/certificate-config$query") {
        deviceId?.let { header("X-Device-Id", it) }
        header("X-PinVault-Features", "redelivery")
        header("X-Test-Peer", peer)
        cn?.let { header("X-Test-Cn", it) }
    }

    private suspend fun HttpResponse.view(): JsonElement? {
        val envelope = Json.parseToJsonElement(bodyAsText()).jsonObject
        return Json.parseToJsonElement(envelope["payload"]!!.jsonPrimitive.content).jsonObject["view"]
    }

    // ── The budget ────────────────────────────────────────────────────────

    @Test
    fun `made-up device ids from one address get 429 after the budget - the full view and cached views still answer`() = testApplication {
        val envelopes = SignedConfigService(localSigning, cacheEnabled = true, viewLimits = ViewSignLimits.of(perSource = 5, perIdentity = 3))
        app(envelopes)

        repeat(5) { i -> assertEquals(HttpStatusCode.OK, fetch(deviceId = "made-up-$i").status, "within the budget: $i") }
        val refused = fetch(deviceId = "made-up-5")
        assertEquals(HttpStatusCode.TooManyRequests, refused.status)
        val retryAfter = refused.headers[HttpHeaders.RetryAfter]?.toLongOrNull()
        assertNotNull(retryAfter, "Retry-After is set")
        assertTrue(retryAfter in 1..600, "within the 10-minute window: $retryAfter")
        assertEquals("rate_limited", Json.parseToJsonElement(refused.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        // Host lists are views too.
        assertEquals(HttpStatusCode.TooManyRequests, fetch("?hosts=made-up.example.com").status)

        // The full view: never limited, from the same address.
        repeat(3) {
            val full = fetch()
            assertEquals(HttpStatusCode.OK, full.status)
            assertNull(full.view(), "the full view carries no view")
        }
        // A view signed before the budget ran out is a cache hit: served, not counted.
        val hits = envelopes.cacheHits.get()
        val cached = fetch(deviceId = "made-up-2")
        assertEquals(HttpStatusCode.OK, cached.status)
        assertEquals("made-up-2", cached.view()!!.jsonObject["deviceId"]!!.jsonPrimitive.content)
        assertEquals(hits + 1, envelopes.cacheHits.get())

        // Another address has its own budget.
        val other = fetch(deviceId = "made-up-6", peer = "203.0.113.9")
        assertEquals(HttpStatusCode.OK, other.status)
        assertEquals("made-up-6", other.view()!!.jsonObject["deviceId"]!!.jsonPrimitive.content)
        // The unsigned answer signs nothing and is not limited.
        assertEquals(HttpStatusCode.OK, fetch("?signed=false&hosts=x.example.com", deviceId = "made-up-7").status)
    }

    @Test
    fun `an admin change starts the views over - the next fetch of a device is a signing and counts`() = testApplication {
        val envelopes = SignedConfigService(localSigning, cacheEnabled = true, viewLimits = ViewSignLimits.of(perSource = 2, perIdentity = 1))
        app(envelopes)
        assertEquals(HttpStatusCode.OK, fetch(deviceId = "dev-a").status)
        assertEquals(HttpStatusCode.OK, fetch(deviceId = "dev-a").status, "cache hit")
        envelopes.invalidate()
        assertEquals(HttpStatusCode.OK, fetch(deviceId = "dev-a").status, "second signing")
        envelopes.invalidate()
        assertEquals(HttpStatusCode.TooManyRequests, fetch(deviceId = "dev-a").status)
        assertEquals(HttpStatusCode.OK, fetch().status, "the full view is re-signed whatever the budget")
    }

    @Test
    fun `on an mTLS listener the budget is the client id's, not the shared address's`() = testApplication {
        val envelopes = SignedConfigService(localSigning, cacheEnabled = true, viewLimits = ViewSignLimits.of(perSource = 2, perIdentity = 3))
        app(envelopes)
        val nat = "192.0.2.50"
        // Device A spends its own budget (more than the address budget would allow).
        repeat(3) { i -> assertEquals(HttpStatusCode.OK, fetch("?hosts=h$i.example.com", peer = nat, cn = "device-a").status, "device-a $i") }
        assertEquals(HttpStatusCode.TooManyRequests, fetch("?hosts=h9.example.com", peer = nat, cn = "device-a").status)
        // Device B behind the same NAT is not affected.
        repeat(3) { i -> assertEquals(HttpStatusCode.OK, fetch("?hosts=b$i.example.com", peer = nat, cn = "device-b").status, "device-b $i") }
        // Nor is the address's own budget, which certificate-less requests use.
        repeat(2) { i -> assertEquals(HttpStatusCode.OK, fetch(deviceId = "plain-$i", peer = nat).status) }
        assertEquals(HttpStatusCode.TooManyRequests, fetch(deviceId = "plain-9", peer = nat).status)
    }

    @Test
    fun `without the cache every request is signed anyway - no budget applies`() = testApplication {
        val envelopes = SignedConfigService(localSigning, cacheEnabled = false, viewLimits = ViewSignLimits.of(perSource = 1, perIdentity = 1))
        app(envelopes)
        repeat(4) { i -> assertEquals(HttpStatusCode.OK, fetch(deviceId = "dev-$i").status) }
    }

    // ── Bounds on what a request can make the server sign ────────────────

    @Test
    fun `a malformed device id or too many host names are refused before anything is signed`() = testApplication {
        val signing = ConfigSigningService(listOf(SlowSigner()))
        val envelopes = SignedConfigService(signing)
        app(envelopes, signing)
        for (bad in listOf("a b", "<script>", "dev,other", "x".repeat(65), "dev/../x")) {
            val res = fetch(deviceId = bad)
            assertEquals(HttpStatusCode.BadRequest, res.status, "'$bad'")
            assertEquals("invalid_device_id", Json.parseToJsonElement(res.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        }
        // The unsigned answer takes no malformed id either.
        assertEquals(HttpStatusCode.BadRequest, fetch("?signed=false", deviceId = "a b").status)
        assertEquals(HttpStatusCode.OK, fetch(deviceId = "x".repeat(64)).status)
        assertEquals(HttpStatusCode.OK, fetch(deviceId = "0123456789abcdef").status)

        val many = (0..2000).joinToString(",") { "h$it.example.com" }
        val tooMany = fetch("?hosts=$many")
        assertEquals(HttpStatusCode.BadRequest, tooMany.status)
        assertEquals("too_many_hosts", Json.parseToJsonElement(tooMany.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.OK, fetch("?hosts=" + (1..2000).joinToString(",") { "h$it.example.com" }).status, "2000 is the library's own limit")
        assertEquals(3L, envelopes.stats().signaturesProduced, "only the three accepted requests were signed")
    }

    // ── Signer capacity ──────────────────────────────────────────────────

    @Test
    fun `narrowed views never take the external signer's last permit nor its queue`() {
        val signer = SlowSigner()
        val signing = ConfigSigningService(listOf(signer), maxConcurrent = 2, maxQueued = 8, queueWaitMs = 5_000)
        val envelopes = SignedConfigService(signing)
        val release = CountDownLatch(1)
        signer.holdNarrowed = release
        val config = pinConfigStore.load(scope)
        val pool = Executors.newFixedThreadPool(12)
        try {
            // Ten made-up devices at once: one narrowed signing runs (all but one of the
            // two permits), the other nine are refused at once — none of them waits.
            val narrowed = (0 until 10).map { i ->
                pool.submit<Result<Any>> { runCatching { envelopes.envelope(scope, config.copy(view = ConfigView.of(null, "made-up-$i"))) } }
            }
            val deadline = System.currentTimeMillis() + 5_000
            while (narrowed.count { it.isDone } < 9 && System.currentTimeMillis() < deadline) Thread.sleep(20)
            assertEquals(9, narrowed.count { it.isDone }, "refused without waiting")
            assertTrue(narrowed.filter { it.isDone }.all { it.get().exceptionOrNull() is ConfigSigningService.SignerBusyException })
            assertEquals(1, signer.running.get())

            // The full view still gets the reserved permit, and so does a pre-signing.
            val full = pool.submit<Any> { envelopes.envelope(scope, config) }.get(5, TimeUnit.SECONDS)
            assertNotNull(full)
            envelopes.invalidate()
            envelopes.prewarm(scope) { pinConfigStore.load(scope) }
            assertEquals(2, signer.fullCalls.get(), "the full view was signed twice while narrowed views held the rest")
            // Vault signatures are not narrowed views either.
            envelopes.vaultSignatures(scope, "model.bin", 1, "x".toByteArray())

            release.countDown()
            assertEquals(1, narrowed.count { it.get(10, TimeUnit.SECONDS).isSuccess })
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `with one signer permit a narrowed view takes it only while nothing waits`() {
        val signer = SlowSigner()
        val signing = ConfigSigningService(listOf(signer), maxConcurrent = 1, maxQueued = 4, queueWaitMs = 5_000)
        val envelopes = SignedConfigService(signing)
        val release = CountDownLatch(1)
        signer.holdNarrowed = release
        val config = pinConfigStore.load(scope)
        val pool = Executors.newFixedThreadPool(4)
        try {
            val first = pool.submit<Any> { envelopes.envelope(scope, config.copy(view = ConfigView.of(null, "dev-1"))) }
            while (signer.running.get() == 0) Thread.sleep(10)
            // The full view queues behind the one narrowed signing...
            val full = pool.submit<Any> { envelopes.envelope(scope, config) }
            Thread.sleep(100)
            // ...and no further narrowed view gets ahead of it.
            assertFailsWith<ConfigSigningService.SignerBusyException> {
                envelopes.envelope(scope, config.copy(view = ConfigView.of(null, "dev-2")))
            }
            release.countDown()
            first.get(5, TimeUnit.SECONDS)
            assertNotNull(full.get(5, TimeUnit.SECONDS))
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun `over HTTP a flood of narrowed requests cannot block the full view`() = testApplication {
        val signer = SlowSigner()
        val signing = ConfigSigningService(listOf(signer), maxConcurrent = 2, maxQueued = 8, queueWaitMs = 5_000)
        val envelopes = SignedConfigService(signing, viewLimits = ViewSignLimits.of(perSource = 4, perIdentity = 4))
        app(envelopes, signing)
        val release = CountDownLatch(1)
        signer.holdNarrowed = release
        try {
            startApplication()
            coroutineScope {
                val held = async { fetch(deviceId = "flood-0").status }
                while (signer.running.get() == 0) delay(10)
                // Narrowed requests now: busy (503) while the share is taken, then over budget (429).
                val flood = (1..8).map { i -> async { fetch(deviceId = "flood-$i").status } }.awaitAll()
                assertTrue(flood.all { it == HttpStatusCode.ServiceUnavailable || it == HttpStatusCode.TooManyRequests }, flood.toString())
                assertTrue(HttpStatusCode.TooManyRequests in flood, "the budget ran out: $flood")
                // The full view answers while the narrowed signing is still held.
                assertEquals(HttpStatusCode.OK, fetch().status)
                assertEquals(1, signer.running.get(), "the narrowed signing is still at the signer")
                release.countDown()
                assertEquals(HttpStatusCode.OK, held.await())
            }
        } finally {
            release.countDown()
        }
    }

    // ── Settings ─────────────────────────────────────────────────────────

    @Test
    fun `the budgets come from the environment - a bad value stops startup, blank is the default`() {
        val address = ViewSignLimits.Requester("198.51.100.7")
        val device = ViewSignLimits.Requester("198.51.100.7", clientId = "dev-a")

        val defaults = assertNotNull(ViewSignLimits.fromEnv(emptyMap()))
        repeat(ViewSignLimits.DEFAULT_PER_SOURCE) { assertTrue(defaults.allow(address)) }
        assertFalse(defaults.allow(address))
        repeat(ViewSignLimits.DEFAULT_PER_IDENTITY) { assertTrue(defaults.allow(device)) }
        assertFalse(defaults.allow(device))

        val blank = assertNotNull(ViewSignLimits.fromEnv(mapOf("CONFIG_VIEW_SIGN_RATE_LIMIT" to "  ", "CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT" to "")))
        repeat(ViewSignLimits.DEFAULT_PER_SOURCE) { assertTrue(blank.allow(address)) }
        assertFalse(blank.allow(address))

        val set = assertNotNull(ViewSignLimits.fromEnv(mapOf("CONFIG_VIEW_SIGN_RATE_LIMIT" to " 2 ", "CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT" to "0")))
        assertTrue(set.allow(address)); assertTrue(set.allow(address)); assertFalse(set.allow(address))
        repeat(1000) { assertTrue(set.allow(device), "0 = no limit per client id") }

        assertNull(ViewSignLimits.fromEnv(mapOf("CONFIG_VIEW_SIGN_RATE_LIMIT" to "0", "CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT" to "0")), "both off")

        for (bad in listOf("abc", "-1", "1.5", "1000001", "12 0", "0x10", "99999999999")) {
            for (name in listOf("CONFIG_VIEW_SIGN_RATE_LIMIT", "CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT")) {
                val e = assertFailsWith<IllegalStateException>("$name=$bad") { ViewSignLimits.fromEnv(mapOf(name to bad)) }
                assertTrue(e.message!!.contains(name), e.message)
            }
        }
    }

    @Test
    fun `retry-after names the end of the window`() {
        var now = 1_000_000L
        val limits = ViewSignLimits.of(perSource = 1, perIdentity = 1, clock = { now })!!
        val who = ViewSignLimits.Requester("198.51.100.7")
        assertTrue(limits.allow(who))
        assertFalse(limits.allow(who))
        assertEquals(600, limits.retryAfterSeconds(who))
        now += 540_000
        assertEquals(60, limits.retryAfterSeconds(who))
        now += 60_000
        assertTrue(limits.allow(who), "a new window")
    }
}
