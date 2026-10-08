package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.AttestationEventStatus
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.keystore.SoftwareClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.AttestationResult
import io.github.umutcansu.pinvault.model.AttestationTokenResult
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

/**
 * The attestation round trip against a mock server: what the request
 * carries (`ATTESTATION.md` §2.2), what a pass, a reject and a refusal do to
 * the status, the token and the events, the config that rides along, the
 * attestation chain, and the refresh arithmetic.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class AttestationManagerTest {

    private lateinit var server: MockWebServer
    private lateinit var api: DefaultCertificateConfigApi
    private lateinit var key: ClientIdentityKeyProvider
    private val now = 1_800_000_000_000L
    private val events = mutableListOf<PinVaultConnectionEvent.Attestation>()
    private val applied = mutableListOf<SignedConfigResponse>()
    private val applyResults = mutableListOf<UpdateResult>()
    private var report = """{"sdkVersion":"2.2.0","signals":{}}"""

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        val sslManager = mockk<DynamicSSLManager>()
        every { sslManager.buildBootstrapClient(any()) } returns OkHttpClient()
        api = DefaultCertificateConfigApi(
            configUrl = server.url("/").toString(),
            bootstrapPins = listOf(HostPin("test.com", listOf("h1", "h2"))),
            sslManager = sslManager
        )
        key = ClientIdentityKeyProvider.software("attest-test-${System.nanoTime()}")
    }

    @After
    fun tearDown() {
        server.shutdown()
        SoftwareClientIdentityKeyProvider.attestation = null
        key.clear()
    }

    private fun block(vararg hosts: String, scoped: List<String> = emptyList()): ConfigApiBlock {
        val builder = ConfigApiBlock.Builder("api", "https://config.example.com:8091/")
            .allowUnpinnedConfigApi()
            .allowUnsigned()
            .attestation()
        if (hosts.isNotEmpty()) builder.tokenHosts(*hosts)
        if (scoped.isNotEmpty()) builder.wantPinsFor(*scoped.toTypedArray())
        return builder.build()
    }

    private fun manager(
        block: ConfigApiBlock = block("api.example.com", "*.cdn.example.com"),
        api: DefaultCertificateConfigApi? = this.api,
        liveConfig: () -> CertificateConfig? = { null },
        deviceId: String? = "device-07"
    ) = AttestationManager(
        block = block,
        api = api,
        identityKey = { key },
        deviceId = { deviceId },
        currentConfigVersion = { 7 },
        currentIssuedAt = { 1_000L },
        liveConfig = liveConfig,
        buildReport = { _, _, _ -> report },
        applyConfig = { signed -> applied += signed; UpdateResult.Updated(9) },
        onConfigApplied = { applyResults += it },
        onEvent = { events += it },
        clock = { now },
        jitter = { 0.5 }
    )

    private fun challenge(nonce: String = "nonce-1", serverTime: Long = now + 5_000) = MockResponse()
        .setHeader("Content-Type", "application/json")
        .setBody("""{"nonce":"$nonce","expiresIn":120,"serverTime":$serverTime}""")

    private fun pass(
        token: String = "eyJ.token.1",
        ttl: Int = 300,
        nextAttestIn: Int = 300,
        extra: String = ""
    ) = MockResponse().setHeader("Content-Type", "application/json").setBody(
        """{"result":"pass","arc":"7f3a9c1e","warnings":["software_key"],"token":"$token","tokenExpiresAt":${now + 5_000 + ttl * 1000L},
           "tokenTtlSeconds":$ttl,"nextAttestIn":$nextAttestIn,"configChanged":false,
           "device":{"registered":true,"firstSeen":true},"policyVersion":3$extra}"""
    )

    private fun reject() = MockResponse().setHeader("Content-Type", "application/json").setBody(
        """{"result":"reject","arc":"0badbeef","rejectionReasons":["rooted"],"warnings":[],"nextAttestIn":300,"policyVersion":3}"""
    )

    private fun body(request: RecordedRequest) = JSONObject(request.body.readUtf8())

    // ── The request ─────────────────────────────────────────────────────

    @Test
    fun `an attestation gets a challenge, then posts the signed report with every field of the design`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass())
        val m = manager(block("api.example.com", scoped = listOf("api.example.com", "cdn.example.com")))

        val status = m.attestNow()

        val first = server.takeRequest()
        assertEquals("GET", first.method)
        assertEquals("/api/v1/attest/challenge", first.path)

        val second = server.takeRequest()
        assertEquals("POST", second.method)
        assertEquals("/api/v1/attest", second.path)
        val json = body(second)
        assertEquals(1, json.getInt("v"))
        assertEquals("nonce-1", json.getString("nonce"))
        assertEquals("device-07", json.getString("deviceId"))
        assertEquals(Base64.getEncoder().encodeToString(key.publicKey().encoded), json.getString("publicKey"))
        assertEquals("the report travels as a string", report, json.getString("report"))
        assertTrue(json.get("report") is String)
        assertEquals(7, json.getInt("currentConfigVersion"))
        assertEquals(1_000L, json.getLong("currentIssuedAt"))
        assertEquals(listOf("api.example.com", "cdn.example.com"), json.getJSONArray("hosts").let { a -> (0 until a.length()).map { a.getString(it) } })
        assertFalse("a software key without a challenge-made chain sends none", json.has("attestationChain"))

        // SHA256withECDSA over pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>, verified with the device key.
        val reportHash = MessageDigest.getInstance("SHA-256").digest(report.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        val canonical = "pinvault-attest:v1:nonce-1:device-07:$reportHash"
        assertEquals(canonical, AttestationManager.canonicalString("nonce-1", "device-07", report))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key.publicKey())
        verifier.update(canonical.toByteArray(Charsets.UTF_8))
        assertTrue(verifier.verify(Base64.getDecoder().decode(json.getString("signature"))))

        assertEquals(AttestationResult.PASS, status.result)
    }

    @Test
    fun `hosts are sent only when the block scopes its pins, and an unusable device id becomes unknown-device`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass())
        manager(deviceId = "bad id with spaces").attestNow()
        server.takeRequest()
        val json = body(server.takeRequest())
        assertFalse(json.has("hosts"))
        assertEquals("unknown-device", json.getString("deviceId"))
    }

    // ── Pass ────────────────────────────────────────────────────────────

    @Test
    fun `a pass holds the token, schedules the refresh and raises a PASS event`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass(ttl = 300, nextAttestIn = 300))
        val m = manager()

        val status = m.attestNow()

        assertEquals(AttestationResult.PASS, status.result)
        assertEquals("7f3a9c1e", status.arc)
        assertEquals(listOf("software_key"), status.warnings)
        assertTrue(status.rejectionReasons.isEmpty())
        assertEquals("device-clock expiry from the TTL", now + 300_000L, status.tokenExpiresAt)
        assertEquals(now, status.lastAttestedAt)
        // min(nextAttestIn 300 s, block 300 s, expiry − 60 s = 240 s), no jitter at 0.5.
        assertEquals(now + 240_000L, status.nextAttestAt)
        assertEquals(5_000L, status.clockSkewMs)
        assertEquals(3, status.policyVersion)
        assertNull(status.lastError)
        assertTrue(status.hasValidToken(now))
        assertEquals(status, m.status)

        assertEquals("eyJ.token.1", m.token("api.example.com", 443, forceRefresh = false))
        assertEquals("a wildcard token host", "eyJ.token.1", m.token("img.cdn.example.com", 443, forceRefresh = false))
        assertTrue(m.handlesHost("api.example.com", 443))
        assertFalse(m.handlesHost("other.example.com", 443))
        assertFalse(m.handlesHost("a.b.cdn.example.com", 443))
        assertEquals("no request for a host that is not a token host", 2, server.requestCount)

        assertEquals(AttestationTokenResult.Token("eyJ.token.1", now + 300_000L), m.fetchToken())
        assertFalse("the token stays out of toString", m.fetchToken().toString().contains("eyJ.token.1"))

        assertEquals(1, events.size)
        assertEquals(AttestationEventStatus.PASS, events[0].status)
        assertEquals("api", events[0].configApiId)
        assertEquals("7f3a9c1e", events[0].arc)
        assertEquals(listOf("software_key"), events[0].warnings)
        assertEquals(now + 300_000L, events[0].tokenExpiresAt)
        assertNull(events[0].failureReason)
        assertTrue(applied.isEmpty())
    }

    @Test
    fun `without tokenHosts the live config's pinned hosts and the Config API listener carry the token`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass())
        val live = CertificateConfig(pins = listOf(HostPin("api.live.test", listOf("p1", "p2")), HostPin("*.cdn.live.test", listOf("p1", "p2"))))
        val m = manager(block = block(), liveConfig = { live })
        m.attestNow()

        assertTrue(m.handlesHost("api.live.test", 443))
        assertTrue(m.handlesHost("x.cdn.live.test", 443))
        assertTrue("the block's own Config API listener", m.handlesHost("config.example.com", 8091))
        assertFalse("another port of it", m.handlesHost("config.example.com", 443))
        assertFalse(m.handlesHost("api.example.com", 443))
    }

    @Test
    fun `a config in a pass answer goes through the updater and is reported like a recovery update`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass(extra = ""","configChanged":true,"config":{"payload":"{\"version\":1}","signature":"c2ln","signatures":[{"keyId":"k1","signature":"c2ln"}]}"""))
        manager().attestNow()

        assertEquals(1, applied.size)
        assertEquals("""{"version":1}""", applied[0].payload)
        assertEquals("c2ln", applied[0].signature)
        assertEquals("k1", applied[0].signatures!!.single().keyId)
        assertEquals(listOf<UpdateResult>(UpdateResult.Updated(9)), applyResults)
    }

    // ── Reject ──────────────────────────────────────────────────────────

    @Test
    fun `a reject holds no token, ignores any config, raises a REJECT event and does not re-attest on demand`() = runTest {
        server.enqueue(challenge())
        server.enqueue(MockResponse().setHeader("Content-Type", "application/json").setBody(
            """{"result":"reject","arc":"0badbeef","rejectionReasons":["rooted","hooking_framework"],"warnings":["adb_enabled"],"nextAttestIn":300,"policyVersion":3,"config":{"payload":"{}","signature":"x"}}"""
        ))
        val m = manager()

        val status = m.attestNow()

        assertEquals(AttestationResult.REJECT, status.result)
        assertEquals("0badbeef", status.arc)
        assertEquals(listOf("rooted", "hooking_framework"), status.rejectionReasons)
        assertEquals(listOf("adb_enabled"), status.warnings)
        assertNull(status.tokenExpiresAt)
        assertEquals(now, status.lastAttestedAt)
        assertEquals(now + 300_000L, status.nextAttestAt)
        assertFalse(status.hasValidToken(now))
        assertTrue("a rejected device gets no config", applied.isEmpty())

        assertNull(m.token("api.example.com", 443, forceRefresh = false))
        assertNull(m.token("api.example.com", 443, forceRefresh = true))
        assertEquals("requests do not turn a reject into a storm", 2, server.requestCount)

        assertEquals(AttestationEventStatus.REJECT, events.single().status)
        assertEquals(listOf("rooted", "hooking_framework"), events.single().rejectionReasons)

        // The explicit token API attests again and reports the reject.
        server.enqueue(challenge())
        server.enqueue(reject())
        val fetched = m.fetchToken()
        assertTrue(fetched.toString(), fetched is AttestationTokenResult.Rejected)
        assertEquals("0badbeef", (fetched as AttestationTokenResult.Rejected).status.arc)
        assertEquals(4, server.requestCount)
    }

    // ── Refusals and failures ───────────────────────────────────────────

    @Test
    fun `a refusal is FAILED with the server's reason, backs off and raises a FAILED event`() = runTest {
        server.enqueue(challenge())
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"key_mismatch","message":"another key is registered for this device"}"""))
        val m = manager()

        val status = m.attestNow()

        assertEquals(AttestationResult.FAILED, status.result)
        assertTrue(status.lastError, status.lastError!!.contains("key_mismatch"))
        assertTrue(status.lastError, status.lastError!!.contains("another key is registered"))
        assertEquals(now + 30_000L, status.nextAttestAt)
        assertNull(status.lastAttestedAt)
        assertEquals(AttestationEventStatus.FAILED, events.single().status)
        assertEquals(status.lastError, events.single().failureReason)

        server.enqueue(challenge())
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"signature_invalid"}"""))
        val fetched = m.fetchToken()
        assertTrue(fetched.toString(), fetched is AttestationTokenResult.Failed)
        assertTrue((fetched as AttestationTokenResult.Failed).message.contains("signature_invalid"))
    }

    @Test
    fun `an unreachable server is FAILED too, and the backoff grows`() = runTest {
        val m = manager()
        server.shutdown()

        val first = m.attestNow()
        assertEquals(AttestationResult.FAILED, first.result)
        assertNotNull(first.lastError)
        assertEquals(now + 30_000L, first.nextAttestAt)

        // The on-demand path honours the backoff: no attempt until nextAttestAt.
        assertNull(m.token("api.example.com", 443, forceRefresh = true))

        val second = m.attestNow()
        assertEquals(now + 60_000L, second.nextAttestAt)
        assertEquals(2, events.size)
    }

    @Test
    fun `a failure keeps the last token until it expires`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass())
        val m = manager()
        m.attestNow()
        server.enqueue(challenge())
        server.enqueue(MockResponse().setResponseCode(503).setBody("busy"))

        val status = m.attestNow()

        assertEquals(AttestationResult.FAILED, status.result)
        assertEquals("the token is still held", now + 300_000L, status.tokenExpiresAt)
        assertEquals("eyJ.token.1", m.token("api.example.com", 443, forceRefresh = false))
        assertEquals("the pass's arc stays", "7f3a9c1e", status.arc)
    }

    @Test
    fun `a custom Config API cannot attest`() = runTest {
        val m = manager(api = null)
        assertEquals(AttestationResult.UNSUPPORTED, m.status.result)
        assertEquals(AttestationResult.UNSUPPORTED, m.attestNow().result)
        assertEquals(AttestationTokenResult.Unsupported, m.fetchToken())
        assertFalse(m.handlesHost("api.example.com", 443))
        assertFalse(m.supported)
        assertTrue(events.isEmpty())
    }

    // ── The attestation chain ───────────────────────────────────────────

    @Test
    fun `the key's chain goes with the first request, not with the next, and again when the server asks for it`() = runTest {
        SoftwareClientIdentityKeyProvider.attestation = { listOf(byteArrayOf(1, 2, 3), byteArrayOf(4)) }
        val m = manager()

        server.enqueue(challenge())
        server.enqueue(pass())
        m.attestNow()
        server.takeRequest()
        val first = body(server.takeRequest()).getJSONArray("attestationChain")
        assertEquals(listOf("AQID", "BA=="), (0 until first.length()).map { first.getString(it) })

        server.enqueue(challenge())
        server.enqueue(pass())
        m.attestNow()
        server.takeRequest()
        assertFalse("registered: a key cannot be re-attested", body(server.takeRequest()).has("attestationChain"))

        server.enqueue(challenge())
        server.enqueue(MockResponse().setResponseCode(403).setBody("""{"error":"attestation_required"}"""))
        m.attestNow()
        server.takeRequest()
        server.takeRequest()

        server.enqueue(challenge())
        server.enqueue(pass())
        m.attestNow()
        server.takeRequest()
        assertTrue("asked for again", body(server.takeRequest()).has("attestationChain"))
    }

    @Test
    fun `the device key is made with the identity attestation challenge of the device id`() = runTest {
        var seen: ByteArray? = null
        SoftwareClientIdentityKeyProvider.attestation = { challenge -> seen = challenge; listOf(byteArrayOf(9)) }
        server.enqueue(challenge())
        server.enqueue(pass())
        manager().attestNow()
        assertTrue(key.exists())
        assertTrue(ClientIdentityKeyProvider.attestationChallenge("device-07").contentEquals(seen!!))
    }

    // ── The refresh arithmetic ──────────────────────────────────────────

    @Test
    fun `the next attestation is the earliest of nextAttestIn, the block interval and the token's expiry minus a minute`() {
        val interval = 5L * 60_000
        assertEquals(240_000L, AttestationManager.refreshDelayMs(300_000L, interval, now + 300_000L, now, 0.5))
        assertEquals("the server asks for sooner", 120_000L, AttestationManager.refreshDelayMs(120_000L, interval, now + 300_000L, now, 0.5))
        assertEquals("the block interval caps it", 60_000L, AttestationManager.refreshDelayMs(600_000L, 60_000L, null, now, 0.5))
        assertEquals("no server value: the block interval", interval, AttestationManager.refreshDelayMs(null, interval, null, now, 0.5))
        assertEquals("never below the floor", 30_000L, AttestationManager.refreshDelayMs(300_000L, interval, now + 10_000L, now, 0.5))
        // ±10 % jitter.
        assertEquals(216_000L, AttestationManager.refreshDelayMs(300_000L, interval, now + 300_000L, now, 0.0))
        assertEquals(264_000L, AttestationManager.refreshDelayMs(300_000L, interval, now + 300_000L, now, 1.0))
        assertTrue(AttestationManager.refreshDelayMs(300_000L, interval, now + 300_000L, now, 0.0) >= AttestationManager.MIN_DELAY_MS)
    }

    @Test
    fun `failures back off from 30 seconds to 5 minutes`() {
        assertEquals(30_000L, AttestationManager.backoffMs(1))
        assertEquals(60_000L, AttestationManager.backoffMs(2))
        assertEquals(120_000L, AttestationManager.backoffMs(3))
        assertEquals(240_000L, AttestationManager.backoffMs(4))
        assertEquals(300_000L, AttestationManager.backoffMs(5))
        assertEquals(300_000L, AttestationManager.backoffMs(50))
        assertEquals(30_000L, AttestationManager.backoffMs(0))
    }

    @Test
    fun `reset forgets the token and the status, and the loop can be started and stopped`() = runTest {
        server.enqueue(challenge())
        server.enqueue(pass())
        val m = manager()
        m.attestNow()
        m.start()
        m.start()
        m.stop()
        m.reset()
        assertEquals(AttestationResult.NOT_ATTESTED, m.status.result)
        assertNull(m.status.tokenExpiresAt)
        // No token, nothing attempted yet: the next request to a token host attests again.
        server.enqueue(challenge())
        server.enqueue(pass(token = "eyJ.token.2"))
        assertEquals("eyJ.token.2", m.token("api.example.com", 443, forceRefresh = false))
    }
}
