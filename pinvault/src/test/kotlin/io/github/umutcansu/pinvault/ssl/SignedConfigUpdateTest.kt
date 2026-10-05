package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.SignedConfigSource
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigExpiredException
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.InvalidPinFormatException
import io.github.umutcansu.pinvault.model.NoConfigAvailableException
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.SignedKeySet
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.SigningKeyStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The updater over signed envelopes and a real [CertificateConfigStore]: what
 * is stored, what is verified again when it is read back, what a holder of a
 * stolen signing key cannot leave behind, and how a custom API that hands
 * over envelopes ([SignedConfigSource]) is treated like the library's own.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SignedConfigUpdateTest {

    // Pins as they are, not with `=` written as \u003d: the tests edit payloads as text.
    private val gson = com.google.gson.GsonBuilder().disableHtmlEscaping().create()
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L
    private val day = 24 * hour

    private val pin1 = TestCertUtil.generateSelfSigned(cn = "a").sha256Pin
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "b").sha256Pin
    private val pin3 = TestCertUtil.generateSelfSigned(cn = "c").sha256Pin

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private val keyA = ecKeyPair()
    private val keyB = ecKeyPair()
    private val recovery = ecKeyPair()

    private fun KeyPair.pub(): String = Base64.getEncoder().encodeToString(public.encoded)
    private fun KeyPair.id(): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(public.encoded))

    private fun KeyPair.sign(payload: String): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(private)
        s.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(s.sign())
    }

    /** A custom backend that serves signed envelopes — and whose `fetchConfig` must never be asked. */
    private class SignedApi : CertificateConfigApi, SignedConfigSource {
        var next: SignedConfigResponse? = null
        var failure: Exception? = null
        var healthy = true
        var fetches = 0
        var gate: CompletableDeferred<Unit>? = null

        override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse {
            fetches++
            gate?.await()
            failure?.let { throw it }
            return next!!
        }

        override suspend fun fetchConfig(currentVersion: Int): CertificateConfig =
            error("a signed block must be served through fetchSignedConfig")

        /** Runs inside the health check, before it answers (tests of what happens meanwhile). */
        var duringHealthCheck: (suspend () -> Unit)? = null
        override suspend fun healthCheck(): Boolean {
            duringHealthCheck?.invoke()
            return healthy
        }
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) =
            EnrollmentResult(ByteArray(0), null)
    }

    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var store: CertificateConfigStore
    private lateinit var keyStore: SigningKeyStore
    private lateinit var api: SignedApi
    private lateinit var provider: HttpClientProvider

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("signed_update_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        store = CertificateConfigStore.createForTest(prefs).also { it.clock = { now } }
        val keyPrefs = context.getSharedPreferences("signed_update_keys", Context.MODE_PRIVATE)
        keyPrefs.edit().clear().commit()
        keyStore = SigningKeyStore.createForTest(keyPrefs)
        api = SignedApi()
        provider = HttpClientProvider(DynamicSSLManager())
    }

    private fun trust(keys: List<KeyPair> = listOf(keyA), withRecovery: Boolean = false) = SignatureTrust(
        "default", keys.map { it.pub() }, 1,
        if (withRecovery) listOf(recovery.pub()) else emptyList(), 1,
        if (withRecovery) keyStore else null
    )

    private fun updater(
        trust: SignatureTrust? = trust(),
        scope: String? = null,
        configApi: CertificateConfigApi = api,
        trustedClock: TrustedClock? = null
    ) = SSLCertificateUpdater(
        context = io.mockk.mockk(relaxed = true),
        configApi = configApi,
        configStore = store,
        httpClientProvider = provider,
        maxRetryCount = 1,
        clock = { now },
        verifier = trust?.let { SignedConfigVerifier(it, scope) { now } },
        trustedClock = trustedClock
    )

    private fun payload(
        version: Int,
        issuedAt: Long,
        expiresAt: Long = issuedAt + hour,
        pins: List<String> = listOf(pin1, pin2),
        hosts: Map<String, Int> = mapOf("api.test" to version),
        scope: String? = null
    ): String {
        val body = linkedMapOf<String, Any>(
            "version" to version,
            "pins" to hosts.map { (host, v) -> mapOf("hostname" to host, "sha256" to pins, "version" to v) },
            "forceUpdate" to false,
            "issuedAt" to issuedAt,
            "expiresAt" to expiresAt
        )
        if (scope != null) body[SignedConfigVerifier.SCOPE_FIELD] = scope
        return gson.toJson(body)
    }

    private fun signed(payload: String, signer: KeyPair = keyA, keySet: SignedKeySet? = null) =
        SignedConfigResponse(payload, signer.sign(payload), signer.id(), null, keySet)

    private fun keySet(version: Int, keys: List<KeyPair>): SignedKeySet {
        val payload = gson.toJson(linkedMapOf("type" to SignatureTrust.KEY_SET_TYPE, "version" to version, "keys" to keys.map { it.pub() }))
        return SignedKeySet(payload, listOf(SignatureEntry(recovery.id(), recovery.sign(payload))))
    }

    private suspend fun apply(response: SignedConfigResponse, with: SSLCertificateUpdater = updater()): UpdateResult {
        api.next = response
        api.failure = null
        return with.updateNow()
    }

    private fun offline() {
        api.failure = java.io.IOException("offline")
    }

    // ── The envelope is stored, and checked again on every read ─────────

    @Test
    fun `a signed config is stored with its envelope and starts offline from it`() = runTest {
        val response = signed(payload(4, issuedAt = now))
        assertEquals(UpdateResult.Updated(4), apply(response))

        val envelope = store.loadEnvelope()!!
        assertEquals(response.payload, envelope.payload)
        assertEquals(listOf(SignatureEntry(keyA.id(), response.signature)), envelope.signatures)

        // A new process: the stored envelope verifies, the config is used.
        provider = HttpClientProvider(DynamicSSLManager())
        offline()
        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
        assertEquals(listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)
    }

    @Test
    fun `stored pins rewritten on disk are not used — the config comes from the envelope`() = runTest {
        apply(signed(payload(4, issuedAt = now)))
        // Code that ran once as the app swaps the stored pins for its own.
        prefs.edit().putString(
            CertificateConfigStore.KEY_PINS_JSON,
            """[{"hostname":"api.test","version":4,"sha256":["$pin3","$pin3"],"forceUpdate":false,"mtls":false}]"""
        ).commit()
        assertEquals(listOf(pin3, pin3), store.load()!!.pins.single().sha256)

        provider = HttpClientProvider(DynamicSSLManager())
        offline()
        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
        assertEquals("the signed pins, not the planted ones", listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)
    }

    @Test
    fun `a stored config without a valid envelope is discarded and init fails closed`() = runTest {
        for (tamper in listOf<(android.content.SharedPreferences.Editor) -> Unit>(
            { it.remove(CertificateConfigStore.KEY_ENVELOPE) },
            { editor ->
                // The envelope of another config, re-labelled: payload and signature no longer match.
                val forged = store.loadEnvelope()!!.let { it.copy(payload = it.payload.replace(pin1, pin3)) }
                editor.putString(
                    CertificateConfigStore.KEY_ENVELOPE,
                    gson.toJson(mapOf("payload" to forged.payload, "signatures" to forged.signatures))
                )
            }
        )) {
            setUp()
            apply(signed(payload(4, issuedAt = now)))
            prefs.edit().also(tamper).commit()

            provider = HttpClientProvider(DynamicSSLManager())
            offline()
            val result = updater().initializeAndUpdate() as InitResult.Failed

            assertTrue(result.reason, result.reason.contains("discarded"))
            assertTrue(result.exception is NoConfigAvailableException)
            assertNull("no config: pinned clients refuse", provider.currentConfig)
            assertNull(store.load())
            assertEquals("the replay watermark stays", now, store.getCurrentIssuedAt())
        }
    }

    @Test
    fun `a discarded stored config is replaced by the next fetch, even at the watermark`() = runTest {
        // A backend that signs once per change serves the same envelope again;
        // with nothing active it must be applied, not refused as a replay.
        val response = signed(payload(4, issuedAt = now))
        apply(response)
        prefs.edit().remove(CertificateConfigStore.KEY_ENVELOPE).commit()

        provider = HttpClientProvider(DynamicSSLManager())
        api.next = response
        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
        assertNotNull(store.loadEnvelope())
    }

    @Test
    fun `after a reset the newest config is accepted again, an older one is not`() = runTest {
        val older = signed(payload(3, issuedAt = now - hour, expiresAt = now + hour))
        val newest = signed(payload(4, issuedAt = now))
        apply(older)
        apply(newest)

        // What PinVault.reset() does to the store and the client.
        store.clearActive()
        provider.reset()

        val replay = apply(older) as UpdateResult.Failed
        assertTrue(replay.reason, replay.reason.contains("replay", ignoreCase = true))
        assertNull(provider.currentConfig)

        assertEquals(UpdateResult.Updated(4), apply(newest))
    }

    @Test
    fun `an unsigned block keeps working without an envelope`() = runTest {
        val plain = io.mockk.mockk<CertificateConfigApi>()
        val config = CertificateConfig(version = 2, pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 2)))
        io.mockk.coEvery { plain.fetchConfig(any()) } returns config
        io.mockk.coEvery { plain.healthCheck() } returns true

        assertEquals(InitResult.Ready(2), updater(trust = null, configApi = plain).initializeAndUpdate())
        assertNull(store.loadEnvelope())

        provider = HttpClientProvider(DynamicSSLManager())
        io.mockk.coEvery { plain.fetchConfig(any()) } throws java.io.IOException("offline")
        assertEquals(InitResult.Ready(2), updater(trust = null, configApi = plain).initializeAndUpdate())
    }

    // ── Change detection over the whole shape ───────────────────────────

    @Test
    fun `a pin removed without a version bump reaches the device`() = runTest {
        apply(signed(payload(4, issuedAt = now - hour, expiresAt = now + hour)))

        val result = apply(signed(payload(4, issuedAt = now, pins = listOf(pin1, pin3))))

        assertEquals(UpdateResult.Updated(4), result)
        assertEquals(listOf(pin1, pin3), provider.currentConfig!!.pins.single().sha256)
        assertEquals(listOf(pin1, pin3), store.load()!!.pins.single().sha256)
    }

    @Test
    fun `different pins at the same issuedAt are still a replay`() = runTest {
        apply(signed(payload(4, issuedAt = now)))

        val result = apply(signed(payload(4, issuedAt = now, pins = listOf(pin1, pin3)))) as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("replay", ignoreCase = true))
        assertEquals(listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)
    }

    @Test
    fun `an unsigned block applies a changed pin set at the same version too`() = runTest {
        val plain = io.mockk.mockk<CertificateConfigApi>()
        fun config(pins: List<String>) = CertificateConfig(version = 2, pins = listOf(HostPin("api.test", pins, version = 2)))
        io.mockk.coEvery { plain.fetchConfig(any()) } returns config(listOf(pin1, pin2))
        val unsigned = updater(trust = null, configApi = plain)
        assertEquals(UpdateResult.Updated(2), unsigned.updateNow())
        assertEquals(UpdateResult.AlreadyCurrent, unsigned.updateNow())

        io.mockk.coEvery { plain.fetchConfig(any()) } returns config(listOf(pin1, pin3))
        assertEquals(UpdateResult.Updated(2), unsigned.updateNow())
        assertEquals(listOf(pin1, pin3), provider.currentConfig!!.pins.single().sha256)
    }

    @Test
    fun `a newer envelope with the same pins is written back with its envelope`() = runTest {
        apply(signed(payload(4, issuedAt = now - hour, expiresAt = now + hour)))
        val fresher = signed(payload(4, issuedAt = now, expiresAt = now + 2 * hour))

        assertEquals(UpdateResult.AlreadyCurrent, apply(fresher))

        assertEquals(fresher.payload, store.loadEnvelope()!!.payload)
        assertEquals(now + 2 * hour, provider.currentConfig!!.expiresAt)
        // And it still verifies when read back.
        provider = HttpClientProvider(DynamicSSLManager())
        offline()
        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
        assertEquals(now + 2 * hour, provider.currentConfig!!.expiresAt)
    }

    // ── Intake: host names, freshness fields, version caps ──────────────

    @Test
    fun `a config with a host name that is not one is refused as a whole`() = runTest {
        val result = apply(signed(payload(4, issuedAt = now, hosts = mapOf("api.test" to 4, "api.bank.com|9|x" to 4)))) as UpdateResult.Failed

        assertTrue(result.exception is InvalidPinFormatException)
        assertNull(store.load())
        assertNull(provider.currentConfig)
    }

    @Test
    fun `a signed config must carry issuedAt and expiresAt`() = runTest {
        val noIssuedAt = apply(signed(payload(4, issuedAt = 0L, expiresAt = now + hour))) as UpdateResult.Failed
        assertTrue(noIssuedAt.reason, noIssuedAt.reason.contains("issuedAt"))

        val noExpiresAt = apply(signed(payload(4, issuedAt = now, expiresAt = 0L))) as UpdateResult.Failed
        assertTrue(noExpiresAt.reason, noExpiresAt.reason.contains("expiresAt"))
        assertNull(store.load())
    }

    @Test
    fun `expiresAt more than thirty days out is refused, with or without issuedAt`() = runTest {
        val signedLong = apply(signed(payload(4, issuedAt = now, expiresAt = now + 31 * day))) as UpdateResult.Failed
        assertTrue(signedLong.reason, signedLong.reason.contains("30 days"))

        // Unsigned, no issuedAt: there used to be nothing to measure the window from.
        val plain = io.mockk.mockk<CertificateConfigApi>()
        io.mockk.coEvery { plain.fetchConfig(any()) } returns CertificateConfig(
            version = 2, pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 2)), expiresAt = now + 400 * day
        )
        val unsignedLong = updater(trust = null, configApi = plain).updateNow() as UpdateResult.Failed
        assertTrue(unsignedLong.reason, unsignedLong.reason.contains("30 days"))
    }

    @Test
    fun `a host that was dropped keeps its watermark and cannot come back lower or far higher`() = runTest {
        apply(signed(payload(5, issuedAt = now - 3 * hour, expiresAt = now + hour, hosts = mapOf("a.test" to 5, "b.test" to 5))))
        apply(signed(payload(6, issuedAt = now - 2 * hour, expiresAt = now + hour, hosts = mapOf("a.test" to 6))))

        val lower = apply(signed(payload(6, issuedAt = now - hour, expiresAt = now + hour, hosts = mapOf("a.test" to 6, "b.test" to 3)))) as UpdateResult.Failed
        assertTrue(lower.reason, lower.reason.contains("downgrade rejected for b.test"))

        val leap = apply(signed(payload(6, issuedAt = now - hour, expiresAt = now + hour, hosts = mapOf("a.test" to 6, "b.test" to Int.MAX_VALUE)))) as UpdateResult.Failed
        assertTrue(leap.reason, leap.reason.contains("version jump rejected for b.test"))

        assertEquals(UpdateResult.Updated(6), apply(signed(payload(6, issuedAt = now, hosts = mapOf("a.test" to 6, "b.test" to 5)))))
    }

    // ── A newer signing-key set ends what a revoked key left behind ─────

    @Test
    fun `revoking a signing key clears the watermarks it pushed up and drops its config`() = runTest {
        val trust = trust(keys = listOf(keyA, keyB), withRecovery = true)
        val updater = updater(trust = trust)
        // The holder of stolen key A plants a config at the edge of what is
        // accepted: issuedAt ahead of the clock, the version a million up.
        assertEquals(
            UpdateResult.Updated(1_000_000),
            apply(signed(payload(1_000_000, issuedAt = now + 50 * 60_000, expiresAt = now + 20 * day, pins = listOf(pin3, pin3))), updater)
        )
        // Every honest config now looks like a replay and a downgrade.
        val honest = payload(3, issuedAt = now)
        assertTrue(apply(signed(honest, signer = keyB), updater) is UpdateResult.Failed)

        // Recovery keys publish set v2 without key A; the honest config rides along.
        val result = apply(signed(honest, signer = keyB, keySet = keySet(2, listOf(keyB))), updater)

        assertEquals(UpdateResult.Updated(3), result)
        assertEquals(now, store.getCurrentIssuedAt())
        assertEquals(mapOf("api.test" to 3), store.getVersionWatermarks())
        assertEquals(listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)
        assertEquals(2, store.keySetVersionSeen())
    }

    @Test
    fun `a config planted with a revoked key goes even when the config next to the new set fails`() = runTest {
        val trust = trust(keys = listOf(keyA, keyB), withRecovery = true)
        val updater = updater(trust = trust)
        apply(signed(payload(7, issuedAt = now, pins = listOf(pin3, pin3))), updater)
        assertNotNull(provider.currentConfig)

        // Set v2 revokes key A, but the config in the same response is still signed with A.
        val result = apply(signed(payload(8, issuedAt = now + 1), signer = keyA, keySet = keySet(2, listOf(keyB))), updater)

        assertTrue(result is UpdateResult.Failed)
        assertNull("the planted config is no longer pinned", provider.currentConfig)
        assertNull(store.load())
        assertEquals(0L, store.getCurrentIssuedAt())
    }

    @Test
    fun `a stored config signed by a key that is still trusted survives the new set`() = runTest {
        val trust = trust(keys = listOf(keyA, keyB), withRecovery = true)
        val updater = updater(trust = trust)
        val current = signed(payload(7, issuedAt = now), signer = keyB)
        apply(current, updater)

        // Same envelope again, now with set v2 (key A revoked): nothing to drop.
        assertEquals(UpdateResult.AlreadyCurrent, apply(current.copy(signingKeys = keySet(2, listOf(keyB))), updater))
        assertEquals(7, provider.currentConfig!!.computedVersion())
        assertEquals(now, store.getCurrentIssuedAt())
    }

    // ── serverScope ─────────────────────────────────────────────────────

    @Test
    fun `with a serverScope only configs signed for that Config API are accepted`() = runTest {
        val scoped = updater(scope = "default-tls")

        val missing = apply(signed(payload(4, issuedAt = now)), scoped) as UpdateResult.Failed
        assertTrue(missing.reason, missing.reason.contains("names no 'configApiId'"))

        val other = apply(signed(payload(4, issuedAt = now, scope = "default-mtls")), scoped) as UpdateResult.Failed
        assertTrue(other.reason, other.reason.contains("signed for Config API 'default-mtls'"))
        assertNull(store.load())

        assertEquals(UpdateResult.Updated(4), apply(signed(payload(4, issuedAt = now, scope = "default-tls")), scoped))
    }

    @Test
    fun `without a serverScope the field is ignored`() = runTest {
        assertEquals(UpdateResult.Updated(4), apply(signed(payload(4, issuedAt = now, scope = "whatever"))))
    }

    @Test
    fun `a stored envelope signed for another scope does not verify either`() = runTest {
        apply(signed(payload(4, issuedAt = now, scope = "default-mtls")))

        provider = HttpClientProvider(DynamicSSLManager())
        offline()
        val result = updater(scope = "default-tls").initializeAndUpdate() as InitResult.Failed
        assertTrue(result.reason, result.reason.contains("discarded"))
    }

    // ── A custom API ────────────────────────────────────────────────────

    @Test
    fun `a custom API's envelope is verified like the library's own`() = runTest {
        val forged = signed(payload(4, issuedAt = now), signer = keyB) // not a trusted key
        val result = apply(forged) as UpdateResult.Failed
        assertTrue(result.reason, result.reason.contains("signature verification failed"))
        assertNull(store.load())

        val tampered = signed(payload(4, issuedAt = now)).let { it.copy(payload = it.payload.replace(pin2, pin3)) }
        assertTrue(apply(tampered) is UpdateResult.Failed)

        val expired = apply(signed(payload(4, issuedAt = now - 2 * hour, expiresAt = now - hour))) as UpdateResult.Failed
        assertTrue(expired.reason, expired.reason.contains("expired"))
    }

    @Test
    fun `a signed block refuses a custom API that cannot hand over envelopes`() = runTest {
        val plain = io.mockk.mockk<CertificateConfigApi>()
        io.mockk.coEvery { plain.fetchConfig(any()) } returns
            CertificateConfig(version = 2, pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 2)))

        val result = updater(configApi = plain).updateNow() as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("SignedConfigSource"))
        io.mockk.coVerify(exactly = 0) { plain.fetchConfig(any()) }
        assertNull(store.load())
    }

    // ── One fetch at a time ─────────────────────────────────────────────

    @Test
    fun `concurrent updates share one fetch`() = runTest {
        val updater = updater()
        api.next = signed(payload(4, issuedAt = now))
        val gate = CompletableDeferred<Unit>().also { api.gate = it }

        val first = async { updater.updateNow() }
        val second = async { updater.updateNow() }
        val third = async { updater.updateNow() }
        testScheduler.runCurrent()
        gate.complete(Unit)

        assertEquals(UpdateResult.Updated(4), first.await())
        assertEquals(UpdateResult.Updated(4), second.await())
        assertEquals(UpdateResult.Updated(4), third.await())
        assertEquals("one fetch for all three callers", 1, api.fetches)

        // The next call, with nothing running, fetches again.
        api.gate = null
        assertEquals(UpdateResult.AlreadyCurrent, updater.updateNow())
        assertEquals(2, api.fetches)
    }

    // ── Expiry does not follow a clock that is set back ─────────────────

    @Test
    fun `setting the device clock back does not revive an expired config`() = runTest {
        var wall = now
        var elapsed = 0L
        val clock = TrustedClock(wall = { wall }, elapsed = { elapsed }, load = { store.highestSeenTime() }, persist = { store.setHighestSeenTime(it) })
        apply(signed(payload(4, issuedAt = now, expiresAt = now + hour)), updater(trustedClock = clock))

        // Two hours pass (the clock sees it), then the wall clock is set back.
        wall = now + 2 * hour
        elapsed = 2 * hour
        clock.checkpoint()
        wall = now + 10 * 60_000

        // A new process over the same store.
        provider = HttpClientProvider(DynamicSSLManager())
        offline()
        val restarted = TrustedClock(wall = { wall }, elapsed = { 0L }, load = { store.highestSeenTime() }, persist = { store.setHighestSeenTime(it) })
        val result = updater(trustedClock = restarted).initializeAndUpdate() as InitResult.Failed
        assertTrue(result.exception is ConfigExpiredException)
    }

    @Test
    fun `a clock reference left ahead is corrected by a newer signed config, not by a replayed one`() = runTest {
        var wall = now
        val clock = TrustedClock(wall = { wall }, elapsed = { 0L }, load = { store.highestSeenTime() }, persist = { store.setHighestSeenTime(it) })
        val updater = updater(trustedClock = clock)
        val first = signed(payload(4, issuedAt = now, expiresAt = now + hour))
        apply(first, updater)

        // The clock was once set a year ahead by mistake, then corrected.
        wall = now + 365 * day
        clock.checkpoint()
        wall = now + 10 * 60_000
        assertTrue(clock.now() > now + 364 * day)

        // The same config served again proves nothing about the time — and by
        // the trusted clock it has expired, so it is refused as such (C7).
        val again = apply(first, updater) as UpdateResult.Failed
        assertTrue(again.reason, again.reason.contains("already expired"))
        assertTrue(clock.now() > now + 364 * day)

        // A config newer than every one before does: the reference follows it.
        assertEquals(UpdateResult.AlreadyCurrent, apply(signed(payload(4, issuedAt = now + 5 * 60_000, expiresAt = now + 2 * hour)), updater))
        assertEquals(wall, clock.now())
        assertEquals(wall, store.highestSeenTime())
    }

    // ── An app update with new compiled-in keys resets the watermarks (C4) ──

    @Test
    fun `new compiled-in signing keys end what the old key pushed up`() = runTest {
        // A stolen keyA pushes the host version and issuedAt as far as the checks allow.
        assertTrue(apply(signed(payload(900_000, issuedAt = now + 50 * 60_000L))) is UpdateResult.Updated)
        val honest = signed(payload(5, issuedAt = now + 60_000L), signer = keyB)

        // Still on keyA's anchors the honest config is a replay / downgrade.
        assertTrue(apply(signed(payload(5, issuedAt = now + 60_000L))) is UpdateResult.Failed)

        // The app update ships keyB instead: the watermarks set under keyA go, and
        // keyA's stored config with them (keyB does not vouch for it).
        val afterUpdate = updater(trust = trust(keys = listOf(keyB)))
        assertEquals(UpdateResult.Updated(5), apply(honest, afterUpdate))
        assertEquals(5, store.getVersionWatermarks()["api.test"])
        assertEquals(now + 60_000L, store.getCurrentIssuedAt())

        // Same anchors from now on: no further reset, replays are refused again.
        assertTrue(apply(signed(payload(4, issuedAt = now + 30_000L), signer = keyB), updater(trust = trust(keys = listOf(keyB)))) is UpdateResult.Failed)
    }

    @Test
    fun `the first time a store meets the anchors check only the fingerprint is recorded`() = runTest {
        apply(signed(payload(7, issuedAt = now)))
        prefs.edit().remove(CertificateConfigStore.KEY_TRUST_ANCHORS).commit()   // a store from before the check
        assertTrue(apply(signed(payload(6, issuedAt = now + 1))) is UpdateResult.Failed)
        assertNotNull(store.trustAnchorsSeen())
        assertEquals(7, store.getVersionWatermarks()["api.test"])
    }

    // ── A rollback only undoes what the health check judged (C6) ──────────

    @Test
    fun `a failed health check does not roll back a newer config applied meanwhile`() = runTest {
        val u = updater()
        api.next = signed(payload(4, issuedAt = now))
        api.healthy = false
        api.duringHealthCheck = {
            api.duringHealthCheck = null
            // The worker (or the pin recovery) applies a newer config while the check runs.
            api.next = signed(payload(5, issuedAt = now + 1))
            assertEquals(UpdateResult.Updated(5), u.updateNow())
        }

        assertTrue(u.initializeAndUpdate() is InitResult.Failed)

        assertEquals("the newer config stays live", 5, provider.currentConfig!!.pins.single().version)
        assertEquals(5, store.load()!!.pins.single().version)
    }

    // ── "Already expired" by the trusted clock (C7) ────────────────────────

    @Test
    fun `a config at the watermark that expired by the trusted clock is not taken back after reset`() = runTest {
        val first = signed(payload(4, issuedAt = now, expiresAt = now + hour))
        assertEquals(UpdateResult.Updated(4), apply(first))
        store.clearActive()   // PinVault.reset()

        // The device has seen time two hours on; its wall clock now says otherwise.
        val ahead = TrustedClock(wall = { now }, elapsed = { 0L }, load = { now + 2 * hour })
        val u = updater(trustedClock = ahead)
        val replay = apply(first, u) as UpdateResult.Failed
        assertTrue(replay.reason, replay.reason.contains("already expired"))

        // A config newer than every config before is judged by the wall clock,
        // so it can still correct a trusted clock that ran ahead.
        assertEquals(UpdateResult.Updated(5), apply(signed(payload(5, issuedAt = now + 60_000L, expiresAt = now + hour)), u))
    }

    @Test
    fun `expiryNow takes the trusted clock except for a config newer than all before`() {
        fun cfg(issuedAt: Long) = CertificateConfig(pins = emptyList(), issuedAt = issuedAt, expiresAt = issuedAt + hour)
        val trusted = { now + 2 * hour }
        assertEquals(now + 2 * hour, SignedConfigVerifier.expiryNow(cfg(now), { now }, trusted, { now }))
        assertEquals(now, SignedConfigVerifier.expiryNow(cfg(now + 1), { now }, trusted, { now }))
        assertEquals("no trusted clock: the wall clock", now, SignedConfigVerifier.expiryNow(cfg(now), { now }, null, { now }))
    }
}
