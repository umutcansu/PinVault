package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ConfigExpiredException
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.NoConfigAvailableException
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Y1/O6: a stored config is bounded by its `expiresAt`, a rollback never
 * lowers the replay watermarks, and values that would lock the device out for
 * good are refused. Runs the updater over a real [CertificateConfigStore].
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ConfigExpiryTest {

    private val pin1 = TestCertUtil.generateSelfSigned(cn = "a").sha256Pin
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "b").sha256Pin
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L

    private lateinit var store: CertificateConfigStore
    private lateinit var api: CertificateConfigApi
    private lateinit var provider: HttpClientProvider

    @Before
    fun setUp() {
        val prefs = ApplicationProvider.getApplicationContext<Context>().getSharedPreferences("expiry_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        store = CertificateConfigStore.createForTest(prefs).also { it.clock = { now } }
        api = mockk()
        provider = HttpClientProvider(DynamicSSLManager())
    }

    private fun updater(graceMs: Long = 0L) = SSLCertificateUpdater(
        context = mockk(relaxed = true),
        configApi = api,
        configStore = store,
        httpClientProvider = provider,
        maxRetryCount = 1,
        expiredConfigGraceMs = graceMs,
        clock = { now }
    )

    private fun config(version: Int, issuedAt: Long, expiresAt: Long, host: String = "api.test") = CertificateConfig(
        version = version,
        pins = listOf(HostPin(host, listOf(pin1, pin2), version = version)),
        issuedAt = issuedAt,
        expiresAt = expiresAt
    )

    // ── Expiry at init ──────────────────────────────────────────────────

    @Test
    fun `expired stored config is refused when the backend is unreachable`() = runTest {
        store.save(config(4, issuedAt = now - 30 * hour, expiresAt = now - 6 * hour))
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("blocked")

        val result = updater().initializeAndUpdate()

        val failed = result as InitResult.Failed
        assertTrue(failed.exception is ConfigExpiredException)
        assertEquals(now - 6 * hour, (failed.exception as ConfigExpiredException).expiresAt)
    }

    @Test
    fun `unexpired stored config still starts offline`() = runTest {
        store.save(config(4, issuedAt = now - hour, expiresAt = now + hour))
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("offline")

        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
    }

    @Test
    fun `grace period keeps an expired config usable that much longer`() = runTest {
        store.save(config(4, issuedAt = now - 30 * hour, expiresAt = now - 6 * hour))
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("offline")

        assertEquals(InitResult.Ready(4), updater(graceMs = 7 * hour).initializeAndUpdate())
        assertTrue(updater(graceMs = 5 * hour).initializeAndUpdate() is InitResult.Failed)
    }

    @Test
    fun `expired stored config is refused without a client certificate too`() = runTest {
        store.save(config(4, issuedAt = now - 30 * hour, expiresAt = now - 6 * hour))

        val result = updater().initializeAndUpdate(needsClientCertificate = true)

        assertTrue((result as InitResult.Failed).exception is ConfigExpiredException)
    }

    @Test
    fun `a fresh envelope with the same pins moves expiresAt forward`() = runTest {
        store.save(config(4, issuedAt = now - 30 * hour, expiresAt = now - 6 * hour))
        coEvery { api.fetchConfig(any()) } returns config(4, issuedAt = now - 60_000, expiresAt = now + 24 * hour)

        val result = updater().initializeAndUpdate()

        assertEquals(InitResult.Ready(4), result)
        assertEquals(now + 24 * hour, store.load()!!.expiresAt)
        assertEquals(now - 60_000, store.getCurrentIssuedAt())
        assertEquals("the live client follows the disk", now + 24 * hour, provider.currentConfig!!.expiresAt)
    }

    @Test
    fun `the same envelope served again replaces an estimated expiresAt`() = runTest {
        // Stored by 2.1.1: no expiresAt kept, so the store estimates first load + 7 days.
        val prefs = ApplicationProvider.getApplicationContext<Context>().getSharedPreferences("expiry_test", Context.MODE_PRIVATE)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 4)
            .putString(CertificateConfigStore.KEY_PINS, "api.test|4|$pin1,$pin2|false")
            .putLong(CertificateConfigStore.KEY_ISSUED_AT, now - hour)
            .commit()
        // The server caches its signature and serves the same envelope, valid for 7 days.
        coEvery { api.fetchConfig(any()) } returns config(4, issuedAt = now - hour, expiresAt = now + 7 * 24 * hour)

        assertEquals(UpdateResult.AlreadyCurrent, updater().updateNow())
        assertEquals(now + 7 * 24 * hour, store.load()!!.expiresAt)
    }

    @Test
    fun `a config stored by 2_1_1 with an old issuedAt still starts offline after the update`() = runTest {
        // 2.1.1 never wrote issuedAt back while the pins stayed the same: weeks old.
        val prefs = ApplicationProvider.getApplicationContext<Context>().getSharedPreferences("expiry_test", Context.MODE_PRIVATE)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 4)
            .putString(CertificateConfigStore.KEY_PINS, "api.test|4|$pin1,$pin2|false")
            .putLong(CertificateConfigStore.KEY_ISSUED_AT, now - 40 * 24 * hour)
            .commit()
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("offline")

        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
        assertEquals(now + 7 * 24 * hour, provider.currentConfig!!.expiresAt)
    }

    @Test
    fun `config without expiresAt never expires`() = runTest {
        store.save(config(4, issuedAt = 0L, expiresAt = 0L))
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("offline")

        assertEquals(InitResult.Ready(4), updater().initializeAndUpdate())
    }

    @Test
    fun `no stored config and no backend is still NoConfigAvailable`() = runTest {
        coEvery { api.fetchConfig(any()) } throws java.io.IOException("offline")

        assertTrue((updater().initializeAndUpdate() as InitResult.Failed).exception is NoConfigAvailableException)
    }

    // ── O6: values that would lock the device out ───────────────────────

    @Test
    fun `issuedAt more than an hour ahead is refused`() = runTest {
        coEvery { api.fetchConfig(any()) } returns config(1, issuedAt = now + 61 * 60_000, expiresAt = now + 24 * hour)

        val result = updater().updateNow() as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("ahead of this device's clock"))
        assertNull(store.load())
    }

    @Test
    fun `issuedAt slightly ahead is accepted`() = runTest {
        coEvery { api.fetchConfig(any()) } returns config(1, issuedAt = now + 50 * 60_000, expiresAt = now + 24 * hour)

        assertTrue(updater().updateNow() is UpdateResult.Updated)
    }

    @Test
    fun `an already expired config from a custom API is refused and the stored one kept`() = runTest {
        store.save(config(4, issuedAt = now - hour, expiresAt = now + hour))
        coEvery { api.fetchConfig(any()) } returns config(5, issuedAt = now - 30 * 60_000, expiresAt = now - 1)

        val result = updater().updateNow() as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("already expired"))
        assertEquals(4, store.load()!!.pins.single().version)
    }

    @Test
    fun `validity window over thirty days is refused`() = runTest {
        coEvery { api.fetchConfig(any()) } returns config(1, issuedAt = now, expiresAt = now + 31 * 24 * hour)

        val result = updater().updateNow() as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("more than 30 days"))
    }

    @Test
    fun `per-host version jump over a million is refused`() = runTest {
        store.save(config(4, issuedAt = now - hour, expiresAt = now + hour))
        coEvery { api.fetchConfig(any()) } returns config(1_000_005, issuedAt = now, expiresAt = now + hour)

        val result = updater().updateNow() as UpdateResult.Failed

        assertTrue(result.reason, result.reason.contains("version jump rejected for api.test"))
        assertEquals(4, store.load()!!.pins.single().version)
    }

    @Test
    fun `a new host starts at a million at most`() = runTest {
        // A host without a watermark has nothing to "jump" from; starting it
        // at Int.MAX_VALUE would leave no version above it.
        coEvery { api.fetchConfig(any()) } returns config(1_000_001, issuedAt = now, expiresAt = now + hour)
        val refused = updater().updateNow() as UpdateResult.Failed
        assertTrue(refused.reason, refused.reason.contains("first version"))
        assertNull(store.load())

        coEvery { api.fetchConfig(any()) } returns config(1_000_000, issuedAt = now, expiresAt = now + hour)
        assertTrue(updater().updateNow() is UpdateResult.Updated)
    }

    // ── Rollback keeps the watermarks ───────────────────────────────────

    @Test
    fun `rollback restores the old pins but not the old watermarks`() = runTest {
        val previous = config(4, issuedAt = now - 2 * hour, expiresAt = now + 20 * hour)
        val rejected = config(5, issuedAt = now - hour, expiresAt = now + 23 * hour)
        store.save(previous)
        coEvery { api.fetchConfig(any()) } returns rejected
        coEvery { api.healthCheck() } returns false

        assertTrue(updater().initializeAndUpdate() is InitResult.Failed)

        assertEquals("previous pins are back", 4, store.load()!!.pins.single().version)
        assertEquals(previous, provider.currentConfig)
        assertEquals("issuedAt watermark stays at the rejected config", now - hour, store.getCurrentIssuedAt())
        assertEquals(5, store.getVersionWatermarks()["api.test"])

        // An older signed config between the two, with other content, is now a replay.
        coEvery { api.fetchConfig(any()) } returns config(3, issuedAt = now - 90 * 60_000, expiresAt = now + hour)
        assertTrue((updater().updateNow() as UpdateResult.Failed).reason.contains("replay"))
        // An older copy of exactly the restored config changes nothing: current, not an alarm.
        coEvery { api.fetchConfig(any()) } returns config(4, issuedAt = now - 90 * 60_000, expiresAt = now + hour)
        assertEquals(UpdateResult.AlreadyCurrent, updater().updateNow())
        assertEquals(previous, provider.currentConfig)
    }

    @Test
    fun `the rolled-back config itself may be applied again`() = runTest {
        val previous = config(4, issuedAt = now - 2 * hour, expiresAt = now + 20 * hour)
        val rejected = config(5, issuedAt = now - hour, expiresAt = now + 23 * hour)
        store.save(previous)
        coEvery { api.fetchConfig(any()) } returns rejected
        coEvery { api.healthCheck() } returns false
        updater().initializeAndUpdate()

        coEvery { api.healthCheck() } returns true
        val result = updater().initializeAndUpdate()

        assertEquals(InitResult.Ready(5), result)
        assertEquals(rejected, store.load())
    }

    @Test
    fun `same issuedAt with other pins is still a replay after a rollback`() = runTest {
        store.save(config(4, issuedAt = now - 2 * hour, expiresAt = now + 20 * hour))
        coEvery { api.fetchConfig(any()) } returns config(5, issuedAt = now - hour, expiresAt = now + 23 * hour)
        coEvery { api.healthCheck() } returns false
        updater().initializeAndUpdate()

        coEvery { api.fetchConfig(any()) } returns config(6, issuedAt = now - hour, expiresAt = now + 23 * hour)
        assertTrue((updater().updateNow() as UpdateResult.Failed).reason.contains("replay"))
    }

    @Test
    fun `first config that fails its health check leaves the watermark in place`() = runTest {
        coEvery { api.fetchConfig(any()) } returns config(5, issuedAt = now - hour, expiresAt = now + 23 * hour)
        coEvery { api.healthCheck() } returns false

        assertTrue(updater().initializeAndUpdate() is InitResult.Failed)

        assertNull(store.load())
        assertNull(provider.currentConfig)
        assertEquals(now - hour, store.getCurrentIssuedAt())
    }
}
