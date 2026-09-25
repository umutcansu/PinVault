package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.InvalidPinFormatException
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A.4 — SSLCertificateUpdater: mTLS host cert version değişimi algılama
 * E.31 — Network timeout retry
 * E.36 — Periyodik update
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SSLCertificateUpdaterTest {

    private lateinit var configApi: CertificateConfigApi
    private lateinit var configStore: CertificateConfigStore
    private lateinit var httpClientProvider: HttpClientProvider
    private lateinit var sslManager: DynamicSSLManager
    private lateinit var certStore: ClientCertSecureStore
    private val password = "changeit"

    // Real SHA-256 pins from generated certs
    private val testCert = TestCertUtil.generateSelfSigned(cn = "pin-test")
    private val backupCert = TestCertUtil.generateSelfSigned(cn = "pin-backup")
    private val pin1 = testCert.sha256Pin
    private val pin2 = backupCert.sha256Pin

    @Before
    fun setUp() {
        configApi = mockk()
        configStore = mockk(relaxed = true)
        sslManager = DynamicSSLManager()
        httpClientProvider = HttpClientProvider(sslManager)
        certStore = mockk(relaxed = true)
    }

    private fun createUpdater(maxRetry: Int = 1): SSLCertificateUpdater {
        val context = mockk<android.content.Context>(relaxed = true)
        return SSLCertificateUpdater(
            context = context,
            configApi = configApi,
            configStore = configStore,
            httpClientProvider = httpClientProvider,
            sslManager = sslManager,
            certStore = certStore,
            clientKeyPassword = password,
            maxRetryCount = maxRetry
        )
    }

    @Test
    fun `updateNow — yeni config algılanır ve kaydedilir`() = runTest {
        val remoteConfig = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1))
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
        verify { configStore.save(remoteConfig) }
    }

    @Test
    fun `updateNow — aynı config ise AlreadyCurrent`() = runTest {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1))
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns config
        coEvery { configApi.fetchConfig(1) } returns config

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.AlreadyCurrent)
    }

    @Test
    fun `updateNow — mTLS host clientCertVersion değişimi algılanır`() = runTest {
        val storedConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.test", listOf(pin1, pin2), version = 1, mtls = true, clientCertVersion = 1)
            )
        )
        val remoteConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.test", listOf(pin1, pin2), version = 2, mtls = true, clientCertVersion = 2)
            )
        )
        val hostCert = TestCertUtil.generateSelfSigned(cn = "client-for-api.test", password = password)

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(1) } returns remoteConfig
        coEvery { configApi.downloadHostClientCert("api.test") } returns hostCert.p12Bytes
        every { certStore.exists("host_api.test") } returns true

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
        // Verify host cert was downloaded and saved
        coVerify { configApi.downloadHostClientCert("api.test") }
        verify { certStore.save("host_api.test", hostCert.p12Bytes) }
    }

    @Test
    fun `updateNow — mTLS host cert indir başarısız olursa store'dan yüklenir`() = runTest {
        val storedConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.test", listOf(pin1, pin2), version = 1)
            )
        )
        val remoteConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.test", listOf(pin1, pin2), version = 2, mtls = true, clientCertVersion = 1)
            )
        )
        val cachedCert = TestCertUtil.generateSelfSigned(cn = "cached", password = password)

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(1) } returns remoteConfig
        coEvery { configApi.downloadHostClientCert("api.test") } throws RuntimeException("Network error")
        every { certStore.exists("host_api.test") } returns false
        every { certStore.load("host_api.test") } returns cachedCert.p12Bytes

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
        // Fallback: load from store
        verify { certStore.load("host_api.test") }
    }

    @Test
    fun `updateNow — non-mtls host cert indirilmez`() = runTest {
        val remoteConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("tls.host", listOf(pin1, pin2), version = 1, mtls = false)
            )
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val updater = createUpdater()
        updater.updateNow()

        coVerify(exactly = 0) { configApi.downloadHostClientCert(any()) }
    }

    @Test
    fun `updateNow — network hata → UpdateResult_Failed`() = runTest {
        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } throws RuntimeException("Connection refused")

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Failed)
        assertEquals("Connection refused", (result as UpdateResult.Failed).reason)
    }

    @Test
    fun `updateNow — host ekleme algılanır`() = runTest {
        val storedConfig = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("old.host", listOf(pin1, pin2), version = 1))
        )
        val remoteConfig = CertificateConfig(
            version = 2,
            pins = listOf(
                HostPin("old.host", listOf(pin1, pin2), version = 1),
                HostPin("new.host", listOf(pin1, pin2), version = 1)
            )
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(1) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
    }

    @Test
    fun `updateNow — host silme algılanır`() = runTest {
        val storedConfig = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("keep.host", listOf(pin1, pin2), version = 1),
                HostPin("remove.host", listOf(pin1, pin2), version = 1)
            )
        )
        val remoteConfig = CertificateConfig(
            version = 2,
            pins = listOf(HostPin("keep.host", listOf(pin1, pin2), version = 1))
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(1) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
    }

    @Test
    fun `updateNow — forceUpdate true tetiklenir`() = runTest {
        val storedConfig = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1))
        )
        val remoteConfig = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1)),
            forceUpdate = true
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(1) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
    }

    @Test
    fun `updateNow — boş pin listesi reddedilir`() = runTest {
        // Remote has no pins but forceUpdate is true to trigger hasChanges
        val remoteConfig = CertificateConfig(version = 1, pins = emptyList(), forceUpdate = true)

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        // Should fail validation (pins.isNotEmpty())
        assertTrue("Expected Failed but got $result", result is UpdateResult.Failed)
    }

    // ── Boş config bir "değişiklik yok" değil, bir hatadır ───────────────────
    //
    // Regression: when BOTH the stored and the remote pin sets were empty,
    // all three change-detect clauses were false, updateNow returned
    // AlreadyCurrent and validateConfig never ran — init reported
    // Ready(v0) while nothing at all was pinned.

    @Test
    fun `updateNow — saklı config yokken boş uzak config reddedilir`() = runTest {
        // forceUpdate is false on purpose: this is the exact shape that used
        // to slip through as AlreadyCurrent.
        val remoteConfig = CertificateConfig(version = 0, pins = emptyList())

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue("Expected Failed but got $result", result is UpdateResult.Failed)
        val failure = result as UpdateResult.Failed
        assertTrue(
            "Failure must carry InvalidPinFormatException, got ${failure.exception}",
            failure.exception is InvalidPinFormatException
        )
        assertTrue(
            "Reason must name the rule: ${failure.reason}",
            failure.reason.contains("at least one pin")
        )
        verify(exactly = 0) { configStore.save(any()) }
    }

    @Test
    fun `updateNow — boş uzak config saklı config'i silmez`() = runTest {
        val storedConfig = CertificateConfig(
            version = 7,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 7))
        )
        val remoteConfig = CertificateConfig(version = 0, pins = emptyList())

        every { configStore.getCurrentVersion() } returns 7
        every { configStore.load() } returns storedConfig
        coEvery { configApi.fetchConfig(7) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue("Expected Failed but got $result", result is UpdateResult.Failed)
        assertTrue(
            "Failure must carry InvalidPinFormatException",
            (result as UpdateResult.Failed).exception is InvalidPinFormatException
        )
        // The stored config is the device's last known-good pin set; a
        // rejected fetch must leave it exactly as it was.
        verify(exactly = 0) { configStore.save(any()) }
        verify(exactly = 0) { configStore.clear() }
    }

    @Test
    fun `initializeAndUpdate — boş config ile Ready dönmez`() = runTest {
        // The user-visible half of the same bug: the app rendered "Hazır —
        // config v0" for a device with no pinned host at all.
        val remoteConfig = CertificateConfig(version = 0, pins = emptyList())

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val updater = createUpdater()
        val result = updater.initializeAndUpdate()

        assertTrue(
            "Expected InitResult.Failed but got $result",
            result is io.github.umutcansu.pinvault.model.InitResult.Failed
        )
        coVerify(exactly = 0) { configApi.healthCheck() }
    }

    // ── Replay & downgrade guards (M-08) ────────────────────────────────────

    @Test
    fun `updateNow — issuedAt eşit ama içerik farklıysa replay reddedilir`() = runTest {
        val storedIssuedAt = 1_000_000_000_000L
        val stored = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = storedIssuedAt
        )
        // Remote claims the host changed (would normally pass change detection)
        // but reuses the SAME issuedAt — a legitimate signer never signs two
        // different configs with one timestamp, so this is a replay shape.
        val remote = CertificateConfig(
            version = 6,
            pins = listOf(HostPin("api.test", listOf(pin2, pin1), version = 6)),
            issuedAt = storedIssuedAt
        )

        every { configStore.getCurrentVersion() } returns 5
        every { configStore.getCurrentIssuedAt() } returns storedIssuedAt
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(5) } returns remote

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue("Expected Failed for replay, got $result", result is UpdateResult.Failed)
        val failure = result as UpdateResult.Failed
        assertTrue(
            "Failure must mention replay: ${failure.reason}",
            failure.reason.contains("replay", ignoreCase = true) || failure.reason.contains("issuedAt")
        )
    }

    @Test
    fun `updateNow — daha eski issuedAt replay olarak reddedilir`() = runTest {
        val storedIssuedAt = 1_000_000_000_000L
        val stored = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = storedIssuedAt
        )
        val remote = stored.copy(issuedAt = storedIssuedAt - 1)

        every { configStore.getCurrentVersion() } returns 5
        every { configStore.getCurrentIssuedAt() } returns storedIssuedAt
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(5) } returns remote

        val result = createUpdater().updateNow()

        assertTrue("Expected Failed for replay, got $result", result is UpdateResult.Failed)
        assertTrue((result as UpdateResult.Failed).reason.contains("replay", ignoreCase = true))
    }

    @Test
    fun `updateNow — aynı imzalı config yeniden gelirse AlreadyCurrent, replay değil`() = runTest {
        // A backend that signs once per change (HSM/KMS signer, signature
        // cache, CDN) serves the byte-identical config until it changes.
        val storedIssuedAt = 1_000_000_000_000L
        val stored = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = storedIssuedAt
        )
        // Same config as delivered; its force flag was honoured on first
        // delivery and cleared on disk since — it must not be re-applied.
        val remote = stored.copy(
            forceUpdate = true,
            pins = stored.pins.map { it.copy(forceUpdate = true) },
            expiresAt = storedIssuedAt + 60_000
        )

        every { configStore.getCurrentVersion() } returns 5
        every { configStore.getCurrentIssuedAt() } returns storedIssuedAt
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(5) } returns remote

        val result = createUpdater().updateNow()

        assertEquals(UpdateResult.AlreadyCurrent, result)
        verify(exactly = 0) { configStore.save(any()) }
    }

    @Test
    fun `updateNow — per-host version downgrade reddedilir`() = runTest {
        val stored = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = 1_000L
        )
        // Remote serves a fresh issuedAt but the per-host version went BACKWARDS
        // — an attacker rotated their captured config but kept the older pins.
        val remote = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3)),
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 5
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(5) } returns remote

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue("Expected Failed for downgrade, got $result", result is UpdateResult.Failed)
        val failure = result as UpdateResult.Failed
        assertTrue(
            "Failure must mention downgrade: ${failure.reason}",
            failure.reason.contains("downgrade", ignoreCase = true)
        )
    }

    // ── Güncelleme sonrası sağlık kapısı ve geri alma (G08) ─────────────────
    //
    // verifyPinnedConnection yalnızca yeni bir config UYGULANDIKTAN hemen sonra
    // çalışır. Kapı açılmazsa yeni config diskte kalmamalı: init bu turda
    // "başarısız" derken bir sonraki açılışta AlreadyCurrent yolundan sessizce
    // "Hazır" olurdu (kapı o yolda hiç çalışmıyor).

    @Test
    fun `init — sağlık kontrolü false dönerse önceki config geri yüklenir`() = runTest {
        val stored = CertificateConfig(
            version = 4,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 4)),
            issuedAt = 1_000L
        )
        val remote = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 4
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(4) } returns remote
        // Default API impl swallows exceptions and returns false — the exact
        // shape the old "clear on exception only" branch could never see.
        coEvery { configApi.healthCheck() } returns false

        val updater = createUpdater()
        val result = updater.initializeAndUpdate()

        assertTrue("Expected Failed but got $result", result is InitResult.Failed)
        assertTrue(
            "Failure must name the health check: ${(result as InitResult.Failed).reason}",
            result.reason.contains("unhealthy", ignoreCase = true)
        )
        // The new config was applied first…
        verify { configStore.save(remote) }
        // …and then rolled back to the last config known to reach the backend.
        verify { configStore.save(stored) }
        verify(exactly = 0) { configStore.clear() }
        assertEquals(
            "live client must be rebuilt with the previous config",
            stored, httpClientProvider.currentConfig
        )
        assertEquals(4, httpClientProvider.getVersion())
    }

    @Test
    fun `init — önceki config yokken sağlık false ise depo temizlenir`() = runTest {
        val remote = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1)),
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.getCurrentIssuedAt() } returns 0L
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remote
        coEvery { configApi.healthCheck() } returns false

        val updater = createUpdater()
        val result = updater.initializeAndUpdate()

        assertTrue("Expected Failed but got $result", result is InitResult.Failed)
        verify { configStore.clear() }
        assertNull(
            "with nothing to roll back to the client must be fail-closed again",
            httpClientProvider.currentConfig
        )
        assertEquals(0, httpClientProvider.getVersion())
    }

    @Test
    fun `init — sağlık kontrolü true ise yeni config kalıcı`() = runTest {
        val stored = CertificateConfig(
            version = 4,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 4)),
            issuedAt = 1_000L
        )
        val remote = CertificateConfig(
            version = 5,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 5)),
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 5
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(any()) } returns remote
        coEvery { configApi.healthCheck() } returns true

        val updater = createUpdater()
        val result = updater.initializeAndUpdate()

        assertTrue("Expected Ready but got $result", result is InitResult.Ready)
        verify { configStore.save(remote) }
        verify(exactly = 0) { configStore.save(stored) }
        verify(exactly = 0) { configStore.clear() }
        assertEquals(
            "the freshly applied config must stay on the live client",
            remote, httpClientProvider.currentConfig
        )
    }

    @Test
    fun `init — sağlık kapısı yalnızca config değiştiğinde çalışır`() = runTest {
        // Offline / unchanged paths must not be gated: AlreadyCurrent means
        // nothing was applied, so there is nothing to verify or roll back.
        val stored = CertificateConfig(
            version = 4,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 4)),
            issuedAt = 1_000L
        )

        every { configStore.getCurrentVersion() } returns 4
        every { configStore.getCurrentIssuedAt() } returns 0L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(4) } returns stored

        val updater = createUpdater()
        val result = updater.initializeAndUpdate()

        assertTrue("Expected Ready but got $result", result is InitResult.Ready)
        coVerify(exactly = 0) { configApi.healthCheck() }
        verify(exactly = 0) { configStore.clear() }
    }

    // ── forceUpdate bayrağının KAPANMASI cihaza ulaşmalı (D04) ──────────────

    @Test
    fun `updateNow — force bayrağı kapanınca saklı kopyadan silinir (AlreadyCurrent)`() = runTest {
        val stored = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3, forceUpdate = true)),
            forceUpdate = true,
            issuedAt = 1_000L
        )
        // Same pins, same version — only the operator's force switch went off.
        val remote = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3, forceUpdate = false)),
            forceUpdate = false,
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 3
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(3) } returns remote

        val updater = createUpdater()
        val result = updater.updateNow()

        // Nothing about the pins changed, so this is NOT an update — the app
        // must keep saying "config is current" (E2E scenario 04).
        assertTrue("Expected AlreadyCurrent but got $result", result is UpdateResult.AlreadyCurrent)

        // …but the cleared flag has to reach the disk, otherwise a cold start
        // with an unreachable backend keeps failing with
        // ForceUpdateFailedException forever (E2E F01 / D04).
        val saved = slot<CertificateConfig>()
        verify { configStore.save(capture(saved)) }
        assertFalse("global forceUpdate must be cleared on disk", saved.captured.forceUpdate)
        assertFalse(
            "per-host forceUpdate must be cleared on disk",
            saved.captured.pins.any { it.forceUpdate }
        )
        // Only the flags change: the validated stored pins are written back,
        // never an unvalidated remote payload.
        assertEquals(stored.pins.map { it.hostname }, saved.captured.pins.map { it.hostname })
        assertEquals(stored.pins.map { it.version }, saved.captured.pins.map { it.version })
        assertEquals(stored.issuedAt, saved.captured.issuedAt)
    }

    @Test
    fun `updateNow — yalnızca host bazlı force kapanırsa da diske yazılır`() = runTest {
        val stored = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3, forceUpdate = true)),
            forceUpdate = false,
            issuedAt = 1_000L
        )
        val remote = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3, forceUpdate = false)),
            forceUpdate = false,
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 3
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(3) } returns remote

        val result = createUpdater().updateNow()

        assertTrue("Expected AlreadyCurrent but got $result", result is UpdateResult.AlreadyCurrent)
        val saved = slot<CertificateConfig>()
        verify { configStore.save(capture(saved)) }
        assertFalse(saved.captured.pins.any { it.forceUpdate })
    }

    @Test
    fun `updateNow — bayraklar zaten aynıysa gereksiz yazma yapılmaz`() = runTest {
        val config = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3)),
            issuedAt = 1_000L
        )

        every { configStore.getCurrentVersion() } returns 3
        every { configStore.getCurrentIssuedAt() } returns 0L
        every { configStore.load() } returns config
        coEvery { configApi.fetchConfig(3) } returns config

        val result = createUpdater().updateNow()

        assertTrue("Expected AlreadyCurrent but got $result", result is UpdateResult.AlreadyCurrent)
        verify(exactly = 0) { configStore.save(any()) }
    }

    @Test
    fun `updateNow — force bayrağı açıkken hâlâ Updated dönüyor`() = runTest {
        // The ON direction is unchanged: force means "re-apply now, even at the
        // same version" (E2E scenario 04, F01).
        val stored = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3)),
            issuedAt = 1_000L
        )
        val remote = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 3, forceUpdate = true)),
            forceUpdate = true,
            issuedAt = 2_000L
        )

        every { configStore.getCurrentVersion() } returns 3
        every { configStore.getCurrentIssuedAt() } returns 1_000L
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(3) } returns remote

        val result = createUpdater().updateNow()

        assertTrue("Expected Updated but got $result", result is UpdateResult.Updated)
        verify { configStore.save(remote) }
    }

    @Test
    fun `updateNow — ilk fetch (storedIssuedAt 0) yeni config'i kabul eder`() = runTest {
        // No prior config persisted → storedIssuedAt == 0L → replay check is
        // a no-op so the very first remote config can install cleanly.
        val remote = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1)),
            issuedAt = 1_000L
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.getCurrentIssuedAt() } returns 0L
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remote

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue("Expected Updated, got $result", result is UpdateResult.Updated)
        verify { configStore.save(remote) }
    }
}
