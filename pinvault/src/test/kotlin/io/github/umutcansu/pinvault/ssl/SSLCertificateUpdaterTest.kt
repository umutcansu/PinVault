package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
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

        // Should fail validation (require pins.isNotEmpty())
        assertTrue("Expected Failed but got $result", result is UpdateResult.Failed)
    }
}
