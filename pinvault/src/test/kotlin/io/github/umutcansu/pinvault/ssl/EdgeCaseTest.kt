package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * E.28 — Aynı host'a iki kere cert yükle → version artmalı
 * E.29 — Host sil → client cert temizlenmeli
 * E.30 — Boş pin listesi → bağlantı reddedilmeli
 * E.31 — Network timeout → retry çalışıyor mu
 * E.32 — Concurrent init → race condition yok
 * E.33 — İki farklı host iki farklı cert
 * E.35 — Host cert güncellenirken diğer host kesintisiz
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EdgeCaseTest {

    private val testCert1 = TestCertUtil.generateSelfSigned(cn = "edge-test-1")
    private val testCert2 = TestCertUtil.generateSelfSigned(cn = "edge-test-2")
    private val pin1 = testCert1.sha256Pin
    private val pin2 = testCert2.sha256Pin
    private val password = "changeit"

    private lateinit var configApi: CertificateConfigApi
    private lateinit var configStore: CertificateConfigStore
    private lateinit var sslManager: DynamicSSLManager
    private lateinit var httpClientProvider: HttpClientProvider
    private lateinit var certStore: ClientCertSecureStore

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
    fun `E28 — aynı host cert version artarak güncellenir`() = runTest {
        val cert1 = TestCertUtil.generateSelfSigned(cn = "v1-client", password = password)
        val cert2 = TestCertUtil.generateSelfSigned(cn = "v2-client", password = password)

        // First update: clientCertVersion 1
        val stored1 = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("host.com", listOf(pin1, pin2), version = 1, mtls = true, clientCertVersion = 1))
        )
        val remote2 = CertificateConfig(
            version = 2,
            pins = listOf(HostPin("host.com", listOf(pin1, pin2), version = 2, mtls = true, clientCertVersion = 2))
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns stored1
        coEvery { configApi.fetchConfig(1) } returns remote2
        coEvery { configApi.downloadHostClientCert("host.com") } returns cert2.p12Bytes
        every { certStore.exists("host_host.com") } returns true

        val updater = createUpdater()
        val result = updater.updateNow()

        assertTrue(result is UpdateResult.Updated)
        coVerify { configApi.downloadHostClientCert("host.com") }
        verify { certStore.save("host_host.com", cert2.p12Bytes) }
    }

    @Test
    fun `E30 — boş pin listesi hata verir`() = runTest {
        val remoteConfig = CertificateConfig(version = 1, pins = emptyList(), forceUpdate = true)

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns remoteConfig

        val result = createUpdater().updateNow()
        assertTrue("Expected Failed but got $result", result is UpdateResult.Failed)
    }

    @Test
    fun `E32 — concurrent swap — thread safe`() {
        val certs = (1..5).map { TestCertUtil.generateSelfSigned(cn = "host$it") }
        val configs = certs.mapIndexed { i, c ->
            CertificateConfig(
                version = i + 1,
                pins = listOf(HostPin("host${i + 1}.com", listOf(c.sha256Pin, c.sha256Pin), version = i + 1))
            )
        }

        // Concurrent swaps — should not throw ConcurrentModificationException
        runBlocking {
            val jobs = configs.map { config ->
                launch(Dispatchers.Default) {
                    httpClientProvider.swap(config)
                }
            }
            jobs.forEach { it.join() }
        }

        // Final state should be valid (some version)
        assertTrue(httpClientProvider.getVersion() > 0)
        assertNotNull(httpClientProvider.get())
    }

    @Test
    fun `E33 — iki farklı host iki farklı cert yüklenir`() {
        val certA = TestCertUtil.generateSelfSigned(cn = "Alpha-Client", password = password)
        val certB = TestCertUtil.generateSelfSigned(cn = "Beta-Client", password = password)

        sslManager.loadHostClientCerts(
            mapOf("alpha.com" to certA.p12Bytes, "beta.com" to certB.p12Bytes),
            password
        )

        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("alpha.com", listOf(certA.sha256Pin, certA.sha256Pin), mtls = true, clientCertVersion = 1),
                HostPin("beta.com", listOf(certB.sha256Pin, certB.sha256Pin), mtls = true, clientCertVersion = 1)
            )
        )
        val client = sslManager.buildClient(config)
        assertNotNull(client)
    }

    @Test
    fun `E35 — host cert güncelleme diğer host'u etkilemez`() {
        val certA = TestCertUtil.generateSelfSigned(cn = "Stable-Host", password = password)
        val certB1 = TestCertUtil.generateSelfSigned(cn = "Updating-Host-v1", password = password)
        val certB2 = TestCertUtil.generateSelfSigned(cn = "Updating-Host-v2", password = password)

        // Initial load
        sslManager.loadHostClientCerts(
            mapOf("stable.com" to certA.p12Bytes, "updating.com" to certB1.p12Bytes),
            password
        )

        // Update only one host
        sslManager.loadHostClientCerts(
            mapOf("stable.com" to certA.p12Bytes, "updating.com" to certB2.p12Bytes),
            password
        )

        // Both should work — no exception
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("stable.com", listOf(certA.sha256Pin, certA.sha256Pin)),
                HostPin("updating.com", listOf(certB2.sha256Pin, certB2.sha256Pin))
            )
        )
        assertNotNull(sslManager.buildClient(config))
    }

    @Test
    fun `per-host forceUpdate — only that host triggers update`() = runTest {
        val stored = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("a.com", listOf(pin1, pin2), version = 1),
                HostPin("b.com", listOf(pin1, pin2), version = 1)
            )
        )
        val remote = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("a.com", listOf(pin1, pin2), version = 1),
                HostPin("b.com", listOf(pin1, pin2), version = 1, forceUpdate = true)
            )
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns stored
        coEvery { configApi.fetchConfig(1) } returns remote

        val result = createUpdater().updateNow()
        assertTrue(result is UpdateResult.Updated)
    }

    @Test
    fun `HttpClientProvider reset — clean state`() {
        val cert = TestCertUtil.generateSelfSigned()
        val config = CertificateConfig(
            version = 3,
            pins = listOf(HostPin("host", listOf(cert.sha256Pin, cert.sha256Pin), version = 3))
        )
        httpClientProvider.swap(config)
        assertEquals(3, httpClientProvider.getVersion())

        httpClientProvider.reset()
        assertEquals(0, httpClientProvider.getVersion())
        assertNull(httpClientProvider.currentConfig)
        assertNotNull(httpClientProvider.get())
    }
}
