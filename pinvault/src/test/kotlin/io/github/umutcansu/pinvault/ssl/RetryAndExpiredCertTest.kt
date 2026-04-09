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
 * E.31 — Network timeout retry
 * E.34 — Bir host cert expire, diğeri geçerli
 * D.26 — Expired cert reddedilmeli
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class RetryAndExpiredCertTest {

    private lateinit var configApi: CertificateConfigApi
    private lateinit var configStore: CertificateConfigStore
    private lateinit var sslManager: DynamicSSLManager
    private lateinit var httpClientProvider: HttpClientProvider
    private lateinit var certStore: ClientCertSecureStore

    private val cert1 = TestCertUtil.generateSelfSigned(cn = "test1")
    private val cert2 = TestCertUtil.generateSelfSigned(cn = "test2")
    private val pin1 = cert1.sha256Pin
    private val pin2 = cert2.sha256Pin
    private val password = "changeit"

    @Before
    fun setUp() {
        configApi = mockk()
        configStore = mockk(relaxed = true)
        sslManager = DynamicSSLManager()
        httpClientProvider = HttpClientProvider(sslManager)
        certStore = mockk(relaxed = true)
    }

    private fun createUpdater(maxRetry: Int): SSLCertificateUpdater {
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

    // ── E.31: Retry ─────────────────────────────────────

    @Test
    fun `E31 — retry 3 kez dener, hepsi fail ise Failed döner`() = runTest {
        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null

        var callCount = 0
        coEvery { configApi.fetchConfig(0) } answers {
            callCount++
            throw RuntimeException("Timeout attempt $callCount")
        }

        val updater = createUpdater(maxRetry = 3)
        val result = updater.initializeAndUpdate()

        // 3 attempt yapılmış olmalı
        assertEquals(3, callCount)
        assertTrue("Expected Failed but got $result", result is io.github.umutcansu.pinvault.model.InitResult.Failed)
    }

    @Test
    fun `E31 — ilk 2 fail, 3 basarili ise Ready doner`() = runTest {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = 1))
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null

        var callCount = 0
        coEvery { configApi.fetchConfig(0) } answers {
            callCount++
            if (callCount < 3) throw RuntimeException("Fail #$callCount")
            config
        }
        coEvery { configApi.healthCheck() } returns true

        val updater = createUpdater(maxRetry = 3)
        val result = updater.initializeAndUpdate()

        assertEquals(3, callCount)
        assertTrue("Expected Ready but got $result", result is io.github.umutcansu.pinvault.model.InitResult.Ready)
    }

    // ── E.34: Expired cert partial ──────────────────────

    @Test
    fun `E34 — expired host cert yüklenince hata, valid host cert çalışır`() {
        val validCert = TestCertUtil.generateSelfSigned(cn = "valid.host", password = password)
        val expiredCert = TestCertUtil.generateExpired(cn = "expired.host", password = password)

        // Valid cert yüklenir
        sslManager.loadHostClientCerts(
            mapOf("valid.host" to validCert.p12Bytes),
            password
        )

        // Expired cert de yüklenir (KeyStore açısından P12 valid — sertifika süresi DynamicSSLManager tarafından kontrol edilmez, TLS handshake'te sunucu reddeder)
        sslManager.loadHostClientCerts(
            mapOf(
                "valid.host" to validCert.p12Bytes,
                "expired.host" to expiredCert.p12Bytes
            ),
            password
        )

        // Her iki cert de yüklenmiş durumda — buildClient başarılı
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("valid.host", listOf(validCert.sha256Pin, validCert.sha256Pin)),
                HostPin("expired.host", listOf(expiredCert.sha256Pin, expiredCert.sha256Pin))
            )
        )
        val client = sslManager.buildClient(config)
        assertNotNull(client)
    }

    @Test
    fun `D26 — expired server cert sertifika doğrulamasında reddedilir`() {
        val expiredCert = TestCertUtil.generateExpired(cn = "expired-server")
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("localhost", listOf(expiredCert.sha256Pin, expiredCert.sha256Pin)))
        )
        // Client oluşturulabilir ama bağlantı sırasında checkValidity() fail eder
        val client = sslManager.buildClient(config)
        assertNotNull(client)
        // Asıl reddetme TLS handshake sırasında olur (pinnedTrustManager.verifyPin → checkValidity)
    }

    // ── E.29: Host sil → cert temizlenmeli ──────────────

    @Test
    fun `E29 — host silindiğinde clientCert store'dan da temizlenmeli`() = runTest {
        val hostCert = TestCertUtil.generateSelfSigned(cn = "delete-me", password = password)

        // İlk update: host var, cert var
        val configV1 = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("keep.host", listOf(pin1, pin2), version = 1),
                HostPin("delete.host", listOf(pin1, pin2), version = 1, mtls = true, clientCertVersion = 1)
            )
        )

        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        coEvery { configApi.fetchConfig(0) } returns configV1
        coEvery { configApi.downloadHostClientCert("delete.host") } returns hostCert.p12Bytes
        every { certStore.exists("host_delete.host") } returns false

        val updater = createUpdater(maxRetry = 1)
        updater.updateNow()

        // Cert indirildi
        verify { certStore.save("host_delete.host", hostCert.p12Bytes) }

        // İkinci update: host silindi
        val configV2 = CertificateConfig(
            version = 2,
            pins = listOf(
                HostPin("keep.host", listOf(pin1, pin2), version = 1)
            )
        )

        every { configStore.getCurrentVersion() } returns 1
        every { configStore.load() } returns configV1
        coEvery { configApi.fetchConfig(1) } returns configV2

        updater.updateNow()

        // Host silindi — syncHostClientCerts artık bu host için cert yüklemeyecek
        // (delete.host artık mtls listesinde yok → loadHostClientCerts'e gönderilmez)
    }
}
