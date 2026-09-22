package io.github.umutcansu.pinvault.ssl

import com.google.gson.Gson
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * L-1 regression: `ConfigApiBlock.wantPinsFor(...)` must actually reach the
 * server. The setting was stored on the block and `fetchScopedConfig` existed,
 * but the updater always called the unscoped `fetchConfig`, so the server never
 * saw `?hosts=` / `X-Device-Id` and always returned the full pin set.
 *
 * These tests go through the real [DefaultCertificateConfigApi] against a
 * [MockWebServer] so the assertion is on the actual wire request.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ScopedConfigFetchTest {

    private lateinit var server: MockWebServer
    private lateinit var configStore: CertificateConfigStore
    private lateinit var certStore: ClientCertSecureStore
    private val gson = Gson()

    private val certA = TestCertUtil.generateSelfSigned(cn = "a.example.com")
    private val certB = TestCertUtil.generateSelfSigned(cn = "b.example.com")

    private val deviceId = "androidid-deadbeef01234567"

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        configStore = mockk(relaxed = true)
        certStore = mockk(relaxed = true)
        every { configStore.getCurrentVersion() } returns 0
        every { configStore.getCurrentIssuedAt() } returns 0L
        every { configStore.load() } returns null
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    /** Unsigned config API — the block under test opts out via allowUnsigned(). */
    private fun api(): DefaultCertificateConfigApi {
        val sslManager = mockk<DynamicSSLManager>()
        every { sslManager.buildBootstrapClient(any()) } returns OkHttpClient()
        return DefaultCertificateConfigApi(
            configUrl = server.url("/").toString(),
            signaturePublicKey = null,
            bootstrapPins = listOf(HostPin("a.example.com", listOf(certA.sha256Pin, certB.sha256Pin))),
            sslManager = sslManager
        )
    }

    private fun updater(
        wantPinsFor: List<String>,
        deviceId: String? = this.deviceId
    ): SSLCertificateUpdater {
        val sslManager = DynamicSSLManager()
        return SSLCertificateUpdater(
            context = mockk(relaxed = true),
            configApi = api(),
            configStore = configStore,
            httpClientProvider = HttpClientProvider(sslManager),
            sslManager = sslManager,
            certStore = certStore,
            clientKeyPassword = "changeit",
            maxRetryCount = 1,
            wantPinsFor = wantPinsFor,
            deviceIdProvider = { deviceId }
        )
    }

    private fun enqueueConfig() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("a.example.com", listOf(certA.sha256Pin, certB.sha256Pin), version = 1)
            )
        )
        server.enqueue(MockResponse().setBody(gson.toJson(config)))
    }

    @Test
    fun `wantPinsFor dolu ise istek hosts query ve X-Device-Id header tasir`() = runTest {
        enqueueConfig()

        val result = updater(listOf("a.example.com", "b.example.com")).updateNow()
        assertTrue("update should succeed, got $result", result is UpdateResult.Updated)

        val request = server.takeRequest()
        val url = request.requestUrl!!

        // Comma-joined host list — Retrofit URL-encodes the comma, so assert
        // on the decoded query value rather than the raw path.
        assertEquals("a.example.com,b.example.com", url.queryParameter("hosts"))
        assertEquals(deviceId, request.getHeader("X-Device-Id"))
        // currentVersion is still forwarded alongside the scoping params.
        assertEquals("0", url.queryParameter("currentVersion"))
    }

    @Test
    fun `wantPinsFor bos ise legacy istek atilir - hosts ve X-Device-Id yok`() = runTest {
        enqueueConfig()

        val result = updater(emptyList()).updateNow()
        assertTrue(result is UpdateResult.Updated)

        val request = server.takeRequest()
        assertNull(request.requestUrl!!.queryParameter("hosts"))
        assertNull(request.getHeader("X-Device-Id"))
    }

    @Test
    fun `deviceId cozulemezse hosts yine gonderilir, header atlanir`() = runTest {
        enqueueConfig()

        val result = updater(listOf("a.example.com"), deviceId = null).updateNow()
        assertTrue(result is UpdateResult.Updated)

        val request = server.takeRequest()
        assertEquals("a.example.com", request.requestUrl!!.queryParameter("hosts"))
        assertNull(request.getHeader("X-Device-Id"))
    }
}
