package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import okhttp3.Request
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * TLS Config API (port 8091) senaryoları.
 *
 * Önkoşul — hepsi çalışıyor OLMALI:
 *   - demo-server management  :8090
 *   - TLS Config API          :8091
 *   - Mock TLS Host           :8443
 *   - Remote mTLS Host        HOST_IP:9443
 *   - Config'te 192.168.1.217 mtls:true, clientCertVersion:1
 */
@RunWith(AndroidJUnit4::class)
class TlsConfigApiTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val configUrl = TestConfig.TLS_CONFIG_URL
    private val tlsHostUrl = TestConfig.TLS_HOST_URL
    private val remoteMtlsHostUrl = TestConfig.MTLS_HOST_URL

    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    @After
    fun tearDown() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    private fun initPinVault(): InitResult {
        val latch = CountDownLatch(1)
        var result: InitResult? = null
        val config = PinVaultConfig.Builder(configUrl)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(2)
            .build()
        PinVault.init(context, config) { result = it; latch.countDown() }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
        return result!!
    }

    // ─── TLS Config API → TLS Host ─────────────────────

    @Test
    fun tlsConfig_init_succeeds() {
        val result = initPinVault()
        assertTrue("Init should be Ready, got: $result", result is InitResult.Ready)
        assertTrue("Version > 0", PinVault.currentVersion() > 0)
    }

    @Test
    fun tlsConfig_tlsHost_returns_200() {
        val init = initPinVault()
        assertTrue("Init: $init", init is InitResult.Ready)

        val client = PinVault.getClient()
        val response = client.newCall(Request.Builder().url(tlsHostUrl).build()).execute()

        assertEquals("TLS host must return 200", 200, response.code)
        val body = response.body?.string() ?: ""
        assertTrue("Response body not empty", body.isNotEmpty())
        // Mock server health endpoint JSON dönmeli
        assertTrue("Response is JSON", body.contains("{") && body.contains("}"))
    }

    @Test
    fun tlsConfig_tlsHost_response_has_tls_info() {
        initPinVault()
        val client = PinVault.getClient()
        val body = client.newCall(Request.Builder().url(tlsHostUrl).build()).execute().body?.string() ?: ""

        assertTrue("serverCertPin mevcut", body.contains("serverCertPin"))
        assertTrue("tls:true", body.contains("\"tls\":true"))
        assertTrue("mtls:false", body.contains("\"mtls\":false"))
    }

    // ─── TLS Config API → mTLS Host cert güvenlik kısıtlaması ────────
    //
    // Host client cert download sadece mTLS Config API üzerinden sunulur.
    // TLS Config API'den host cert indirilmez — güvenlik gereği.
    // Tam akış: enroll → mTLS Config API → host cert auto-download.

    @Test
    fun tlsConfig_hostCert_not_downloaded_on_tls_api() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        // TLS Config API üzerinden host client cert download engellendi (403)
        // Bu güvenlik kısıtlaması: host cert'ler sadece mTLS API'den sunulur
        assertFalse(
            "TLS Config API üzerinden host cert indirilmemeli",
            PinVault.isEnrolled(context, TestConfig.MTLS_HOST_CERT_LABEL)
        )
    }

    @Test
    fun tlsConfig_hostCert_unenroll_is_noop_on_tls() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        // TLS API'de host cert yok — unenroll hata vermemeli
        PinVault.unenroll(context, TestConfig.MTLS_HOST_CERT_LABEL)
        assertFalse(PinVault.isEnrolled(context, TestConfig.MTLS_HOST_CERT_LABEL))
    }
}
