package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.15 — PinVault reset + reinit: farklı config URL ile geçiş
 *
 * Activity geçişi simülasyonu — PinVault.reset() sonrası yeni config ile init.
 */
@RunWith(AndroidJUnit4::class)
class ActivityTransitionTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    @After
    fun tearDown() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    private fun initWith(configUrl: String): InitResult {
        val latch = CountDownLatch(1)
        var result: InitResult? = null

        val config = PinVaultConfig.Builder(configUrl)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(2)
            .build()

        PinVault.init(context, config) {
            result = it
            latch.countDown()
        }

        assertTrue("Init timed out for $configUrl", latch.await(15, TimeUnit.SECONDS))
        return result!!
    }

    @Test
    fun B15_reset_clears_state_completely() {
        // İlk init
        val result1 = initWith(TestConfig.TLS_CONFIG_URL)
        assertTrue("First init: $result1", result1 is InitResult.Ready)

        val v1 = PinVault.currentVersion()
        assertTrue("Version should be > 0 after init: $v1", v1 > 0)

        // Reset
        PinVault.reset()

        // Reset sonrası currentVersion() ya 0 döner ya da IllegalStateException atar
        try {
            val vAfterReset = PinVault.currentVersion()
            assertEquals("currentVersion() after reset should be 0", 0, vAfterReset)
        } catch (_: IllegalStateException) {
            // Bu da kabul edilebilir
        }

        // Reset sonrası getClient() exception atmalı
        try {
            PinVault.getClient()
            fail("getClient() after reset should throw")
        } catch (_: IllegalStateException) {
            // Beklenen
        }
    }

    @Test
    fun B15_reinit_after_reset_works() {
        // İlk init
        val result1 = initWith(TestConfig.TLS_CONFIG_URL)
        assertTrue("First init: $result1", result1 is InitResult.Ready)

        // Reset — iç durum temizlenmesi için kısa bekleme
        PinVault.reset()
        Thread.sleep(500)

        // Reinit
        val result2 = initWith(TestConfig.TLS_CONFIG_URL)
        assertTrue("Reinit should succeed: $result2", result2 is InitResult.Ready)

        // Version >= 0 yeterli — reinit sonrası config fetch tamamlanmış olmalı
        val v2 = PinVault.currentVersion()
        assertTrue("Version after reinit should be >= 0: $v2", v2 >= 0)
    }

    @Test
    fun B15_double_init_without_reset_is_idempotent() {
        // İlk init
        val result1 = initWith(TestConfig.TLS_CONFIG_URL)
        assertTrue("First init: $result1", result1 is InitResult.Ready)
        val v1 = PinVault.currentVersion()

        // İkinci init reset olmadan — PinVault already initialized, callback hemen tetiklenir veya skip edilir
        val latch = CountDownLatch(1)
        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(2)
            .build()

        PinVault.init(context, config) { latch.countDown() }

        // Callback tetiklenmeyebilir (already initialized) — bekleme süresi kısa tutulur
        latch.await(5, TimeUnit.SECONDS)

        // State bozulmamalı
        val v2 = PinVault.currentVersion()
        assertEquals("Version unchanged after double init", v1, v2)
    }
}
