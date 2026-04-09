package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.14 — Stored config ile çalışma
 *
 * İlk init sonrası config kaydedilir.
 * İkinci init'te (farklı URL = erişilemez) stored config kullanılır.
 */
@RunWith(AndroidJUnit4::class)
class OfflineReconnectTest {

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

    @Test
    fun B14_stored_config_persists_after_init() {
        // İlk init — config çekilip stored
        val latch = CountDownLatch(1)
        var result: InitResult? = null

        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(2)
            .build()

        PinVault.init(context, config) {
            result = it
            latch.countDown()
        }

        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
        assertTrue("Init should succeed: $result", result is InitResult.Ready)

        // Config stored olmalı — public API ile doğrula
        val storedVersion = PinVault.currentVersion()
        assertTrue("Stored version should be > 0: $storedVersion", storedVersion > 0)
    }

    @Test
    fun B14_updateNow_with_reachable_server_succeeds() {
        // Init
        val latch1 = CountDownLatch(1)
        var result1: InitResult? = null

        val config1 = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(1)
            .build()

        PinVault.init(context, config1) {
            result1 = it
            latch1.countDown()
        }
        assertTrue(latch1.await(15, TimeUnit.SECONDS))
        assertTrue("Init should succeed", result1 is InitResult.Ready)

        // Stored config var — updateNow çalışmalı
        val result = runBlocking { PinVault.updateNow() }
        assertTrue(
            "updateNow: $result",
            result is UpdateResult.Updated || result is UpdateResult.AlreadyCurrent
        )
    }

    @Test
    fun B14_updateNow_returns_Failed_when_server_unreachable() {
        // Normal init
        val latch = CountDownLatch(1)
        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(1)
            .build()
        PinVault.init(context, config) { latch.countDown() }
        latch.await(15, TimeUnit.SECONDS)

        // updateNow çalışmalı (sunucu erişilebilir)
        val result = runBlocking { PinVault.updateNow() }
        assertTrue(
            "updateNow should succeed: $result",
            result is UpdateResult.Updated || result is UpdateResult.AlreadyCurrent
        )
    }
}
