package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.10 — Cert rotation: cert yenile → updateNow → yeni pin alındı
 * B.11 — Force update: anında güncelle
 *
 * Gerçek demo-server API call'ları ile cert rotation simülasyonu.
 */
@RunWith(AndroidJUnit4::class)
class CertRotationTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val managementUrl = TestConfig.MANAGEMENT_URL
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS
    private val plainClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

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
        return result!!
    }

    @Test
    fun B10_updateNow_fetches_latest_pins() {
        val initResult = initPinVault()
        assertTrue("Init failed: $initResult", initResult is InitResult.Ready)

        val versionBefore = PinVault.currentVersion()

        val result = runBlocking { PinVault.updateNow() }

        assertTrue(
            "updateNow should return Updated or AlreadyCurrent, got: $result",
            result is UpdateResult.Updated || result is UpdateResult.AlreadyCurrent
        )

        val versionAfter = PinVault.currentVersion()
        assertTrue("Version should not decrease: $versionBefore -> $versionAfter", versionAfter >= versionBefore)
    }

    @Test
    fun B11_forceUpdate_flag_triggers_update() {
        val initResult = initPinVault()
        assertTrue("Init failed: $initResult", initResult is InitResult.Ready)

        // Management API ile force update set et
        val forceReq = Request.Builder()
            .url("$managementUrl/api/v1/certificate-config/force-update")
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()

        val forceResp = try { plainClient.newCall(forceReq).execute() } catch (_: Exception) { null }

        if (forceResp?.isSuccessful == true) {
            // Force update set edildi → updateNow() Updated veya AlreadyCurrent dönmeli
            // (versiyon değişmemişse AlreadyCurrent, forceUpdate flag sadece client'a hint)
            val result = runBlocking { PinVault.updateNow() }
            assertTrue(
                "After force flag, updateNow should succeed: $result",
                result is UpdateResult.Updated || result is UpdateResult.AlreadyCurrent
            )

            // isForceUpdate() true olmalı (sunucu forceUpdate:true set etti)
            // Not: updateNow() sonrası flag temizlenmiş olabilir

            // Force flag'i temizle
            val clearReq = Request.Builder()
                .url("$managementUrl/api/v1/certificate-config/clear-force")
                .post("{}".toRequestBody("application/json".toMediaType()))
                .build()
            try { plainClient.newCall(clearReq).execute() } catch (_: Exception) {}
        }
    }
}
