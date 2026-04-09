package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
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
 * mTLS Config API (port 8092) senaryoları.
 *
 * Token-based enrollment kullanır — güvenli akış:
 *   1. Management API'den enrollment token üret
 *   2. Token ile PinVault.enroll() çağır → client cert al
 *   3. mTLS Config API'ye client cert ile bağlan
 *
 * Önkoşul:
 *   - demo-server management    :8090
 *   - mTLS Config API           :8092  (mode=mtls)
 *   - TLS Config API            :8091  (enrollment için)
 *   - Mock TLS Host             :8443
 */
@RunWith(AndroidJUnit4::class)
class MtlsConfigApiTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val mtlsConfigUrl = TestConfig.MTLS_CONFIG_URL
    private val tlsConfigUrl = TestConfig.TLS_CONFIG_URL
    private val tlsHostUrl = TestConfig.TLS_HOST_URL

    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        PinVault.unenroll(context)
    }

    @After
    fun tearDown() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    private fun initWith(url: String, retries: Int = 1): InitResult {
        var lastResult: InitResult? = null
        for (attempt in 1..retries) {
            val latch = CountDownLatch(1)
            var result: InitResult? = null
            val config = PinVaultConfig.Builder(url)
                .bootstrapPins(bootstrapPins)
                .configEndpoint("api/v1/certificate-config?signed=false")
                .maxRetryCount(1)
                .build()
            PinVault.init(context, config) { result = it; latch.countDown() }
            assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
            lastResult = result!!
            if (lastResult is InitResult.Ready || attempt == retries) break
            try { PinVault.reset() } catch (_: Exception) {}
            Thread.sleep(2000)
        }
        return lastResult!!
    }

    /**
     * Management API'den enrollment token üretir.
     * Güvenli enrollment akışının ilk adımı.
     */
    private fun generateEnrollmentToken(): String {
        val clientId = "test-${System.currentTimeMillis()}"
        val resp = TestConfig.plainClient.newCall(
            Request.Builder()
                .url("${TestConfig.MANAGEMENT_URL}/api/v1/enrollment-tokens/generate")
                .post("""{"clientId":"$clientId"}""".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        assertTrue("Token üretme başarılı olmalı: ${resp.code}", resp.isSuccessful)
        val body = resp.body?.string() ?: ""
        return Regex(""""token":"([^"]+)"""").find(body)?.groupValues?.get(1)
            ?: throw AssertionError("Token parse edilemedi: $body")
    }

    /**
     * Token-based enrollment — güvenli akış.
     * Management API'den token üretir, PinVault.enroll() ile kayıt olur.
     */
    private fun enrollWithToken(): Boolean {
        val token = generateEnrollmentToken()
        return runBlocking { PinVault.enroll(context, token) }
    }

    // ─── mTLS Config API — enrollment olmadan reddedilir ─

    @Test
    fun mtlsConfig_without_enrollment_fails() {
        val result = initWith(mtlsConfigUrl)

        assertTrue(
            "mTLS Config API cert olmadan reddetmeli, got: $result",
            result is InitResult.Failed
        )

        val reason = (result as InitResult.Failed).reason
        assertTrue(
            "Hata SSL/bağlantı ile ilgili olmalı: $reason",
            reason.contains("SSL", ignoreCase = true) ||
            reason.contains("handshake", ignoreCase = true) ||
            reason.contains("CERTIFICATE", ignoreCase = true) ||
            reason.contains("Connection", ignoreCase = true) ||
            reason.contains("unreachable", ignoreCase = true)
        )
    }

    // ─── mTLS Config API — token enrollment sonrası ─────

    @Test
    fun mtlsConfig_after_enrollment_init_succeeds() {
        val tlsInit = initWith(tlsConfigUrl)
        assertTrue("TLS init: $tlsInit", tlsInit is InitResult.Ready)

        assertTrue("Token enrollment başarılı olmalı", enrollWithToken())
        assertTrue("Enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()

        PinVault.reset()
        val mtlsInit = initWith(mtlsConfigUrl, retries = 3)
        assertTrue("mTLS Config API cert ile çalışmalı: $mtlsInit", mtlsInit is InitResult.Ready)
    }

    // ─── mTLS Config API → TLS Host ────────────────────

    @Test
    fun mtlsConfig_to_tlsHost_returns_200() {
        val tlsInit = initWith(tlsConfigUrl)
        assertTrue(tlsInit is InitResult.Ready)
        assertTrue("Enroll", enrollWithToken())

        TestConfig.waitForMtlsRestart()

        PinVault.reset()
        val init = initWith(mtlsConfigUrl, retries = 3)
        assertTrue("Init: $init", init is InitResult.Ready)

        val response = PinVault.getClient().newCall(Request.Builder().url(tlsHostUrl).build()).execute()
        assertEquals("TLS host 200 dönmeli", 200, response.code)
    }

    // ─── mTLS Config API → enrollment korunuyor ─────

    @Test
    fun mtlsConfig_enrollment_persists_after_reinit() {
        val tlsInit = initWith(tlsConfigUrl)
        assertTrue(tlsInit is InitResult.Ready)
        assertTrue("Enroll", enrollWithToken())
        assertTrue("Enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()

        PinVault.reset()
        val init = initWith(mtlsConfigUrl, retries = 3)
        assertTrue("Init: $init", init is InitResult.Ready)

        assertTrue("Enrollment mTLS reinit sonrası korunmalı", PinVault.isEnrolled(context))
    }

    // ─── Unenroll sonrası mTLS Config API reddeder ──────

    @Test
    fun mtlsConfig_unenroll_then_init_fails() {
        val tlsInit = initWith(tlsConfigUrl)
        assertTrue(tlsInit is InitResult.Ready)
        assertTrue(enrollWithToken())

        PinVault.unenroll(context)
        assertFalse("Unenroll sonrası false", PinVault.isEnrolled(context))

        PinVault.reset()
        val result = initWith(mtlsConfigUrl)
        assertTrue("Unenroll sonrası reddedilmeli: $result", result is InitResult.Failed)
    }

    // ─── Re-enrollment: unenroll → yeni token → tekrar mTLS ─

    @Test
    fun mtlsConfig_reenroll_after_unenroll_works() {
        // 1. İlk enrollment
        val tlsInit = initWith(tlsConfigUrl)
        assertTrue("TLS init: $tlsInit", tlsInit is InitResult.Ready)
        assertTrue("İlk enrollment", enrollWithToken())
        assertTrue("Enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()

        // 2. mTLS çalışıyor
        PinVault.reset()
        val firstMtls = initWith(mtlsConfigUrl, retries = 3)
        assertTrue("İlk mTLS init: $firstMtls", firstMtls is InitResult.Ready)

        // 3. Unenroll — sertifika siliniyor
        PinVault.unenroll(context)
        assertFalse("Unenroll sonrası false", PinVault.isEnrolled(context))

        // 4. Yeni token ile tekrar enrollment
        PinVault.reset()
        val tlsInit2 = initWith(tlsConfigUrl)
        assertTrue("TLS re-init: $tlsInit2", tlsInit2 is InitResult.Ready)
        assertTrue("Re-enrollment", enrollWithToken())
        assertTrue("Re-enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()

        // 5. mTLS tekrar çalışıyor
        PinVault.reset()
        val secondMtls = initWith(mtlsConfigUrl, retries = 3)
        assertTrue("Re-enrollment sonrası mTLS çalışmalı: $secondMtls", secondMtls is InitResult.Ready)
    }
}
