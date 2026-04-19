package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.13 — Pin mismatch recovery Espresso testleri.
 *
 * Test 1: Yanlış pin ile programmatik init → Failed
 * Test 2: TlsToTlsActivity doğru pinlerle açılır → Ready + bağlantı 200
 *         (yanlış pin sonrası recovery senaryosu)
 */
@RunWith(AndroidJUnit4::class)
class PinMismatchRecoveryTest {

    @get:org.junit.Rule
    val qaScreenshots = QaScreenshotRule()

    private var scenario: ActivityScenario<TlsToTlsActivity>? = null

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        qaScreenshots.capture("final")
        try { scenario?.close() } catch (_: Exception) {}
        try { PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickTest() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    // ── B.13: Wrong pin → failure ───────────────────────

    @Test
    fun B13_wrong_pin_causes_ssl_failure() {
        // Yanlış pin ile programmatik init — Activity açmadan
        val wrongPin = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val latch = CountDownLatch(1)
        var initResult: InitResult? = null

        val config = PinVaultConfig.Builder()
            .configApi("default", TestConfig.TLS_CONFIG_URL) {
                bootstrapPins(listOf(HostPin(TestConfig.HOST_IP, listOf(wrongPin, wrongPin))))
                configEndpoint("api/v1/certificate-config?signed=false")
            }
            .maxRetryCount(1)
            .build()

        PinVault.init(context, config) {
            initResult = it
            latch.countDown()
        }
        latch.await(10, TimeUnit.SECONDS)

        assertTrue(
            "Init with wrong pin should fail: $initResult",
            initResult is InitResult.Failed
        )

        // Yanlış pin sonrası Activity aç — "Failed" durumu görünmeli
        PinVault.reset()
        Thread.sleep(500)

        // Tekrar yanlış pinle init → Activity Failed gösterecek
        PinVault.init(context, config) { latch.countDown() }
        Thread.sleep(5000)

        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // TlsToTlsActivity doğru pinlerle init eder → recovery → Ready
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ── B.13: Recovery with correct pins ────────────────

    @Test
    fun B13_recovery_after_correct_reinit() {
        // ── 1) ÖNCE: Activity açılır, sunucudan v1 pin cache'lenir, Ready. ─
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        qaScreenshots.capture("before-rotation")

        // ── 2) AKSİYON: Admin API ile canlı cert rotate et — mockServerManager
        //       8444 portundaki mock host'u yeni cert ile yeniden başlatır.
        //       Cihazın cache'indeki v1 pin artık geçersiz; gerçek saha senaryosu. ─
        rotateServerCert(TestConfig.HOST_IP)
        Thread.sleep(3000) // mock host restart + TCP socket reset
        qaScreenshots.capture("cert-rotated")

        // ── 3) KANITLAYICI: TEST CONNECTION → cache v1 pin × cert v2 → SSL
        //       mismatch → PinRecoveryInterceptor → fetch v2 config → retry → 200 ─
        qaScreenshots.capture("button-click")
        clickTest()

        // ── 4) SONRA: Recovery başarılı — 200 OK. ─
        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }

    /** Management API üzerinden host cert'ini rotate eder (v1 → v2). */
    private fun rotateServerCert(hostname: String) {
        // Mock host restart ~3s sürdüğü için admin client'ın 3s readTimeout'unu bypass edip
        // bu çağrı için ayrı uzun-timeout client kuruyoruz.
        val client = okhttp3.OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .addInterceptor { chain ->
                chain.proceed(chain.request().newBuilder()
                    .header("X-API-Key", TestConfig.ADMIN_API_KEY)
                    .build())
            }
            .build()
        val req = Request.Builder()
            .url("${TestConfig.MANAGEMENT_URL}/api/v1/hosts/$hostname/regenerate-cert")
            .header("X-Scope", "default")
            .post("".toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(req).execute().use { resp ->
            assertTrue("regenerate-cert 2xx olmalı: ${resp.code} ${resp.body?.string()}", resp.isSuccessful)
        }
    }

    /**
     * Local pin cache'i doğrudan EncryptedSharedPreferences üzerinden bozar —
     * [hostname] için mevcut pin hash'lerini yanlış değerle değiştirir.
     * (Rotation tabanlı testte artık kullanılmıyor; ileride gerekebilir diye korunur.)
     */
    @Suppress("unused")
    private fun poisonCachedPin(hostname: String) {
        val masterKey = androidx.security.crypto.MasterKey.Builder(context)
            .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM)
            .build()
        val prefs = androidx.security.crypto.EncryptedSharedPreferences.create(
            context, "ssl_cert_config_default", masterKey,
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        val existing = prefs.getString("config_pins", "") ?: ""
        val wrong = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val poisoned = existing.split("\n").joinToString("\n") { line ->
            val parts = line.split("|")
            if (parts.size >= 3 && parts[0] == hostname) {
                "${parts[0]}|${parts[1]}|$wrong,$wrong"
            } else line
        }
        prefs.edit().putString("config_pins", poisoned).apply()
    }
}
