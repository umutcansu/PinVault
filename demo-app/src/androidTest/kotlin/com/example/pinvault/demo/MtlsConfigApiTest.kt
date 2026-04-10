package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * mTLS Config API (port 8092) Espresso UI testleri.
 *
 * MtlsToTlsActivity üzerinden:
 *   - Enrollment olmadan → "Enrollment required"
 *   - Token enrollment → init → "Ready"
 *   - btnTest → TLS host bağlantısı → 200
 *   - Enrollment persistence, unenroll, re-enroll
 *
 * Enrollment helper metotları programmatik (Management API token üretimi).
 * Activity UI ile doğrulama.
 */
@RunWith(AndroidJUnit4::class)
class MtlsConfigApiTest {

    private var scenario: ActivityScenario<MtlsToTlsActivity>? = null

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        try { PinVault.unenroll(context) } catch (_: Exception) {}
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        try { scenario?.close() } catch (_: Exception) {}
        try { PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickTest() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    /**
     * Management API'den enrollment token üretir.
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
     * TLS Config API üzerinden enrollment yapar (programmatik).
     * MtlsToTlsActivity UI'ı kullanmadan — hızlı enrollment helper.
     */
    private fun enrollProgrammatically() {
        // TLS init for enrollment
        val latch = CountDownLatch(1)
        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(1)
            .build()
        PinVault.init(context, config) { latch.countDown() }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))

        val token = generateEnrollmentToken()
        val enrolled = runBlocking { PinVault.enroll(context, token) }
        assertTrue("Enrollment başarılı olmalı", enrolled)
        assertTrue("Enrolled olmalı", PinVault.isEnrolled(context))

        TestConfig.waitForMtlsRestart()
        PinVault.reset()
        Thread.sleep(500)
    }

    // ─── mTLS — enrollment olmadan → reddedilir ─────────

    @Test
    fun mtlsConfig_without_enrollment_fails() {
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // MtlsToTlsActivity requiresEnrollment=true → enrollment olmadan ready olmaz
        onView(withId(R.id.tvStatus))
            .check(matches(not(withText(containsString("✓")))))
        onView(withId(R.id.enrollmentCard))
            .check(matches(isDisplayed()))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✗"))))
    }

    // ─── mTLS — enrollment sonrası init succeeds ────────

    @Test
    fun mtlsConfig_after_enrollment_init_succeeds() {
        enrollProgrammatically()

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(15000)

        // Enrollment var → Activity init eder → Ready
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ─── mTLS → TLS Host → 200 ─────────────────────────

    @Test
    fun mtlsConfig_to_tlsHost_returns_200() {
        enrollProgrammatically()

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(15000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        clickTest()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }

    // ─── mTLS — enrollment reinit sonrası korunuyor ─────

    @Test
    fun mtlsConfig_enrollment_persists_after_reinit() {
        enrollProgrammatically()

        // İlk launch
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(15000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Kapat
        scenario!!.close()
        PinVault.reset()
        Thread.sleep(500)

        // Tekrar launch — enrollment persist etmiş olmalı
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(15000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ─── Unenroll → mTLS reddeder ──────────────────────

    @Test
    fun mtlsConfig_unenroll_then_init_fails() {
        enrollProgrammatically()

        // Enrolled durumu doğrula
        assertTrue(PinVault.isEnrolled(context))

        // Unenroll
        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))

        // Activity aç — enrollment yok → "Enrollment required"
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(not(withText(containsString("✓")))))
    }

    // ─── Re-enrollment çalışır ──────────────────────────

    @Test
    fun mtlsConfig_reenroll_after_unenroll_works() {
        // İlk enrollment
        enrollProgrammatically()

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(15000)
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Unenroll
        scenario!!.close()
        PinVault.unenroll(context)
        PinVault.reset()
        Thread.sleep(500)

        assertFalse(PinVault.isEnrolled(context))

        // Re-enrollment
        enrollProgrammatically()
        Thread.sleep(2000) // allow re-enrollment to settle on physical devices

        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(18000) // physical device needs more time for mTLS init

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }
}
