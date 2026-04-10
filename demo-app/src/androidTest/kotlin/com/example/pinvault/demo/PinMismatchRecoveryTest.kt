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

        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(listOf(HostPin(TestConfig.HOST_IP, listOf(wrongPin, wrongPin))))
            .configEndpoint("api/v1/certificate-config?signed=false")
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
        // Doğru pinlerle Activity aç
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // Ready — doğru pinlerle init başarılı
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Pinned client ile bağlantı
        clickTest()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }
}
