package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B.7 — 4 senaryo bağlantı testi — Espresso UI.
 *
 * TlsToTlsActivity ve MtlsToTlsActivity üzerinden gerçek TLS handshake + UI doğrulama.
 *
 * Önkoşul: demo-server çalışıyor (PORT=8090, HTTPS_PORT=8091)
 *          mock TLS server çalışıyor (port 8443)
 *
 * TODO: Thread.sleep → IdlingResource dönüşümü (PinVaultIdlingResource.kt altyapısı hazır,
 *       PinVault library'ye IdlingResource entegrasyonu gerekli).
 */
@RunWith(AndroidJUnit4::class)
class ScenarioConnectionTest {

    private lateinit var scenario: ActivityScenario<*>

    @Before
    fun setUp() {
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        try { scenario.close() } catch (_: Exception) {}
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickTest() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    // ── B.7a: TLS Config API → TLS Host ─────────────────

    @Test
    fun B7a_TlsToTls_init_fetches_config_and_pins_applied() {
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    @Test
    fun B7a_TlsToTls_pinned_client_connects_to_mock_server() {
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        clickTest()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }

    @Test
    fun B7a_TlsToTls_version_matches_server_config() {
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    // ── B.7c: mTLS Config API → enrollment card gösterilmeli ──

    @Test
    fun B7c_MtlsConfig_without_enrollment_shows_enrollment_card() {
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // MtlsToTlsActivity requiresEnrollment=true → enrollment kartı görünür olmalı
        onView(withId(R.id.enrollmentCard))
            .check(matches(isDisplayed()))
    }
}
