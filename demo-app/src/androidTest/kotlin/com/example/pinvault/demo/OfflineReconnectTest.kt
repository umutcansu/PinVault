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
 * B.14 — Stored config persistence Espresso testleri.
 *
 * İlk init sonrası config kaydedilir, UI'da "Ready" + version gösterilir.
 * btnUpdate ile updateNow tetiklenir, sonuç ekranda doğrulanır.
 *
 * TlsToTlsActivity üzerinden.
 */
@RunWith(AndroidJUnit4::class)
class OfflineReconnectTest {

    private lateinit var scenario: ActivityScenario<TlsToTlsActivity>

    @Before
    fun setUp() {
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)
    }

    @After
    fun tearDown() {
        try { scenario.close() } catch (_: Exception) {}
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickUpdate() {
        onView(withId(R.id.btnUpdate)).perform(click())
        Thread.sleep(6000)
    }

    // ── B.14: Stored config ─────────────────────────────

    @Test
    fun B14_stored_config_persists_after_init() {
        // Init Ready — config stored
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Version > 0 — tvVersion görünür olmalı
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    @Test
    fun B14_updateNow_with_reachable_server_succeeds() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        clickUpdate()

        // Update sonucu tvResult'ta görünmeli
        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))

        // Log'da update kaydı
        onView(withId(R.id.logContainer))
            .check(matches(hasMinimumChildCount(2)))
    }

    @Test
    fun B14_updateNow_returns_result_after_stored_config() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // İlk update — stored config var, sunucu erişilebilir
        clickUpdate()

        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))

        // İkinci update — hâlâ çalışmalı
        clickUpdate()

        onView(withId(R.id.logContainer))
            .check(matches(hasMinimumChildCount(3)))
    }
}
