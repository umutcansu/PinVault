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
 * B.15 — PinVault reset + reinit Espresso testleri.
 *
 * Activity geçişi simülasyonu — Activity aç/kapat/tekrar aç.
 * TlsToTlsActivity üzerinden.
 */
@RunWith(AndroidJUnit4::class)
class ActivityTransitionTest {

    private var scenario: ActivityScenario<TlsToTlsActivity>? = null

    @Before
    fun setUp() {
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
    }

    @After
    fun tearDown() {
        try { scenario?.close() } catch (_: Exception) {}
        try { io.github.umutcansu.pinvault.PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickUpdate() {
        onView(withId(R.id.btnUpdate)).perform(click())
        Thread.sleep(6000)
    }

    // ── B.15: Reset → state temizlenir ──────────────────

    @Test
    fun B15_reset_clears_state_completely() {
        // İlk Activity aç — Ready
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Activity kapat + PinVault reset
        scenario!!.close()
        io.github.umutcansu.pinvault.PinVault.reset()
        Thread.sleep(500)

        // Tekrar Activity aç — yeniden init edilmeli
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }

    // ── B.15: Reinit after reset ────────────────────────

    @Test
    fun B15_reinit_after_reset_works() {
        // İlk Activity
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Kapat + reset
        scenario!!.close()
        io.github.umutcansu.pinvault.PinVault.reset()
        Thread.sleep(500)

        // Yeniden aç
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    // ── B.15: Double init idempotent ────────────────────

    @Test
    fun B15_double_init_without_reset_is_idempotent() {
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))

        // btnUpdate ile updateNow() — state bozulmamalı
        clickUpdate()

        // Version hâlâ görünür — crash yok
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }
}
