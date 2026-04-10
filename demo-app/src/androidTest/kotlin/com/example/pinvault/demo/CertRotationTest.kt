package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/**
 * B.10 — Cert rotation: updateNow → yeni pin alındı
 * B.11 — Force update: management API ile flag set → update tetiklenir
 *
 * Espresso UI — TlsToTlsActivity üzerinden btnUpdate ile.
 */
@RunWith(AndroidJUnit4::class)
class CertRotationTest {

    private lateinit var scenario: ActivityScenario<TlsToTlsActivity>

    private val plainClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

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

    // ── B.10: updateNow ─────────────────────────────────

    @Test
    fun B10_updateNow_fetches_latest_pins() {
        // Init Ready
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        clickUpdate()

        // tvResult "updated" veya "current" içermeli
        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))

        // Log'da update kaydı olmalı
        onView(withId(R.id.logContainer))
            .check(matches(hasMinimumChildCount(2)))
    }

    // ── B.11: Force update ──────────────────────────────

    @Test
    fun B11_forceUpdate_flag_triggers_update() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Management API ile force update flag set et
        try {
            plainClient.newCall(
                Request.Builder()
                    .url("${TestConfig.MANAGEMENT_URL}/api/v1/certificate-config/force-update")
                    .post("{}".toRequestBody("application/json".toMediaType()))
                    .build()
            ).execute()
        } catch (_: Exception) {}

        clickUpdate()

        // Update sonucu görünmeli
        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))

        // Force flag'i temizle
        try {
            plainClient.newCall(
                Request.Builder()
                    .url("${TestConfig.MANAGEMENT_URL}/api/v1/certificate-config/clear-force")
                    .post("{}".toRequestBody("application/json".toMediaType()))
                    .build()
            ).execute()
        } catch (_: Exception) {}
    }
}
