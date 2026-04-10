package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS Config API (port 8091) Espresso UI testleri.
 *
 * TlsToTlsActivity üzerinden:
 *   - Init → Ready durumu
 *   - btnTest → TLS host bağlantısı → 200 + TLS bilgisi
 *   - Host cert TLS API'den indirilmez
 *
 * Önkoşul:
 *   - demo-server management  :8090
 *   - TLS Config API          :8091
 *   - Mock TLS Host           :8443
 */
@RunWith(AndroidJUnit4::class)
class TlsConfigApiTest {

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

    private fun clickTest() {
        onView(withId(R.id.btnTest)).perform(click())
        Thread.sleep(8000)
    }

    // ─── TLS Config API → Init ─────────────────────────

    @Test
    fun tlsConfig_init_succeeds() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    // ─── TLS Config API → TLS Host → 200 ───────────────

    @Test
    fun tlsConfig_tlsHost_returns_200() {
        clickTest()

        onView(withId(R.id.tvResult))
            .check(matches(withText(containsString("200"))))
    }

    // ─── TLS Host response has TLS info ─────────────────

    @Test
    fun tlsConfig_tlsHost_response_has_tls_info() {
        clickTest()

        // certInfoCard TLS bilgisini gösterir
        onView(withId(R.id.certInfoCard))
            .check(matches(isDisplayed()))
        onView(withId(R.id.tvCertInfo))
            .check(matches(withText(containsString("TLS"))))
    }

    // ─── TLS API'den host cert indirilmez ───────────────

    @Test
    fun tlsConfig_hostCert_not_downloaded_on_tls_api() {
        // TlsToTlsActivity enrollment kartını göstermez (requiresEnrollment=false)
        // enrollmentCard GONE olmalı
        onView(withId(R.id.enrollmentCard))
            .check(matches(not(isDisplayed())))
    }

    // ─── Unenroll TLS API'de no-op ─────────────────────

    @Test
    fun tlsConfig_hostCert_unenroll_is_noop_on_tls() {
        // TLS senaryosunda enrollment yok — enrollmentCard gizli
        onView(withId(R.id.enrollmentCard))
            .check(matches(not(isDisplayed())))

        // Init başarılı — Ready durumunda
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }
}
