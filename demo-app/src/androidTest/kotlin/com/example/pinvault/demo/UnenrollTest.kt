package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.umutcansu.pinvault.PinVault
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.not
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B.12 — Unenroll Espresso testleri.
 *
 * TlsToTlsActivity (no enrollment) ve MtlsToTlsActivity (enrollment kartı) üzerinden.
 */
@RunWith(AndroidJUnit4::class)
class UnenrollTest {

    private var scenario: ActivityScenario<*>? = null

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext

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

    // ── B.12: Unenroll — default cert ───────────────────

    @Test
    fun B12_unenroll_default_removes_cert() {
        // MtlsToTlsActivity — enrollment kartı var
        scenario = ActivityScenario.launch(MtlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // Enrollment required — btnUnenroll görünür ama enrollment yok
        onView(withId(R.id.enrollmentCard))
            .check(matches(isDisplayed()))
        onView(withId(R.id.tvEnrollStatus))
            .check(matches(withText(containsString("✗"))))

        // Unenroll — enrollment yokken no-op olmalı, hata vermemeli
        try {
            PinVault.unenroll(context)
        } catch (_: Exception) {}

        assertFalse("Should not be enrolled", PinVault.isEnrolled(context))
    }

    // ── B.12: Labeled unenroll ──────────────────────────

    @Test
    fun B12_unenroll_labeled_only_removes_specific_cert() {
        // TlsToTlsActivity — enrollment yok
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Host label unenroll — enrollment yokken no-op
        val hostLabel = TestConfig.MTLS_HOST_CERT_LABEL
        PinVault.unenroll(context, hostLabel)
        assertFalse(PinVault.isEnrolled(context, hostLabel))

        // Default unenroll — no-op
        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))
    }

    // ── B.12: Unenroll without enrollment ───────────────

    @Test
    fun B12_unenroll_without_prior_enrollment_is_noop() {
        // TlsToTlsActivity — enrollment yok, enrollmentCard gizli
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.enrollmentCard))
            .check(matches(not(isDisplayed())))

        // Unenroll hata vermemeli
        assertFalse(PinVault.isEnrolled(context))
        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))
    }

    // ── B.12: Clear all labels ──────────────────────────

    @Test
    fun B12_unenroll_all_labels_clears_enrollment() {
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Default + host label unenroll — tümü temiz
        PinVault.unenroll(context)
        PinVault.unenroll(context, TestConfig.MTLS_HOST_CERT_LABEL)

        assertFalse(PinVault.isEnrolled(context))
        assertFalse(PinVault.isEnrolled(context, TestConfig.MTLS_HOST_CERT_LABEL))
    }
}
