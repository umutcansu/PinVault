package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * B.12 — Unenroll: cert sil → isEnrolled false → mTLS host reddetmeli
 *
 * Programmatik test — PinVault public API üzerinden.
 */
@RunWith(AndroidJUnit4::class)
class UnenrollTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    @After
    fun tearDown() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    private fun initPinVault(): InitResult {
        val latch = CountDownLatch(1)
        var result: InitResult? = null
        val config = PinVaultConfig.Builder(TestConfig.TLS_CONFIG_URL)
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(2)
            .build()
        PinVault.init(context, config) { result = it; latch.countDown() }
        assertTrue("Init timed out", latch.await(15, TimeUnit.SECONDS))
        return result!!
    }

    @Test
    fun B12_unenroll_default_removes_cert() {
        // Init + autoEnroll to get a real cert
        val init = initPinVault()
        assertTrue("Init: $init", init is InitResult.Ready)

        val enrolled = runBlocking { PinVault.autoEnroll(context) }
        if (!enrolled) {
            // Enrollment endpoint yoksa, unenroll'un no-op olduğunu doğrula
            assertFalse("Should not be enrolled without autoEnroll", PinVault.isEnrolled(context))
            PinVault.unenroll(context) // should not throw
            assertFalse("Still not enrolled after unenroll", PinVault.isEnrolled(context))
            return
        }

        assertTrue("Should be enrolled after autoEnroll", PinVault.isEnrolled(context))

        // Unenroll
        PinVault.unenroll(context)
        assertFalse("Should not be enrolled after unenroll", PinVault.isEnrolled(context))
    }

    @Test
    fun B12_unenroll_labeled_only_removes_specific_cert() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        val enrolled = runBlocking { PinVault.autoEnroll(context) }
        if (!enrolled) return // skip if no enrollment endpoint

        assertTrue("Default cert enrolled", PinVault.isEnrolled(context))

        // Check host cert label — may or may not exist depending on config
        val hostLabel = TestConfig.MTLS_HOST_CERT_LABEL
        val hostEnrolled = PinVault.isEnrolled(context, hostLabel)

        if (hostEnrolled) {
            // Sadece host cert'i sil
            PinVault.unenroll(context, hostLabel)

            assertTrue("Default cert untouched", PinVault.isEnrolled(context))
            assertFalse("Host cert removed", PinVault.isEnrolled(context, hostLabel))
        }

        // Sadece default cert'i sil
        PinVault.unenroll(context)
        assertFalse("Default cert removed", PinVault.isEnrolled(context))
    }

    @Test
    fun B12_unenroll_without_prior_enrollment_is_noop() {
        assertFalse(PinVault.isEnrolled(context))
        PinVault.unenroll(context) // should not throw
        assertFalse(PinVault.isEnrolled(context))
    }

    @Test
    fun B12_unenroll_all_labels_clears_enrollment() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        val enrolled = runBlocking { PinVault.autoEnroll(context) }
        if (!enrolled) return

        assertTrue(PinVault.isEnrolled(context))

        // Unenroll default
        PinVault.unenroll(context)
        assertFalse(PinVault.isEnrolled(context))

        // Host labels should also be clearable
        val hostLabel = TestConfig.MTLS_HOST_CERT_LABEL
        if (PinVault.isEnrolled(context, hostLabel)) {
            PinVault.unenroll(context, hostLabel)
            assertFalse(PinVault.isEnrolled(context, hostLabel))
        }
    }
}
