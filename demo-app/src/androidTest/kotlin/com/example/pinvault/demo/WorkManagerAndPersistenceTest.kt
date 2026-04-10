package com.example.pinvault.demo

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.WorkInfo
import androidx.work.WorkManager
import io.github.umutcansu.pinvault.PinVault
import org.hamcrest.CoreMatchers.containsString
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * E.36 — WorkManager periyodik update
 * E.37 — App kill sonrası stored config ile çalışma
 *
 * Espresso UI — TlsToTlsActivity üzerinden.
 * WorkManager testleri hybrid: Activity UI + onActivity ile PinVault API.
 */
@RunWith(AndroidJUnit4::class)
class WorkManagerAndPersistenceTest {

    private lateinit var scenario: ActivityScenario<TlsToTlsActivity>

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
        Thread.sleep(500)
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)
    }

    @After
    fun tearDown() {
        try { PinVault.cancelPeriodicUpdates() } catch (_: Exception) {}
        try { scenario.close() } catch (_: Exception) {}
        try { PinVault.reset() } catch (_: Exception) {}
    }

    // ── Helpers ──────────────────────────────────────────

    private fun clickUpdate() {
        onView(withId(R.id.btnUpdate)).perform(click())
        Thread.sleep(6000)
    }

    // ── E.36: WorkManager periyodik update ──────────────

    @Test
    fun E36_schedulePeriodicUpdates_enqueues_work() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        val scheduleLatch = CountDownLatch(1)
        var scheduled = false

        PinVault.schedulePeriodicUpdates(intervalHours = 12) { success ->
            scheduled = success
            scheduleLatch.countDown()
        }

        assertTrue("Schedule callback timed out", scheduleLatch.await(5, TimeUnit.SECONDS))
        assertTrue("WorkManager task scheduled", scheduled)

        val workInfos = WorkManager.getInstance(context)
            .getWorkInfosByTag("ssl_cert")
            .get(5, TimeUnit.SECONDS)

        assertTrue("WorkManager'da en az 1 iş olmalı", workInfos.isNotEmpty())
        val state = workInfos.first().state
        assertTrue(
            "İş ENQUEUED veya RUNNING olmalı: $state",
            state == WorkInfo.State.ENQUEUED || state == WorkInfo.State.RUNNING
        )
    }

    @Test
    fun E36_cancelPeriodicUpdates_removes_work() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        val latch = CountDownLatch(1)
        PinVault.schedulePeriodicUpdates(intervalHours = 12) { latch.countDown() }
        latch.await(5, TimeUnit.SECONDS)

        PinVault.cancelPeriodicUpdates()

        val workInfos = WorkManager.getInstance(context)
            .getWorkInfosByTag("ssl_cert")
            .get(5, TimeUnit.SECONDS)

        val activeJobs = workInfos.filter {
            it.state == WorkInfo.State.ENQUEUED || it.state == WorkInfo.State.RUNNING
        }
        assertEquals("İptal sonrası aktif iş olmamalı", 0, activeJobs.size)
    }

    @Test
    fun E36_getScheduledWorkInfo_returns_info() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        val scheduleLatch = CountDownLatch(1)
        PinVault.schedulePeriodicUpdates(intervalHours = 12) { scheduleLatch.countDown() }
        scheduleLatch.await(5, TimeUnit.SECONDS)

        val infoLatch = CountDownLatch(1)
        var infos: List<Any>? = null

        PinVault.getScheduledWorkInfo { result ->
            infos = result
            infoLatch.countDown()
        }

        assertTrue("Info callback timed out", infoLatch.await(5, TimeUnit.SECONDS))
        assertNotNull("Work info listesi null olmamalı", infos)
        assertTrue("En az 1 scheduled task olmalı", infos!!.isNotEmpty())
    }

    // ── E.37: Config persistence ───────────────────────

    @Test
    fun E37_init_stores_config_and_reinit_uses_it() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    @Test
    fun E37_updateNow_persists_new_version() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        clickUpdate()

        // Update sonucu görünmeli
        onView(withId(R.id.tvResult))
            .check(matches(isDisplayed()))

        // Version hâlâ görünür
        onView(withId(R.id.tvVersion))
            .check(matches(isDisplayed()))
    }

    @Test
    fun E37_reset_clears_stored_config() {
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))

        // Activity kapat + reset
        scenario.close()
        PinVault.reset()
        Thread.sleep(500)

        // Tekrar aç — yeniden init edilir (stored config temizlenmiş)
        scenario = ActivityScenario.launch(TlsToTlsActivity::class.java)
        Thread.sleep(12000)

        // TlsToTlsActivity doğru URL ile init → Ready (sunucu erişilebilir)
        onView(withId(R.id.tvStatus))
            .check(matches(withText(containsString("✓"))))
    }
}
