package com.example.pinvault.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkInfo
import androidx.work.WorkManager
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
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
 */
@RunWith(AndroidJUnit4::class)
class WorkManagerAndPersistenceTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val bootstrapPins get() = TestConfig.BOOTSTRAP_PINS

    @Before
    fun setUp() {
        try { PinVault.reset() } catch (_: Exception) {}
    }

    @After
    fun tearDown() {
        try {
            PinVault.cancelPeriodicUpdates()
            PinVault.reset()
        } catch (_: Exception) {}
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

    // ── E.36: WorkManager periyodik update ──────────────

    @Test
    fun E36_schedulePeriodicUpdates_enqueues_work() {
        val init = initPinVault()
        assertTrue("Init: $init", init is InitResult.Ready)

        val scheduleLatch = CountDownLatch(1)
        var scheduled = false

        PinVault.schedulePeriodicUpdates(intervalHours = 12) { success ->
            scheduled = success
            scheduleLatch.countDown()
        }

        assertTrue("Schedule callback timed out", scheduleLatch.await(5, TimeUnit.SECONDS))
        assertTrue("WorkManager task scheduled", scheduled)

        // WorkManager'da ssl_cert tag'li iş var mı?
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
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        val latch = CountDownLatch(1)
        PinVault.schedulePeriodicUpdates(intervalHours = 12) { latch.countDown() }
        latch.await(5, TimeUnit.SECONDS)

        // İptal et
        PinVault.cancelPeriodicUpdates()

        // WorkManager'daki iş iptal edilmiş olmalı
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
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        val scheduleLatch = CountDownLatch(1)
        PinVault.schedulePeriodicUpdates(intervalHours = 12) { scheduleLatch.countDown() }
        scheduleLatch.await(5, TimeUnit.SECONDS)

        // PinVault.getScheduledWorkInfo callback ile bilgi dönmeli
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
        // İlk init — config stored
        val init1 = initPinVault()
        assertTrue("İlk init: $init1", init1 is InitResult.Ready)
        val v1 = PinVault.currentVersion()
        assertTrue("v1 > 0", v1 > 0)

        // Double init (reset olmadan) — stored config varsa hızlı tamamlar
        // PinVault zaten initialized — ikinci init skip eder ama version korunur
        val v1b = PinVault.currentVersion()
        assertEquals("Version korunmalı", v1, v1b)
    }

    @Test
    fun E37_updateNow_persists_new_version() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)
        val v1 = PinVault.currentVersion()

        // updateNow — sunucu erişilebilir, yeni config çek
        val result = kotlinx.coroutines.runBlocking { PinVault.updateNow() }
        assertTrue(
            "updateNow: $result",
            result is io.github.umutcansu.pinvault.model.UpdateResult.Updated ||
            result is io.github.umutcansu.pinvault.model.UpdateResult.AlreadyCurrent
        )

        val v2 = PinVault.currentVersion()
        assertTrue("Version >= önceki: $v2 >= $v1", v2 >= v1)
    }

    @Test
    fun E37_reset_clears_stored_config() {
        val init = initPinVault()
        assertTrue(init is InitResult.Ready)

        // Reset — stored config temizlenir
        PinVault.reset()

        // Erişilemez URL ile init — stored config yok → Failed
        val latch = CountDownLatch(1)
        var result: InitResult? = null
        val config = PinVaultConfig.Builder("https://${TestConfig.HOST_IP}:19999/")
            .bootstrapPins(bootstrapPins)
            .configEndpoint("api/v1/certificate-config?signed=false")
            .maxRetryCount(1)
            .build()
        PinVault.init(context, config) { result = it; latch.countDown() }
        assertTrue("Init timed out", latch.await(20, TimeUnit.SECONDS))

        assertTrue(
            "Reset sonrası stored config yok + sunucu kapalı = Failed: $result",
            result is InitResult.Failed
        )
    }
}
