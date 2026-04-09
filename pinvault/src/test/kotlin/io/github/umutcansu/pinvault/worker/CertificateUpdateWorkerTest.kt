package io.github.umutcansu.pinvault.worker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.work.ListenableWorker.Result
import androidx.work.testing.TestListenableWorkerBuilder
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.UpdateResult
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CertificateUpdateWorkerTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        mockkObject(PinVault)
        // relaxed mock for notifyUpdateResult since it's a side-effect call
        io.mockk.every { PinVault.notifyUpdateResult(any()) } returns Unit
    }

    @After
    fun tearDown() {
        unmockkObject(PinVault)
    }

    private fun buildWorker(runAttemptCount: Int = 0): CertificateUpdateWorker {
        return TestListenableWorkerBuilder<CertificateUpdateWorker>(context)
            .setRunAttemptCount(runAttemptCount)
            .build()
    }

    @Test
    fun `doWork returns success on Updated result`() = runTest {
        coEvery { PinVault.updateNow() } returns UpdateResult.Updated(5)

        val worker = buildWorker()
        val result = worker.doWork()

        assertEquals(Result.success(), result)
    }

    @Test
    fun `doWork returns success on AlreadyCurrent result`() = runTest {
        coEvery { PinVault.updateNow() } returns UpdateResult.AlreadyCurrent

        val worker = buildWorker()
        val result = worker.doWork()

        assertEquals(Result.success(), result)
    }

    @Test
    fun `doWork returns retry on Failed when attempt below max`() = runTest {
        coEvery { PinVault.updateNow() } returns UpdateResult.Failed("network error")

        val worker = buildWorker(runAttemptCount = 0)
        val result = worker.doWork()

        assertEquals(Result.retry(), result)
    }

    @Test
    fun `doWork returns failure on Failed when attempt at max`() = runTest {
        coEvery { PinVault.updateNow() } returns UpdateResult.Failed("network error")

        val worker = buildWorker(runAttemptCount = 3)
        val result = worker.doWork()

        assertEquals(Result.failure(), result)
    }

    @Test
    fun `doWork returns retry on Failed at attempt 2`() = runTest {
        coEvery { PinVault.updateNow() } returns UpdateResult.Failed("timeout")

        val worker = buildWorker(runAttemptCount = 2)
        val result = worker.doWork()

        assertEquals(Result.retry(), result)
    }

    @Test
    fun `notifyUpdateResult called with correct result`() = runTest {
        val updateResult = UpdateResult.Updated(10)
        coEvery { PinVault.updateNow() } returns updateResult

        val worker = buildWorker()
        worker.doWork()

        io.mockk.verify { PinVault.notifyUpdateResult(updateResult) }
    }
}
