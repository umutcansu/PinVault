package io.github.umutcansu.pinvault.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.model.UpdateResult
import timber.log.Timber

/**
 * WorkManager worker that periodically updates the SSL certificate config.
 * Accesses [PinVault] singleton directly (no Hilt needed).
 */
class CertificateUpdateWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        Timber.d("CertificateUpdateWorker started (attempt: %d)", runAttemptCount)

        val updateResult = PinVault.updateNow()
        PinVault.notifyUpdateResult(updateResult)

        // Sync vault files with updateWithPins=true
        try {
            PinVault.syncAllFiles()
        } catch (e: Exception) {
            Timber.e(e, "Vault file sync failed during periodic update")
        }

        return when (updateResult) {
            is UpdateResult.Updated -> {
                Timber.d("Worker: config updated to version %d", updateResult.newVersion)
                Result.success()
            }

            is UpdateResult.AlreadyCurrent -> {
                Timber.d("Worker: config already up to date")
                Result.success()
            }

            is UpdateResult.Failed -> {
                Timber.e("Worker: update failed — %s", updateResult.reason)
                if (runAttemptCount < MAX_RETRIES) {
                    Result.retry()
                } else {
                    Result.failure()
                }
            }
        }
    }

    companion object {
        private const val MAX_RETRIES = 3
    }
}
