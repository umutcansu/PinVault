package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.BackendUnreachableException
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ForceUpdateFailedException
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.InvalidPinFormatException
import io.github.umutcansu.pinvault.model.NoConfigAvailableException
import io.github.umutcansu.pinvault.model.PinMismatchException
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.worker.CertificateUpdateWorker
import kotlinx.coroutines.delay
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * Core orchestrator: fetches config from backend, persists it, swaps the HTTP client.
 *
 * Typical lifecycle:
 * 1. App start → [initializeAndUpdate] loads stored config + fetches latest with retry
 * 2. Background → [schedulePeriodicUpdates] runs every N hours via WorkManager
 */
internal class SSLCertificateUpdater(
    private val context: Context,
    private val configApi: CertificateConfigApi,
    private val configStore: CertificateConfigStore,
    private val httpClientProvider: HttpClientProvider,
    private val maxRetryCount: Int = DEFAULT_MAX_RETRY
) {

    /**
     * Full initialization flow:
     * 1. Load stored config (if any)
     * 2. Try to fetch latest from backend with retry
     * 3. Decide if we can proceed based on forceUpdate flag
     */
    suspend fun initializeAndUpdate(): InitResult {
        // 1. Load stored config (if any)
        val storedConfig = loadFromStore()

        // 2. Try to fetch latest from backend with retry
        val updateResult = updateWithRetry()

        return when (updateResult) {
            is UpdateResult.Updated -> {
                // 3. Hash'ler güncellendi — pinlenmiş bağlantıyla doğrula
                val verifyResult = verifyPinnedConnection()
                if (verifyResult is InitResult.Failed) return verifyResult

                Timber.d("Init ready — updated to version: %d", updateResult.newVersion)
                InitResult.Ready(updateResult.newVersion)
            }

            is UpdateResult.AlreadyCurrent -> {
                val version = configStore.getCurrentVersion()
                Timber.d("Init ready — already current version: %d", version)
                InitResult.Ready(version)
            }

            is UpdateResult.Failed -> {
                if (storedConfig == null) {
                    Timber.e("Init failed — no stored config and backend unreachable")
                    InitResult.Failed(
                        reason = "No stored config and backend unreachable: ${updateResult.reason}",
                        exception = NoConfigAvailableException(cause = updateResult.exception)
                    )
                } else if (storedConfig.forceUpdate) {
                    Timber.e("Init failed — forceUpdate=true but backend unreachable")
                    InitResult.Failed(
                        reason = "Force update required but backend unreachable: ${updateResult.reason}",
                        exception = ForceUpdateFailedException(cause = updateResult.exception)
                    )
                } else {
                    Timber.w(
                        "Init ready with stored config — version: %d (backend unreachable)",
                        storedConfig.version
                    )
                    InitResult.Ready(storedConfig.version)
                }
            }
        }
    }

    /**
     * Hash'ler uygulandıktan sonra pinlenmiş client ile health check yapar.
     * Hash yanlışsa SSLPeerUnverifiedException fırlar → InitResult.Failed döner.
     */
    private suspend fun verifyPinnedConnection(): InitResult {
        return try {
            val healthy = configApi.healthCheck()
            if (healthy) {
                Timber.d("Pinned connection verified — health check OK")
                InitResult.Ready(configStore.getCurrentVersion())
            } else {
                Timber.e("Pinned connection verified but health check returned unhealthy")
                InitResult.Failed(
                    reason = "Backend returned unhealthy status after pin update",
                    exception = BackendUnreachableException("Health check returned unhealthy after pin update")
                )
            }
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            Timber.e(e, "Pin mismatch — hashes do not match server certificate")
            configStore.clear()
            httpClientProvider.reset()
            InitResult.Failed(
                reason = "Pin hashes do not match server certificate",
                exception = PinMismatchException(cause = e)
            )
        } catch (e: Exception) {
            Timber.e(e, "Pinned connection verification failed")
            configStore.clear()
            httpClientProvider.reset()
            InitResult.Failed(
                reason = "Pin verification failed: ${e.message}",
                exception = BackendUnreachableException(cause = e)
            )
        }
    }

    private fun loadFromStore(): CertificateConfig? {
        val stored = configStore.load()
        if (stored != null) {
            httpClientProvider.swap(stored)
            Timber.d("Loaded stored config — version: %d", stored.version)
        } else {
            Timber.d("No stored config — client using system defaults")
        }
        return stored
    }

    private suspend fun updateWithRetry(): UpdateResult {
        var lastResult: UpdateResult = UpdateResult.Failed("No attempt made")

        for (attempt in 1..maxRetryCount) {
            Timber.d("Update attempt %d/%d", attempt, maxRetryCount)
            lastResult = updateNow()

            when (lastResult) {
                is UpdateResult.Updated,
                is UpdateResult.AlreadyCurrent -> return lastResult
                is UpdateResult.Failed -> {
                    if (attempt < maxRetryCount) {
                        val delayMs = RETRY_BASE_DELAY_MS * attempt
                        Timber.w("Attempt %d failed, retrying in %dms", attempt, delayMs)
                        delay(delayMs)
                    }
                }
            }
        }

        return lastResult
    }

    suspend fun updateNow(): UpdateResult {
        return try {
            val currentVersion = configStore.getCurrentVersion()
            Timber.d("Fetching config update — current version: %d", currentVersion)

            val remoteConfig = configApi.fetchConfig(currentVersion)

            // Strict equality: if versions match exactly, no update needed.
            // Accepts "downgrades" (e.g. after a backend reset) so the client
            // always converges to whatever the server currently provides.
            if (remoteConfig.version == currentVersion && !remoteConfig.forceUpdate) {
                Timber.d("Config is already current (version: %d)", currentVersion)
                return UpdateResult.AlreadyCurrent
            }

            validateConfig(remoteConfig)
            configStore.save(remoteConfig)
            httpClientProvider.swap(remoteConfig)

            Timber.d(
                "Config updated: %d → %d (%d hosts pinned)",
                currentVersion, remoteConfig.version, remoteConfig.pins.size
            )

            UpdateResult.Updated(remoteConfig.version)
        } catch (e: Exception) {
            Timber.e(e, "Config update failed")
            UpdateResult.Failed(
                reason = e.message ?: "Unknown error",
                exception = e
            )
        }
    }

    fun schedulePeriodicUpdates(intervalHours: Long = DEFAULT_INTERVAL_HOURS) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<CertificateUpdateWorker>(
            intervalHours, TimeUnit.HOURS
        )
            .setConstraints(constraints)
            .addTag(WORK_TAG)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )

        Timber.d("Periodic certificate updates scheduled — every %d hours", intervalHours)
    }

    fun cancelPeriodicUpdates() {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        Timber.d("Periodic certificate updates cancelled")
    }

    private fun validateConfig(config: CertificateConfig) {
        require(config.pins.isNotEmpty()) { "Config must contain at least one pin entry" }
        config.pins.forEach { pin ->
            require(pin.sha256.size >= 2) {
                "Host ${pin.hostname} must have at least 2 pins (primary + backup)"
            }
            pin.sha256.forEachIndexed { index, hash ->
                validateHash(pin.hostname, index, hash)
            }
        }
    }

    private fun validateHash(hostname: String, index: Int, hash: String) {
        if (hash.isBlank()) {
            throw InvalidPinFormatException("Hash at index $index for $hostname is blank")
        }

        // SHA-256 = 32 bytes → Base64 = 44 characters (with padding)
        if (hash.length != 44) {
            throw InvalidPinFormatException(
                "Hash at index $index for $hostname has invalid length: ${hash.length} (expected 44)"
            )
        }

        // Valid Base64 check
        try {
            val decoded = android.util.Base64.decode(hash, android.util.Base64.DEFAULT)
            if (decoded.size != 32) {
                throw InvalidPinFormatException(
                    "Hash at index $index for $hostname decoded to ${decoded.size} bytes (expected 32)"
                )
            }
        } catch (e: IllegalArgumentException) {
            throw InvalidPinFormatException(
                "Hash at index $index for $hostname is not valid Base64: $hash", e
            )
        }
    }

    companion object {
        private const val WORK_NAME = "ssl_cert_update"
        private const val WORK_TAG = "ssl_cert"
        private const val DEFAULT_INTERVAL_HOURS = 12L
        private const val DEFAULT_MAX_RETRY = 3
        private const val RETRY_BASE_DELAY_MS = 2000L
    }
}
