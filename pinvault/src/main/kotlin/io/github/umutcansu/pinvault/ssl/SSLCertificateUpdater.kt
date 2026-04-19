package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
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
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
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
    private val sslManager: DynamicSSLManager? = null,
    private val certStore: ClientCertSecureStore? = null,
    private val clientKeyPassword: String = "",
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

            // Per-host version comparison: check if any host changed
            val storedConfig = configStore.load()
            val storedVersions = storedConfig?.pins?.associate { it.hostname to it.version } ?: emptyMap()

            val hasChanges = remoteConfig.forceUpdate || remoteConfig.pins.any { remotePin ->
                val storedVersion = storedVersions[remotePin.hostname]
                storedVersion == null || remotePin.version != storedVersion || remotePin.forceUpdate
            } || storedVersions.keys != remoteConfig.pins.map { it.hostname }.toSet()

            if (!hasChanges) {
                Timber.d("Config is already current — no host version changes")
                return UpdateResult.AlreadyCurrent
            }

            validateConfig(remoteConfig)
            configStore.save(remoteConfig)
            httpClientProvider.swap(remoteConfig)

            // Sync host-specific client certs for mTLS hosts
            syncHostClientCerts(remoteConfig, storedConfig)

            val newVersion = remoteConfig.computedVersion()
            Timber.d(
                "Config updated: %d → %d (%d hosts pinned)",
                currentVersion, newVersion, remoteConfig.pins.size
            )

            UpdateResult.Updated(newVersion)
        } catch (e: Exception) {
            Timber.e(e, "Config update failed")
            UpdateResult.Failed(
                reason = e.message ?: "Unknown error",
                exception = e
            )
        }
    }

    fun schedulePeriodicUpdates(intervalHours: Long = DEFAULT_INTERVAL_HOURS, onScheduled: ((Boolean) -> Unit)? = null) {
        schedulePeriodicUpdatesMinutes(intervalHours * 60, onScheduled)
    }

    fun schedulePeriodicUpdatesMinutes(intervalMinutes: Long, onScheduled: ((Boolean) -> Unit)? = null) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<CertificateUpdateWorker>(
            intervalMinutes, TimeUnit.MINUTES
        )
            .setConstraints(constraints)
            .addTag(WORK_TAG)
            .build()

        val operation = WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.REPLACE,
            request
        )

        operation.result.addListener({
            try {
                operation.result.get()
                Timber.d("Periodic certificate updates scheduled — every %d minutes", intervalMinutes)
                onScheduled?.invoke(true)
            } catch (e: Exception) {
                Timber.e(e, "Failed to schedule periodic updates")
                onScheduled?.invoke(false)
            }
        }, { it.run() })
    }

    fun cancelPeriodicUpdates() {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        Timber.d("Periodic certificate updates cancelled")
    }

    fun getScheduledWorkInfo(callback: (List<io.github.umutcansu.pinvault.model.ScheduledTaskInfo>) -> Unit) {
        val future = WorkManager.getInstance(context).getWorkInfosByTag(WORK_TAG)
        future.addListener({
            try {
                val infos = future.get().map { wi ->
                    io.github.umutcansu.pinvault.model.ScheduledTaskInfo(
                        id = wi.id.toString(),
                        state = when (wi.state) {
                            WorkInfo.State.ENQUEUED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.ENQUEUED
                            WorkInfo.State.RUNNING -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.RUNNING
                            WorkInfo.State.SUCCEEDED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.SUCCEEDED
                            WorkInfo.State.FAILED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.FAILED
                            WorkInfo.State.CANCELLED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.CANCELLED
                            WorkInfo.State.BLOCKED -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.BLOCKED
                            else -> io.github.umutcansu.pinvault.model.ScheduledTaskInfo.State.UNKNOWN
                        },
                        runAttemptCount = wi.runAttemptCount
                    )
                }
                callback(infos)
            } catch (e: Exception) {
                Timber.e(e, "Failed to get work info")
                callback(emptyList())
            }
        }, { it.run() })
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

    /**
     * Downloads and stores host-specific client certs for mTLS hosts.
     * Only downloads when clientCertVersion changed or cert is new.
     */
    private suspend fun syncHostClientCerts(
        remoteConfig: CertificateConfig,
        storedConfig: CertificateConfig?
    ) {
        if (sslManager == null || certStore == null) return

        val mtlsHosts = remoteConfig.pins.filter { it.mtls && it.clientCertVersion != null }
        if (mtlsHosts.isEmpty()) return

        val storedCertVersions = storedConfig?.pins
            ?.filter { it.mtls && it.clientCertVersion != null }
            ?.associate { it.hostname to it.clientCertVersion }
            ?: emptyMap()

        val hostCerts = mutableMapOf<String, ByteArray>()

        for (pin in mtlsHosts) {
            val label = "host_${pin.hostname}"
            val storedVersion = storedCertVersions[pin.hostname]
            val needsDownload = storedVersion != pin.clientCertVersion || !certStore.exists(label)

            if (needsDownload) {
                try {
                    val p12 = configApi.downloadHostClientCert(pin.hostname)
                    certStore.save(label, p12)
                    hostCerts[pin.hostname] = p12
                    Timber.d(
                        "Host client cert downloaded: %s (v%d → v%d)",
                        pin.hostname, storedVersion, pin.clientCertVersion
                    )
                } catch (e: Exception) {
                    // 403 = cihaz enroll olmamış → beklenen senaryo, W seviyesinde.
                    // Diğer hatalar E seviyesinde (gerçek sorun).
                    val is403 = (e as? retrofit2.HttpException)?.code() == 403
                    if (is403) {
                        Timber.d("Host client cert unavailable for %s (not enrolled / HTTP 403)", pin.hostname)
                    } else {
                        Timber.w(e, "Failed to download client cert for %s", pin.hostname)
                    }
                    // Try loading from store as fallback
                    certStore.load(label)?.let { hostCerts[pin.hostname] = it }
                }
            } else {
                // Already up-to-date — load from store
                certStore.load(label)?.let { hostCerts[pin.hostname] = it }
            }
        }

        if (hostCerts.isNotEmpty()) {
            sslManager.loadHostClientCerts(hostCerts, clientKeyPassword)
            // Re-swap to pick up new KeyManagers
            httpClientProvider.currentConfig?.let { httpClientProvider.swap(it) }
            Timber.d("Host client certs synced: %d hosts", hostCerts.size)
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
