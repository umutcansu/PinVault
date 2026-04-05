package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import okhttp3.OkHttpClient
import timber.log.Timber

/**
 * Thread-safe holder for the current pinned OkHttpClient.
 *
 * When the certificate config is updated, [swap] atomically replaces
 * the client. Existing in-flight requests complete normally;
 * new requests use the new client.
 */
internal class HttpClientProvider(
    private val sslManager: DynamicSSLManager
) {

    @Volatile
    private var currentClient: OkHttpClient = sslManager.buildClient(null)

    @Volatile
    private var currentVersion: Int = 0

    @Volatile
    var currentConfig: CertificateConfig? = null
        private set

    /** Set by PinVault after updater is created */
    @Volatile
    internal var recoveryUpdater: (suspend () -> Boolean)? = null

    private val recoveryInterceptor: PinRecoveryInterceptor by lazy {
        PinRecoveryInterceptor(
            updater = {
                val fn = recoveryUpdater ?: return@PinRecoveryInterceptor false
                kotlinx.coroutines.runBlocking { fn() }
            },
            newClientProvider = { get() }
        )
    }

    fun get(): OkHttpClient = currentClient

    fun getVersion(): Int = currentVersion

    fun swap(newConfig: CertificateConfig) {
        synchronized(this) {
            val oldClient = currentClient
            currentConfig = newConfig
            currentClient = sslManager.buildClient(newConfig, recoveryInterceptor = recoveryInterceptor)
            currentVersion = newConfig.computedVersion()

            // evictAll on background thread to avoid NetworkOnMainThreadException
            Thread { oldClient.connectionPool.evictAll() }.start()

            Timber.d(
                "HttpClient swapped — new version: %d, %d pinned hosts",
                newConfig.computedVersion(), newConfig.pins.size
            )
        }
    }

    fun reset() {
        synchronized(this) {
            val oldClient = currentClient
            currentConfig = null
            currentClient = sslManager.buildClient(null)
            currentVersion = 0
            Thread { oldClient.connectionPool.evictAll() }.start()
            Timber.w("HttpClient reset to system defaults")
        }
    }
}
