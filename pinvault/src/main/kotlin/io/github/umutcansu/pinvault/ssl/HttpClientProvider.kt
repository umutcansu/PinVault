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

    fun get(): OkHttpClient = currentClient

    fun getVersion(): Int = currentVersion

    fun swap(newConfig: CertificateConfig) {
        synchronized(this) {
            val oldClient = currentClient
            currentConfig = newConfig
            currentClient = sslManager.buildClient(newConfig)
            currentVersion = newConfig.version
            oldClient.connectionPool.evictAll()

            Timber.d(
                "HttpClient swapped — new version: %d, %d pinned hosts",
                newConfig.version, newConfig.pins.size
            )
        }
    }

    fun reset() {
        synchronized(this) {
            currentClient.connectionPool.evictAll()
            currentConfig = null
            currentClient = sslManager.buildClient(null)
            currentVersion = 0
            Timber.w("HttpClient reset to system defaults")
        }
    }
}
