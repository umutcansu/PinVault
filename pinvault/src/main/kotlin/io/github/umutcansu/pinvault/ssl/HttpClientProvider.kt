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
    var currentConfig: CertificateConfig? = null
        private set

    /**
     * Starts as a fail-closed client: pinning is installed over the live
     * [currentConfig], so every TLS handshake is refused until [swap]
     * publishes the first config — and starts succeeding right after, even
     * for callers still holding this instance. Handing out a system-trust
     * client here (the pre-fix behaviour) let `PinVault.getClient()` callers
     * skip pinning entirely during the init window and after [reset].
     */
    @Volatile
    private var currentClient: OkHttpClient = sslManager.buildDynamicClient({ currentConfig })

    @Volatile
    private var currentVersion: Int = 0

    /** Set by PinVault after updater is created */
    @Volatile
    internal var recoveryUpdater: (suspend () -> Boolean)? = null

    /**
     * The interceptor that retries a failed request after refreshing pins.
     * Visible to [io.github.umutcansu.pinvault.PinVault] so the public
     * `applyTo(OkHttpClient.Builder)` entry point can install it on
     * builders the caller maintains themselves — same recovery semantics
     * as [get].
     */
    internal val recoveryInterceptor: PinRecoveryInterceptor by lazy {
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

    /**
     * Replaces the live config WITHOUT rebuilding the client.
     *
     * For changes that leave every pin untouched — today only a cleared
     * `forceUpdate` flag — rebuilding the client and evicting its connection
     * pool would be pure cost. But the in-memory copy must still follow the
     * disk, otherwise `PinVault.isForceUpdate()` (and anything else reading
     * [currentConfig]) keeps reporting the stale flag until the next process
     * start. The dynamic trust manager reads [currentConfig] on every
     * handshake, so it sees the new object immediately; the pins are equal,
     * so nothing about verification changes.
     */
    fun replaceConfigInPlace(newConfig: CertificateConfig) {
        synchronized(this) {
            currentConfig = newConfig
            currentVersion = newConfig.computedVersion()
        }
    }

    /**
     * Drops the active config. The replacement client is fail-closed (see
     * [currentClient]) — pinning is never downgraded to system trust.
     */
    fun reset() {
        synchronized(this) {
            val oldClient = currentClient
            currentConfig = null
            currentClient = sslManager.buildDynamicClient({ currentConfig })
            currentVersion = 0
            Thread { oldClient.connectionPool.evictAll() }.start()
            Timber.w("HttpClient reset — no config; TLS refused until the next init/swap")
        }
    }
}
