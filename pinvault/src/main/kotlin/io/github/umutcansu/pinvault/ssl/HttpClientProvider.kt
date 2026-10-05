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
 *
 * Every change of the pins — [swap], [reset], a [replaceConfigInPlace] whose
 * pins differ — is reported to the SSL manager ([DynamicSSLManager.onPinsChanged]):
 * fresh TLS session caches, and the pooled connections of every client the
 * library handed out are closed, not only the one being replaced.
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
            currentConfig = newConfig
            // Over the LIVE config, not a snapshot of newConfig: a freshness
            // write-back ([replaceConfigInPlace]) must reach this client too,
            // or a config that expired and was then renewed with the same pins
            // would keep refusing handshakes (ConfigExpiredException) for the
            // rest of the process — the recovery interceptor retries on get().
            currentClient = sslManager.buildDynamicClient({ currentConfig }, recoveryInterceptor = recoveryInterceptor)
            currentVersion = newConfig.computedVersion()

            // Closes the old client's pooled connections (and those of every
            // other client built here), on a background thread.
            sslManager.onPinsChanged()

            Timber.d(
                "HttpClient swapped — new version: %d, %d pinned hosts",
                newConfig.computedVersion(), newConfig.pins.size
            )
        }
    }

    /**
     * Replaces the live config WITHOUT rebuilding the client.
     *
     * For changes that leave every pin untouched — a cleared `forceUpdate`
     * flag, a newer `issuedAt` / `expiresAt` — rebuilding the client and
     * evicting its connection pool would be pure cost. Should the pins differ
     * after all, the change is treated as what it is: sessions and pooled
     * connections go ([DynamicSSLManager.onPinsChanged]). But the in-memory copy must still follow the
     * disk, otherwise `PinVault.isForceUpdate()` (and anything else reading
     * [currentConfig]) keeps reporting the stale flag until the next process
     * start. Every client [get] hands out reads [currentConfig] on every
     * handshake, so it sees the new object immediately: the pins are equal,
     * and a moved-forward `expiresAt` takes effect at the next handshake.
     */
    fun replaceConfigInPlace(newConfig: CertificateConfig) {
        synchronized(this) {
            val pinsChanged = currentConfig?.let { pinShape(it) != pinShape(newConfig) } ?: true
            currentConfig = newConfig
            currentVersion = newConfig.computedVersion()
            if (pinsChanged) sslManager.onPinsChanged()
        }
    }

    private fun pinShape(config: CertificateConfig) =
        config.pins.associate { it.hostname.lowercase() to it.sha256.toSet() }

    /**
     * Drops the active config. The replacement client is fail-closed (see
     * [currentClient]) — pinning is never downgraded to system trust.
     */
    fun reset() {
        synchronized(this) {
            currentConfig = null
            currentClient = sslManager.buildDynamicClient({ currentConfig })
            currentVersion = 0
            sslManager.onPinsChanged()
            Timber.w("HttpClient reset — no config; TLS refused until the next init/swap")
        }
    }
}
