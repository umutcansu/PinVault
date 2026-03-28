package io.github.umutcansu.pinvault

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import timber.log.Timber

/**
 * Main entry point for the dynamic SSL certificate pinning library.
 *
 * ## Suspend (Kotlin coroutine projeleri)
 *
 * ```kotlin
 * val result = PinVault.init(
 *     context = applicationContext,
 *     configUrl = "https://api.example.com/",
 *     bootstrapPins = listOf(
 *         HostPin("api.example.com", listOf("hash1...", "hash2..."))
 *     )
 * )
 * when (result) {
 *     is InitResult.Ready -> PinVault.applyTo(builder)
 *     is InitResult.Failed -> // hata
 * }
 * ```
 *
 * ## Callback (Java / coroutine olmayan projeler)
 *
 * ```kotlin
 * PinVault.init(
 *     context = applicationContext,
 *     configUrl = "https://api.example.com/",
 *     bootstrapPins = listOf(...),
 *     onResult = { result ->
 *         when (result) {
 *             is InitResult.Ready -> PinVault.applyTo(builder)
 *             is InitResult.Failed -> // hata
 *         }
 *     }
 * )
 * ```
 */
object PinVault {

    private lateinit var sslManager: DynamicSSLManager
    private lateinit var clientProvider: HttpClientProvider
    private lateinit var updater: SSLCertificateUpdater
    private lateinit var configStore: CertificateConfigStore

    @Volatile
    private var initialized = false

    // ── Config holder ────────────────────────────────────────────────────────

    @Volatile
    private var pinManagerConfig: PinVaultConfig? = null

    // ── Init (PinVaultConfig — recommended) ─────────────────────────────

    /**
     * Initializes the library with a [PinVaultConfig] (suspend version).
     *
     * ```kotlin
     * val config = PinVaultConfig.Builder("https://api.example.com/")
     *     .bootstrapPins(listOf(HostPin("api.example.com", listOf("hash1", "hash2"))))
     *     .build()
     * val result = PinVault.init(context, config)
     * ```
     */
    suspend fun init(context: Context, config: PinVaultConfig): InitResult {
        pinManagerConfig = config
        setup(context, config, null)
            ?: return InitResult.Ready(clientProvider.getVersion())
        return executeInit()
    }

    /**
     * Initializes the library with a [PinVaultConfig] (callback version).
     */
    fun init(context: Context, config: PinVaultConfig, onResult: (InitResult) -> Unit) {
        pinManagerConfig = config
        val alreadyReady = setup(context, config, null)
        if (alreadyReady == null) {
            onResult(InitResult.Ready(clientProvider.getVersion()))
            return
        }
        CoroutineScope(Dispatchers.IO).launch {
            val result = executeInit()
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    // ── Init (legacy — backward compatible) ───────────────────────────────

    /**
     * Initializes the library (suspend version — legacy overload).
     * Prefer [init(Context, PinVaultConfig)] for new integrations.
     */
    suspend fun init(
        context: Context,
        configUrl: String,
        bootstrapPins: List<HostPin>,
        maxRetryCount: Int = 3,
        configApi: CertificateConfigApi? = null
    ): InitResult {
        val config = PinVaultConfig(
            configUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/",
            bootstrapPins = bootstrapPins,
            maxRetryCount = maxRetryCount
        )
        pinManagerConfig = config
        setup(context, config, configApi)
            ?: return InitResult.Ready(clientProvider.getVersion())
        return executeInit()
    }

    /**
     * Initializes the library (callback version — legacy overload).
     * Prefer [init(Context, PinVaultConfig, (InitResult) -> Unit)] for new integrations.
     */
    fun init(
        context: Context,
        configUrl: String,
        bootstrapPins: List<HostPin>,
        maxRetryCount: Int = 3,
        configApi: CertificateConfigApi? = null,
        onResult: (InitResult) -> Unit
    ) {
        val config = PinVaultConfig(
            configUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/",
            bootstrapPins = bootstrapPins,
            maxRetryCount = maxRetryCount
        )
        pinManagerConfig = config
        val alreadyReady = setup(context, config, configApi)
        if (alreadyReady == null) {
            onResult(InitResult.Ready(clientProvider.getVersion()))
            return
        }
        CoroutineScope(Dispatchers.IO).launch {
            val result = executeInit()
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    // ── Internal setup ────────────────────────────────────────────────────

    /**
     * Sets up internal components. Returns Unit if setup was performed,
     * null if already initialized (caller should return early).
     */
    private fun setup(
        context: Context,
        config: PinVaultConfig,
        configApi: CertificateConfigApi?
    ): Unit? {
        synchronized(this) {
            if (initialized) {
                Timber.w("PinVault already initialized — skipping")
                return null
            }

            val appContext = context.applicationContext

            sslManager = DynamicSSLManager()
            clientProvider = HttpClientProvider(sslManager)
            configStore = CertificateConfigStore(appContext)

            val api = configApi ?: DefaultCertificateConfigApi(
                configUrl = config.configUrl,
                configEndpoint = config.configEndpoint,
                healthEndpoint = config.healthEndpoint,
                signaturePublicKey = config.signaturePublicKey,
                bootstrapPins = config.bootstrapPins,
                sslManager = sslManager
            )

            updater = SSLCertificateUpdater(
                context = appContext,
                configApi = api,
                configStore = configStore,
                httpClientProvider = clientProvider,
                maxRetryCount = config.maxRetryCount
            )

            initialized = true
            return Unit
        }
    }

    private suspend fun executeInit(): InitResult {
        val result = updater.initializeAndUpdate()

        if (result is InitResult.Failed) {
            synchronized(this) {
                initialized = false
            }
        }

        return result
    }

    /**
     * Applies SSL certificate pinning to an existing [OkHttpClient.Builder].
     * Replaces the old BKS trust store setup.
     */
    fun applyTo(builder: OkHttpClient.Builder) {
        checkInitialized()
        val config = clientProvider.currentConfig
        if (config != null) {
            sslManager.applyTo(builder, config)
        } else {
            Timber.w("No certificate config available — builder unchanged (system defaults)")
        }
    }

    /**
     * Returns a ready-to-use OkHttpClient with current pinning applied.
     */
    fun getClient(): OkHttpClient {
        checkInitialized()
        return clientProvider.get()
    }

    /**
     * Returns a ready-to-use OkHttpClient with current pinning and custom settings.
     */
    fun getClient(connectionSettings: HttpConnectionSettings): OkHttpClient {
        checkInitialized()
        return sslManager.buildClient(clientProvider.currentConfig, connectionSettings)
    }

    /**
     * Fetches the latest config from backend, persists it, and updates pinning.
     */
    suspend fun updateNow(): UpdateResult {
        checkInitialized()
        return updater.updateNow()
    }

    /**
     * Schedules periodic config updates via WorkManager.
     * Default interval comes from [PinVaultConfig.updateIntervalHours].
     */
    fun schedulePeriodicUpdates(
        intervalHours: Long = pinManagerConfig?.updateIntervalHours
            ?: PinVaultConfig.DEFAULT_UPDATE_INTERVAL_HOURS
    ) {
        checkInitialized()
        updater.schedulePeriodicUpdates(intervalHours)
    }

    /**
     * Cancels periodic updates.
     */
    fun cancelPeriodicUpdates() {
        checkInitialized()
        updater.cancelPeriodicUpdates()
    }

    /**
     * Returns the current config version, or 0 if no config is loaded.
     */
    fun currentVersion(): Int {
        checkInitialized()
        return clientProvider.getVersion()
    }

    /**
     * Returns true if the backend has set forceUpdate=true in the current config,
     * meaning the client must update pins immediately without prompting the user.
     */
    fun isForceUpdate(): Boolean {
        checkInitialized()
        return clientProvider.currentConfig?.forceUpdate ?: false
    }

    /**
     * Resets to system defaults (no pinning). Use only as emergency fallback.
     * Also resets the initialized flag so the next init() call performs a full
     * re-initialization (re-fetches config from the backend).
     */
    fun reset() {
        synchronized(this) {
            if (!initialized) return
            clientProvider.reset()
            configStore.clear()
            initialized = false
        }
        Timber.w("PinVault reset — pinning disabled, re-init required")
    }

    private fun checkInitialized() {
        check(initialized) {
            "PinVault not initialized. Call PinVault.init() first."
        }
    }
}
