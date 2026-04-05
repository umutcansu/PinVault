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
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
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

    // ── Update listener ─────────────────────────────────────────────────────

    /**
     * Listener for background pin update events.
     * Called on the main thread when WorkManager completes a periodic update.
     */
    fun interface OnUpdateListener {
        fun onUpdate(result: UpdateResult)
    }

    @Volatile
    private var updateListener: OnUpdateListener? = null

    fun setOnUpdateListener(listener: OnUpdateListener?) {
        updateListener = listener
    }

    internal fun notifyUpdateResult(result: UpdateResult) {
        updateListener?.onUpdate(result)
    }

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
            val certStore = ClientCertSecureStore(appContext)

            // mTLS: client keystore yükle (öncelik sırası: direct bytes > stored by label > enrollment)
            val p12Bytes = config.clientKeystoreBytes
                ?: certStore.load(config.clientCertLabel)

            if (p12Bytes != null) {
                sslManager.loadClientKeystore(p12Bytes, config.clientKeyPassword)
            }

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
                sslManager = sslManager,
                certStore = certStore,
                clientKeyPassword = config.clientKeyPassword,
                maxRetryCount = config.maxRetryCount
            )

            // Wire up pin recovery: on pin mismatch → auto update + retry + notify UI
            clientProvider.recoveryUpdater = suspend {
                val result = updater.updateNow()
                notifyUpdateResult(result)
                result is UpdateResult.Updated
            }

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
     * If [PinVaultConfig.updateIntervalMinutes] is set, it takes precedence over hours.
     */
    fun schedulePeriodicUpdates(
        intervalHours: Long = pinManagerConfig?.updateIntervalHours
            ?: PinVaultConfig.DEFAULT_UPDATE_INTERVAL_HOURS,
        onScheduled: ((Boolean) -> Unit)? = null
    ) {
        checkInitialized()
        val minutes = pinManagerConfig?.updateIntervalMinutes
        if (minutes != null) {
            updater.schedulePeriodicUpdatesMinutes(minutes, onScheduled)
        } else {
            updater.schedulePeriodicUpdates(intervalHours, onScheduled)
        }
    }

    /**
     * Cancels periodic updates.
     */
    fun cancelPeriodicUpdates() {
        checkInitialized()
        updater.cancelPeriodicUpdates()
    }

    /**
     * Returns info about scheduled pin update tasks.
     */
    fun getScheduledWorkInfo(callback: (List<io.github.umutcansu.pinvault.model.ScheduledTaskInfo>) -> Unit) {
        checkInitialized()
        updater.getScheduledWorkInfo(callback)
    }

    /**
     * Enrolls this device using a one-time token.
     * Downloads P12 client cert from server, stores it encrypted, and loads it for mTLS.
     *
     * @return true if enrollment succeeded
     */
    /**
     * Enrolls this device using a one-time token.
     * Downloads P12 client cert from server, stores it encrypted with the configured label.
     *
     * @param label Optional label override. If null, uses [PinVaultConfig.clientCertLabel].
     * @return true if enrollment succeeded
     */
    suspend fun enroll(context: Context, token: String, label: String? = null): Boolean {
        val config = pinManagerConfig ?: return false
        val certStore = ClientCertSecureStore(context.applicationContext)
        val certLabel = label ?: config.clientCertLabel

        if (certStore.exists(certLabel)) {
            Timber.d("Client cert already exists [%s] — skipping enrollment", certLabel)
            return true
        }

        return try {
            val bootstrapClient = sslManager.buildBootstrapClient(config.bootstrapPins)
            val url = config.configUrl + config.enrollmentEndpoint
            val requestBody = """{"token":"$token"}""".toRequestBody("application/json".toMediaType())
            val request = okhttp3.Request.Builder().url(url).post(requestBody).build()
            val response = bootstrapClient.newCall(request).execute()

            if (!response.isSuccessful) {
                Timber.e("Enrollment failed — HTTP %d", response.code)
                return false
            }

            val p12Bytes = response.body?.bytes() ?: return false
            certStore.save(certLabel, p12Bytes)
            sslManager.loadClientKeystore(p12Bytes, config.clientKeyPassword)

            // Rebuild client with mTLS
            clientProvider.currentConfig?.let { clientProvider.swap(it) }

            Timber.d("Enrollment successful — client cert stored [%s]", certLabel)
            true
        } catch (e: Exception) {
            Timber.e(e, "Enrollment failed")
            false
        }
    }

    /**
     * Automatically enrolls this device using its device ID (no token needed).
     * Config API generates a client cert for this device and returns P12.
     * Call this during init when mTLS hosts are expected.
     *
     * @return true if enrollment succeeded or cert already exists
     */
    suspend fun autoEnroll(context: Context): Boolean {
        val config = pinManagerConfig ?: return false
        val certStore = ClientCertSecureStore(context.applicationContext)
        val certLabel = config.clientCertLabel

        if (certStore.exists(certLabel)) {
            Timber.d("Client cert already exists — skipping auto-enrollment")
            return true
        }

        return try {
            val deviceId = android.provider.Settings.Secure.getString(
                context.contentResolver, android.provider.Settings.Secure.ANDROID_ID
            ) ?: "unknown-device"

            val url = config.configUrl + config.enrollmentEndpoint
            Timber.d("Auto-enrollment: deviceId=%s, url=%s", deviceId, url)

            val bootstrapClient = sslManager.buildBootstrapClient(config.bootstrapPins)
            val requestBody = """{"deviceId":"$deviceId"}""".toRequestBody("application/json".toMediaType())
            val request = okhttp3.Request.Builder().url(url).post(requestBody).build()
            val response = bootstrapClient.newCall(request).execute()

            if (!response.isSuccessful) {
                Timber.e("Auto-enrollment failed — HTTP %d from %s", response.code, url)
                return false
            }

            val p12Bytes = response.body?.bytes() ?: return false
            Timber.d("Auto-enrollment: received P12 (%d bytes)", p12Bytes.size)

            certStore.save(certLabel, p12Bytes)
            sslManager.loadClientKeystore(p12Bytes, config.clientKeyPassword)
            clientProvider.currentConfig?.let { clientProvider.swap(it) }

            Timber.d("Auto-enrollment successful — cert stored [%s], %d bytes, from %s", certLabel, p12Bytes.size, url)
            true
        } catch (e: Exception) {
            Timber.e(e, "Auto-enrollment failed")
            false
        }
    }

    /**
     * Checks if a client certificate is enrolled on this device.
     * @param label Optional label. If null, checks the default label.
     */
    fun isEnrolled(context: Context, label: String? = null): Boolean {
        val store = ClientCertSecureStore(context.applicationContext)
        return store.exists(label ?: ClientCertSecureStore.DEFAULT_LABEL)
    }

    /**
     * Removes the enrolled client certificate from this device.
     * @param label Optional label. If null, removes the default label.
     */
    fun unenroll(context: Context, label: String? = null) {
        val store = ClientCertSecureStore(context.applicationContext)
        store.clear(label ?: ClientCertSecureStore.DEFAULT_LABEL)
        Timber.i("Client certificate removed [%s]", label ?: "default")
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
