package io.github.umutcansu.pinvault

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.EncryptedFileStorageProvider
import io.github.umutcansu.pinvault.store.VaultFileStore
import io.github.umutcansu.pinvault.store.VaultStorageProvider
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
    private lateinit var defaultVaultFileStore: VaultFileStore
    private var vaultStorageProviders: Map<String, VaultStorageProvider> = emptyMap()
    private lateinit var configApi: io.github.umutcansu.pinvault.api.CertificateConfigApi

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

    // ── Vault File listener ─────────────────────────────────────────────

    fun interface OnFileUpdateListener {
        fun onFileUpdate(key: String, result: VaultFileResult)
    }

    @Volatile
    private var fileUpdateListener: OnFileUpdateListener? = null

    fun setOnFileUpdateListener(listener: OnFileUpdateListener?) {
        fileUpdateListener = listener
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

            // ── Vault file storage ─────────────────────────────────────────
            defaultVaultFileStore = VaultFileStore(appContext)
            val encryptedFileProvider by lazy { EncryptedFileStorageProvider(appContext) }
            vaultStorageProviders = config.vaultFiles.mapValues { (_, fileConfig) ->
                fileConfig.storageProvider ?: when (fileConfig.storageStrategy) {
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_FILE -> encryptedFileProvider
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_PREFS -> defaultVaultFileStore
                }
            }

            val resolvedApi = configApi ?: DefaultCertificateConfigApi(
                configUrl = config.configUrl,
                configEndpoint = config.configEndpoint,
                healthEndpoint = config.healthEndpoint,
                signaturePublicKey = config.signaturePublicKey,
                bootstrapPins = config.bootstrapPins,
                sslManager = sslManager
            )
            this.configApi = resolvedApi

            updater = SSLCertificateUpdater(
                context = appContext,
                configApi = resolvedApi,
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

    // ── Vault File API ─────────────────────────────────────────────────

    /**
     * Fetches a vault file from the backend and stores it encrypted.
     *
     * @param key The vault file key registered in [PinVaultConfig].
     * @return [VaultFileResult.Updated], [VaultFileResult.AlreadyCurrent], or [VaultFileResult.Failed].
     */
    suspend fun fetchFile(key: String): VaultFileResult {
        checkInitialized()
        val fileConfig = pinManagerConfig?.vaultFiles?.get(key)
            ?: return VaultFileResult.Failed(key, "Vault file '$key' not registered in config")
        return fetchFileInternal(key, fileConfig)
    }

    /**
     * Loads a cached vault file from encrypted storage.
     * Returns null if the file hasn't been fetched yet.
     */
    fun loadFile(key: String): ByteArray? {
        checkInitialized()
        return getStorageFor(key).load(key)
    }

    /**
     * Loads a cached vault file as a UTF-8 string.
     * Returns null if the file hasn't been fetched yet.
     */
    fun loadFileAsString(key: String): String? {
        return loadFile(key)?.toString(Charsets.UTF_8)
    }

    /**
     * Returns true if a vault file exists in cached storage.
     */
    fun hasFile(key: String): Boolean {
        checkInitialized()
        return getStorageFor(key).exists(key)
    }

    /**
     * Returns the current version of a cached vault file, or 0 if not cached.
     */
    fun fileVersion(key: String): Int {
        checkInitialized()
        return getStorageFor(key).getVersion(key)
    }

    /**
     * Removes a cached vault file from encrypted storage.
     */
    fun clearFile(key: String) {
        checkInitialized()
        getStorageFor(key).clear(key)
        Timber.d("Vault file cleared: %s", key)
    }

    /**
     * Syncs all registered vault files that have [VaultFileConfig.updateWithPins] set to true.
     * Called automatically during periodic updates.
     *
     * @return Map of file key to result.
     */
    suspend fun syncAllFiles(): Map<String, VaultFileResult> {
        checkInitialized()
        val config = pinManagerConfig ?: return emptyMap()
        val results = mutableMapOf<String, VaultFileResult>()
        for ((key, fileConfig) in config.vaultFiles) {
            if (fileConfig.updateWithPins) {
                val result = fetchFileInternal(key, fileConfig)
                results[key] = result
                fileUpdateListener?.onFileUpdate(key, result)
            }
        }
        return results
    }

    private suspend fun fetchFileInternal(key: String, config: VaultFileConfig): VaultFileResult {
        val result = try {
            val storage = getStorageFor(key)
            val currentVersion = storage.getVersion(key)
            val bytes = configApi.downloadVaultFile(config.endpoint)

            // Compare with stored content to determine if updated
            val storedBytes = storage.load(key)
            if (storedBytes != null && bytes.contentEquals(storedBytes)) {
                VaultFileResult.AlreadyCurrent(key, currentVersion)
            } else {
                val newVersion = currentVersion + 1
                storage.save(key, bytes, newVersion)
                Timber.d("Vault file updated: %s (v%d → v%d, %d bytes)", key, currentVersion, newVersion, bytes.size)
                VaultFileResult.Updated(key, newVersion, bytes)
            }
        } catch (e: Exception) {
            Timber.e(e, "Vault file fetch failed: %s", key)
            VaultFileResult.Failed(key, e.message ?: "Unknown error", e)
        }

        // Fire-and-forget report to server
        reportFileDownload(key, result)
        return result
    }

    private suspend fun reportFileDownload(key: String, result: VaultFileResult) {
        val configUrl = pinManagerConfig?.configUrl ?: return
        val version = when (result) {
            is VaultFileResult.Updated -> result.version
            is VaultFileResult.AlreadyCurrent -> result.version
            is VaultFileResult.Failed -> 0
        }
        val status = when (result) {
            is VaultFileResult.Updated -> "downloaded"
            is VaultFileResult.AlreadyCurrent -> "cached"
            is VaultFileResult.Failed -> "failed"
        }
        val label = pinManagerConfig?.clientCertLabel ?: "default"

        kotlinx.coroutines.withContext(Dispatchers.IO) {
            try {
                val json = """{"key":"$key","version":$version,"status":"$status","deviceManufacturer":"${android.os.Build.MANUFACTURER}","deviceModel":"${android.os.Build.MODEL}","enrollmentLabel":"$label","deviceId":"${android.os.Build.MANUFACTURER}_${android.os.Build.MODEL}"}"""
                val url = "${configUrl}api/v1/vault/report"
                val body = json.toRequestBody("application/json".toMediaType())
                val request = okhttp3.Request.Builder().url(url).post(body).build()
                // Use trust-all client for report — self-signed certs, report is non-critical telemetry
                val trustAll = object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
                }
                val sslCtx = javax.net.ssl.SSLContext.getInstance("TLS")
                sslCtx.init(null, arrayOf(trustAll), java.security.SecureRandom())
                val reportClient = okhttp3.OkHttpClient.Builder()
                    .sslSocketFactory(sslCtx.socketFactory, trustAll)
                    .hostnameVerifier { _, _ -> true }
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()
                reportClient.newCall(request).execute().close()
                Timber.d("Vault file report sent: %s → %s", key, status)
            } catch (e: Exception) {
                Timber.e(e, "Failed to report vault file download: %s", key)
            }
        }
    }

    private fun getStorageFor(key: String): VaultStorageProvider {
        return vaultStorageProviders[key] ?: defaultVaultFileStore
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
