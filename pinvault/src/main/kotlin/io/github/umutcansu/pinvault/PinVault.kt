package io.github.umutcansu.pinvault

import android.content.Context
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.internal.ConfigApiClient
import io.github.umutcansu.pinvault.internal.VaultFileRouter
import io.github.umutcansu.pinvault.keystore.DeviceKeyProvider
import io.github.umutcansu.pinvault.model.ConfigApiBlock
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
 * ```kotlin
 * val config = PinVaultConfig.Builder()
 *     .configApi("api", "https://api.example.com/") {
 *         bootstrapPins(listOf(HostPin("api.example.com", listOf("hash1", "hash2"))))
 *     }
 *     .build()
 *
 * // Suspend — Kotlin coroutines:
 * val result = PinVault.init(applicationContext, config)
 *
 * // Callback — Java / non-coroutine callers:
 * PinVault.init(applicationContext, config) { result ->
 *     when (result) {
 *         is InitResult.Ready -> PinVault.applyTo(builder)
 *         is InitResult.Failed -> // hata
 *     }
 * }
 * ```
 */
object PinVault {

    private lateinit var appContext: Context

    // Per-Config-API clients, keyed by ConfigApiBlock.id. The first block is
    // the "primary" and exposes its SSL/client/updater as top-level properties.
    private var configApiClients: Map<String, ConfigApiClient> = emptyMap()

    // Primary mirrors — populated from the first ConfigApiClient (enroll /
    // applyTo / getClient use these).
    private lateinit var sslManager: DynamicSSLManager
    private lateinit var clientProvider: HttpClientProvider
    private lateinit var updater: SSLCertificateUpdater
    private lateinit var configStore: CertificateConfigStore
    private lateinit var defaultVaultFileStore: VaultFileStore
    private var vaultStorageProviders: Map<String, VaultStorageProvider> = emptyMap()
    private lateinit var configApi: io.github.umutcansu.pinvault.api.CertificateConfigApi

    // V2: E2E decryption key material.
    private var deviceKeyProvider: DeviceKeyProvider? = null

    // V2: routes fetchFile() to the correct per-block client.
    private lateinit var vaultRouter: VaultFileRouter

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

    /** Initializes the library with a [PinVaultConfig] (suspend version). */
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

            appContext = context.applicationContext

            // ── Vault file storage (shared across all Config APIs; storage is
            // not scoped per-API because file keys are globally unique).
            defaultVaultFileStore = VaultFileStore(appContext)
            val encryptedFileProvider by lazy { EncryptedFileStorageProvider(appContext) }
            vaultStorageProviders = config.vaultFiles.mapValues { (_, fileConfig) ->
                fileConfig.storageProvider ?: when (fileConfig.storageStrategy) {
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_FILE -> encryptedFileProvider
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_PREFS -> defaultVaultFileStore
                }
            }

            // ── Per-Config-API clients. Static-pin mode has zero blocks and
            // skips this entirely (handled in executeInit).
            val clients = mutableMapOf<String, ConfigApiClient>()
            for ((id, block) in config.configApis) {
                // The legacy configApi override is only applied to the default
                // block — custom backends with multi-API are expected to impl
                // CertificateConfigApi themselves per-block.
                val apiOverride = if (id == config.defaultConfigApi?.id) configApi else null
                clients[id] = ConfigApiClient(
                    block = block,
                    context = appContext,
                    customApi = apiOverride,
                    recoveryListener = { result -> notifyUpdateResult(result) }
                )
            }
            configApiClients = clients

            // ── Legacy primary mirrors (default / first block). These keep
            // the pre-V2 public API (applyTo, getClient, enroll, etc.) working.
            val defaultBlock = config.defaultConfigApi
            if (defaultBlock != null) {
                val defaultClient = clients[defaultBlock.id]!!
                sslManager = defaultClient.sslManager
                clientProvider = defaultClient.clientProvider
                updater = defaultClient.updater
                configStore = defaultClient.configStore
                this.configApi = defaultClient.api
            } else {
                // Static pin-only mode: create minimal placeholders. executeInit
                // will swap in the static config directly.
                sslManager = DynamicSSLManager()
                clientProvider = HttpClientProvider(sslManager)
                configStore = CertificateConfigStore(appContext)
                this.configApi = object : CertificateConfigApi {
                    override suspend fun healthCheck() = true
                    override suspend fun fetchConfig(currentVersion: Int) =
                        config.staticPins ?: io.github.umutcansu.pinvault.model.CertificateConfig(pins = emptyList())
                    override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
                    override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
                    override suspend fun enroll(
                        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?
                    ) = io.github.umutcansu.pinvault.model.EnrollmentResult(ByteArray(0), null)
                }
                updater = SSLCertificateUpdater(
                    context = appContext,
                    configApi = this.configApi,
                    configStore = configStore,
                    httpClientProvider = clientProvider,
                    sslManager = sslManager,
                    certStore = ClientCertSecureStore(appContext),
                    clientKeyPassword = "changeit",
                    maxRetryCount = config.maxRetryCount
                )
            }

            // ── V2 vault router wiring. deviceKeyProvider is created only
            // when at least one vault file declares encryption=END_TO_END.
            val needsE2E = config.vaultFiles.values.any {
                it.encryption == io.github.umutcansu.pinvault.model.VaultFileEncryption.END_TO_END
            }
            deviceKeyProvider = if (needsE2E) {
                DeviceKeyProvider.androidKeystore(appContext).also { it.ensureKeyPair() }
            } else null

            vaultRouter = VaultFileRouter(
                clients = clients,
                storageFor = { key -> getStorageFor(key) },
                deviceKeyProvider = deviceKeyProvider,
                deviceIdProvider = {
                    resolveDeviceIdentity(pinManagerConfig)?.second ?: ""
                }
            )

            initialized = true
            return Unit
        }
    }

    private suspend fun executeInit(): InitResult {
        // Static pin mode — no server contact needed
        val staticConfig = pinManagerConfig?.staticPins
        if (staticConfig != null) {
            Timber.d("Static pin mode — using embedded config (v%d, %d hosts)",
                staticConfig.computedVersion(), staticConfig.pins.size)
            clientProvider.swap(staticConfig)
            configStore.save(staticConfig)
            return InitResult.Ready(staticConfig.computedVersion())
        }

        // V2: initialize ALL Config APIs. The default block's result is
        // returned to the caller (preserves pre-V2 semantics); other blocks'
        // failures are logged but don't fail the init unless the default does.
        val defaultId = pinManagerConfig?.defaultConfigApi?.id
        val results = mutableMapOf<String, InitResult>()
        for ((id, client) in configApiClients) {
            try {
                results[id] = client.initializeAndUpdate()
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] init failed", id)
                results[id] = InitResult.Failed(e.message ?: "init failed", e)
            }
        }

        // V2: register device public key on every Config API for E2E files.
        val kp = deviceKeyProvider
        if (kp != null) {
            val deviceId = resolveDeviceIdentity(pinManagerConfig)?.second ?: "unknown"
            try {
                vaultRouter.registerDevicePublicKey(deviceId, kp.getPublicKeyPem())
            } catch (e: Exception) {
                Timber.w(e, "Device public key registration partially failed")
            }
        }

        val defaultResult = results[defaultId] ?: results.values.firstOrNull()
            ?: return InitResult.Failed("No Config APIs configured", null)

        if (defaultResult is InitResult.Failed) {
            synchronized(this) { initialized = false }
        }

        return defaultResult
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
     * @param label Optional label override. If null, uses the default Config API's clientCertLabel.
     * @return true if enrollment succeeded
     */
    suspend fun enroll(context: Context, token: String, label: String? = null): Boolean {
        val config = pinManagerConfig ?: return false
        val defaultBlock = config.defaultConfigApi ?: return false
        val certStore = ClientCertSecureStore(context.applicationContext)
        val certLabel = label ?: defaultBlock.clientCertLabel

        if (certStore.exists(certLabel)) {
            Timber.d("Client cert already exists [%s] — skipping enrollment", certLabel)
            return true
        }

        return try {
            val identity = resolveDeviceIdentity(config)
            val result = configApi.enroll(
                token = token,
                deviceId = null,
                deviceAlias = identity?.first,
                deviceUid = identity?.second
            )

            validateP12(result.p12Bytes, result.p12Hash, defaultBlock.clientKeyPassword)
            certStore.save(certLabel, result.p12Bytes)
            sslManager.loadClientKeystore(result.p12Bytes, defaultBlock.clientKeyPassword)

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
        val defaultBlock = config.defaultConfigApi ?: return false
        val certStore = ClientCertSecureStore(context.applicationContext)
        val certLabel = defaultBlock.clientCertLabel

        if (certStore.exists(certLabel)) {
            Timber.d("Client cert already exists — skipping auto-enrollment")
            return true
        }

        return try {
            val deviceId = android.provider.Settings.Secure.getString(
                context.contentResolver, android.provider.Settings.Secure.ANDROID_ID
            ) ?: "unknown-device"

            val identity = resolveDeviceIdentity(config)
            Timber.d("Auto-enrollment: deviceId=%s", deviceId)

            val result = configApi.enroll(
                token = null,
                deviceId = deviceId,
                deviceAlias = identity?.first,
                deviceUid = identity?.second
            )

            Timber.d("Auto-enrollment: received P12 (%d bytes)", result.p12Bytes.size)
            validateP12(result.p12Bytes, result.p12Hash, defaultBlock.clientKeyPassword)

            certStore.save(certLabel, result.p12Bytes)
            sslManager.loadClientKeystore(result.p12Bytes, defaultBlock.clientKeyPassword)
            clientProvider.currentConfig?.let { clientProvider.swap(it) }

            Timber.d("Auto-enrollment successful — cert stored [%s], %d bytes", certLabel, result.p12Bytes.size)
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
     * Enrolled client sertifikasının CN (Common Name) alanını döndürür —
     * QA kanıt akışında mobil ekran görüntüsünü sunucudaki kayıtla
     * bire bir eşleştirmek için kullanılır.
     */
    fun enrolledClientCN(context: Context, label: String? = null): String? {
        val store = ClientCertSecureStore(context.applicationContext)
        val p12 = store.load(label ?: ClientCertSecureStore.DEFAULT_LABEL) ?: return null
        val password = pinManagerConfig?.configApis?.values?.firstOrNull()?.clientKeyPassword ?: return null
        return try {
            val ks = java.security.KeyStore.getInstance("PKCS12")
            ks.load(p12.inputStream(), password.toCharArray())
            val alias = ks.aliases().toList().firstOrNull() ?: return null
            val cert = ks.getCertificate(alias) as? java.security.cert.X509Certificate ?: return null
            cert.subjectX500Principal.name
                .substringAfter("CN=", "")
                .substringBefore(",")
                .ifBlank { null }
        } catch (e: Exception) {
            Timber.w(e, "enrolledClientCN: could not parse P12")
            null
        }
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

    private suspend fun fetchFileInternal(key: String, fileConfig: VaultFileConfig): VaultFileResult {
        // V2: delegate the actual fetch + decrypt to VaultFileRouter, then
        // send the distribution report ourselves (has to include deviceAlias
        // / manufacturer / model which live on PinVaultConfig).
        val result = vaultRouter.fetchFile(fileConfig)

        try {
            kotlinx.coroutines.withTimeout(5000) { reportFileDownload(key, fileConfig, result) }
        } catch (_: Exception) {
            Timber.w("Vault file report timed out for: %s", key)
        }
        return result
    }

    private suspend fun reportFileDownload(
        key: String,
        fileConfig: VaultFileConfig,
        result: VaultFileResult
    ) {
        val identity = resolveDeviceIdentity(pinManagerConfig)
        val cfg = pinManagerConfig
        val enrollmentLabel = cfg?.configApis?.get(fileConfig.configApiId)?.clientCertLabel
            ?: cfg?.defaultConfigApi?.clientCertLabel
            ?: "default"

        val report = io.github.umutcansu.pinvault.model.VaultDownloadReport(
            key = key,
            version = when (result) {
                is VaultFileResult.Updated -> result.version
                is VaultFileResult.AlreadyCurrent -> result.version
                is VaultFileResult.Failed -> 0
            },
            status = when (result) {
                is VaultFileResult.Updated -> "downloaded"
                is VaultFileResult.AlreadyCurrent -> "cached"
                is VaultFileResult.Failed -> "failed"
            },
            deviceManufacturer = android.os.Build.MANUFACTURER,
            deviceModel = android.os.Build.MODEL,
            enrollmentLabel = enrollmentLabel,
            deviceId = identity?.second ?: "unknown",
            deviceAlias = identity?.first ?: android.os.Build.MODEL,
            // Başarısız fetch'te UI/debug için sebep gönder. Başarılıda null.
            failureReason = (result as? VaultFileResult.Failed)?.reason,
            // Hangi yetkilendirmeyle fetch denendi — audit için web UI + mobile
            // log'larda görünür. Policy enum'undan türetilir, runtime override yok.
            authMethod = when (fileConfig.accessPolicy) {
                io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.PUBLIC -> "public"
                io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.API_KEY -> "api_key"
                io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.TOKEN -> "token"
                io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.TOKEN_MTLS -> "token_mtls"
            }
        )

        kotlinx.coroutines.withContext(Dispatchers.IO) {
            try {
                vaultRouter.report(fileConfig, report)
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
     * Per-host pin versions from the current config, keyed by hostname.
     * Returns an empty map if no config is loaded.
     */
    fun hostPinVersions(): Map<String, Int> {
        checkInitialized()
        return clientProvider.currentConfig?.pins
            ?.associate { it.hostname to it.version }
            ?: emptyMap()
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
     * Returns (deviceAlias, deviceUid) pair.
     * deviceAlias = user-defined name from config, or Build.MODEL as fallback.
     * deviceUid   = ANDROID_ID (unique per app+device).
     */
    private fun resolveDeviceIdentity(config: PinVaultConfig?): Pair<String, String>? {
        val uid = try {
            android.provider.Settings.Secure.getString(
                appContext.contentResolver, android.provider.Settings.Secure.ANDROID_ID
            ) ?: return null
        } catch (_: Exception) { return null }

        val alias = config?.deviceAlias ?: "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"
        return alias to uid
    }

    /**
     * Validates P12 bytes: checks SHA-256 hash (if server provides it) and PKCS12 format.
     */
    private fun validateP12(p12Bytes: ByteArray, serverHash: String?, password: String) {
        // 1. Hash verification (if server provides X-P12-SHA256 header)
        if (serverHash != null) {
            val localHash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(p12Bytes)
                .let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            if (localHash != serverHash) {
                throw SecurityException("P12 integrity check failed — SHA-256 mismatch (transport corruption or tampering)")
            }
            Timber.d("P12 SHA-256 hash verified")
        } else {
            Timber.w("Server did not provide X-P12-SHA256 header — hash verification skipped")
        }

        // 2. PKCS12 format validation
        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(p12Bytes.inputStream(), password.toCharArray())
        val aliases = ks.aliases().toList()
        if (aliases.isEmpty()) {
            throw SecurityException("P12 keystore contains no entries — invalid certificate")
        }
        Timber.d("P12 format validated — %d entries", aliases.size)
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
