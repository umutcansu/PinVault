package io.github.umutcansu.pinvault

import android.content.Context
import androidx.fragment.app.FragmentActivity
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.internal.ConfigApiClient
import io.github.umutcansu.pinvault.internal.UserAuthPrompt
import io.github.umutcansu.pinvault.internal.VaultFileRouter
import io.github.umutcansu.pinvault.keystore.DeviceKeyProvider
import io.github.umutcansu.pinvault.keystore.KeystoreUserAuthKeys
import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.EnrollmentRefusedException
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.EncryptedFileStorageProvider
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
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

    /**
     * The device identity key behind a CSR-enrolled client certificate, per
     * label. Android Keystore in production; Robolectric tests swap in
     * [io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider.software].
     */
    internal var identityKeyFactory: (label: String) -> io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider =
        { io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider.androidKeystore(it) }

    /**
     * Where a private key that arrived in a PKCS12 is kept: the Android
     * Keystore, non-exportable. Robolectric tests swap in
     * [io.github.umutcansu.pinvault.keystore.ImportedClientKeys.software].
     */
    internal var importedKeysFactory: () -> io.github.umutcansu.pinvault.keystore.ImportedClientKeys =
        { io.github.umutcansu.pinvault.keystore.ImportedClientKeys.androidKeystore() }

    /** What is remembered about each stored vault file (signatures, last confirmation). Tests swap in an in-memory one. */
    internal var vaultFileMetaFactory: (Context) -> io.github.umutcansu.pinvault.store.VaultFileMeta =
        { io.github.umutcansu.pinvault.store.VaultFileMeta.persistent(it) }

    /** Checks a stored vault file every time it is read; set up in [setup]. */
    private var vaultGuard: io.github.umutcansu.pinvault.internal.VaultFileGuard? = null

    /** Keys behind [UserAuth] vault files. Android Keystore in production; tests swap in a software one. */
    internal var userAuthKeysFactory: (Context) -> UserAuthKeys = { context ->
        // Generated with an attestation challenge bound to the device id the
        // library sends (X-Device-Id), so the server can check the chain.
        KeystoreUserAuthKeys(context) { resolveDeviceIdentity(pinManagerConfig, context)?.second }
    }

    /** Where the router keeps which user-auth key it registered with each Config API. */
    internal var userAuthRegistrationsFactory: (Context) -> io.github.umutcansu.pinvault.store.UserAuthRegistrations =
        { io.github.umutcansu.pinvault.store.UserAuthRegistrations.persistent(it) }

    /** The device's user-auth key; null when no vault file uses [UserAuth]. */
    private var userAuthKeys: UserAuthKeys? = null

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

    /**
     * Runtime-attach (or detach) a [io.github.umutcansu.pinvault.api.PinVaultConnectionListener].
     * The builder-time alternative is [PinVaultConfig.Builder.onConnectionEvent].
     *
     * Use this when the listener cannot be constructed before [init] returns
     * — e.g. a [io.github.umutcansu.pinvault.reporter.PinVaultBackendReporter]
     * whose [OkHttpClient] needs [applyTo] for pinning, which in turn requires
     * the active config to already be loaded.
     *
     * Each Config API block's `DynamicSSLManager` receives the listener so
     * handshake events from every per-block client funnel through the same
     * callback. **Replaces any listener previously attached** — whether via
     * `onConnectionEvent(...)` at build time or a prior call to this method.
     * Passing `null` detaches the listener entirely; subsequent events are
     * dropped at the dispatcher.
     *
     * Connection events that fire *before* this method is called (e.g. the
     * bootstrap config fetch handshake) are not delivered — register the
     * listener at builder time via `onConnectionEvent(...)` if you need
     * those too.
     */
    fun setConnectionListener(
        listener: io.github.umutcansu.pinvault.api.PinVaultConnectionListener?
    ) {
        checkInitialized()
        if (configApiClients.isNotEmpty()) {
            configApiClients.values.forEach { it.sslManager.setConnectionListener(listener) }
        } else {
            sslManager.setConnectionListener(listener)
        }
    }

    internal fun notifyUpdateResult(result: UpdateResult) {
        updateListener?.onUpdate(result)
        emitConfigUpdateEvent(result)
    }

    /**
     * Bridges the [UpdateResult] (config-rotation channel) onto the
     * [io.github.umutcansu.pinvault.api.PinVaultConnectionListener] pipe so
     * that consumers subscribing via `onConnectionEvent(...)` see both
     * handshake events and config-rotation events from a single listener.
     * Safe to call before [pinManagerConfig] / [sslManager] are fully
     * wired — the dispatcher short-circuits when no listener is attached.
     */
    private fun emitConfigUpdateEvent(result: UpdateResult) {
        if (!::sslManager.isInitialized) return
        val status = when (result) {
            is UpdateResult.Updated -> io.github.umutcansu.pinvault.api.ConfigUpdateStatus.UPDATED
            UpdateResult.AlreadyCurrent -> io.github.umutcansu.pinvault.api.ConfigUpdateStatus.UNCHANGED
            is UpdateResult.Failed -> io.github.umutcansu.pinvault.api.ConfigUpdateStatus.FAILED
        }
        val newVersion = when (result) {
            is UpdateResult.Updated -> result.newVersion
            UpdateResult.AlreadyCurrent,
            is UpdateResult.Failed -> clientProvider.getVersion()
        }
        val failureReason = (result as? UpdateResult.Failed)?.reason
        sslManager.dispatchEvent(
            io.github.umutcansu.pinvault.api.PinVaultConnectionEvent.ConfigUpdate(
                status = status,
                newVersion = newVersion,
                deviceManufacturer = android.os.Build.MANUFACTURER ?: "",
                deviceModel = android.os.Build.MODEL ?: "",
                failureReason = failureReason
            )
        )
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
        initRefusal(config)?.let { return it }
        pinManagerConfig = config
        return when (val setUp = setupSafely(context, config, null)) {
            is SetUp.Failed -> setUp.result
            SetUp.AlreadyInitialized -> InitResult.Ready(clientProvider.getVersion())
            SetUp.Done -> executeInitSafely()
        }
    }

    /**
     * Initializes the library with a [PinVaultConfig] (callback version).
     */
    fun init(context: Context, config: PinVaultConfig, onResult: (InitResult) -> Unit) {
        initRefusal(config)?.let { return onResult(it) }
        pinManagerConfig = config
        when (val setUp = setupSafely(context, config, null)) {
            is SetUp.Failed -> return onResult(setUp.result)
            SetUp.AlreadyInitialized -> return onResult(InitResult.Ready(clientProvider.getVersion()))
            SetUp.Done -> Unit
        }
        CoroutineScope(Dispatchers.IO).launch {
            val result = executeInitSafely()
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    /**
     * Initializes with a custom [CertificateConfigApi] implementation (suspend).
     * The override is applied to the default (first-registered) Config API block.
     * For multi-API setups, implement one [CertificateConfigApi] per block and
     * branch inside the impl based on the caller's block id.
     *
     * ## Signed configs
     * A block with signing keys (`signaturePublicKey(s)`) gets verified
     * configs or none. `fetchConfig` returns an already parsed config that
     * nothing can verify, so for such a block [configApi] must also implement
     * [io.github.umutcansu.pinvault.api.SignedConfigSource]: PinVault then
     * fetches the signed envelope through it and checks it exactly as it does
     * for its own HTTP client — signatures, `issuedAt` / `expiresAt`, replay,
     * signing-key sets, `serverScope` — and keeps the envelope with the
     * stored config. Without it, init returns [InitResult.Failed] unless the
     * block called `allowUnsigned()`, which says in the app's own code that
     * these configs are not verified (no replay protection, no expiry, no
     * integrity check on the stored config).
     */
    suspend fun init(context: Context, config: PinVaultConfig, configApi: CertificateConfigApi): InitResult {
        initRefusal(config)?.let { return it }
        pinManagerConfig = config
        return when (val setUp = setupSafely(context, config, configApi)) {
            is SetUp.Failed -> setUp.result
            SetUp.AlreadyInitialized -> InitResult.Ready(clientProvider.getVersion())
            SetUp.Done -> executeInitSafely()
        }
    }

    /** Callback variant of [init] with a custom [CertificateConfigApi]. */
    fun init(context: Context, config: PinVaultConfig, configApi: CertificateConfigApi, onResult: (InitResult) -> Unit) {
        initRefusal(config)?.let { return onResult(it) }
        pinManagerConfig = config
        when (val setUp = setupSafely(context, config, configApi)) {
            is SetUp.Failed -> return onResult(setUp.result)
            SetUp.AlreadyInitialized -> return onResult(InitResult.Ready(clientProvider.getVersion()))
            SetUp.Done -> Unit
        }
        CoroutineScope(Dispatchers.IO).launch {
            val result = executeInitSafely()
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    // ── Init (legacy — backward compatible) ───────────────────────────────

    // ── Internal setup ────────────────────────────────────────────────────

    /**
     * The refusal of [config]'s [io.github.umutcansu.pinvault.model.EnvironmentGuard]
     * for [operation], or null when there is no guard or it allows it. A
     * guard that throws refuses (fail closed). Nothing is changed either way.
     */
    internal fun environmentRefusal(
        config: PinVaultConfig?,
        operation: io.github.umutcansu.pinvault.model.GuardedOperation
    ): io.github.umutcansu.pinvault.model.UntrustedEnvironmentException? {
        val guard = config?.environmentGuard ?: return null
        val allowed = try {
            guard.allows(operation)
        } catch (e: Exception) {
            Timber.e(e, "Environment guard threw for %s — refusing", operation)
            return io.github.umutcansu.pinvault.model.UntrustedEnvironmentException(
                operation, "The app's environment guard failed for $operation (${e.javaClass.simpleName}); refused", e
            )
        }
        if (allowed) return null
        Timber.w("Environment guard refused %s", operation)
        return io.github.umutcansu.pinvault.model.UntrustedEnvironmentException(operation)
    }

    /** [InitResult.Failed] when the guard refuses init; the library's state is left as it was. */
    private fun initRefusal(config: PinVaultConfig): InitResult.Failed? =
        environmentRefusal(config, io.github.umutcansu.pinvault.model.GuardedOperation.INIT)
            ?.let { InitResult.Failed(it.message ?: "Refused by the environment guard", it) }

    private fun enrollRefusal(config: PinVaultConfig?): ClientCertEnrollmentResult.Failed? =
        environmentRefusal(config, io.github.umutcansu.pinvault.model.GuardedOperation.ENROLL)
            ?.let { ClientCertEnrollmentResult.Failed(it.message ?: "Refused by the environment guard", it) }

    private sealed class SetUp {
        object Done : SetUp()
        object AlreadyInitialized : SetUp()
        class Failed(val result: InitResult.Failed) : SetUp()
    }

    /**
     * [setup], with a failure of the encrypted storage reported as
     * [InitResult.Failed] instead of thrown at the caller: the stores open
     * with Android Keystore keys, and a Keystore that cannot be used right
     * now — a hiccup, or a locked device under `requireUnlockedDevice()` — is
     * no reason to crash `Application.onCreate`. Nothing is initialized
     * then; call `init` again.
     */
    private fun setupSafely(context: Context, config: PinVaultConfig, configApi: CertificateConfigApi?): SetUp = try {
        applyKeystoreOptions(config)
        if (setup(context, config, configApi) == null) SetUp.AlreadyInitialized else SetUp.Done
    } catch (e: Exception) {
        Timber.e(e, "PinVault setup failed")
        synchronized(this) { initialized = false }
        val locked = config.requireUnlockedDevice && runCatching {
            context.applicationContext.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceLocked == true
        }.getOrDefault(false)
        val reason = if (locked) {
            "PinVault's storage is locked while the device is locked (requireUnlockedDevice): init again once it is unlocked"
        } else {
            "PinVault could not be set up (${e.javaClass.simpleName}: ${e.message}); nothing was initialized"
        }
        SetUp.Failed(InitResult.Failed(reason, e))
    }

    /** `requireUnlockedDevice()` / `requireHardwareBackedKeys()` reach the places that generate Keystore keys without seeing a config. */
    private fun applyKeystoreOptions(config: PinVaultConfig) {
        io.github.umutcansu.pinvault.keystore.KeystoreOptions.unlockedDeviceRequired = config.requireUnlockedDevice
        io.github.umutcansu.pinvault.keystore.KeystoreOptions.hardwareBackedRequired = config.requireHardwareBackedKeys
    }

    /**
     * Where this device's mTLS identity key lives, as the Android Keystore
     * reports it — StrongBox, the TEE, software — or null when no identity
     * key exists yet (nothing enrolled). Read locally, no network. A key an
     * earlier version generated is reported too; [PinVaultConfig.Builder.requireHardwareBackedKeys]
     * applies only to keys generated after it is set.
     */
    fun identityKeySecurityLevel(label: String? = null): io.github.umutcansu.pinvault.model.KeySecurityLevel? {
        val key = identityKeyFactory(label ?: defaultCertLabel())
        return if (key.exists()) key.securityLevel() else null
    }

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
            val keys = if (config.vaultFiles.values.any { it.userAuth != UserAuth.NONE }) userAuthKeysFactory(appContext) else null
            userAuthKeys = keys
            vaultStorageProviders = config.vaultFiles.mapValues { (_, fileConfig) ->
                val storage = fileConfig.storageProvider ?: when (fileConfig.storageStrategy) {
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_FILE -> encryptedFileProvider
                    io.github.umutcansu.pinvault.model.StorageStrategy.ENCRYPTED_PREFS -> defaultVaultFileStore
                }
                if (fileConfig.userAuth == UserAuth.NONE || keys == null) storage
                else UserAuthVaultStorage(
                    storage, keys, fileConfig.userAuth,
                    serverSealedOnly = fileConfig.encryption == io.github.umutcansu.pinvault.model.VaultFileEncryption.USER_AUTH
                )
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
                    recoveryListener = { result -> notifyUpdateResult(result) },
                    identityKeyFactory = identityKeyFactory,
                    // A revoked identity is refused on every request; tell the
                    // app at once, the same way a refused renewal does.
                    reenrollListener = { reason ->
                        dispatchRenewalEvent(id, io.github.umutcansu.pinvault.model.ClientCertRenewalResult.ReenrollRequired(reason))
                    },
                    expiredConfigGraceMs = config.expiredConfigGraceMs,
                    caTrustHosts = config.caTrustHosts,
                    importedKeys = importedKeysFactory(),
                    // The server refused THIS device's certificate: its files go.
                    onIdentityRevoked = { wipeOnRevocation(id) },
                    expectedSignerSha256 = config.expectedSignerSha256,
                    integrityVerdictProvider = config.integrityVerdictProvider,
                    managedTrustRoots = config.managedTrustRoots
                )
            }
            configApiClients = clients

            // ── What is checked every time a stored vault file is read: its
            // signature, and how long ago the server last confirmed it.
            val guard = io.github.umutcansu.pinvault.internal.VaultFileGuard(
                meta = vaultFileMetaFactory(appContext),
                now = { apiId -> configApiClients[apiId]?.trustedClock?.now() ?: System.currentTimeMillis() },
                defaultMaxOfflineAgeMs = config.vaultFileMaxOfflineAgeMs,
                onRemoved = { key, reason -> fileUpdateListener?.onFileUpdate(key, VaultFileResult.Failed(key, reason)) }
            )
            vaultGuard = guard

            // Wire the user-supplied PinVaultConnectionListener into every
            // per-Config-API SSL manager so that pin-verify success / mismatch
            // events surface to the consumer regardless of which block the
            // request was routed through. Listener is opt-in — null is the
            // default and keeps the library completely silent.
            config.connectionListener?.let { listener ->
                clients.values.forEach { it.sslManager.setConnectionListener(listener) }
            }

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
                sslManager.requireCaTrust(config.caTrustHosts)
                sslManager.managedTrustRootsEnabled = config.managedTrustRoots
                config.connectionListener?.let { sslManager.setConnectionListener(it) }
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
                // Static-pin mode never fetches mTLS host certs, so the
                // clientKeyPassword is unused in this branch. Pass an empty
                // string rather than the legacy "changeit" placeholder —
                // a hardcoded password value should never appear in source.
                updater = SSLCertificateUpdater(
                    context = appContext,
                    configApi = this.configApi,
                    configStore = configStore,
                    httpClientProvider = clientProvider,
                    sslManager = sslManager,
                    certStore = ClientCertSecureStore(appContext),
                    clientKeyPassword = "",
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
                },
                userAuthKeys = keys,
                files = { pinManagerConfig?.vaultFiles?.values.orEmpty() },
                registrations = if (keys != null) userAuthRegistrationsFactory(appContext)
                else io.github.umutcansu.pinvault.store.UserAuthRegistrations.InMemory(),
                guard = guard
            )

            initialized = true
            return Unit
        }
    }

    /**
     * [executeInit] behind a safety net: an unexpected failure becomes
     * [InitResult.Failed] (pinning stays fail-closed) instead of an exception
     * that, in the callback variants, would crash the app from a background
     * thread. [LinkageError] is included: it means an API this device lacks.
     */
    private suspend fun executeInitSafely(): InitResult = try {
        executeInit()
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Timber.e(e, "PinVault init failed unexpectedly")
        synchronized(this) { initialized = false }
        InitResult.Failed(e.message ?: e.javaClass.simpleName, e)
    } catch (e: LinkageError) {
        Timber.e(e, "PinVault init failed: this device lacks an API it needs")
        synchronized(this) { initialized = false }
        InitResult.Failed(e.toString(), IllegalStateException(e.toString(), e))
    }

    private suspend fun executeInit(): InitResult {
        // Static pin mode — no server contact needed
        val staticConfig = pinManagerConfig?.staticPins
        if (staticConfig != null) {
            Timber.d("Static pin mode — using embedded config (v%d, %d hosts)",
                staticConfig.computedVersion(), staticConfig.pins.size)
            // Compiled-in pins are held to the same rules as fetched ones:
            // host names that are host names, pins that are SHA-256 hashes.
            try {
                io.github.umutcansu.pinvault.ssl.PinConfigValidator.validate(staticConfig)
            } catch (e: io.github.umutcansu.pinvault.model.InvalidPinFormatException) {
                Timber.e("Static pins refused: %s", e.message)
                synchronized(this) { initialized = false }
                return InitResult.Failed("Static pins are not valid: ${e.message}", e)
            }
            clientProvider.swap(staticConfig)
            configStore.save(staticConfig)
            return InitResult.Ready(staticConfig.computedVersion())
        }

        // V2: initialize ALL Config APIs. The default block's result is
        // returned to the caller (preserves pre-V2 semantics); other blocks'
        // failures are logged but don't fail the init unless the default does.
        val defaultId = pinManagerConfig?.defaultConfigApi?.id

        // A device whose enrollment waited for approval asks again first: once
        // let in, its certificate is what reaches an mTLS Config API below.
        pickUpPendingEnrollments()

        // Keep CSR-enrolled client certificates alive BEFORE the first config
        // fetch: an expired certificate would make that fetch fail on an mTLS
        // Config API, and renewal needs only the bootstrap pins, not a config.
        // The outcome never changes the init result — a failed renewal is
        // retried on the next periodic update.
        for ((id, client) in configApiClients) {
            try {
                emitRenewalEvent(id, client.renewer.renewIfNeeded())
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] client cert renewal check failed", id)
            }
        }

        val results = mutableMapOf<String, InitResult>()
        for ((id, client) in configApiClients) {
            try {
                results[id] = client.initializeAndUpdate()
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] init failed", id)
                results[id] = InitResult.Failed(e.message ?: "init failed", e)
            }
        }

        // Attesting blocks attest once, now that the stored config is loaded
        // and the mTLS renewal check ran, and keep re-attesting in the
        // background. A reject (or a failure) never fails init: the app reads
        // attestationStatus(); no token and no config come through this
        // channel until the next pass.
        for ((id, client) in configApiClients) {
            val attestation = client.attestation ?: continue
            try {
                val status = attestation.attestNow()
                Timber.d("ConfigApi[%s] attestation at init: %s", id, status.result)
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] attestation at init failed", id)
            }
            attestation.start()
        }

        // V2: register device public key on every Config API for E2E files.
        val kp = deviceKeyProvider
        if (kp != null) {
            val deviceId = resolveDeviceIdentity(pinManagerConfig)?.second ?: "unknown"
            try {
                vaultRouter.registerDevicePublicKey(deviceId, kp.getPublicKeyPem(),
                    pinManagerConfig?.vaultFiles?.values.orEmpty())
            } catch (e: Exception) {
                Timber.w(e, "Device public key registration partially failed")
            } catch (e: LinkageError) {
                // An API this device lacks: per-device vault files stay
                // unavailable, everything else keeps working.
                Timber.e(e, "Device public key registration is not supported on this device")
            }
        }

        // The user-auth key goes to every Config API with a user_auth file,
        // so the server can seal those files for it. A key made later (a new
        // one after Android retired the old) is registered before the next
        // such fetch.
        if (userAuthKeys != null) {
            try {
                vaultRouter.registerUserAuthKeyEverywhere(resolveDeviceIdentity(pinManagerConfig)?.second ?: "")
            } catch (e: Exception) {
                Timber.w(e, "User-auth key registration partially failed")
            } catch (e: LinkageError) {
                Timber.e(e, "User-auth key registration is not supported on this device")
            }
        }

        // Files past their offline lifetime go now (wipeWhenStale), whether or
        // not anything reads them.
        wipeStaleVaultFiles()

        val defaultResult = results[defaultId] ?: results.values.firstOrNull()
            ?: return InitResult.Failed("No Config APIs configured", null)

        if (defaultResult is InitResult.Failed) {
            synchronized(this) { initialized = false }
        }

        return defaultResult
    }

    /**
     * Convenience: plants a [Timber.DebugTree] **only if no Timber tree
     * is currently planted**. PinVault uses Timber internally for all of
     * its diagnostic logs (pin verification, config updates, recovery
     * attempts, etc.). Without at least one tree planted, those logs are
     * silently dropped — which is a common cause of "is the recovery
     * interceptor even running?" confusion.
     *
     * This is **opt-in**. PinVault never plants a tree on its own,
     * because the consuming app's logging policy (Crashlytics, custom
     * release tree, structured logger) must stay in control. Most
     * production apps already have their own Timber setup and should
     * skip this entirely.
     *
     * Typical usage in `Application.onCreate`:
     * ```
     * if (BuildConfig.DEBUG) PinVault.enableDebugLogging()
     * ```
     */
    fun enableDebugLogging() {
        if (Timber.treeCount == 0) {
            Timber.plant(Timber.DebugTree())
        }
    }

    /**
     * Applies SSL certificate pinning **and the pin-recovery interceptor**
     * to an existing [OkHttpClient.Builder]. Use this when you maintain
     * your own [OkHttpClient] (custom timeouts, interceptors, dispatchers,
     * etc.) but still want PinVault's automatic recovery on pin mismatch.
     *
     * Equivalent in capability to [getClient]: both wire pinning + recovery.
     * The trust manager is dynamic — the active config is re-read on every
     * TLS handshake, so pins published by [updateNow] or WorkManager swaps
     * apply to the next request the builder issues without re-calling this
     * function and without waiting for the recovery interceptor.
     *
     * ## Connections that are already open
     * A handshake happens once per connection; an HTTP/2 or keep-alive
     * connection, or a resumed TLS session, is not shown to the trust manager
     * again. This call therefore also adds a network interceptor that checks
     * the connection's certificates against the live config — and the
     * config's expiry — before every request, and closes a connection that no
     * longer passes. That is the protection a client built this way has: the
     * connection pool is the app's, the library does not empty it when pins
     * change (it does for [getClient]). Keep the interceptors this call adds;
     * a `builder.networkInterceptors().clear()` afterwards removes the check.
     */
    fun applyTo(builder: OkHttpClient.Builder) {
        checkInitialized()
        if (clientProvider.currentConfig == null) {
            // checkInitialized passed but no config has reached the provider yet —
            // happens in the brief window between setup() and executeInit() on the
            // callback init path. The dynamic trust manager will refuse the first
            // handshake (fail-closed) until updateNow / init populates the config.
            Timber.w(
                "PinVault.applyTo called before initial config arrived — " +
                "TLS handshakes will refuse to connect until init completes."
            )
        }
        sslManager.applyTo(builder) { clientProvider.currentConfig }
        // The token goes on before (outside) the recovery interceptor, so a
        // request the recovery retries still carries it.
        attestationTokenInterceptor()?.let { builder.addInterceptor(it) }
        builder.addInterceptor(clientProvider.recoveryInterceptor)
    }

    /**
     * The interceptor that adds `PinVault-Token` for the token hosts of every
     * attesting block (the default block's first), or null when no block
     * attests. For clients the app owns ([applyTo], [getClient] with settings);
     * each block's own client carries its own block's interceptor.
     */
    private fun attestationTokenInterceptor(): io.github.umutcansu.pinvault.api.AttestationTokenInterceptor? {
        if (configApiClients.values.none { it.attestation != null }) return null
        return io.github.umutcansu.pinvault.api.AttestationTokenInterceptor {
            configApiClients.values.mapNotNull { it.attestation }
        }
    }

    /**
     * Returns a ready-to-use OkHttpClient with current pinning applied.
     *
     * Fail-closed: while no config has been applied yet (callback-style
     * [init] still in flight on a first launch) the client refuses TLS
     * handshakes with a [javax.net.ssl.SSLHandshakeException] instead of
     * silently falling back to system trust. Wait for [InitResult.Ready]
     * before issuing pinned requests.
     */
    fun getClient(): OkHttpClient {
        checkInitialized()
        return clientProvider.get()
    }

    /**
     * Returns a ready-to-use OkHttpClient with current pinning and custom
     * settings. The pin set is re-read on every handshake, so config swaps
     * apply without rebuilding the client; like [getClient] it is fail-closed
     * while no config is loaded.
     *
     * ## Difference from [getClient] and [applyTo] — no pin-mismatch recovery
     * This overload installs **pinning only**. Unlike the no-argument
     * [getClient] and [applyTo], it does NOT add the pin-recovery
     * interceptor, so a pin mismatch surfaces to the caller as an
     * [javax.net.ssl.SSLPeerUnverifiedException] / `SSLHandshakeException`
     * and PinVault does **not** automatically re-fetch the config and retry
     * the request. Rotating the server certificate therefore breaks requests
     * issued through this client until the next config update lands (periodic
     * WorkManager run, or an explicit [updateNow]). When one lands, this
     * client's pooled connections are closed, and — as with every client the
     * library builds or configures — each request re-checks its connection's
     * certificates against the live config. The same goes for expiry:
     * once the config passes its `expiresAt` (plus `expiredConfigGrace`) this
     * client refuses every handshake with a `ConfigExpiredException` cause
     * until something else fetches a fresh config — run
     * [schedulePeriodicUpdates] alongside it.
     *
     * Pick this overload when you want custom timeouts with full control over
     * retry behaviour; use [applyTo] on your own builder when you want custom
     * settings *and* automatic recovery.
     */
    fun getClient(connectionSettings: HttpConnectionSettings): OkHttpClient {
        checkInitialized()
        return sslManager.buildDynamicClient(
            { clientProvider.currentConfig },
            connectionSettings,
            extraInterceptors = listOfNotNull(attestationTokenInterceptor())
        )
    }

    // ── Attestation (ATTESTATION.md) ────────────────────────────────────

    /**
     * Attests the device with a Config API block's server now — measures the
     * app and the device, signs the report with the block's device key, and
     * asks for a verdict — and returns what it came to. On a pass a fresh
     * `PinVault-Token` is held (and a newer signed pin config applied when
     * the server sent one); on a reject there is no token. The library
     * attests on its own at [init], every few minutes while the process
     * lives, and on every periodic update; call this to attest on demand
     * (after the user fixed something, a "check again" button).
     *
     * Single flight per block: a call that arrives while an attestation is
     * running waits for that one. Never throws for a server answer; see
     * [io.github.umutcansu.pinvault.model.AttestationStatus.lastError].
     *
     * @param configApiId the block; null = the default block.
     * @return the block's new status; `UNSUPPORTED` for a block without
     *   `attestation()`, with a custom `CertificateConfigApi`, or for an
     *   unknown id; `FAILED` before [init].
     */
    suspend fun attestNow(configApiId: String? = null): io.github.umutcansu.pinvault.model.AttestationStatus {
        val id = configApiId ?: pinManagerConfig?.defaultConfigApi?.id ?: ""
        if (!initialized) {
            return io.github.umutcansu.pinvault.model.AttestationStatus(
                id, io.github.umutcansu.pinvault.model.AttestationResult.FAILED, lastError = "PinVault not initialized"
            )
        }
        val manager = configApiClients[id]?.attestation ?: return notAttesting(id)
        return manager.attestNow()
    }

    /** Callback variant of [attestNow]; [onResult] runs on the main thread. */
    fun attestNow(
        configApiId: String? = null,
        onResult: (io.github.umutcansu.pinvault.model.AttestationStatus) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            val result = attestNow(configApiId)
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    /**
     * The `PinVault-Token` for requests the app sends through a client of
     * its own (one not built or configured by PinVault): the token held for
     * the block whose token hosts cover [host], attesting first when none
     * with enough life is held. Put it in the header named by
     * [attestationHeaderName]. Clients from [getClient] and [applyTo] add
     * it themselves.
     *
     * @param host a host name (optionally `host:port`); null = the default block.
     * @return the token, or why there is none: `Rejected` with the status,
     *   `Failed` with the reason, `Unsupported` when no attesting block
     *   covers the host.
     */
    suspend fun fetchAttestationToken(host: String? = null): io.github.umutcansu.pinvault.model.AttestationTokenResult {
        if (!initialized) return io.github.umutcansu.pinvault.model.AttestationTokenResult.Failed("PinVault not initialized")
        val manager = if (host == null) {
            pinManagerConfig?.defaultConfigApi?.id?.let { configApiClients[it]?.attestation }
        } else {
            val name = host.substringBefore(':').trim()
            val port = host.substringAfter(':', "").toIntOrNull() ?: -1
            configApiClients.values.mapNotNull { it.attestation }.firstOrNull { it.handlesHost(name, port) }
        }
        return manager?.fetchToken() ?: io.github.umutcansu.pinvault.model.AttestationTokenResult.Unsupported
    }

    /** Callback variant of [fetchAttestationToken]; [onResult] runs on the main thread. */
    fun fetchAttestationToken(
        host: String? = null,
        onResult: (io.github.umutcansu.pinvault.model.AttestationTokenResult) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            val result = fetchAttestationToken(host)
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    /**
     * The last attestation outcome of a Config API block — result, ARC,
     * the reasons and warnings the policy reveals, the token's expiry, when
     * the next attestation is due, the clock skew and the last error. Read
     * locally, no network. `NOT_ATTESTED` before the first round,
     * `UNSUPPORTED` for a block that does not attest or an unknown id.
     *
     * @param configApiId the block; null = the default block.
     */
    @JvmOverloads
    fun attestationStatus(configApiId: String? = null): io.github.umutcansu.pinvault.model.AttestationStatus {
        checkInitialized()
        val id = configApiId ?: pinManagerConfig?.defaultConfigApi?.id ?: ""
        return configApiClients[id]?.attestation?.status ?: notAttesting(id)
    }

    /** The request header the attestation token travels in: `PinVault-Token`. */
    fun attestationHeaderName(): String = io.github.umutcansu.pinvault.api.AttestationTokenInterceptor.HEADER

    private fun notAttesting(configApiId: String) = io.github.umutcansu.pinvault.model.AttestationStatus(
        configApiId = configApiId,
        result = io.github.umutcansu.pinvault.model.AttestationResult.UNSUPPORTED,
        lastError = if (configApiId in configApiClients) {
            "Config API '$configApiId' does not attest: call attestation() on the block"
        } else {
            "No Config API block '$configApiId'"
        }
    )

    /** Every attesting block attests, for the periodic worker. Never throws. */
    internal suspend fun attestAll() {
        if (!initialized) return
        for ((id, client) in configApiClients) {
            val attestation = client.attestation ?: continue
            try {
                attestation.attestNow()
                // A process the worker woke runs no init: the loop starts here.
                attestation.start()
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] periodic attestation failed", id)
            }
        }
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
     * Enrolls this device with a one-time token, or with an enrollment code
     * many devices share. A code whose policy asks for an administrator's
     * approval answers [ClientCertEnrollmentResult.Pending] first (this
     * returns false then); see [checkPendingEnrollment].
     *
     * The device generates a signing key in the Android Keystore, sends a
     * certificate signing request over it, and stores the chain the server
     * issues; the private key never leaves the device and the certificate is
     * renewed automatically from then on (see [renewClientCertIfNeeded]).
     * The key is generated with an Android key attestation challenge made
     * from the device id of the request, and its attestation chain goes
     * along, so a server that verifies the chain can tell a key the Android
     * Keystore made for this package, on hardware whose attestation root it
     * trusts, from a key made in software or by other code; the chain speaks
     * for where the key lives and which app asked for it, not for the state
     * of the device beyond what verified boot records (see `ATTESTATION.md`
     * for the device measurement).
     *
     * A server that answers with a key of its own making (a P12) is refused
     * unless the block called `allowServerGeneratedKey()`; so is enrolling
     * at all when the Keystore cannot make a key.
     *
     * @param label Optional label override. If null, uses the default Config API's clientCertLabel.
     * @return true if enrollment succeeded (or a credential already exists);
     *         [enrollForResult] says why it did not
     */
    suspend fun enroll(context: Context, token: String, label: String? = null): Boolean =
        enrollForResult(context, token, label) is ClientCertEnrollmentResult.Enrolled

    /**
     * [enroll], with the reason when it does not work: a refusal the user can
     * act on (a used token, a device enrolled under another id, a revoked id),
     * a wait for an administrator's approval ([ClientCertEnrollmentResult.Pending])
     * or a failure to reach the server. See [ClientCertEnrollmentResult].
     */
    suspend fun enrollForResult(context: Context, token: String, label: String? = null): ClientCertEnrollmentResult =
        enrollInternal(context, token = token, deviceId = null, label = label)

    /**
     * Automatically enrolls this device using its device ID (no token needed).
     * Call this during init when mTLS hosts are expected. Same credential
     * flow as [enroll].
     *
     * A server that takes applications without a token only after an
     * administrator's approval (the reference server's "code-less applications")
     * answers [ClientCertEnrollmentResult.Pending]: show the device's
     * [enrollmentVerificationCode] and wait — see [checkPendingEnrollment].
     *
     * @return true if enrollment succeeded or cert already exists;
     *         [autoEnrollForResult] says why it did not
     */
    suspend fun autoEnroll(context: Context): Boolean =
        autoEnrollForResult(context) is ClientCertEnrollmentResult.Enrolled

    /** [autoEnroll], with the reason when it does not work. See [enrollForResult]. */
    suspend fun autoEnrollForResult(context: Context): ClientCertEnrollmentResult {
        // SECURITY NOTE (M-02): ANDROID_ID is a soft identifier. On rooted
        // devices it can be spoofed; on multi-user devices it is per-user.
        // Treat the resulting enrollment as a convenience credential, not
        // a hardware-attested identity. For high-assurance use cases, send a
        // Play Integrity verdict with integrityTokenProvider and have the
        // server enforce it (INTEGRITY_VERIFICATION=enforce).
        val androidId = io.github.umutcansu.pinvault.internal.DeviceIdentity.androidId(context)
        val deviceId = androidId ?: "unknown-device"
        // The id itself stays out of the log: it identifies the device.
        Timber.d("Auto-enrollment: device id available: %b", androidId != null)
        return enrollInternal(context, token = null, deviceId = deviceId, label = null)
    }

    /**
     * Enrolls before [init] — the first start of an app whose Config API is
     * an mTLS listener. The device has no client certificate yet, so `init`
     * cannot reach that API; enroll first, then init once:
     *
     * ```kotlin
     * if (!PinVault.isEnrolled(context, config)) PinVault.enroll(context, config, token)
     * PinVault.init(context, config)
     * ```
     *
     * Goes to the default block's `enrollmentUrl` (a TLS listener). The
     * credential is stored; the next [init] loads it. When PinVault is
     * already initialized this is the same as [enroll] without a config.
     *
     * @return true if enrollment succeeded (or a credential already exists);
     *         [enrollForResult] says why it did not
     */
    suspend fun enroll(context: Context, config: PinVaultConfig, token: String): Boolean =
        enrollForResult(context, config, token) is ClientCertEnrollmentResult.Enrolled

    /** [enroll] before [init], with the reason when it does not work. See [ClientCertEnrollmentResult]. */
    suspend fun enrollForResult(context: Context, config: PinVaultConfig, token: String): ClientCertEnrollmentResult =
        enrollBeforeInit(context, config, token = token, deviceId = null)

    /** [autoEnroll] before [init]; see [enroll] with a config. */
    suspend fun autoEnroll(context: Context, config: PinVaultConfig): Boolean =
        autoEnrollForResult(context, config) is ClientCertEnrollmentResult.Enrolled

    /** [autoEnroll] before [init], with the reason when it does not work. */
    suspend fun autoEnrollForResult(context: Context, config: PinVaultConfig): ClientCertEnrollmentResult {
        val deviceId = io.github.umutcansu.pinvault.internal.DeviceIdentity
            .androidId(context) ?: "unknown-device"
        return enrollBeforeInit(context, config, token = null, deviceId = deviceId)
    }

    /**
     * Whether the default block of [config] has an enrolled client certificate. Usable before [init].
     *
     * From Java this is `isEnrolledWithConfig`: a second `isEnrolled(Context, …)` would make
     * every existing `isEnrolled(context, null)` call ambiguous.
     */
    @JvmName("isEnrolledWithConfig")
    fun isEnrolled(context: Context, config: PinVaultConfig): Boolean {
        applyKeystoreOptions(config)
        return ClientCertSecureStore(context.applicationContext)
            .exists(config.defaultConfigApi?.clientCertLabel ?: ClientCertSecureStore.DEFAULT_LABEL)
    }

    /**
     * The verification code of this device's enrollment key, `4F7K-2QXM-9D3T-H6WP`
     * (80 bits of the key's SHA-256; the first eight characters are the code
     * earlier versions showed): the
     * administrator sees the same code next to the device's request while it
     * waits for approval, so it is what the app shows on its "waiting" screen.
     * Null when there is no enrollment key (never applied, or unenrolled).
     *
     * @param label Optional label. If null, uses the default Config API's `clientCertLabel`.
     */
    fun enrollmentVerificationCode(context: Context, label: String? = null): String? {
        val key = identityKeyFactory(label ?: defaultCertLabel())
        return try {
            if (key.exists()) io.github.umutcansu.pinvault.internal.VerificationCode.of(key.publicKey()) else null
        } catch (e: Exception) {
            Timber.w(e, "Could not read the enrollment key for its verification code")
            null
        }
    }

    /**
     * Whether this device enrolled with a code that waits for an
     * administrator's approval ([ClientCertEnrollmentResult.Pending]) and has
     * no certificate yet. [checkPendingEnrollment] asks again; [init] and the
     * periodic update ask on their own. [unenroll] gives the request up.
     *
     * @param label Optional label. If null, uses the default Config API's `clientCertLabel`.
     */
    fun isEnrollmentPending(context: Context, label: String? = null): Boolean {
        val store = ClientCertSecureStore(context.applicationContext)
        val certLabel = label ?: defaultCertLabel()
        return !store.exists(certLabel) && store.loadPendingRequest(certLabel) != null
    }

    /**
     * [isEnrollmentPending] for the default block of [config]; usable before [init].
     * From Java this is `isEnrollmentPendingWithConfig` (see [isEnrolled]).
     */
    @JvmName("isEnrollmentPendingWithConfig")
    fun isEnrollmentPending(context: Context, config: PinVaultConfig): Boolean {
        applyKeystoreOptions(config)
        return isEnrollmentPending(context, config.defaultConfigApi?.clientCertLabel ?: ClientCertSecureStore.DEFAULT_LABEL)
    }

    /**
     * Asks whether a device that was told to wait
     * ([ClientCertEnrollmentResult.Pending]) has been approved:
     * [ClientCertEnrollmentResult.Enrolled] once it has — the certificate is
     * stored and presented from then on — `Pending` while it still waits, and
     * `Refused` with [io.github.umutcansu.pinvault.model.EnrollmentRefusal.REJECTED]
     * when an administrator turned it away. Call it while a "waiting for
     * approval" screen is up; [init] and the periodic update ask on their own.
     */
    suspend fun checkPendingEnrollment(context: Context): ClientCertEnrollmentResult {
        pendingCheckShortcut(context, defaultCertLabel())?.let { return it }
        return enrollInternal(context, token = null, deviceId = null, label = null)
    }

    /** [checkPendingEnrollment] for the default block of [config]; usable before [init]. */
    suspend fun checkPendingEnrollment(context: Context, config: PinVaultConfig): ClientCertEnrollmentResult {
        if (initialized) return checkPendingEnrollment(context)
        applyKeystoreOptions(config)
        val block = config.defaultConfigApi ?: return NO_CONFIG_API_BLOCK
        pendingCheckShortcut(context, block.clientCertLabel)?.let { return it }
        return enrollBeforeInit(context, config, token = null, deviceId = null)
    }

    /** Enrolled already, or nothing waiting: answered without asking the server. */
    private fun pendingCheckShortcut(context: Context, certLabel: String): ClientCertEnrollmentResult? = try {
        val store = ClientCertSecureStore.openStrict(context.applicationContext)
        when {
            store.exists(certLabel) -> ClientCertEnrollmentResult.Enrolled(alreadyEnrolled = true)
            store.loadPendingRequest(certLabel) == null -> ClientCertEnrollmentResult.Failed("No enrollment is waiting for approval")
            else -> null
        }
    } catch (e: Exception) {
        credentialStoreUnreadable(certLabel, e)
    }

    /**
     * The enroll paths read the credential store strictly: a credential that
     * cannot be read right now (a Keystore failure) must not look like none
     * — a new enrollment would replace it, and a refused one may delete the
     * key it was issued over. Nothing is sent then.
     */
    private fun credentialStoreUnreadable(certLabel: String, e: Exception): ClientCertEnrollmentResult.Failed {
        Timber.e(e, "Client credential store cannot be read right now [%s] — not enrolling", certLabel)
        return ClientCertEnrollmentResult.Failed(
            "The stored client credentials cannot be read right now (${e.javaClass.simpleName}: ${e.message}); nothing was sent — try again later", e
        )
    }

    /** True when a credential is stored under [certLabel]; throws when that cannot be told right now. */
    private fun hasStoredCredential(context: Context, certLabel: String): Boolean =
        ClientCertSecureStore.openStrict(context.applicationContext).exists(certLabel)

    /**
     * A device told to wait asks again on its own: at [init] (before the
     * first config fetch, so an mTLS Config API is reachable once approved)
     * and on every periodic update. Never throws.
     */
    internal suspend fun pickUpPendingEnrollments() {
        if (!initialized) return
        val certLabel = defaultCertLabel()
        val waiting = try {
            val store = ClientCertSecureStore.openStrict(appContext)
            !store.exists(certLabel) && store.loadPendingRequest(certLabel) != null
        } catch (e: Exception) {
            Timber.w(e, "Client credential store cannot be read right now [%s] — pending enrollment not checked", certLabel)
            false
        }
        if (!waiting) return
        when (val result = enrollInternal(appContext, token = null, deviceId = null, label = null)) {
            is ClientCertEnrollmentResult.Enrolled -> Timber.i("Enrollment approved — client certificate stored [%s]", certLabel)
            is ClientCertEnrollmentResult.Pending -> Timber.d("Enrollment still waits for approval [%s]", certLabel)
            else -> if ((result as? ClientCertEnrollmentResult.Failed)?.cause is io.github.umutcansu.pinvault.model.UntrustedEnvironmentException) {
                Timber.w("Pending enrollment not checked: the environment guard refused it [%s]", certLabel)
            } else {
                Timber.w("Enrollment waiting for approval ended: %s", result)
            }
        }
    }

    private suspend fun enrollBeforeInit(context: Context, config: PinVaultConfig, token: String?, deviceId: String?): ClientCertEnrollmentResult {
        if (initialized) return enrollInternal(context, token, deviceId, label = null)
        enrollRefusal(config)?.let { return it }
        applyKeystoreOptions(config)
        val block = config.defaultConfigApi ?: return NO_CONFIG_API_BLOCK
        val certLabel = block.clientCertLabel
        val stored = try { hasStoredCredential(context, certLabel) } catch (e: Exception) { return credentialStoreUnreadable(certLabel, e) }
        if (stored) {
            Timber.d("Client cert already exists [%s] — skipping enrollment", certLabel)
            return ClientCertEnrollmentResult.Enrolled(alreadyEnrolled = true)
        }
        // The same rule init applies: https and bootstrap pins, or an explicit opt-out.
        block.configurationError()?.let { return ClientCertEnrollmentResult.Failed(it) }
        return try {
            // A client for the block alone — the library's state is untouched;
            // the next init picks the stored credential up.
            applyKeystoreOptions(config)
            val api = ConfigApiClient(
                block, context.applicationContext, identityKeyFactory = identityKeyFactory, importedKeys = importedKeysFactory()
            ).api
            val enrolled = enrollAndStore(context, config, block, api, token, deviceId, certLabel)
            ClientCertEnrollmentResult.Enrolled(keySecurityLevel = enrolled.keySecurityLevel())
        } catch (e: Exception) {
            enrollmentFailure(e)
        }
    }

    private suspend fun enrollInternal(context: Context, token: String?, deviceId: String?, label: String?): ClientCertEnrollmentResult {
        val config = pinManagerConfig ?: return ClientCertEnrollmentResult.Failed(
            "PinVault is not initialized: call init first, or enroll with the config before init"
        )
        enrollRefusal(config)?.let { return it }
        val defaultBlock = config.defaultConfigApi ?: return NO_CONFIG_API_BLOCK
        val certLabel = label ?: defaultBlock.clientCertLabel

        val stored = try { hasStoredCredential(context, certLabel) } catch (e: Exception) { return credentialStoreUnreadable(certLabel, e) }
        if (stored) {
            Timber.d("Client cert already exists [%s] — skipping enrollment", certLabel)
            return ClientCertEnrollmentResult.Enrolled(alreadyEnrolled = true)
        }

        return try {
            val enrolled = enrollAndStore(context, config, defaultBlock, configApi, token, deviceId, certLabel)
            when (enrolled) {
                is Enrolled.Chain -> sslManager.loadClientKey(enrolled.key.privateKey(), enrolled.certs.toTypedArray())
                is Enrolled.Imported -> sslManager.loadClientKey(enrolled.privateKey, enrolled.certs)
                is Enrolled.P12 -> sslManager.loadClientKeystore(enrolled.bytes, defaultBlock.clientKeyPassword)
            }
            // Present the new identity on every client, the Config API's included.
            (configApi as? DefaultCertificateConfigApi)?.rebuildBootstrapClient()
            clientProvider.currentConfig?.let { clientProvider.swap(it) }
            ClientCertEnrollmentResult.Enrolled(keySecurityLevel = enrolled.keySecurityLevel())
        } catch (e: Exception) {
            enrollmentFailure(e)
        }
    }

    private sealed class Enrolled {
        class Chain(val key: io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider, val certs: List<java.security.cert.X509Certificate>) : Enrolled()
        /** A server-made key (`allowServerGeneratedKey()`), now a non-exportable Keystore key. */
        class Imported(val privateKey: java.security.PrivateKey, val certs: Array<java.security.cert.X509Certificate>) : Enrolled()
        /** A server-made key the platform refused to import: kept as a PKCS12. */
        class P12(val bytes: ByteArray) : Enrolled()

        /** Where the private key of this enrollment lives, as the Keystore reports it. */
        fun keySecurityLevel(): io.github.umutcansu.pinvault.model.KeySecurityLevel = when (this) {
            is Chain -> runCatching { key.securityLevel() }.getOrDefault(io.github.umutcansu.pinvault.model.KeySecurityLevel.UNKNOWN)
            is Imported -> io.github.umutcansu.pinvault.keystore.KeyInspector.securityLevel(privateKey)
            // A PKCS12 in app storage: software by definition.
            is P12 -> io.github.umutcansu.pinvault.model.KeySecurityLevel.SOFTWARE
        }
    }

    private val NO_CONFIG_API_BLOCK = ClientCertEnrollmentResult.Failed("The config has no Config API block")

    /** A refusal the app can act on (with the server's reason), or a failure to get an answer. */
    private fun enrollmentFailure(e: Exception): ClientCertEnrollmentResult {
        if (e is io.github.umutcansu.pinvault.model.EnrollmentPendingException) {
            Timber.i("Enrollment waits for an administrator's approval — request %s", e.requestId)
            return ClientCertEnrollmentResult.Pending(e.requestId, e.clientId, e.serverMessage, e.retryAfterSeconds, e.verificationCode)
        }
        Timber.e(e, "Enrollment failed")
        return if (e is EnrollmentRefusedException) {
            ClientCertEnrollmentResult.Refused(e.refusal, e.httpStatus, e.serverError, e.serverMessage)
        } else {
            ClientCertEnrollmentResult.Failed(e.message ?: e.javaClass.simpleName, e)
        }
    }

    /**
     * Enrollment through [api] for [block], stored under [certLabel]: a CSR
     * over a fresh Keystore key — attested when the device can — answered
     * with a certificate chain. Only a block that called
     * `allowServerGeneratedKey()` also takes a key the server made (a P12
     * answer, or P12 enrollment when the Keystore cannot make a key); that
     * key is then imported into the Keystore. Throws on failure; stores
     * nothing then.
     */
    private suspend fun enrollAndStore(
        context: Context,
        config: PinVaultConfig,
        block: ConfigApiBlock,
        api: CertificateConfigApi,
        token: String?,
        deviceId: String?,
        certLabel: String
    ): Enrolled {
        applyKeystoreOptions(config)
        // Strict: what EnrollmentRequests reads here decides whether a key may go.
        val certStore = ClientCertSecureStore.openStrict(context.applicationContext)
        val identity = resolveDeviceIdentity(config, context)
        val key = identityKeyFactory(certLabel)
        // The device id this request carries: `deviceUid` on every path, and
        // `deviceId` alone when the device has no ANDROID_ID to send as one.
        // The key's attestation challenge is made from it, so the server can
        // tell the key was generated for this request's device.
        val attestedId = identity?.second ?: deviceId
        val challenge = attestedId?.takeIf { it.isNotBlank() }
            ?.let { io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider.attestationChallenge(it) }

        // A device told to wait for approval asks again by its request id (see EnrollmentRequests).
        val result = io.github.umutcansu.pinvault.internal.EnrollmentRequests.send(
            api, certStore, key, certLabel, token, deviceId, identity?.first, identity?.second,
            allowServerGeneratedKey = block.allowServerGeneratedKey,
            integrity = config.integrityTokenProvider
        ) {
            try {
                key.ensureKeyPair(challenge)
                io.github.umutcansu.pinvault.crypto.Pkcs10Csr.encode(
                    deviceId ?: identity?.second ?: "device", key.publicKey(), key::sign
                )
            } catch (e: Exception) {
                // Some ROMs' Keystores refuse. Only a block that asked for it
                // falls back to a key the server makes.
                if (!block.allowServerGeneratedKey) {
                    throw IllegalStateException(
                        "This device could not create its key in the Android Keystore (${e.javaClass.simpleName}: ${e.message}), " +
                            "and the Config API block does not accept a key the server generates. Nothing was sent; the " +
                            "token is not spent. Call allowServerGeneratedKey() on the block only if such a key is acceptable.",
                        e
                    )
                }
                Timber.w(e, "Could not build a CSR — asking the server for a key (allowServerGeneratedKey)")
                null
            }
        }

        val chain = result.certificateChainPem
        if (chain != null) {
            val certs = io.github.umutcansu.pinvault.internal.ClientCertRenewer.acceptIssuedChain(
                chain, key, expectedIssuer = null, caPins = block.clientCaPins, maxLifetimeDays = block.maxClientCertLifetimeDays
            )
            certStore.saveChain(certLabel, chain)
            Timber.d("Enrollment successful — certificate chain stored, valid until %s", certs[0].notAfter)
            return Enrolled.Chain(key, certs)
        }

        // Only reached with allowServerGeneratedKey(): the server made the key.
        val p12 = acceptEnrolledP12(result, block.clientKeyPassword)
        // No orphan identity key next to a server-made one — unless a chain
        // under this label is over it (never deleted then; see EnrollmentRequests).
        if (io.github.umutcansu.pinvault.internal.EnrollmentRequests.mayDeleteKey(certStore, certLabel)) runCatching { key.clear() }
        val imported = try {
            io.github.umutcansu.pinvault.internal.ImportedIdentities(certStore, importedKeysFactory())
                .import(certLabel, p12, block.clientKeyPassword)
        } catch (e: Exception) {
            Timber.w(e, "The enrolled PKCS12 could not be read for import")
            null
        }
        if (imported != null) {
            p12.fill(0)
            Timber.d("Enrollment successful — server-made key imported into the Android Keystore, chain stored")
            return Enrolled.Imported(imported.privateKey, imported.chain)
        }
        certStore.save(certLabel, p12)
        Timber.w("Enrollment successful — the Keystore refused the server-made key; stored as a PKCS12 (%d bytes)", p12.size)
        return Enrolled.P12(p12)
    }

    // ── Client certificate renewal ──────────────────────────────────────

    /**
     * Renews the client certificate of a Config API block when its remaining
     * lifetime is below the block's threshold, or always with [force].
     * Runs on its own at init and on every periodic update; call it to
     * renew on demand (a "Renew" button, a re-try after a failure).
     *
     * @param configApiId the block; null = the default block.
     */
    suspend fun renewClientCertIfNeeded(
        configApiId: String? = null,
        force: Boolean = false
    ): io.github.umutcansu.pinvault.model.ClientCertRenewalResult {
        if (!initialized) {
            return io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Failed("PinVault not initialized")
        }
        val id = configApiId ?: pinManagerConfig?.defaultConfigApi?.id
        val client = id?.let { configApiClients[it] }
            ?: return io.github.umutcansu.pinvault.model.ClientCertRenewalResult.NotApplicable
        return client.renewer.renewIfNeeded(force).also { emitRenewalEvent(client.block.id, it) }
    }

    /** Callback variant of [renewClientCertIfNeeded]; [onResult] runs on the main thread. */
    fun renewClientCertIfNeeded(
        configApiId: String? = null,
        force: Boolean = false,
        onResult: (io.github.umutcansu.pinvault.model.ClientCertRenewalResult) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            val result = renewClientCertIfNeeded(configApiId, force)
            kotlinx.coroutines.withContext(Dispatchers.Main) { onResult(result) }
        }
    }

    /**
     * Config fetch for every block but the default one (the worker updates
     * that through [updateNow]), so their configs do not run past `expiresAt`
     * in a long-lived process. Never throws.
     */
    internal suspend fun updateOtherConfigApis() {
        if (!initialized) return
        val defaultId = pinManagerConfig?.defaultConfigApi?.id
        for ((id, client) in configApiClients) {
            if (id == defaultId) continue
            try {
                client.updateNow()
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] periodic config update failed", id)
            }
        }
    }

    /** Every block's renewal check, for the periodic worker. Never throws. */
    internal suspend fun renewClientCertsIfNeeded() {
        if (!initialized) return
        for ((id, client) in configApiClients) {
            try {
                emitRenewalEvent(id, client.renewer.renewIfNeeded())
            } catch (e: Exception) {
                Timber.e(e, "ConfigApi[%s] client cert renewal failed", id)
            }
        }
    }

    private fun emitRenewalEvent(configApiId: String, result: io.github.umutcansu.pinvault.model.ClientCertRenewalResult) {
        // No wipe here: a refused renewal wipes only when it went over mTLS
        // presenting the current certificate, and the renewer has done that
        // already (ConfigApiClient's onRefusedOverMtls). The same answer on
        // the recovery door — TLS, no client certificate, so from a listener
        // that saw no identity — only reaches the app as the event.
        // The refusal that made renewal fail may already have been reported
        // from the request itself; the app hears it once per identity.
        if (result is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.ReenrollRequired &&
            configApiClients[configApiId]?.claimReenrollNotice() == false
        ) return
        dispatchRenewalEvent(configApiId, result)
    }

    /**
     * `wipeVaultFilesOnRevocation()`: deletes the files of a Config API whose
     * server refused this device's identity. Called only for an answer that
     * was about that identity — a `reenroll_required` on a connection that
     * presented the certificate, or the answer to its own renewal over that
     * mTLS connection (never one from the recovery door). A bare
     * `403 reenroll_required` on a connection without a client certificate
     * (a TLS-only block, a request before enrollment) reaches the app as the
     * event, and deletes nothing.
     */
    private fun wipeOnRevocation(configApiId: String) {
        if (pinManagerConfig?.wipeVaultFilesOnRevocation == true) wipeVaultFilesOf(setOf(configApiId))
    }

    private fun dispatchRenewalEvent(configApiId: String, result: io.github.umutcansu.pinvault.model.ClientCertRenewalResult) {
        if (!::sslManager.isInitialized) return
        val status = when (result) {
            is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Renewed -> io.github.umutcansu.pinvault.api.ClientCertRenewalStatus.RENEWED
            is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.NotNeeded -> io.github.umutcansu.pinvault.api.ClientCertRenewalStatus.NOT_NEEDED
            is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.ReenrollRequired -> io.github.umutcansu.pinvault.api.ClientCertRenewalStatus.REENROLL_REQUIRED
            is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Failed -> io.github.umutcansu.pinvault.api.ClientCertRenewalStatus.FAILED
            io.github.umutcansu.pinvault.model.ClientCertRenewalResult.NotApplicable -> return
        }
        sslManager.dispatchEvent(
            io.github.umutcansu.pinvault.api.PinVaultConnectionEvent.ClientCertRenewal(
                status = status,
                notAfterEpochMs = when (result) {
                    is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Renewed -> result.notAfterEpochMs
                    is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.NotNeeded -> result.notAfterEpochMs
                    else -> 0L
                },
                via = (result as? io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Renewed)?.via,
                configApiId = configApiId,
                deviceManufacturer = android.os.Build.MANUFACTURER ?: "",
                deviceModel = android.os.Build.MODEL ?: "",
                failureReason = when (result) {
                    is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.Failed -> result.reason
                    is io.github.umutcansu.pinvault.model.ClientCertRenewalResult.ReenrollRequired -> result.reason
                    else -> null
                }
            )
        )
    }

    /**
     * The storage label [enroll] / [autoEnroll] write to when the caller does
     * not pass one explicitly: the default Config API block's
     * `clientCertLabel`, falling back to the store default when the library
     * has not been configured yet.
     *
     * [isEnrolled], [unenroll] and [enrolledClientCN] used to fall back to
     * [ClientCertSecureStore.DEFAULT_LABEL] directly. With a custom
     * `clientCertLabel(...)` that meant enrollment wrote to one key while the
     * status/removal calls read another — `isEnrolled` returned false right
     * after a successful enroll and `unenroll` deleted nothing. All four paths
     * now resolve the label the same way.
     */
    private fun defaultCertLabel(): String =
        pinManagerConfig?.defaultConfigApi?.clientCertLabel
            ?: ClientCertSecureStore.DEFAULT_LABEL

    /**
     * Checks if a client certificate is enrolled on this device.
     * @param label Optional label. If null, uses the default Config API's
     *        `clientCertLabel` — the same label [enroll] writes to.
     */
    fun isEnrolled(context: Context, label: String? = null): Boolean {
        val store = ClientCertSecureStore(context.applicationContext)
        return store.exists(label ?: defaultCertLabel())
    }

    /**
     * Removes the enrolled client certificate from this device.
     *
     * Also gives up an enrollment that waits for approval (and its key).
     *
     * Clears both the persisted P12 **and** the in-memory KeyManager, then
     * rebuilds the active client so the very next request stops presenting a
     * client certificate. (Previously only the store was cleared, so mTLS kept
     * working from the loaded KeyManager until the process restarted.)
     *
     * @param label Optional label. If null, uses the default Config API's
     *        `clientCertLabel` — the same label [enroll] writes to.
     */
    fun unenroll(context: Context, label: String? = null) {
        val certLabel = label ?: defaultCertLabel()
        val store = ClientCertSecureStore(context.applicationContext)
        store.clear(certLabel)
        // The identity key behind a CSR-enrolled certificate goes with it: a
        // re-enrollment is a new identity, not the old key with a new cert.
        runCatching { identityKeyFactory(certLabel).clear() }
            .onFailure { Timber.w(it, "Could not delete the client identity key [%s]", certLabel) }
        // So does a server-made key that was imported into the Keystore.
        runCatching {
            importedKeysFactory().delete(io.github.umutcansu.pinvault.keystore.ImportedClientKeys.aliasFor(certLabel))
        }.onFailure { Timber.w(it, "Could not delete the imported client key [%s]", certLabel) }

        // Drop the live key material too. Guarded on `initialized` because
        // unenroll is callable before/after init (QA flows call it on a cold
        // process), and the primary mirrors are only populated by setup().
        if (initialized) {
            configApiClients.values.forEach { client ->
                client.sslManager.clearClientKeystore()
                (client.api as? DefaultCertificateConfigApi)?.rebuildBootstrapClient()
                client.clientProvider.currentConfig?.let { client.clientProvider.swap(it) }
            }
            if (configApiClients.isEmpty()) {
                sslManager.clearClientKeystore()
                clientProvider.currentConfig?.let { clientProvider.swap(it) }
            }
        }

        Timber.i("Client certificate removed [%s] — client cert no longer presented", certLabel)
    }

    /**
     * [unenroll], and with [wipeVaultFiles] also deletes the vault files of
     * every Config API that uses the client certificate stored under that
     * label for mTLS: its `clientCertLabel` is that label AND it names an
     * `enrollmentUrl` or `renewalUrl`, bundles a `clientKeystore`, or has a
     * `token_mtls` vault file. (Every block has a label — the default one
     * unless set — so a TLS-only block sharing it keeps its files.) Copies
     * locked with [VaultFileConfig.userAuth] are included — what
     * [PinVaultConfig.Builder.wipeVaultFilesOnRevocation] does when the server
     * revokes the device. The wipe needs [init] (the files' storage is set up
     * there); before it, only the certificate is removed.
     */
    fun unenroll(context: Context, label: String?, wipeVaultFiles: Boolean) {
        unenroll(context, label)
        if (!wipeVaultFiles) return
        if (!initialized) {
            Timber.w("unenroll: vault files can only be wiped after init — none wiped")
            return
        }
        val certLabel = label ?: defaultCertLabel()
        val config = pinManagerConfig ?: return
        val ids = io.github.umutcansu.pinvault.internal.VaultFileWipe.mtlsBlocksUsing(
            certLabel, config.configApis.values, config.vaultFiles.values
        )
        if (ids.isEmpty()) Timber.w("unenroll: no Config API uses [%s] for mTLS — no vault files wiped", certLabel)
        wipeVaultFilesOf(ids)
    }

    /**
     * Deletes every stored vault file bound to [configApiIds]. The user-auth
     * key belongs to the device, not to one Config API, so it goes only when
     * no locked file is left anywhere; a new one is made and registered on
     * the next fetch. Never throws.
     */
    private fun wipeVaultFilesOf(configApiIds: Set<String>) {
        val config = pinManagerConfig ?: return
        if (configApiIds.isEmpty() || !::defaultVaultFileStore.isInitialized) return
        io.github.umutcansu.pinvault.internal.VaultFileWipe.wipe(
            configApiIds, config.vaultFiles.values, ::getStorageFor, userAuthKeys
        ) {
            if (::vaultRouter.isInitialized) vaultRouter.forgetUserAuthRegistrations()
        }
        // What was remembered about the wiped copies goes with them.
        config.vaultFiles.values.filter { it.configApiId in configApiIds }.forEach { vaultGuard?.forget(it.key) }
    }

    /**
     * Deletes every stored vault file that is past its `maxOfflineAge` and
     * asked for `wipeWhenStale()`. Runs at [init] and on every periodic
     * update, so a device that stays offline loses such a file even when the
     * app never tries to read it. Never throws.
     */
    internal fun wipeStaleVaultFiles() {
        if (!initialized) return
        val config = pinManagerConfig ?: return
        try {
            vaultGuard?.sweep(config.vaultFiles.values, ::getStorageFor)
        } catch (e: Exception) {
            Timber.w(e, "Could not check the offline lifetime of the stored vault files")
        }
    }

    /**
     * Enrolled client sertifikasının CN (Common Name) alanını döndürür —
     * QA kanıt akışında mobil ekran görüntüsünü sunucudaki kayıtla
     * bire bir eşleştirmek için kullanılır.
     */
    fun enrolledClientCN(context: Context, label: String? = null): String? =
        enrolledLeaf(context, label)?.subjectX500Principal?.name
            ?.substringAfter("CN=", "")
            ?.substringBefore(",")
            ?.ifBlank { null }

    /**
     * When the enrolled client certificate expires, epoch ms — or null when
     * nothing is enrolled. Read from the stored certificate, no network.
     */
    fun enrolledClientNotAfter(context: Context, label: String? = null): Long? =
        enrolledLeaf(context, label)?.notAfter?.time

    /** The enrolled leaf certificate, whichever form it is stored in. */
    private fun enrolledLeaf(context: Context, label: String?): java.security.cert.X509Certificate? {
        val store = ClientCertSecureStore(context.applicationContext)
        val certLabel = label ?: defaultCertLabel()
        return try {
            when (store.mode(certLabel)) {
                ClientCertSecureStore.Mode.CHAIN ->
                    io.github.umutcansu.pinvault.crypto.Pkcs10Csr.parsePemChain(store.loadChain(certLabel)!!).first()
                ClientCertSecureStore.Mode.IMPORTED ->
                    io.github.umutcansu.pinvault.crypto.Pkcs10Csr.parsePemChain(store.loadImported(certLabel)!!).first()
                ClientCertSecureStore.Mode.P12 -> {
                    val p12 = store.load(certLabel) ?: return null
                    val password = pinManagerConfig?.configApis?.values?.firstOrNull()?.clientKeyPassword ?: return null
                    val ks = java.security.KeyStore.getInstance("PKCS12")
                    ks.load(p12.inputStream(), password.toCharArray())
                    val alias = ks.aliases().toList().firstOrNull() ?: return null
                    ks.getCertificate(alias) as? java.security.cert.X509Certificate
                }
                ClientCertSecureStore.Mode.NONE -> null
            }
        } catch (e: Exception) {
            Timber.w(e, "enrolledLeaf: could not read the stored client certificate")
            null
        }
    }

    // ── Vault File API ─────────────────────────────────────────────────

    /**
     * Fetches a vault file from the backend and stores it encrypted.
     *
     * For a file locked with [VaultFileConfig.userAuth], [VaultFileResult.Updated.bytes]
     * is empty (so is the [OnFileUpdateListener]'s copy): the content is only
     * handed out by [unlockFile], after the prompt.
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
     * Returns null if the file hasn't been fetched yet, and for a file locked
     * with [VaultFileConfig.userAuth]: open those with [unlockFile].
     *
     * The stored copy is checked every time, not only when it was downloaded:
     *  - a file of a Config API that signs its files is verified again with
     *    the signatures it was stored with and the keys trusted now. A copy
     *    that fails — changed, swapped, or signed by a key revoked since — is
     *    deleted and null is returned;
     *  - a file past its `maxOfflineAge` is not returned (and deleted with
     *    `wipeWhenStale()`).
     *
     * [fileStatus] says which of these it was when this returns null. A copy
     * a signed block stored with an earlier version of the library has no
     * signature on record: it is not returned until the next [fetchFile] has
     * downloaded it again ([VaultFileStatus.NEEDS_FETCH]).
     */
    fun loadFile(key: String): ByteArray? {
        checkInitialized()
        val storage = getStorageFor(key)
        val file = pinManagerConfig?.vaultFiles?.get(key)
        val guard = vaultGuard
        if (file == null || guard == null) return storage.load(key)
        return when (val read = guard.load(file, storage, vaultRouter.storedVerifier(file))) {
            is io.github.umutcansu.pinvault.internal.VaultFileGuard.Read.Content -> read.bytes
            else -> null
        }
    }

    /**
     * What [loadFile] / [unlockFile] would make of the stored copy of [key],
     * without reading its content: available, locked, not stored, past its
     * offline lifetime, waiting to be fetched again, or — after a copy was
     * deleted because it failed its check — [VaultFileStatus.INTEGRITY_FAILED]
     * until the next successful fetch. See [VaultFileStatus].
     *
     * A copy's signature is verified when it is read, so a tampered copy
     * shows as `AVAILABLE` here until `loadFile` / `unlockFile` has looked.
     */
    fun fileStatus(key: String): io.github.umutcansu.pinvault.model.VaultFileStatus {
        checkInitialized()
        val storage = getStorageFor(key)
        val file = pinManagerConfig?.vaultFiles?.get(key)
        val guard = vaultGuard
        if (file == null || guard == null) {
            return if (storage.exists(key)) io.github.umutcansu.pinvault.model.VaultFileStatus.AVAILABLE
            else io.github.umutcansu.pinvault.model.VaultFileStatus.NOT_STORED
        }
        return guard.status(file, storage, vaultRouter.storedVerifier(file))
    }

    /**
     * Opens a vault file locked with [VaultFileConfig.userAuth]: shows the
     * system prompt (strong biometric or the screen lock) and returns the
     * content once the user passes it. A file without a lock comes back
     * without a prompt, so callers can use this for every file.
     *
     * [VaultFileUnlockResult.Invalidated] means Android retired the key: the
     * screen lock was removed, or — only for the fingerprint-only key made on
     * Android 7–10 — the enrolled fingerprints changed (see [UserAuth]). The
     * stored copy is gone and [fetchFile] downloads it again.
     *
     * [VaultFileUnlockResult.Stale] means the file is past its
     * `maxOfflineAge`; no prompt is shown. A copy that is opened is checked
     * like [loadFile] checks it: one that fails its stored signature is
     * deleted and reported as [VaultFileUnlockResult.Failed].
     *
     * A [io.github.umutcansu.pinvault.model.VaultFileEncryption.USER_AUTH]
     * file is decrypted here, after the prompt, and its signature checked
     * with the same keys a fetch uses; one that fails is deleted and reported
     * as [VaultFileUnlockResult.Failed]. For such a file anything stored that
     * is not the server's sealed copy, and a copy sealed for another key, is
     * deleted and reported as [VaultFileUnlockResult.Invalidated] (fetch it
     * again; the key is registered again first).
     *
     * A newer `USER_AUTH` copy downloaded while a verified one was stored
     * waits in a pending slot and is opened first here: when it passes, it
     * replaces the stored copy (and only then counts as confirmed by the
     * server); when it fails, it alone is deleted and the copy it was to
     * replace is opened instead — which, for a per-use key, asks for the
     * prompt once more.
     */
    suspend fun unlockFile(
        activity: FragmentActivity,
        key: String,
        prompt: VaultFileUnlockPrompt
    ): VaultFileUnlockResult {
        checkInitialized()
        // Before the prompt: on a device the app does not trust, the content never reaches memory.
        environmentRefusal(pinManagerConfig, io.github.umutcansu.pinvault.model.GuardedOperation.UNLOCK_FILE)
            ?.let { return VaultFileUnlockResult.Failed(key, it.message ?: "Refused by the environment guard", it) }
        val storage = getStorageFor(key)
        val file = pinManagerConfig?.vaultFiles?.get(key)
        val guard = vaultGuard
        // A server-sealed (USER_AUTH) copy carries its signatures and is
        // checked inside unlock, once it is open. No verifier for such a file
        // = not opened (fail closed). Every other copy is checked below with
        // the signatures stored when it was fetched.
        val sealedByServer = file?.takeIf { it.encryption == io.github.umutcansu.pinvault.model.VaultFileEncryption.USER_AUTH }
        val verifier = sealedByServer?.let { vaultRouter.unlockVerifier(it) }
        return kotlinx.coroutines.withContext(Dispatchers.IO) {
            // Past its offline lifetime: no prompt for a file that is not handed out.
            if (file != null && guard != null) {
                guard.beforeUnlock(file, storage)?.let { refused ->
                    return@withContext if (refused.status == io.github.umutcansu.pinvault.model.VaultFileStatus.STALE) {
                        VaultFileUnlockResult.Stale(key)
                    } else {
                        VaultFileUnlockResult.Failed(key, refused.reason)
                    }
                }
            }
            val hadCopy = storage.exists(key)
            val result = if (storage is UserAuthVaultStorage) {
                storage.unlock(
                    key,
                    { kind, cipher -> UserAuthPrompt.authenticate(activity, prompt, kind, cipher) },
                    verify = verifier,
                    // Sealed for a key the server no longer has: register again before the next fetch.
                    onSealedForAnotherKey = { sealedByServer?.let { vaultRouter.forgetUserAuthRegistration(it.configApiId) } },
                    // A newer server-sealed copy passed its check and replaced
                    // the stored one: only now is it confirmed (L-10).
                    onPromoted = { version -> if (file != null && guard != null) guard.promoted(file, version) }
                )
            } else {
                storage.load(key)?.let { VaultFileUnlockResult.Unlocked(key, storage.getVersion(key), it) }
                    ?: VaultFileUnlockResult.NotFound(key)
            }
            if (file == null || guard == null) return@withContext result
            if (result is VaultFileUnlockResult.Failed && hadCopy && !storage.exists(key)) {
                // The copy failed the check done at unlock and was deleted there.
                guard.integrityFailed(file, result.reason)
            }
            if (result !is VaultFileUnlockResult.Unlocked) return@withContext result
            when (val read = guard.check(file, storage, result.bytes, result.version, vaultRouter.storedVerifier(file))) {
                is io.github.umutcansu.pinvault.internal.VaultFileGuard.Read.Content -> result
                is io.github.umutcansu.pinvault.internal.VaultFileGuard.Read.Refused -> VaultFileUnlockResult.Failed(key, read.reason)
                io.github.umutcansu.pinvault.internal.VaultFileGuard.Read.Absent -> VaultFileUnlockResult.NotFound(key)
            }
        }
    }

    /** Callback variant of [unlockFile]; [onResult] runs on the main thread. */
    fun unlockFile(
        activity: FragmentActivity,
        key: String,
        prompt: VaultFileUnlockPrompt,
        onResult: (VaultFileUnlockResult) -> Unit
    ) {
        CoroutineScope(Dispatchers.Main).launch {
            onResult(unlockFile(activity, key, prompt))
        }
    }

    /** True when the stored copy of [key] opens only through [unlockFile]. */
    fun isFileLocked(key: String): Boolean {
        checkInitialized()
        return (getStorageFor(key) as? UserAuthVaultStorage)?.isLocked(key) == true
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
        vaultGuard?.forget(key)
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
        // A refusal by the app's environment guard downloads nothing and is
        // reported like any failed fetch (the server sees why).
        val result = environmentRefusal(pinManagerConfig, io.github.umutcansu.pinvault.model.GuardedOperation.FETCH_FILE)
            ?.let { VaultFileResult.Failed(key, it.message ?: "Refused by the environment guard", it) }
            ?: vaultRouter.fetchFile(fileConfig)

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
            // The fixed class of the failure, never its text. The reason can
            // carry an exception message — which padding step of an
            // end_to_end envelope failed, say — and whoever answers the
            // download must not learn that from the report. The text stays in
            // the local log (the router logs it) and in the result the app gets.
            failureReason = (result as? VaultFileResult.Failed)?.code,
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
     * Returns the currently applied SHA-256 SPKI pin hashes for [hostname],
     * or `null` if the host has no entry in the active config. Hashes are
     * Base64-encoded (no `sha256/` prefix) — prepend `"sha256/"` yourself
     * when handing them to OkHttp's [okhttp3.CertificatePinner.Builder.add].
     *
     * Intended for setups where a separate networking module owns its own
     * HTTP client and PinVault is not a direct dependency there. The
     * caller should re-extract after every [OnUpdateListener] callback so
     * the local pinner stays in sync with the dynamic config — the snapshot
     * returned here goes stale the moment a new config is applied.
     *
     * Hostname matching is case-insensitive on the exact entry; wildcard
     * patterns like `*.example.com` are returned as-is and not expanded.
     */
    fun pinsForHost(hostname: String): List<String>? {
        checkInitialized()
        val needle = hostname.lowercase()
        return clientProvider.currentConfig?.pins
            ?.firstOrNull { it.hostname.lowercase() == needle }
            ?.sha256
    }

    /**
     * Snapshot of every hostname → pin-list pair in the active config.
     * Empty when no config has been applied yet.
     *
     * Wildcard entries (e.g. `*.example.com`) are preserved verbatim — it is
     * the caller's job to decide how to expand them for their HTTP client.
     *
     * Exposed as a property (not a function) — callers can write
     * `PinVault.currentPins` directly, no parentheses. Keeps the read-only
     * feel for a parameterless snapshot.
     */
    val currentPins: Map<String, List<String>>
        get() {
            checkInitialized()
            return clientProvider.currentConfig?.pins
                ?.associate { it.hostname to it.sha256 }
                ?: emptyMap()
        }

    /**
     * How the given Config API block verifies config and vault signatures right
     * now: trusted key ids, required signature count, applied signing-key set
     * version, recovery keys, and which keys signed the last accepted config.
     *
     * @param configApiId the block id; `null` = the default (first) block.
     * @return `null` for a block whose configs are not verified — it runs
     *   unsigned (`allowUnsigned()`), including a custom [CertificateConfigApi]
     *   that does not implement
     *   [io.github.umutcansu.pinvault.api.SignedConfigSource] — for an unknown
     *   id, in static-pin mode, and while the signing-key store cannot be read.
     */
    @JvmOverloads
    fun signingStatus(configApiId: String? = null): io.github.umutcansu.pinvault.model.SigningStatus? {
        checkInitialized()
        val id = configApiId ?: pinManagerConfig?.defaultConfigApi?.id ?: return null
        val client = configApiClients[id]?.takeIf { it.configsVerified } ?: return null
        return try {
            client.signatureTrust?.status()
        } catch (e: io.github.umutcansu.pinvault.model.StoreUnreadableException) {
            Timber.w(e, "signingStatus: the signing-key store is unreadable right now")
            null
        }
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
    private fun resolveDeviceIdentity(config: PinVaultConfig?, context: Context = appContext): Pair<String, String>? {
        // Same source as the X-Device-Id sent on scoped config fetches and
        // vault downloads — see DeviceIdentity for why that must stay in sync.
        // [context] is passed explicitly before init, when appContext is not set.
        val uid = io.github.umutcansu.pinvault.internal.DeviceIdentity
            .androidId(context.applicationContext) ?: return null

        val alias = config?.deviceAlias ?: "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"
        return alias to uid
    }

    /**
     * Checks an enrolled P12 (integrity hash, format) and returns it wrapped
     * with [localPassword]. A one-off password the server sent with it
     * (`X-P12-Password`) is used here once and never stored; without one the
     * bundle must already open with [localPassword], as before.
     */
    private fun acceptEnrolledP12(result: io.github.umutcansu.pinvault.model.EnrollmentResult, localPassword: String): ByteArray {
        val oneOff = result.p12Password
        validateP12(result.p12Bytes, result.p12Hash, oneOff ?: localPassword)
        return if (oneOff != null) io.github.umutcansu.pinvault.internal.P12Rewrap.rewrap(result.p12Bytes, oneOff, localPassword)
        else result.p12Bytes
    }

    /**
     * Validates P12 bytes: requires server-supplied SHA-256 hash and PKCS12
     * format. The hash header is mandatory — a MITM that drops the header
     * could otherwise inject a P12 with an attacker-controlled cert (H-05).
     */
    private fun validateP12(p12Bytes: ByteArray, serverHash: String?, password: String) {
        // 1. Hash verification — server MUST provide X-P12-SHA256 header.
        if (serverHash.isNullOrBlank()) {
            throw SecurityException(
                "Server did not provide X-P12-SHA256 header — refusing to install P12. " +
                "The enrollment endpoint must return the SHA-256 of the P12 bytes so the " +
                "client can detect transport-level tampering or header stripping."
            )
        }
        val localHashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(p12Bytes)
        val serverHashBytes = try {
            android.util.Base64.decode(serverHash, android.util.Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            throw SecurityException(
                "Invalid X-P12-SHA256 header — not valid Base64. Refusing to install P12.",
                e
            )
        }
        // Constant-time comparison: String.equals short-circuits on first mismatch,
        // which leaks a timing oracle against an attacker who controls the header.
        // MessageDigest.isEqual loops the full length regardless of mismatch position.
        if (!java.security.MessageDigest.isEqual(localHashBytes, serverHashBytes)) {
            throw SecurityException("P12 integrity check failed — SHA-256 mismatch (transport corruption or tampering)")
        }
        Timber.d("P12 SHA-256 hash verified")

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
     * Clears the active pinning state and the persisted config of every
     * Config API, and resets the initialized flag so the next [init] performs
     * a full re-initialization (re-fetches config from the backend).
     *
     * Clients obtained earlier refuse TLS handshakes until that re-init
     * publishes a config — pinning is never silently downgraded to system
     * trust.
     *
     * What it does NOT clear: the replay watermarks (the highest `issuedAt`
     * and per-host versions accepted so far), the signing-key set, the
     * trusted-clock reference, and the client certificate. `reset()` can be
     * called by the host app — and by anything that can reach the host app's
     * code — so it must not be a way to make the device accept an older
     * signed config again. The re-init accepts the newest config the device
     * has seen or a newer one, nothing older.
     */
    fun reset() {
        synchronized(this) {
            if (!initialized) return
            if (configApiClients.isEmpty()) {
                // Static-pin mode.
                clientProvider.reset()
                configStore.clearActive()
            } else {
                configApiClients.values.forEach { client ->
                    // The refresh loop stops and the token goes; the next init attests again.
                    client.attestation?.reset()
                    client.clientProvider.reset()
                    client.configStore.clearActive()
                }
            }
            initialized = false
        }
        Timber.w("PinVault reset — config cleared (replay watermarks kept), TLS refused until re-init")
    }

    /**
     * [reset], and also wipes everything the config stores hold: replay
     * watermarks and the trusted-clock reference included. For tests that
     * need a clean slate between cases; not part of the public API, because
     * forgetting the watermarks is exactly what a replay needs.
     */
    @androidx.annotation.VisibleForTesting
    internal fun resetAndWipeStoredState() {
        synchronized(this) {
            if (!initialized) return
            if (configApiClients.isEmpty()) {
                clientProvider.reset()
                configStore.wipeAll()
            } else {
                configApiClients.values.forEach { client ->
                    client.attestation?.reset()
                    client.clientProvider.reset()
                    client.configStore.wipeAll()
                }
            }
            initialized = false
        }
        Timber.w("PinVault reset — stored config state wiped, TLS refused until re-init")
    }

    private fun checkInitialized() {
        check(initialized) {
            "PinVault not initialized. Call PinVault.init() first."
        }
    }
}
