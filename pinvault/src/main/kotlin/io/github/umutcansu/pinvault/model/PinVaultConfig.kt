package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

/**
 * Configuration for [io.github.umutcansu.pinvault.PinVault].
 *
 * ## Single Config API
 *
 * ```kotlin
 * val config = PinVaultConfig.Builder()
 *     .configApi("api", "https://api.example.com/") {
 *         bootstrapPins(listOf(HostPin("api.example.com", listOf("sha256/AAAA…"))))
 *     }
 *     .vaultFile("flags") {
 *         configApi("api")
 *         endpoint("api/v1/vault/flags")
 *     }
 *     .build()
 *
 * PinVault.init(context, config)
 * ```
 *
 * ## Multi-Config-API
 *
 * ```kotlin
 * val config = PinVaultConfig.Builder()
 *     .configApi("prod-tls", "https://host:8091") {
 *         bootstrapPins(prodTlsPins)
 *         wantPinsFor("cdn.example.com", "api.example.com")
 *     }
 *     .configApi("secure-mtls", "https://host:8092") {
 *         bootstrapPins(secureMtlsPins)
 *         clientKeystore(p12Bytes, devicePassword)
 *     }
 *     .vaultFile("feature-flags") {
 *         configApi("prod-tls"); endpoint("api/v1/vault/feature-flags")
 *     }
 *     .vaultFile("ml-model") {
 *         configApi("secure-mtls")
 *         storage(StorageStrategy.ENCRYPTED_FILE)
 *         accessPolicy(VaultFileAccessPolicy.TOKEN)
 *         accessToken { tokenStore["ml-model"] ?: "" }
 *         encryption(VaultFileEncryption.END_TO_END)
 *     }
 *     .build()
 * ```
 *
 * ## Offline (static pins, no server)
 *
 * ```kotlin
 * val config = PinVaultConfig.static(
 *     HostPin("api.example.com", listOf("pin1", "pin2"))
 * )
 * ```
 */
data class PinVaultConfig(
    /** All Config APIs registered on this config, keyed by id. */
    val configApis: Map<String, ConfigApiBlock>,
    /** Max retry attempts when backend is unreachable during init. */
    val maxRetryCount: Int = DEFAULT_MAX_RETRY,
    /** Periodic update interval (hours). */
    val updateIntervalHours: Long = DEFAULT_UPDATE_INTERVAL_HOURS,
    /** Periodic update interval (minutes). Takes precedence over hours if set. */
    val updateIntervalMinutes: Long? = null,
    /** Human-readable device name for server-side tracking. */
    val deviceAlias: String? = null,
    /** Registered vault files keyed by their [VaultFileConfig.key]. */
    val vaultFiles: Map<String, VaultFileConfig> = emptyMap(),
    /** Pre-loaded static pins for offline mode. When set, no Config API is contacted. */
    val staticPins: CertificateConfig? = null,
    /**
     * Optional listener for [io.github.umutcansu.pinvault.api.PinVaultConnectionEvent]s.
     * When `null` (default), the library does not invoke any callback —
     * keeping PinVault server-agnostic out of the box. Wire one via
     * [Builder.onConnectionEvent] or use the canned helper
     * [Builder.reportToPinVaultBackend] for the demo-server JSON format.
     */
    val connectionListener: PinVaultConnectionListener? = null
) {

    /** First registered block — convenience for internal single-API code paths. */
    val defaultConfigApi: ConfigApiBlock? get() = configApis.values.firstOrNull()

    class Builder {
        private val configApiBlocks = mutableMapOf<String, ConfigApiBlock>()
        private var maxRetryCount: Int = DEFAULT_MAX_RETRY
        private var updateIntervalHours: Long = DEFAULT_UPDATE_INTERVAL_HOURS
        private var updateIntervalMinutes: Long? = null
        private var deviceAlias: String? = null
        private var staticPins: CertificateConfig? = null
        private val vaultFiles = mutableMapOf<String, VaultFileConfig>()
        private var connectionListener: PinVaultConnectionListener? = null

        /**
         * Register a Config API. Calling twice with the same id replaces the
         * prior block (useful for overrides in tests).
         *
         * ### Device backups
         *
         * Every block keeps its pins in its own namespace of one encrypted file,
         * `shared_prefs/pinvault_secure_config.xml`, which PinVault's bundled
         * backup rules exclude from cloud backup and device transfer (audit M-07:
         * restoring an old backup would otherwise reinstate an old pin set). Any
         * [id] is covered; PinVault 2.0.x used one file per id, which the rules
         * could only name for the library's own ids.
         */
        fun configApi(id: String, url: String, init: ConfigApiBlock.Builder.() -> Unit) = apply {
            configApiBlocks[id] = ConfigApiBlock.Builder(id, url).apply(init).build()
        }

        fun maxRetryCount(count: Int) = apply { this.maxRetryCount = count }
        fun updateIntervalHours(hours: Long) = apply { this.updateIntervalHours = hours }
        fun updateIntervalMinutes(minutes: Long) = apply { this.updateIntervalMinutes = minutes }
        fun deviceAlias(alias: String) = apply { this.deviceAlias = alias }
        fun staticPins(config: CertificateConfig) = apply { this.staticPins = config }

        fun vaultFile(key: String, init: VaultFileConfig.Builder.() -> Unit) = apply {
            vaultFiles[key] = VaultFileConfig.Builder(key).apply(init).build()
        }

        /**
         * Register a callback that receives every
         * [io.github.umutcansu.pinvault.api.PinVaultConnectionEvent] PinVault
         * emits — currently fired on every TLS handshake whose certificate
         * was checked against the configured pins.
         *
         * The library never reaches out to a remote endpoint by itself; this
         * listener is the only way to observe connection telemetry. Use it
         * to push to your own analytics, logger, or backend.
         *
         * For PinVault demo-server's expected JSON format see
         * [reportToPinVaultBackend].
         */
        fun onConnectionEvent(listener: PinVaultConnectionListener) = apply {
            this.connectionListener = listener
        }

        fun build(): PinVaultConfig {
            if (staticPins == null) {
                require(configApiBlocks.isNotEmpty()) {
                    "At least one Config API (or staticPins for offline mode) is required"
                }
                configApiBlocks.values.forEach { block ->
                    require(block.bootstrapPins.isNotEmpty()) {
                        "bootstrapPins must not be empty for Config API '${block.id}' (or use staticPins for offline mode)"
                    }
                }
                vaultFiles.values.forEach { vf ->
                    require(vf.configApiId in configApiBlocks) {
                        "VaultFile '${vf.key}' references unknown configApi '${vf.configApiId}'. " +
                                "Registered: ${configApiBlocks.keys}"
                    }
                }
            }

            vaultFiles.values.forEach { warnIfPolicyUnusableFromDevice(it) }

            return PinVaultConfig(
                configApis = configApiBlocks.toMap(),
                maxRetryCount = maxRetryCount,
                updateIntervalHours = updateIntervalHours,
                updateIntervalMinutes = updateIntervalMinutes,
                deviceAlias = deviceAlias,
                vaultFiles = vaultFiles.toMap(),
                staticPins = staticPins,
                connectionListener = connectionListener
            )
        }
    }

    companion object {

        // ── Build-time diagnostics ──────────────────────────────────────────
        //
        // The warning below describes a configuration that compiles, runs and
        // silently does the wrong thing. It is logged once per distinct value
        // so a Builder used per screen (or in a test loop) does not spam the log.

        private val warnedApiKeyFiles = ConcurrentHashMap.newKeySet<String>()

        /**
         * Warns when a vault file is declared with
         * [VaultFileAccessPolicy.API_KEY].
         *
         * That policy is enforced with the server's admin `X-API-Key`, and the
         * library deliberately never sends it from a device — shipping an admin
         * key inside an APK would hand it to everyone who downloads the app. A
         * file declared this way therefore fails with HTTP 401 on every single
         * fetch, and the only visible trace is a `failed` row in the server's
         * distribution history.
         */
        private fun warnIfPolicyUnusableFromDevice(file: VaultFileConfig) {
            if (file.accessPolicy != VaultFileAccessPolicy.API_KEY) return
            if (!warnedApiKeyFiles.add("${file.configApiId}/${file.key}")) return
            Timber.w(
                "VaultFile '%s' uses accessPolicy=API_KEY, which CANNOT be satisfied from a device: " +
                    "the library never sends the server's admin X-API-Key (it would be extractable " +
                    "from the APK), so every fetch of this file will fail with HTTP 401. " +
                    "API_KEY is for server-side tooling only — use TOKEN or TOKEN_MTLS for " +
                    "device-facing files, or PUBLIC for genuinely public ones.",
                file.key
            )
        }

        /** Offline / embedded static pin config. No Config API required. */
        fun static(vararg pins: HostPin) = PinVaultConfig(
            configApis = emptyMap(),
            staticPins = CertificateConfig(
                pins = pins.toList(),
                forceUpdate = false
            )
        )

        const val DEFAULT_CONFIG_ENDPOINT = "api/v1/certificate-config"
        const val DEFAULT_HEALTH_ENDPOINT = "health"
        const val DEFAULT_MAX_RETRY = 3
        const val DEFAULT_UPDATE_INTERVAL_HOURS = 12L
        const val DEFAULT_ENROLLMENT_ENDPOINT = "api/v1/client-certs/enroll"
        const val DEFAULT_CLIENT_CERT_ENDPOINT = "api/v1/client-certs"
        const val DEFAULT_VAULT_REPORT_ENDPOINT = "api/v1/vault/report"
        const val DEFAULT_CERT_LABEL = "default"
    }
}
