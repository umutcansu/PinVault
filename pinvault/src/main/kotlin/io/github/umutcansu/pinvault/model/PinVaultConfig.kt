package io.github.umutcansu.pinvault.model

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
    val staticPins: CertificateConfig? = null
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

        /**
         * Register a Config API. Calling twice with the same id replaces the
         * prior block (useful for overrides in tests).
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

            return PinVaultConfig(
                configApis = configApiBlocks.toMap(),
                maxRetryCount = maxRetryCount,
                updateIntervalHours = updateIntervalHours,
                updateIntervalMinutes = updateIntervalMinutes,
                deviceAlias = deviceAlias,
                vaultFiles = vaultFiles.toMap(),
                staticPins = staticPins
            )
        }
    }

    companion object {
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
