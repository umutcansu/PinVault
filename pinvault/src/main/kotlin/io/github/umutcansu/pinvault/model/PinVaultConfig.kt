package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import io.github.umutcansu.pinvault.store.CertificateConfigStore
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
         * ### Custom ids and device backups
         *
         * Each block persists its pins in its own encrypted preferences file,
         * `shared_prefs/ssl_cert_config_<id>.xml`. PinVault ships backup rules
         * that exclude those files from cloud backup and device transfer
         * (audit M-07: restoring an old backup would otherwise reinstate an
         * old pin set), **but Android's `<exclude>` takes no wildcards**, so
         * the bundled rules can only name the ids the library knows:
         * `default`, `default-tls` and `secure-mtls`.
         *
         * If you pass any other [id], PinVault's rules do not cover your
         * stored pins. Close it in your own app by either:
         *  - setting `android:allowBackup="false"` on `<application>`, or
         *  - adding `<exclude domain="sharedpref" path="ssl_cert_config_<id>.xml" />`
         *    to your own `fullBackupContent` **and** to both the
         *    `<cloud-backup>` and `<device-transfer>` sections of your
         *    `dataExtractionRules`.
         *
         * [build] logs a warning once per uncovered id.
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
                configApiBlocks.keys.forEach { warnIfBackupRulesMissCoverage(it) }
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
        // Both warnings below describe a configuration that compiles, runs and
        // silently does the wrong thing. They are logged once per distinct
        // value so a Builder used per screen (or in a test loop) does not
        // spam the log.

        private val warnedBackupIds = ConcurrentHashMap.newKeySet<String>()
        private val warnedApiKeyFiles = ConcurrentHashMap.newKeySet<String>()

        /**
         * Config API ids whose stored pin config the library's bundled backup
         * rules already exclude. Android's `<exclude>` takes no wildcards, so
         * the rule files have to name every `shared_prefs` file literally —
         * which means only these ids are covered out of the box.
         *
         * Keep in sync with `res/xml/pinvault_backup_rules.xml` and
         * `res/xml/pinvault_data_extraction_rules.xml`.
         */
        private val BACKUP_RULE_COVERED_IDS =
            setOf("", ConfigApiBlock.DEFAULT_ID, "default-tls", "secure-mtls")

        /**
         * Warns when a Config API id is not named in
         * `res/xml/pinvault_backup_rules.xml` /
         * `pinvault_data_extraction_rules.xml`.
         *
         * The stored config lives in `shared_prefs/ssl_cert_config_<id>.xml`
         * (see [CertificateConfigStore.prefsNameFor]). An id the rules do not
         * name ends up in cloud backup and device-transfer payloads, and
         * restoring an older backup reinstates an older pin set — the
         * pin-downgrade path the exclusions exist to close (audit M-07).
         */
        private fun warnIfBackupRulesMissCoverage(configApiId: String) {
            if (configApiId in BACKUP_RULE_COVERED_IDS) return
            if (!warnedBackupIds.add(configApiId)) return
            val prefsFile = CertificateConfigStore.prefsNameFor(configApiId) + ".xml"
            Timber.w(
                "Config API id '%s' is NOT covered by PinVault's bundled backup rules. " +
                    "Its stored pin config (shared_prefs/%s) will be included in cloud backup " +
                    "and device transfer, which lets a restored backup downgrade pins (M-07). " +
                    "Android backup rules do not support wildcards, so fix it in YOUR app: set " +
                    "android:allowBackup=\"false\", or add <exclude domain=\"sharedpref\" path=\"%s\" /> " +
                    "to your own fullBackupContent and dataExtractionRules (cloud-backup AND device-transfer).",
                configApiId, prefsFile, prefsFile
            )
        }

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
