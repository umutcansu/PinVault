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
 *         // Base64 SHA-256 of the SubjectPublicKeyInfo, no "sha256/" prefix; primary + backup
 *         bootstrapPins(listOf(HostPin("api.example.com", listOf("AAAA…=", "BBBB…="))))
 *         signaturePublicKey(SIGNING_KEY)   // or allowUnsigned() for tests
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
 *         signaturePublicKey(SIGNING_KEY)
 *         wantPinsFor("cdn.example.com", "api.example.com")
 *     }
 *     .configApi("secure-mtls", "https://host:8092") {
 *         bootstrapPins(secureMtlsPins)
 *         signaturePublicKey(SIGNING_KEY)
 *         clientKeystore(p12Bytes, devicePassword)
 *     }
 *     .vaultFile("feature-flags") {
 *         configApi("prod-tls"); endpoint("api/v1/vault/feature-flags")
 *     }
 *     .vaultFile("ml-model") {
 *         configApi("secure-mtls")
 *         endpoint("api/v1/vault/ml-model")
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
    val connectionListener: PinVaultConnectionListener? = null,
    /** How long a config may be used past its `expiresAt`. See [Builder.expiredConfigGrace]. */
    val expiredConfigGraceMs: Long = 0L,
    /** Hosts whose chain must also pass the platform CAs. See [Builder.requireCaTrust]. */
    val caTrustHosts: List<String> = emptyList(),
    /** Delete a Config API's vault files when its identity is revoked. See [Builder.wipeVaultFilesOnRevocation]. */
    val wipeVaultFilesOnRevocation: Boolean = false,
    /**
     * Default offline lifetime of stored vault files, in milliseconds; 0 = no
     * limit. See [Builder.vaultFileMaxOfflineAge].
     */
    val vaultFileMaxOfflineAgeMs: Long = 0L,
    /** Generate the library's Keystore keys so they work only while the device is unlocked. See [Builder.requireUnlockedDevice]. */
    val requireUnlockedDevice: Boolean = false,
    /** Refuse Keystore keys made outside secure hardware. See [Builder.requireHardwareBackedKeys]. */
    val requireHardwareBackedKeys: Boolean = false,
    /** A second opinion forwarded inside attestation reports. See [Builder.integrityVerdictProvider]. */
    val integrityVerdictProvider: io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider? = null,
    /**
     * SHA-256 digests of the app's expected signing certificates, lowercase
     * hex without separators. See [Builder.expectedSignerSha256].
     */
    val expectedSignerSha256: List<String> = emptyList(),
    /** Accept, for hosts without a pin entry, chains the platform validates to a root the signed config lists. See [Builder.managedTrustRoots]. */
    val managedTrustRoots: Boolean = false,
    /** The app's verdict on the device, asked before sensitive operations. See [Builder.environmentGuard]. */
    val environmentGuard: EnvironmentGuard? = null,
    /** Integrity token sent with every enrollment request. See [Builder.integrityTokenProvider]. */
    val integrityTokenProvider: IntegrityTokenProvider? = null,
    /**
     * With [requireUnlockedDevice]: make a key without the requirement when
     * the Keystore refuses one with it, instead of failing. See
     * [Builder.requireUnlockedDevice].
     */
    val requireUnlockedDeviceFallback: Boolean = false
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
        private var expiredConfigGraceMs: Long = 0L
        private val caTrustHosts = mutableListOf<String>()
        private var wipeVaultFilesOnRevocation = false
        private var vaultFileMaxOfflineAgeMs: Long = 0L
        private var requireUnlockedDevice = false
        private var requireUnlockedDeviceFallback = false
        private var requireHardwareBackedKeys = false
        private var integrityVerdictProvider: io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider? = null
        private var expectedSignerSha256: List<String> = emptyList()
        private var managedTrustRoots = false

        /**
         * A second opinion on the device's integrity (Play Integrity,
         * typically) that goes along inside every attestation report as
         * `verdictProvider` — see
         * [io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider].
         * Only used by blocks that called `attestation()`. The library
         * forwards the token verbatim; verifying it is the server's job
         * (the reference server verifies Play Integrity tokens with the
         * Play Console keys). The optional `pinvault-play-integrity`
         * artifact provides `PlayIntegrityVerdictProvider(context, cloudProjectNumber)`.
         */
        fun integrityVerdictProvider(provider: io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider) = apply {
            this.integrityVerdictProvider = provider
        }

        /**
         * SHA-256 digests of the signing certificates this app is expected to
         * carry — the release certificate's, and a debug one's if debug
         * builds attest too. Hex, with or without colons (`3c:4f:…` as
         * `apksigner` / `keytool` print it), any case. When set, the
         * attestation report's `app_integrity` signal is raised by the
         * device itself when none of the APK's signers matches; the server
         * compares the digests with its own list (`ATTESTATION_SIGNER_SHA256`)
         * either way. Not set: the client does not judge.
         */
        fun expectedSignerSha256(vararg hex: String) = apply {
            this.expectedSignerSha256 = hex.map { digest ->
                io.github.umutcansu.pinvault.integrity.normalizeSha256Hex(digest)
                    ?: throw IllegalArgumentException("expectedSignerSha256: '$digest' is not a SHA-256 in hex (64 hex characters, colons allowed)")
            }.distinct()
        }

        /** [expectedSignerSha256] for a list (Java-friendly). */
        fun expectedSignerSha256(hex: List<String>) = expectedSignerSha256(*hex.toTypedArray())

        private var environmentGuard: EnvironmentGuard? = null
        private var integrityTokenProvider: IntegrityTokenProvider? = null

        /**
         * Keep using a config for [amount] [unit] after its `expiresAt`.
         *
         * A signed config is valid until its `expiresAt` (the server's
         * `CONFIG_TTL_SECONDS`, 24 hours by default). Past that the device
         * needs a fresh one: `init` fails with [ConfigExpiredException] when
         * the Config API cannot be reached, and pinned clients refuse
         * handshakes until a fetch succeeds. That is what keeps someone who
         * blocks the Config API from holding the device on old pins.
         *
         * The default is zero (fail closed). Apps that prefer to keep working
         * through a longer outage can allow a grace period here, accepting
         * that a blocked Config API holds them on old pins that much longer.
         * Configs without an `expiresAt` (static pins, `allowUnsigned()`
         * backends that send none) never expire.
         */
        fun expiredConfigGrace(amount: Long, unit: java.util.concurrent.TimeUnit) = apply {
            require(amount >= 0) { "expiredConfigGrace must not be negative" }
            this.expiredConfigGraceMs = unit.toMillis(amount)
        }

        /**
         * For these hosts the server's certificate must ALSO be trusted by the
         * platform's certificate authorities, in addition to matching a pin.
         * Both checks must pass.
         *
         * Pins come from whoever signs the config. Without this, the config
         * signer is in effect a private certificate authority for every pinned
         * host: a stolen signing key can pin an attacker's own certificate. A
         * host listed here also needs a certificate from a real CA, so a
         * signing key alone is not enough. This setting is compiled into the
         * app; nothing the server sends can turn it off.
         *
         * Patterns use the pin syntax: `api.example.com`, `*.example.com`
         * (exactly one label), optionally with `:port`. The trust store is the
         * platform default, including the app's network security config. Do
         * not list hosts with self-signed or private-CA certificates (such as
         * the reference server's own listeners): their handshakes would fail.
         * Applies to every handshake PinVault pins, the Config API's included.
         */
        fun requireCaTrust(vararg hostPatterns: String) = apply {
            hostPatterns.forEach { pattern ->
                val host = pattern.trim().lowercase()
                require(host.isNotEmpty() && "://" !in host && '/' !in host) {
                    "requireCaTrust: '$pattern' is not a host pattern (use api.example.com, *.example.com or host:port)"
                }
                val wildcard = host.startsWith("*.")
                val rest = if (wildcard) host.substring(2) else host
                require('*' !in rest && (!wildcard || '.' in rest.substringBefore(':'))) {
                    "requireCaTrust: '$pattern' — a wildcard must be '*.' followed by a domain with at least one dot"
                }
                caTrustHosts += host
            }
        }

        /**
         * Delete every vault file bound to a Config API when that API says
         * this device's identity is revoked (`403 reenroll_required`, the
         * [io.github.umutcansu.pinvault.api.ClientCertRenewalStatus.REENROLL_REQUIRED]
         * event). Off by default: by then the files are already on the device,
         * and a revoked device keeps reading them until the app removes them.
         *
         * Only the files of the Config API that refused the device are wiped,
         * including copies locked with `userAuth`. The answer is not signed,
         * so it wipes only when it was about this device's identity: it came
         * on a connection that presented the client certificate the block has
         * loaded, or it answers that certificate's own renewal request. The
         * same answer on a connection without a client certificate (a
         * TLS-only block, a request before enrollment) raises the event and
         * deletes nothing. A device revoked while it is offline never gets
         * the answer: see [vaultFileMaxOfflineAge]. Access tokens for vault
         * files belong to the app (`accessToken { … }`); forget them when the
         * event arrives. `PinVault.unenroll(context, label, wipeVaultFiles = true)`
         * does the same on demand.
         */
        fun wipeVaultFilesOnRevocation() = apply { this.wipeVaultFilesOnRevocation = true }

        /**
         * The default offline lifetime of every vault file: how long a stored
         * copy may be read without the server confirming it. A file's own
         * `maxOfflineAge(...)` overrides it. See
         * [VaultFileConfig.Builder.maxOfflineAge] for what it does and why.
         *
         * Not set (the default): no limit — a stored file stays readable for
         * as long as the app's data exists, also on a device the server has
         * revoked in the meantime that never came online again.
         */
        fun vaultFileMaxOfflineAge(amount: Long, unit: java.util.concurrent.TimeUnit) = apply {
            require(amount >= 0) { "vaultFileMaxOfflineAge must not be negative" }
            this.vaultFileMaxOfflineAgeMs = unit.toMillis(amount)
        }

        /**
         * Generate the library's Android Keystore keys so that they work only
         * while the device is unlocked (`setUnlockedDeviceRequired(true)`,
         * Android 9+): the mTLS identity key, the per-device vault key, the
         * keys of the encrypted stores and of `ENCRYPTED_FILE` vault files,
         * and keys imported from a P12. On a locked phone nothing the library
         * stored can then be decrypted and the client certificate cannot be
         * presented — by the app or by anything running as it.
         *
         * What it costs: work that runs behind a locked screen fails until
         * the user unlocks the phone. A periodic update then ends in
         * `UpdateResult.Failed` (the `ConfigUpdate` event's `FAILED`), a file
         * sync in `VaultFileResult.Failed`, `init` in `InitResult.Failed`,
         * `loadFile` returns null with `fileStatus` =
         * [VaultFileStatus.STORAGE_UNAVAILABLE]; nothing stored is deleted and
         * the next run after an unlock works again.
         *
         * It applies to keys generated from now on. Keys an earlier version
         * (or an earlier start without this call) generated keep working
         * while locked until they are replaced: the identity key at the next
         * enrollment, the store keys when the app's data is cleared. A device
         * without a screen lock has nothing to unlock: the flag has no effect
         * there. On Android 7 and 8 it is ignored.
         *
         * If a device's Keystore refuses to generate a key with the flag,
         * the operation that needed the key fails with
         * [UnlockedDeviceKeyRequiredException] (`init` returns `Failed` for
         * the store keys, enrollment and vault files report `Failed`): you
         * asked for keys that work only while the device is unlocked, and a
         * key without that requirement would silently be less than that.
         * With [allowFallback] the key is generated without the flag
         * instead and a warning is logged — for apps that would rather run
         * unprotected on such a ROM than not at all.
         */
        @JvmOverloads
        fun requireUnlockedDevice(allowFallback: Boolean = false) = apply {
            this.requireUnlockedDevice = true
            this.requireUnlockedDeviceFallback = allowFallback
        }

        /**
         * Refuse a Keystore key the device makes outside secure hardware.
         *
         * The library asks for StrongBox first and the TEE next, but what it
         * gets is the Keystore's decision: a ROM that cannot do either hands
         * out a software key, which a rooted device can copy. By default the
         * library uses such a key and logs a warning; its level is reported
         * ([KeySecurityLevel]: on the enrollment result and in the
         * attestation report, so the server sees it too). With this option a
         * key the Keystore reports as `software` or `unknown` is deleted
         * again and the operation fails with [HardwareBackedKeyRequiredException]:
         * enrollment, vault files and — for the store keys made on first use —
         * `init`. Applies to keys generated from now on; keys that already
         * exist are used as they are (read their level with
         * `PinVault.identityKeySecurityLevel`). Emulators have no secure
         * hardware: do not set this for emulator builds.
         */
        fun requireHardwareBackedKeys() = apply { this.requireHardwareBackedKeys = true }

        /**
         * Managed trust roots (Approov's "managed trust roots"): a host that
         * has **no pin entry** is accepted when the platform's CAs validate its
         * chain **and** the chain contains a certificate whose key is one of
         * the signed config's `trustRoots` (SPKI pins of root CAs), and the
         * leaf names the host. The device's trust store stops being the
         * authority for such hosts: a CA a user or an attacker added to the
         * device is not in the list, and a root the operator stops listing
         * stops being trusted on the next config, without an app update.
         * Hosts with a pin entry are unchanged; pins stay the stricter choice.
         * Off: hosts without a pin entry are refused, as always. The list
         * comes from the server with the config (`"trustRoots": [...]`) and
         * is covered by its signature.
         */
        fun managedTrustRoots() = apply { this.managedTrustRoots = true }

        /**
         * Ask [guard] before every [GuardedOperation] — init, enrollment,
         * vault file download, unlock — and refuse the operation when it says
         * no. Wire the verdict of your root / hooking / debugger detection
         * here (a RASP product, RootBeer): PinVault detects nothing itself.
         * See [EnvironmentGuard].
         */
        fun environmentGuard(guard: EnvironmentGuard) = apply { this.environmentGuard = guard }

        /**
         * Send an integrity token (Play Integrity, or a RASP product's
         * attestation) with every enrollment request, bound to that request.
         * The server verifies it (the reference server's
         * `INTEGRITY_VERIFICATION`); the app does not. See [IntegrityTokenProvider].
         */
        fun integrityTokenProvider(provider: IntegrityTokenProvider) = apply { this.integrityTokenProvider = provider }

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
            // Each block keeps its config and replay watermarks in a namespace
            // named after its id, with anything but [A-Za-z0-9_-] turned into
            // `_`: ids like `a.b` and `a_b` would share one and overwrite each
            // other's watermarks. Refused instead of silently merged.
            configApiBlocks.keys.groupBy { io.github.umutcansu.pinvault.store.CertificateConfigStore.namespaceFor(it) }
                .values.firstOrNull { it.size > 1 }?.let { clash ->
                    throw IllegalArgumentException(
                        "Config API ids ${clash.joinToString { "'$it'" }} would share one config store (characters " +
                            "other than letters, digits, '_' and '-' are stored as '_'); give them distinct ids"
                    )
                }
            if (staticPins == null) {
                require(configApiBlocks.isNotEmpty()) {
                    "At least one Config API (or staticPins for offline mode) is required"
                }
                configApiBlocks.values.forEach { block ->
                    require(block.bootstrapPins.isNotEmpty() || block.allowUnpinnedConfigApi) {
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
                connectionListener = connectionListener,
                expiredConfigGraceMs = expiredConfigGraceMs,
                caTrustHosts = caTrustHosts.distinct(),
                wipeVaultFilesOnRevocation = wipeVaultFilesOnRevocation,
                vaultFileMaxOfflineAgeMs = vaultFileMaxOfflineAgeMs,
                requireUnlockedDevice = requireUnlockedDevice,
                requireHardwareBackedKeys = requireHardwareBackedKeys,
                integrityVerdictProvider = integrityVerdictProvider,
                expectedSignerSha256 = expectedSignerSha256,
                managedTrustRoots = managedTrustRoots,
                environmentGuard = environmentGuard,
                integrityTokenProvider = integrityTokenProvider,
                requireUnlockedDeviceFallback = requireUnlockedDeviceFallback
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

        /**
         * Offline / embedded static pin config. No Config API required.
         *
         * The pins are checked at `PinVault.init` like fetched ones (host
         * names, 44-character Base64 SHA-256 pins); init fails for a config
         * that is not well-formed. Static pins carry no signature and no
         * expiry, and their stored copy has no integrity check — they are
         * re-applied from the app's own code at every init.
         */
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
