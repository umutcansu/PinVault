package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.api.PinVaultConnectionListener
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnvironmentGuard
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.PinVaultConfig
import io.github.umutcansu.pinvault.model.StorageStrategy
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt
import java.util.concurrent.TimeUnit

/** What `start(config)` needs besides the library's own config. */
internal class ParsedConfig(
    val config: PinVaultConfig,
    /** Non-null when JS registered an `environmentGuard`. */
    val guardTimeoutMs: Long?,
    /** `android.pinGlobalNetworking` (default true). */
    val pinGlobalNetworking: Boolean,
)

/**
 * JSON config from JS → [PinVaultConfig] through the library's own builders,
 * so every builder rule (`require`) still applies. The JSON keys are the
 * builder method names. Unknown keys, wrong types and out-of-range sizes are
 * refused with [BridgeInputException]; builder refusals surface as their
 * `IllegalArgumentException` (both are `E_INVALID_CONFIG` for JS).
 *
 * Not exposed on purpose: `clientKeystore(bytes, password)` (a P12 and its
 * password would cross the JS bridge — enroll instead), custom
 * `CertificateConfigApi` / storage providers / integrity providers (native
 * objects), `reportToPinVaultBackend`.
 */
internal object ConfigParser {

    const val MAX_CONFIG_APIS = 16
    const val MAX_VAULT_FILES = 64
    const val MAX_PINS = 256
    const val MAX_PINS_PER_HOST = 16
    private const val KEY_LENGTH = 4096

    fun parse(
        json: String,
        tokens: VaultTokenStore,
        guardFactory: (timeoutMs: Long) -> EnvironmentGuard,
        listener: PinVaultConnectionListener?,
    ): ParsedConfig {
        val root = StrictJson.parseObject(json, "config")
        val builder = PinVaultConfig.Builder()

        root.objList("configApis", MAX_CONFIG_APIS)?.forEach { addConfigApi(builder, it) }
        root.objList("vaultFiles", MAX_VAULT_FILES)?.forEach { addVaultFile(builder, it, tokens) }
        root.obj("staticPins")?.let { builder.staticPins(staticPins(it)) }

        root.int("maxRetryCount", 0, 10)?.let { builder.maxRetryCount(it) }
        root.long("updateIntervalHours", 1, 24L * 30)?.let { builder.updateIntervalHours(it) }
        root.long("updateIntervalMinutes", 15, 60L * 24 * 30)?.let { builder.updateIntervalMinutes(it) }
        root.string("deviceAlias", 128)?.let { builder.deviceAlias(it) }
        root.obj("expiredConfigGrace")?.let { d -> duration(d).let { builder.expiredConfigGrace(it.first, it.second) } }
        root.stringList("requireCaTrust", 64, 255)?.let { builder.requireCaTrust(*it.toTypedArray()) }
        if (root.bool("wipeVaultFilesOnRevocation") == true) builder.wipeVaultFilesOnRevocation()
        root.obj("vaultFileMaxOfflineAge")?.let { d -> duration(d).let { builder.vaultFileMaxOfflineAge(it.first, it.second) } }
        val requireUnlocked = root.bool("requireUnlockedDevice") == true
        if (root.bool("requireHardwareBackedKeys") == true) builder.requireHardwareBackedKeys()
        if (root.bool("managedTrustRoots") == true) builder.managedTrustRoots()
        root.stringList("expectedSignerSha256", 16, 128)?.let { builder.expectedSignerSha256(it) }

        var guardTimeout: Long? = null
        root.obj("environmentGuard")?.let { g ->
            guardTimeout = g.long("timeoutMs", JsEnvironmentGuard.MIN_TIMEOUT_MS, JsEnvironmentGuard.MAX_TIMEOUT_MS)
                ?: JsEnvironmentGuard.DEFAULT_TIMEOUT_MS
            g.finish()
            builder.environmentGuard(guardFactory(guardTimeout!!))
        }

        var allowFallback = false
        var pinGlobal = true
        root.obj("android")?.let { a ->
            allowFallback = a.bool("requireUnlockedDeviceAllowFallback") == true
            pinGlobal = a.bool("pinGlobalNetworking") ?: true
            a.finish()
        }
        if (allowFallback && !requireUnlocked) {
            throw BridgeInputException("config.android.requireUnlockedDeviceAllowFallback: needs requireUnlockedDevice: true")
        }
        if (requireUnlocked) builder.requireUnlockedDevice(allowFallback)
        // iOS-only settings: the iOS side reads them; here only their shape is checked.
        root.obj("ios")

        root.finish()
        listener?.let { builder.onConnectionEvent(it) }
        return ParsedConfig(builder.build(), guardTimeout, pinGlobal)
    }

    private fun duration(d: Fields): Pair<Long, TimeUnit> {
        val amount = d.long("amount", 0, 10L * 365 * 24 * 3600 * 1000) ?: throw BridgeInputException("${d.path}.amount: required")
        val unit = when (val u = d.requireString("unit", 16)) {
            "MILLISECONDS" -> TimeUnit.MILLISECONDS
            "SECONDS" -> TimeUnit.SECONDS
            "MINUTES" -> TimeUnit.MINUTES
            "HOURS" -> TimeUnit.HOURS
            "DAYS" -> TimeUnit.DAYS
            else -> throw BridgeInputException("${d.path}.unit: '$u' is not one of MILLISECONDS, SECONDS, MINUTES, HOURS, DAYS")
        }
        d.finish()
        return amount to unit
    }

    private fun httpsUrl(f: Fields, key: String): String? {
        val url = f.string(key, 2048) ?: return null
        if (!url.startsWith("https://")) throw BridgeInputException("${f.path}.$key: must be an https:// URL")
        return url
    }

    fun hostPin(p: Fields): HostPin {
        val hostname = p.requireString("hostname", 255)
        val pins = p.stringList("sha256", MAX_PINS_PER_HOST, 128) ?: throw BridgeInputException("${p.path}.sha256: required")
        val pin = HostPin(
            hostname = hostname,
            sha256 = pins,
            version = p.int("version", 0, Int.MAX_VALUE) ?: 0,
            forceUpdate = p.bool("forceUpdate") ?: false,
            mtls = p.bool("mtls") ?: false,
            clientCertVersion = p.int("clientCertVersion", 0, Int.MAX_VALUE),
        )
        p.finish()
        return pin
    }

    private fun staticPins(s: Fields): CertificateConfig {
        val pins = s.objList("pins", MAX_PINS)?.map(::hostPin) ?: throw BridgeInputException("${s.path}.pins: required")
        val config = CertificateConfig(
            version = s.int("version", 0, Int.MAX_VALUE) ?: 0,
            pins = pins,
            forceUpdate = s.bool("forceUpdate") ?: false,
        )
        s.finish()
        return config
    }

    private fun addConfigApi(builder: PinVaultConfig.Builder, b: Fields) {
        val id = b.requireString("id", 128)
        val url = httpsUrl(b, "url") ?: throw BridgeInputException("${b.path}.url: required")
        // Read everything before the builder runs, so a refusal names the JSON path.
        val bootstrapPins = b.objList("bootstrapPins", MAX_PINS)?.map(::hostPin)
        val configEndpoint = b.string("configEndpoint", 512)
        val healthEndpoint = b.string("healthEndpoint", 512)
        val oneKey = b.string("signaturePublicKey", KEY_LENGTH, multiline = true)
        val keys = b.stringList("signaturePublicKeys", 16, KEY_LENGTH, multiline = true)
        if (oneKey != null && keys != null) {
            throw BridgeInputException("${b.path}: give signaturePublicKey or signaturePublicKeys, not both")
        }
        val requiredSignatures = b.int("requiredSignatures", 1, 16)
        val recoveryKeys = b.stringList("recoveryPublicKeys", 16, KEY_LENGTH, multiline = true)
        val requiredRecovery = b.int("requiredRecoverySignatures", 1, 16)
        val allowUnsigned = b.bool("allowUnsigned") == true
        val serverScope = b.string("serverScope", 128)
        val allowUnpinned = b.bool("allowUnpinnedConfigApi") == true
        val allowServerKey = b.bool("allowServerGeneratedKey") == true
        val clientCaPins = b.stringList("clientCaPins", 16, 128)
        val maxLifetime = b.int("maxClientCertLifetimeDays", 1, 3650)
        val clientCertHosts = b.stringList("clientCertHosts", 64, 2048)
        val enrollmentEndpoint = b.string("enrollmentEndpoint", 512)
        val clientCertEndpoint = b.string("clientCertEndpoint", 512)
        val vaultReportEndpoint = b.string("vaultReportEndpoint", 512)
        val clientCertLabel = b.string("clientCertLabel", 128)
        val wantPinsFor = b.stringList("wantPinsFor", 256, 255)
        val renewalUrl = httpsUrl(b, "renewalUrl")
        val enrollmentUrl = httpsUrl(b, "enrollmentUrl")
        val threshold = b.double("clientCertRenewalThreshold", 0.0, 1.0)
        val disableRenewal = b.bool("disableClientCertRenewal") == true
        val attestation = b.bool("attestation") == true
        val attestationInterval = b.obj("attestationInterval")?.let(::duration)
        val tokenHosts = b.stringList("tokenHosts", 64, 255)
        b.finish()

        builder.configApi(id, url) {
            bootstrapPins?.let { this.bootstrapPins(it) }
            configEndpoint?.let { this.configEndpoint(it) }
            healthEndpoint?.let { this.healthEndpoint(it) }
            oneKey?.let { this.signaturePublicKey(it) }
            keys?.let { this.signaturePublicKeys(it) }
            requiredSignatures?.let { this.requiredSignatures(it) }
            recoveryKeys?.let { this.recoveryPublicKeys(it) }
            requiredRecovery?.let { this.requiredRecoverySignatures(it) }
            if (allowUnsigned) this.allowUnsigned()
            serverScope?.let { this.serverScope(it) }
            if (allowUnpinned) this.allowUnpinnedConfigApi()
            if (allowServerKey) this.allowServerGeneratedKey()
            clientCaPins?.let { this.clientCaPins(it) }
            maxLifetime?.let { this.maxClientCertLifetimeDays(it) }
            clientCertHosts?.let { this.clientCertHosts(it) }
            enrollmentEndpoint?.let { this.enrollmentEndpoint(it) }
            clientCertEndpoint?.let { this.clientCertEndpoint(it) }
            vaultReportEndpoint?.let { this.vaultReportEndpoint(it) }
            clientCertLabel?.let { this.clientCertLabel(it) }
            wantPinsFor?.let { this.wantPinsFor(*it.toTypedArray()) }
            renewalUrl?.let { this.renewalUrl(it) }
            enrollmentUrl?.let { this.enrollmentUrl(it) }
            threshold?.let { this.clientCertRenewalThreshold(it) }
            if (disableRenewal) this.disableClientCertRenewal()
            if (attestation) this.attestation()
            attestationInterval?.let { this.attestationInterval(it.first, it.second) }
            tokenHosts?.let { this.tokenHosts(it) }
        }
    }

    private fun addVaultFile(builder: PinVaultConfig.Builder, f: Fields, tokens: VaultTokenStore) {
        val key = f.requireString("key", 128)
        val endpoint = f.requireString("endpoint", 512)
        val signatureKey = f.string("signaturePublicKey", KEY_LENGTH, multiline = true)
        val updateWithPins = f.bool("updateWithPins")
        val storage = f.enum("storage", StorageStrategy.values())
        val configApi = f.string("configApi", 128)
        val policy = f.enum("accessPolicy", VaultFileAccessPolicy.values())
        val encryption = f.enum("encryption", VaultFileEncryption.values())
        val userAuth = f.enum("userAuth", UserAuth.values())
        val maxOfflineAge = f.obj("maxOfflineAge")?.let(::duration)
        val wipeWhenStale = f.bool("wipeWhenStale") == true
        f.finish()

        builder.vaultFile(key) {
            this.endpoint(endpoint)
            signatureKey?.let { this.signaturePublicKey(it) }
            updateWithPins?.let { this.updateWithPins(it) }
            storage?.let { this.storage(it) }
            configApi?.let { this.configApi(it) }
            policy?.let { this.accessPolicy(it) }
            if (policy == VaultFileAccessPolicy.TOKEN || policy == VaultFileAccessPolicy.TOKEN_MTLS) {
                // Read on every download; the token never leaves native memory.
                this.accessToken { tokens.get(key) }
            }
            encryption?.let { this.encryption(it) }
            userAuth?.let { this.userAuth(it) }
            maxOfflineAge?.let { this.maxOfflineAge(it.first, it.second) }
            if (wipeWhenStale) this.wipeWhenStale()
        }
    }

    /** `unlockFile` prompt texts + the content encoding. */
    fun unlockPrompt(json: String): Pair<VaultFileUnlockPrompt, String> {
        val p = StrictJson.parseObject(json, "prompt", maxChars = 16 * 1024)
        val prompt = VaultFileUnlockPrompt(
            title = p.requireString("title", 256),
            subtitle = p.string("subtitle", 256),
            description = p.string("description", 1024),
            negativeButtonText = p.string("negativeButtonText", 64) ?: "Cancel",
        )
        val encoding = ResultMapper.checkEncoding(p.string("encoding", 16) ?: ResultMapper.UTF8)
        p.finish()
        return prompt to encoding
    }
}
