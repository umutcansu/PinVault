// JSON config from JS → PinVaultConfig through the library's own builders (the
// Swift twin of ConfigParser.kt; same keys, same limits). Unknown keys, wrong
// types and out-of-range sizes are refused with BridgeInputError; builder
// refusals surface from `build()` as PinVaultError.invalidConfiguration.
//
// Not exposed on purpose: `clientKeystore(_:password:)` (a P12 and its password
// would cross the JS bridge — enroll instead), custom CertificateConfigApi /
// storage / integrity providers (native objects), `reportToPinVaultBackend`.
import Foundation
import PinVault

public struct ParsedConfig {
    public let config: PinVaultConfig
    /// Non-nil when JS registered an `environmentGuard`.
    public let guardTimeoutMs: Int64?
    /// `requirePinnedReactNativeNetworking`: start fails when RN's https does not go through PinVault.
    public var requirePinnedReactNativeNetworking = false
    /// `ios.reactNativeMaxResponseBytes`: the bound of a React Native https answer (default 50 MiB).
    public var reactNativeMaxResponseBytes = ReactNetworking.defaultMaxResponseBytes
    /// True when a native security file was applied.
    public var nativeSecurityApplied = false
}

public enum ConfigParser {
    public static let maxConfigApis = 16
    public static let maxVaultFiles = 64
    public static let maxPins = 256
    public static let maxPinsPerHost = 16
    static let keyLength = 4096

    /// - Parameters:
    ///   - native: the app's native security file (``NativeSecurity``); nil = none.
    ///   - release: a release build: without a native file, the relaxations (`allowUnsigned`, …) are refused from JS.
    public static func parse(
        _ json: String,
        tokens: VaultTokenStore,
        guardFactory: (Int64) -> any EnvironmentGuard,
        listener: PinVaultConnectionListener?,
        native: NativeSecurity? = nil,
        release: Bool = false
    ) throws -> ParsedConfig {
        let root = try StrictJSON.parseObject(json, path: "config")
        let builder = PinVaultConfig.Builder()

        for api in try root.objectList("configApis", maxItems: maxConfigApis) ?? [] {
            try addConfigApi(builder, api, native: native, release: release)
        }
        for file in try root.objectList("vaultFiles", maxItems: maxVaultFiles) ?? [] { try addVaultFile(builder, file, tokens) }
        let jsStaticPins = try root.object("staticPins").map(staticPins)
        if let pins = try SecurityPolicy.staticPins(path: "config.staticPins", js: jsStaticPins, native: native) {
            builder.staticPins(pins)
        }

        if let v = try root.int("maxRetryCount", min: 0, max: 10) { builder.maxRetryCount(v) }
        if let v = try root.int64("updateIntervalHours", min: 1, max: 24 * 30) { builder.updateIntervalHours(v) }
        if let v = try root.int64("updateIntervalMinutes", min: 15, max: 60 * 24 * 30) { builder.updateIntervalMinutes(v) }
        if let v = try root.string("deviceAlias", maxLength: 128) { builder.deviceAlias(v) }
        if let d = try root.object("expiredConfigGrace") { let (a, u) = try duration(d); builder.expiredConfigGrace(a, u) }
        if let v = try root.stringList("requireCaTrust", maxItems: 64, maxLength: 255) { builder.requireCaTrust(v) }
        if try root.bool("wipeVaultFilesOnRevocation") == true { builder.wipeVaultFilesOnRevocation() }
        if let d = try root.object("vaultFileMaxOfflineAge") { let (a, u) = try duration(d); builder.vaultFileMaxOfflineAge(a, u) }
        if try root.bool("requireUnlockedDevice") == true { builder.requireUnlockedDevice() }
        if try root.bool("requireHardwareBackedKeys") == true { builder.requireHardwareBackedKeys() }
        if try root.bool("managedTrustRoots") == true { builder.managedTrustRoots() }
        if let v = try root.stringList("expectedSignerSha256", maxItems: 16, maxLength: 128) { builder.expectedSignerSha256(v) }

        var guardTimeout: Int64?
        if let g = try root.object("environmentGuard") {
            let timeout = try g.int64("timeoutMs", min: JSEnvironmentGuard.minTimeoutMs, max: JSEnvironmentGuard.maxTimeoutMs)
                ?? JSEnvironmentGuard.defaultTimeoutMs
            try g.finish()
            guardTimeout = timeout
            builder.environmentGuard(guardFactory(timeout))
        }

        let requirePinned = try root.bool("requirePinnedReactNativeNetworking") == true
        // Android-only settings: the Android side reads them; here only their shape is checked.
        _ = try root.object("android")
        var maxRN = ReactNetworking.defaultMaxResponseBytes
        if let ios = try root.object("ios") {
            if let v = try ios.int64("reactNativeMaxResponseBytes", min: 1, max: ReactNetworking.maxResponseBytesLimit) { maxRN = v }
            if let resolve = try ios.stringMap("resolve", maxItems: 64, maxKeyLength: 255, maxValueLength: 255) {
                for (host, address) in resolve.sorted(by: { $0.key < $1.key }) { builder.resolve(host: host, to: address) }
            }
            if let v = try ios.stringList("expectedBundleIds", maxItems: 16, maxLength: 255) { builder.expectedBundleId(v) }
            if let v = try ios.stringList("expectedTeamIds", maxItems: 16, maxLength: 32) { builder.expectedTeamId(v) }
            if let v = try ios.enumValue("userAuthStrength", UserAuthStrength.self) { builder.userAuthStrength(v) }
            try ios.finish()
        }

        try root.finish()
        if let listener { builder.onConnectionEvent(listener) }
        var parsed = ParsedConfig(config: try builder.build(), guardTimeoutMs: guardTimeout)
        parsed.requirePinnedReactNativeNetworking = requirePinned
        parsed.reactNativeMaxResponseBytes = maxRN
        parsed.nativeSecurityApplied = native != nil
        return parsed
    }

    static func duration(_ d: Fields) throws -> (Int64, TimeUnit) {
        guard let amount = try d.int64("amount", min: 0, max: 10 * 365 * 24 * 3600 * 1000) else {
            throw BridgeInputError("\(d.path).amount: required")
        }
        let raw = try d.requireString("unit", maxLength: 16)
        let allowed: [TimeUnit] = [.milliseconds, .seconds, .minutes, .hours, .days]
        guard let unit = TimeUnit(rawValue: raw), allowed.contains(unit) else {
            throw BridgeInputError("\(d.path).unit: '\(raw)' is not one of MILLISECONDS, SECONDS, MINUTES, HOURS, DAYS")
        }
        try d.finish()
        return (amount, unit)
    }

    static func httpsUrl(_ f: Fields, _ key: String) throws -> String? {
        guard let url = try f.string(key, maxLength: 2048) else { return nil }
        guard url.hasPrefix("https://") else { throw BridgeInputError("\(f.path).\(key): must be an https:// URL") }
        return url
    }

    public static func hostPin(_ p: Fields) throws -> HostPin {
        let hostname = try p.requireString("hostname", maxLength: 255)
        guard let pins = try p.stringList("sha256", maxItems: maxPinsPerHost, maxLength: 128) else {
            throw BridgeInputError("\(p.path).sha256: required")
        }
        let pin = HostPin(
            hostname: hostname,
            sha256: pins,
            version: try p.int("version", min: 0, max: Int(Int32.max)) ?? 0,
            forceUpdate: try p.bool("forceUpdate") ?? false,
            mtls: try p.bool("mtls") ?? false,
            clientCertVersion: try p.int("clientCertVersion", min: 0, max: Int(Int32.max))
        )
        try p.finish()
        // The Kotlin constructor's rule (≥ 2 pins), applied here so the refusal names the path.
        do { try pin.validate() } catch { throw BridgeInputError("\(p.path): \((error as? PinVaultError)?.message ?? "\(error)")") }
        return pin
    }

    public static func staticPins(_ s: Fields) throws -> CertificateConfig {
        guard let pins = try s.objectList("pins", maxItems: maxPins)?.map(hostPin) else {
            throw BridgeInputError("\(s.path).pins: required")
        }
        let config = CertificateConfig(
            version: try s.int("version", min: 0, max: Int(Int32.max)) ?? 0,
            pins: pins,
            forceUpdate: try s.bool("forceUpdate") ?? false
        )
        try s.finish()
        return config
    }

    static func addConfigApi(_ builder: PinVaultConfig.Builder, _ b: Fields, native: NativeSecurity?, release: Bool) throws {
        let id = try b.requireString("id", maxLength: 128)
        guard let url = try httpsUrl(b, "url") else { throw BridgeInputError("\(b.path).url: required") }
        let bootstrapPins = try b.objectList("bootstrapPins", maxItems: maxPins)?.map(hostPin)
        let configEndpoint = try b.string("configEndpoint", maxLength: 512)
        let healthEndpoint = try b.string("healthEndpoint", maxLength: 512)
        let oneKey = try b.string("signaturePublicKey", maxLength: keyLength, multiline: true)
        let keys = try b.stringList("signaturePublicKeys", maxItems: 16, maxLength: keyLength, multiline: true)
        if oneKey != nil && keys != nil {
            throw BridgeInputError("\(b.path): give signaturePublicKey or signaturePublicKeys, not both")
        }
        let requiredSignatures = try b.int("requiredSignatures", min: 1, max: 16)
        let recoveryKeys = try b.stringList("recoveryPublicKeys", maxItems: 16, maxLength: keyLength, multiline: true)
        let requiredRecovery = try b.int("requiredRecoverySignatures", min: 1, max: 16)
        let allowUnsigned = try b.bool("allowUnsigned") == true
        let serverScope = try b.string("serverScope", maxLength: 128)
        let allowUnpinned = try b.bool("allowUnpinnedConfigApi") == true
        let allowServerKey = try b.bool("allowServerGeneratedKey") == true
        let clientCaPins = try b.stringList("clientCaPins", maxItems: 16, maxLength: 128)
        let maxLifetime = try b.int("maxClientCertLifetimeDays", min: 1, max: 3650)
        let clientCertHosts = try b.stringList("clientCertHosts", maxItems: 64, maxLength: 2048)
        let enrollmentEndpoint = try b.string("enrollmentEndpoint", maxLength: 512)
        let clientCertEndpoint = try b.string("clientCertEndpoint", maxLength: 512)
        let vaultReportEndpoint = try b.string("vaultReportEndpoint", maxLength: 512)
        let clientCertLabel = try b.string("clientCertLabel", maxLength: 128)
        let wantPinsFor = try b.stringList("wantPinsFor", maxItems: 256, maxLength: 255)
        let renewalUrl = try httpsUrl(b, "renewalUrl")
        let enrollmentUrl = try httpsUrl(b, "enrollmentUrl")
        let threshold = try b.double("clientCertRenewalThreshold", min: 0, max: 1)
        let disableRenewal = try b.bool("disableClientCertRenewal") == true
        let attestation = try b.bool("attestation") == true
        let attestationInterval = try b.object("attestationInterval").map(duration)
        let tokenHosts = try b.stringList("tokenHosts", maxItems: 64, maxLength: 255)
        try b.finish()

        // The trust anchors and relaxations: the native security file decides, JS only repeats.
        let sec = try SecurityPolicy.apply(
            path: b.path, id: id,
            js: SecurityFields(
                bootstrapPins: bootstrapPins, oneKey: oneKey, keys: keys, requiredSignatures: requiredSignatures,
                recoveryKeys: recoveryKeys, requiredRecovery: requiredRecovery, serverScope: serverScope,
                clientCaPins: clientCaPins, allowUnsigned: allowUnsigned, allowUnpinned: allowUnpinned,
                allowServerKey: allowServerKey
            ),
            native: native, release: release
        )

        builder.configApi(id, url: url) { api in
            if let v = sec.bootstrapPins { api.bootstrapPins(v) }
            if let configEndpoint { api.configEndpoint(configEndpoint) }
            if let healthEndpoint { api.healthEndpoint(healthEndpoint) }
            if let v = sec.oneKey { api.signaturePublicKey(v) }
            if let v = sec.keys { api.signaturePublicKeys(v) }
            if let v = sec.requiredSignatures { api.requiredSignatures(v) }
            if let v = sec.recoveryKeys { api.recoveryPublicKeys(v) }
            if let v = sec.requiredRecovery { api.requiredRecoverySignatures(v) }
            if sec.allowUnsigned { api.allowUnsigned() }
            if let v = sec.serverScope { api.serverScope(v) }
            if sec.allowUnpinned { api.allowUnpinnedConfigApi() }
            if sec.allowServerKey { api.allowServerGeneratedKey() }
            if let v = sec.clientCaPins { api.clientCaPins(v) }
            if let maxLifetime { api.maxClientCertLifetimeDays(maxLifetime) }
            if let clientCertHosts { api.clientCertHosts(clientCertHosts) }
            if let enrollmentEndpoint { api.enrollmentEndpoint(enrollmentEndpoint) }
            if let clientCertEndpoint { api.clientCertEndpoint(clientCertEndpoint) }
            if let vaultReportEndpoint { api.vaultReportEndpoint(vaultReportEndpoint) }
            if let clientCertLabel { api.clientCertLabel(clientCertLabel) }
            if let wantPinsFor { api.wantPinsFor(wantPinsFor) }
            if let renewalUrl { api.renewalUrl(renewalUrl) }
            if let enrollmentUrl { api.enrollmentUrl(enrollmentUrl) }
            if let threshold { api.clientCertRenewalThreshold(threshold) }
            if disableRenewal { api.disableClientCertRenewal() }
            if attestation { api.attestation() }
            if let (amount, unit) = attestationInterval { api.attestationInterval(amount, unit) }
            if let tokenHosts { api.tokenHosts(tokenHosts) }
        }
    }

    static func addVaultFile(_ builder: PinVaultConfig.Builder, _ f: Fields, _ tokens: VaultTokenStore) throws {
        let key = try f.requireString("key", maxLength: 128)
        let endpoint = try f.requireString("endpoint", maxLength: 512)
        let signatureKey = try f.string("signaturePublicKey", maxLength: keyLength, multiline: true)
        let updateWithPins = try f.bool("updateWithPins")
        let storage = try f.enumValue("storage", StorageStrategy.self)
        let configApi = try f.string("configApi", maxLength: 128)
        let policy = try f.enumValue("accessPolicy", VaultFileAccessPolicy.self)
        let encryption = try f.enumValue("encryption", VaultFileEncryption.self)
        let userAuth = try f.enumValue("userAuth", UserAuth.self)
        let maxOfflineAge = try f.object("maxOfflineAge").map(duration)
        let wipeWhenStale = try f.bool("wipeWhenStale") == true
        try f.finish()

        builder.vaultFile(key) { file in
            file.endpoint(endpoint)
            if let signatureKey { file.signaturePublicKey(signatureKey) }
            if let updateWithPins { file.updateWithPins(updateWithPins) }
            if let storage { file.storage(storage) }
            if let configApi { file.configApi(configApi) }
            if let policy {
                file.accessPolicy(policy)
                if policy == .token || policy == .tokenMtls {
                    // Read on every download; the token never leaves native memory.
                    file.accessToken { tokens.get(key) }
                }
            }
            if let encryption { file.encryption(encryption) }
            if let userAuth { file.userAuth(userAuth) }
            if let (amount, unit) = maxOfflineAge { file.maxOfflineAge(amount, unit) }
            if wipeWhenStale { file.wipeWhenStale() }
        }
    }

    /// `unlockFile` prompt texts + the content encoding.
    public static func unlockPrompt(_ json: String) throws -> (VaultFileUnlockPrompt, String) {
        let p = try StrictJSON.parseObject(json, path: "prompt", maxChars: 16 * 1024)
        let prompt = VaultFileUnlockPrompt(
            title: try p.requireString("title", maxLength: 256),
            subtitle: try p.string("subtitle", maxLength: 256),
            description: try p.string("description", maxLength: 1024),
            negativeButtonText: try p.string("negativeButtonText", maxLength: 64) ?? "Cancel"
        )
        let encoding = try ResultMapper.checkEncoding(try p.string("encoding", maxLength: 16) ?? ResultMapper.utf8)
        try p.finish()
        return (prompt, encoding)
    }
}
