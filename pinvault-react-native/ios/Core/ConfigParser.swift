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
    ///   - release: a release build: without a native file, a config with Config APIs or static
    ///     pins is refused (unless `noFileAllowed`) and the relaxations (`allowUnsigned`, …) are
    ///     refused from JS; `expiredConfigGrace` is capped.
    ///   - noFileAllowed: the app's Info.plist accepts a release start without the file (``NativeSecurity/noFileInfoKey``).
    public static func parse(
        _ json: String,
        tokens: VaultTokenStore,
        guardFactory: (Int64) -> any EnvironmentGuard,
        listener: PinVaultConnectionListener?,
        native: NativeSecurity? = nil,
        release: Bool = false,
        noFileAllowed: Bool = false,
        reactNetworkingEnabled: Bool = true
    ) throws -> ParsedConfig {
        let root = try StrictJSON.parseObject(json, path: "config")
        let builder = PinVaultConfig.Builder()
        let require = native?.require ?? NativeSecurity.Require()

        let configApis = try root.objectList("configApis", maxItems: maxConfigApis)
        let vaultFiles = try root.objectList("vaultFiles", maxItems: maxVaultFiles)
        let jsStaticPins = try root.object("staticPins").map(staticPins)
        if release && native == nil && !noFileAllowed && (!(configApis ?? []).isEmpty || jsStaticPins != nil) {
            throw BridgeInputError(
                "config: a release build takes its trust anchors only from the app's native security file " +
                    "(\(NativeSecurity.resourceName).json, README \"Native security file\"); none is shipped. " +
                    "An app that accepts JS-only anchors says so in its Info.plist: \(NativeSecurity.noFileInfoKey) = YES"
            )
        }
        for api in configApis ?? [] {
            try addConfigApi(builder, api, native: native, release: release)
        }
        for file in vaultFiles ?? [] { try addVaultFile(builder, file, tokens, native: native) }
        if let pins = try SecurityPolicy.staticPins(path: "config.staticPins", js: jsStaticPins, native: native) {
            builder.staticPins(pins)
        }

        if let v = try root.int("maxRetryCount", min: 0, max: 10) { builder.maxRetryCount(v) }
        if let v = try root.int64("updateIntervalHours", min: 1, max: 24 * 30) { builder.updateIntervalHours(v) }
        if let v = try root.int64("updateIntervalMinutes", min: 15, max: 60 * 24 * 30) { builder.updateIntervalMinutes(v) }
        if let v = try root.string("deviceAlias", maxLength: 128) { builder.deviceAlias(v) }
        if let d = try root.object("expiredConfigGrace") {
            let (a, u) = try duration(d)
            let ms = millis(a, u)
            if release && ms > NativeSecurity.maxReleaseGraceMs { throw BridgeInputError("\(d.path): a release build takes at most 7 days") }
            if let max = require.expiredConfigGraceMs, ms > max {
                throw BridgeInputError("\(d.path): longer than the app's native security file allows (\(max / 1000) s)")
            }
            builder.expiredConfigGrace(a, u)
        } else if let max = require.expiredConfigGraceMs {
            builder.expiredConfigGrace(max, .milliseconds)
        }
        // `require` hosts are added to JS's: JS can name more, never fewer.
        let caTrust = (try root.stringList("requireCaTrust", maxItems: 64, maxLength: 255) ?? []) + (require.requireCaTrust ?? [])
        if !caTrust.isEmpty {
            var seen = Set<String>()
            builder.requireCaTrust(caTrust.filter { seen.insert($0).inserted })
        }
        if try root.bool("wipeVaultFilesOnRevocation") == true || require.wipeVaultFilesOnRevocation { builder.wipeVaultFilesOnRevocation() }
        if let d = try root.object("vaultFileMaxOfflineAge") {
            let (a, u) = try duration(d)
            if let max = require.vaultFileMaxOfflineAgeMs {
                let ms = millis(a, u)
                // 0 = no limit: longer than any.
                if ms == 0 || ms > max { throw BridgeInputError("\(d.path): longer than the app's native security file allows (\(max / 1000) s)") }
            }
            builder.vaultFileMaxOfflineAge(a, u)
        } else if let max = require.vaultFileMaxOfflineAgeMs {
            builder.vaultFileMaxOfflineAge(max, .milliseconds)
        }
        if try root.bool("requireUnlockedDevice") == true || require.requireUnlockedDevice { builder.requireUnlockedDevice() }
        if try root.bool("requireHardwareBackedKeys") == true || require.requireHardwareBackedKeys { builder.requireHardwareBackedKeys() }
        if try root.bool("managedTrustRoots") == true || require.managedTrustRoots { builder.managedTrustRoots() }
        if let v = try root.stringList("expectedSignerSha256", maxItems: 16, maxLength: 128) { builder.expectedSignerSha256(v) }

        var guardTimeout: Int64?
        if let g = try root.object("environmentGuard") {
            let timeout = try g.int64("timeoutMs", min: JSEnvironmentGuard.minTimeoutMs, max: JSEnvironmentGuard.maxTimeoutMs)
                ?? JSEnvironmentGuard.defaultTimeoutMs
            try g.finish()
            guardTimeout = timeout
            builder.environmentGuard(guardFactory(timeout))
        }

        // On by default in a release build — unless the app opted out of pinning RN's
        // networking natively (Info.plist PinVaultPinReactNativeNetworking = NO).
        let requirePinned = try root.bool("requirePinnedReactNativeNetworking") ?? (release && reactNetworkingEnabled)
        // Android-only settings: the Android side reads them; here only their shape is checked.
        _ = try root.object("android")
        var maxRN = ReactNetworking.defaultMaxResponseBytes
        if let ios = try root.object("ios") {
            if let v = try ios.int64("reactNativeMaxResponseBytes", min: 1, max: ReactNetworking.maxResponseBytesLimit) { maxRN = v }
            if let resolve = try ios.stringMap("resolve", maxItems: 64, maxKeyLength: 255, maxValueLength: 255) {
                for (host, address) in resolve.sorted(by: { $0.key < $1.key }) { builder.resolve(host: host, to: address) }
            }
            if let v = try fixedList("config.ios.expectedBundleIds", require.expectedBundleIds,
                                     try ios.stringList("expectedBundleIds", maxItems: 16, maxLength: 255), native) {
                builder.expectedBundleId(v)
            }
            if let v = try fixedList("config.ios.expectedTeamIds", require.expectedTeamIds,
                                     try ios.stringList("expectedTeamIds", maxItems: 16, maxLength: 32), native) {
                builder.expectedTeamId(v)
            }
            let jsStrength = try ios.enumValue("userAuthStrength", UserAuthStrength.self)
            if let fixed = require.userAuthStrength, let jsStrength, jsStrength != fixed {
                throw BridgeInputError("config.ios.userAuthStrength: differs from the app's native security file (\(native?.source ?? "")); the native value is fixed")
            }
            if let v = require.userAuthStrength ?? jsStrength { builder.userAuthStrength(v) }
            try ios.finish()
        }

        else {
            if let v = require.expectedBundleIds { builder.expectedBundleId(v) }
            if let v = require.expectedTeamIds { builder.expectedTeamId(v) }
            if let v = require.userAuthStrength { builder.userAuthStrength(v) }
        }

        try root.finish()
        if let listener { builder.onConnectionEvent(listener) }
        var parsed = ParsedConfig(config: try builder.build(), guardTimeoutMs: guardTimeout)
        parsed.requirePinnedReactNativeNetworking = requirePinned
        parsed.reactNativeMaxResponseBytes = maxRN
        parsed.nativeSecurityApplied = native != nil
        return parsed
    }

    /// A JS list against the native file's: fixed where the file gives it.
    static func fixedList(_ path: String, _ native: [String]?, _ js: [String]?, _ file: NativeSecurity?) throws -> [String]? {
        guard let native else { return js }
        if let js, !NativeSecurity.sameKeys(js, native) {
            throw BridgeInputError("\(path): differs from the app's native security file (\(file?.source ?? "")); the native value is fixed")
        }
        return native
    }

    static func millis(_ amount: Int64, _ unit: TimeUnit) -> Int64 {
        switch unit {
        case .milliseconds: return amount
        case .seconds: return amount.multipliedReportingOverflow(by: 1000).overflow ? .max : amount * 1000
        case .minutes: return amount.multipliedReportingOverflow(by: 60_000).overflow ? .max : amount * 60_000
        case .hours: return amount.multipliedReportingOverflow(by: 3_600_000).overflow ? .max : amount * 3_600_000
        case .days: return amount.multipliedReportingOverflow(by: 86_400_000).overflow ? .max : amount * 86_400_000
        default: return .max
        }
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

    /// An endpoint path resolved relative to the block's base URL. An absolute
    /// value — a scheme (`://`) or a root (`/`, `\`) — would silently retarget the
    /// request past the pinned host (`URL(string:relativeTo:)` honours it), so it
    /// is refused (RN-2). Returns nil when the optional field is absent.
    static func relEndpoint(_ f: Fields, _ key: String, maxLength: Int) throws -> String? {
        guard let v = try f.string(key, maxLength: maxLength) else { return nil }
        if v.contains("://") || v.hasPrefix("/") || v.hasPrefix("\\") {
            throw BridgeInputError("\(f.path).\(key): must be a relative path, not an absolute URL")
        }
        return v
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
        let configEndpoint = try relEndpoint(b, "configEndpoint", maxLength: 512)
        let healthEndpoint = try relEndpoint(b, "healthEndpoint", maxLength: 512)
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
        let enrollmentEndpoint = try relEndpoint(b, "enrollmentEndpoint", maxLength: 512)
        let clientCertEndpoint = try relEndpoint(b, "clientCertEndpoint", maxLength: 512)
        let vaultReportEndpoint = try relEndpoint(b, "vaultReportEndpoint", maxLength: 512)
        let clientCertLabel = try b.string("clientCertLabel", maxLength: 128)
        let wantPinsFor = try b.stringList("wantPinsFor", maxItems: 256, maxLength: 255)
        let renewalUrl = try httpsUrl(b, "renewalUrl")
        let enrollmentUrl = try httpsUrl(b, "enrollmentUrl")
        let threshold = try b.double("clientCertRenewalThreshold", min: 0, max: 1)
        let disableRenewal = try b.bool("disableClientCertRenewal") == true
        let jsAttestation = try b.bool("attestation")
        let attestationInterval = try b.object("attestationInterval").map(duration)
        let jsTokenHosts = try b.stringList("tokenHosts", maxItems: 64, maxLength: 255)
        let jsProof = try b.bool("proofOfPossession")
        try b.finish()

        // Where the block talks to and who gets its token and identity: fixed where the file says.
        let nativeBlock = native?.blocks[id]
        func fixed(_ key: String) -> BridgeInputError {
            BridgeInputError("\(b.path).\(key): differs from the app's native security file (\(native?.source ?? "")); the native value is fixed")
        }
        var blockUrl = url
        if let n = nativeBlock?.url {
            if n != url { throw fixed("url") }
            blockUrl = n
        }
        if nativeBlock?.attestation == true && jsAttestation == false {
            throw BridgeInputError("\(b.path).attestation: the app's native security file turns it on; JS cannot turn it off")
        }
        let attestation = jsAttestation == true || nativeBlock?.attestation == true
        if nativeBlock?.proofOfPossession == true && jsProof == false {
            throw BridgeInputError("\(b.path).proofOfPossession: the app's native security file turns it on; JS cannot turn it off")
        }
        let proof = jsProof == true || nativeBlock?.proofOfPossession == true
        let lower: ([String]) -> [String] = { $0.map { $0.lowercased() } }
        var tokenHosts = jsTokenHosts
        if let n = nativeBlock?.tokenHosts {
            if let j = jsTokenHosts, !NativeSecurity.sameKeys(lower(j), lower(n)) { throw fixed("tokenHosts") }
            tokenHosts = n
        }
        var fixedEnrollmentUrl = enrollmentUrl
        if let n = nativeBlock?.enrollmentUrl {
            if let j = enrollmentUrl, j != n { throw fixed("enrollmentUrl") }
            fixedEnrollmentUrl = n
        }
        var fixedRenewalUrl = renewalUrl
        if let n = nativeBlock?.renewalUrl {
            if let j = renewalUrl, j != n { throw fixed("renewalUrl") }
            fixedRenewalUrl = n
        }
        // Who gets the device's identity is the file's call in a release build: JS cannot
        // add a host the file does not name (tokenHosts only narrows the library's default).
        if release, let nativeBlock, nativeBlock.clientCertHosts == nil, clientCertHosts != nil {
            throw BridgeInputError("\(b.path).clientCertHosts: a release build takes it only from the app's native security file "
                + "(\(native?.source ?? "")); declare clientCertHosts for Config API '\(id)' there")
        }
        var certHosts = clientCertHosts
        if let n = nativeBlock?.clientCertHosts {
            if let j = clientCertHosts, !NativeSecurity.sameKeys(lower(j), lower(n)) { throw fixed("clientCertHosts") }
            certHosts = n
        }

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

        builder.configApi(id, url: blockUrl) { api in
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
            if let certHosts { api.clientCertHosts(certHosts) }
            if let enrollmentEndpoint { api.enrollmentEndpoint(enrollmentEndpoint) }
            if let clientCertEndpoint { api.clientCertEndpoint(clientCertEndpoint) }
            if let vaultReportEndpoint { api.vaultReportEndpoint(vaultReportEndpoint) }
            if let clientCertLabel { api.clientCertLabel(clientCertLabel) }
            if let wantPinsFor { api.wantPinsFor(wantPinsFor) }
            if let fixedRenewalUrl { api.renewalUrl(fixedRenewalUrl) }
            if let fixedEnrollmentUrl { api.enrollmentUrl(fixedEnrollmentUrl) }
            if let threshold { api.clientCertRenewalThreshold(threshold) }
            if disableRenewal { api.disableClientCertRenewal() }
            if attestation { api.attestation() }
            if let (amount, unit) = attestationInterval { api.attestationInterval(amount, unit) }
            if let tokenHosts { api.tokenHosts(tokenHosts) }
            if proof { api.proofOfPossession() }
        }
    }

    static func addVaultFile(_ builder: PinVaultConfig.Builder, _ f: Fields, _ tokens: VaultTokenStore, native: NativeSecurity?) throws {
        let key = try f.requireString("key", maxLength: 128)
        let endpoint = try f.requireString("endpoint", maxLength: 512)
        if endpoint.contains("://") || endpoint.hasPrefix("/") || endpoint.hasPrefix("\\") {
            throw BridgeInputError("\(f.path).endpoint: must be a relative path, not an absolute URL")
        }
        let jsSignatureKey = try f.string("signaturePublicKey", maxLength: keyLength, multiline: true)
        let updateWithPins = try f.bool("updateWithPins")
        let storage = try f.enumValue("storage", StorageStrategy.self)
        let configApi = try f.string("configApi", maxLength: 128)
        let policy = try f.enumValue("accessPolicy", VaultFileAccessPolicy.self)
        let jsEncryption = try f.enumValue("encryption", VaultFileEncryption.self)
        let jsUserAuth = try f.enumValue("userAuth", UserAuth.self)
        let maxOfflineAge = try f.object("maxOfflineAge").map(duration)
        let wipeWhenStale = try f.bool("wipeWhenStale") == true
        try f.finish()
        var offlineAge = maxOfflineAge

        // A file the native security file names keeps its signature key, encryption and lock.
        var signatureKey = jsSignatureKey
        var encryption = jsEncryption
        var userAuth = jsUserAuth
        if let files = native?.vaultFiles {
            guard let declared = files[key] else {
                throw BridgeInputError("\(f.path): vault file '\(key)' is not declared in the app's native security file (\(native?.source ?? ""))")
            }
            func fixed(_ field: String) -> BridgeInputError {
                BridgeInputError("\(f.path).\(field): differs from the app's native security file (\(native?.source ?? "")); the native value is fixed")
            }
            if let n = declared.signaturePublicKey {
                if let j = jsSignatureKey, j.trimmingCharacters(in: .whitespacesAndNewlines) != n.trimmingCharacters(in: .whitespacesAndNewlines) {
                    throw fixed("signaturePublicKey")
                }
                signatureKey = n
            }
            if let n = declared.encryption {
                if let j = jsEncryption, j != n { throw fixed("encryption") }
                encryption = n
            }
            if let n = declared.userAuth {
                if let j = jsUserAuth, j != n { throw fixed("userAuth") }
                userAuth = n
            }
            if let max = declared.maxOfflineAgeMs, maxOfflineAge == nil {
                offlineAge = (max, .milliseconds)
            }
        }
        // The tighter of the file's own cap and the config-wide one: a per-file value
        // overrides the config's, so it must not escape the config-wide cap either.
        let cap = [native?.vaultFiles?[key]?.maxOfflineAgeMs, native?.require.vaultFileMaxOfflineAgeMs].compactMap { $0 }.min()
        if let cap, let (a, u) = maxOfflineAge {
            let ms = millis(a, u)
            // 0 = no limit: longer than any.
            if ms == 0 || ms > cap {
                throw BridgeInputError("\(f.path).maxOfflineAge: longer than the app's native security file allows (\(cap / 1000) s)")
            }
        }

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
            if let (amount, unit) = offlineAge { file.maxOfflineAge(amount, unit) }
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
