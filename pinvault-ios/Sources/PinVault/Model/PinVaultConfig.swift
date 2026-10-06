import Foundation

/// Configuration for ``PinVault``.
///
/// ```swift
/// let config = try PinVaultConfig.Builder()
///     .configApi("default-tls", url: "https://192.168.1.10:6651/") { block in
///         block.bootstrapPins([HostPin(hostname: "192.168.1.10", sha256: [p1, p2])])
///         block.signaturePublicKey(base64)
///         block.serverScope("default-tls")
///     }
///     .vaultFile("sample-flags") { file in file.endpoint("api/v1/vault/sample-flags") }
///     .build()
/// let result = await PinVault.shared.start(config: config)
/// ```
///
/// Offline (static pins, no server): `PinVaultConfig.static(HostPin(hostname: "api.example.com", sha256: [p1, p2]))`.
public struct PinVaultConfig: Sendable {
    /// Every Config API, keyed by id.
    public let configApis: [String: ConfigApiBlock]
    /// The Config API ids in registration order; the first is the default block.
    public let configApiIds: [String]
    /// Max retry attempts when the backend is unreachable during start.
    public let maxRetryCount: Int
    /// Periodic update interval (hours).
    public let updateIntervalHours: Int64
    /// Periodic update interval (minutes); wins over hours when set.
    public let updateIntervalMinutes: Int64?
    /// Human-readable device name for server-side tracking.
    public let deviceAlias: String?
    /// Registered vault files, keyed by ``VaultFileConfig/key``.
    public let vaultFiles: [String: VaultFileConfig]
    /// The vault file keys in registration order.
    public let vaultFileKeys: [String]
    /// Pre-loaded static pins for offline mode: no Config API is contacted.
    public let staticPins: CertificateConfig?
    /// Receives every ``PinVaultConnectionEvent``; nil = the library stays silent.
    public let connectionListener: PinVaultConnectionListener?
    /// How long a config may be used past its `expiresAt` (ms).
    public let expiredConfigGraceMs: Int64
    /// Hosts whose chain must also pass the platform CAs.
    public let caTrustHosts: [String]
    /// Delete a Config API's vault files when its identity is revoked.
    public let wipeVaultFilesOnRevocation: Bool
    /// Default offline lifetime of stored vault files (ms); 0 = no limit.
    public let vaultFileMaxOfflineAgeMs: Int64
    /// Keys and stores usable only while the device is unlocked.
    public let requireUnlockedDevice: Bool
    /// Refuse keys made outside secure hardware.
    public let requireHardwareBackedKeys: Bool
    /// A second opinion forwarded inside attestation reports.
    public let integrityVerdictProvider: (any IntegrityVerdictProvider)?
    /// Android: SHA-256 of the expected APK signers (lowercase hex). iOS reports no signer digests.
    public let expectedSignerSha256: [String]
    /// Accept hosts without a pin entry when the platform validates them to a root the signed config lists.
    public let managedTrustRoots: Bool
    /// The app's verdict on the device, asked before sensitive operations.
    public let environmentGuard: (any EnvironmentGuard)?
    /// Integrity token sent with every enrollment request.
    public let integrityTokenProvider: (any IntegrityTokenProvider)?
    /// iOS: logical host (lower case) → connection address (``Builder/resolve(host:to:)``).
    public let resolvedHosts: [String: String]
    /// iOS: bundle ids the app is expected to have (`app_integrity` signal); empty = not judged.
    public let expectedBundleIds: [String]
    /// iOS: Apple team ids the app is expected to be signed by (`app_integrity` signal); empty = not judged.
    public let expectedTeamIds: [String]

    public init(
        configApis: [ConfigApiBlock],
        maxRetryCount: Int = PinVaultConfig.defaultMaxRetry,
        updateIntervalHours: Int64 = PinVaultConfig.defaultUpdateIntervalHours,
        updateIntervalMinutes: Int64? = nil,
        deviceAlias: String? = nil,
        vaultFiles: [VaultFileConfig] = [],
        staticPins: CertificateConfig? = nil,
        connectionListener: PinVaultConnectionListener? = nil,
        expiredConfigGraceMs: Int64 = 0,
        caTrustHosts: [String] = [],
        wipeVaultFilesOnRevocation: Bool = false,
        vaultFileMaxOfflineAgeMs: Int64 = 0,
        requireUnlockedDevice: Bool = false,
        requireHardwareBackedKeys: Bool = false,
        integrityVerdictProvider: (any IntegrityVerdictProvider)? = nil,
        expectedSignerSha256: [String] = [],
        managedTrustRoots: Bool = false,
        environmentGuard: (any EnvironmentGuard)? = nil,
        integrityTokenProvider: (any IntegrityTokenProvider)? = nil,
        resolvedHosts: [String: String] = [:],
        expectedBundleIds: [String] = [],
        expectedTeamIds: [String] = []
    ) {
        var apis: [String: ConfigApiBlock] = [:]
        var ids: [String] = []
        for block in configApis {
            if apis[block.id] == nil { ids.append(block.id) }
            apis[block.id] = block
        }
        var files: [String: VaultFileConfig] = [:]
        var keys: [String] = []
        for file in vaultFiles {
            if files[file.key] == nil { keys.append(file.key) }
            files[file.key] = file
        }
        self.configApis = apis
        self.configApiIds = ids
        self.maxRetryCount = maxRetryCount
        self.updateIntervalHours = updateIntervalHours
        self.updateIntervalMinutes = updateIntervalMinutes
        self.deviceAlias = deviceAlias
        self.vaultFiles = files
        self.vaultFileKeys = keys
        self.staticPins = staticPins
        self.connectionListener = connectionListener
        self.expiredConfigGraceMs = expiredConfigGraceMs
        self.caTrustHosts = caTrustHosts
        self.wipeVaultFilesOnRevocation = wipeVaultFilesOnRevocation
        self.vaultFileMaxOfflineAgeMs = vaultFileMaxOfflineAgeMs
        self.requireUnlockedDevice = requireUnlockedDevice
        self.requireHardwareBackedKeys = requireHardwareBackedKeys
        self.integrityVerdictProvider = integrityVerdictProvider
        self.expectedSignerSha256 = expectedSignerSha256
        self.managedTrustRoots = managedTrustRoots
        self.environmentGuard = environmentGuard
        self.integrityTokenProvider = integrityTokenProvider
        self.resolvedHosts = resolvedHosts
        self.expectedBundleIds = expectedBundleIds
        self.expectedTeamIds = expectedTeamIds
    }

    /// The first registered block — the "default" one single-API calls use.
    public var defaultConfigApi: ConfigApiBlock? {
        configApiIds.first.flatMap { configApis[$0] }
    }

    /// The blocks in registration order.
    public var orderedConfigApis: [ConfigApiBlock] {
        configApiIds.compactMap { configApis[$0] }
    }

    /// The vault files in registration order.
    public var orderedVaultFiles: [VaultFileConfig] {
        vaultFileKeys.compactMap { vaultFiles[$0] }
    }

    // MARK: Builder

    /// The DSL builder. Methods record the first invalid argument (Kotlin's
    /// `require`); ``build()`` throws it as ``PinVaultError/invalidConfiguration(_:)``.
    public final class Builder {
        private var blocks: [String: ConfigApiBlock] = [:]
        private var blockIds: [String] = []
        private var maxRetryCount = PinVaultConfig.defaultMaxRetry
        private var updateIntervalHours = PinVaultConfig.defaultUpdateIntervalHours
        private var updateIntervalMinutes: Int64?
        private var deviceAlias: String?
        private var staticPins: CertificateConfig?
        private var files: [String: VaultFileConfig] = [:]
        private var fileKeys: [String] = []
        private var connectionListener: PinVaultConnectionListener?
        private var expiredConfigGraceMs: Int64 = 0
        private var caTrustHosts: [String] = []
        private var wipeOnRevocation = false
        private var vaultFileMaxOfflineAgeMs: Int64 = 0
        private var unlockedDeviceRequired = false
        private var hardwareKeysRequired = false
        private var integrityVerdictProvider: (any IntegrityVerdictProvider)?
        private var expectedSignerSha256: [String] = []
        private var managedRootsEnabled = false
        private var environmentGuard: (any EnvironmentGuard)?
        private var integrityTokenProvider: (any IntegrityTokenProvider)?
        private var resolvedHosts: [String: String] = [:]
        private var expectedBundleIds: [String] = []
        private var expectedTeamIds: [String] = []
        private var firstError: PinVaultError?

        public init() {}

        private func refuse(_ error: any Error) {
            guard firstError == nil else { return }
            firstError = (error as? PinVaultError) ?? .invalidConfiguration(String(describing: error))
        }

        private func refuse(_ message: String) {
            refuse(PinVaultError.invalidConfiguration(message))
        }

        /// A second opinion on the device's integrity that goes along inside
        /// every attestation report as `verdictProvider`, verbatim; the server verifies it.
        @discardableResult public func integrityVerdictProvider(_ provider: any IntegrityVerdictProvider) -> Builder {
            integrityVerdictProvider = provider
            return self
        }

        /// Android: SHA-256 digests of the expected signing certificates (hex,
        /// colons allowed, any case). Kept for parity; iOS uses
        /// ``expectedBundleId(_:)`` / ``expectedTeamId(_:)`` for `app_integrity`.
        @discardableResult public func expectedSignerSha256(_ hex: String...) -> Builder { expectedSignerSha256(hex) }

        @discardableResult public func expectedSignerSha256(_ hex: [String]) -> Builder {
            var digests: [String] = []
            for digest in hex {
                guard let normalized = normalizeSha256Hex(digest) else {
                    refuse("expectedSignerSha256: '\(digest)' is not a SHA-256 in hex (64 hex characters, colons allowed)")
                    return self
                }
                digests.append(normalized)
            }
            expectedSignerSha256 = digests.distinctPreservingOrder()
            return self
        }

        /// iOS: the bundle identifier(s) this app is expected to run as. When
        /// set, the attestation report's `app_integrity` signal is raised by the
        /// device itself when the running bundle id is not one of them.
        @discardableResult public func expectedBundleId(_ bundleIds: String...) -> Builder { expectedBundleId(bundleIds) }

        @discardableResult public func expectedBundleId(_ bundleIds: [String]) -> Builder {
            var accepted: [String] = []
            for id in bundleIds {
                let value = id.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty, value.unicodeScalars.allSatisfy(Self.isBundleIdScalar) else {
                    refuse("expectedBundleId: '\(id)' is not a bundle identifier (letters, digits, '.' and '-')")
                    return self
                }
                accepted.append(value)
            }
            expectedBundleIds = accepted.distinctPreservingOrder()
            return self
        }

        /// iOS: the Apple team id(s) (10 characters) the app is expected to be
        /// signed by — the counterpart of ``expectedSignerSha256(_:)-(String...)`` for `app_integrity`.
        @discardableResult public func expectedTeamId(_ teamIds: String...) -> Builder { expectedTeamId(teamIds) }

        @discardableResult public func expectedTeamId(_ teamIds: [String]) -> Builder {
            var accepted: [String] = []
            for id in teamIds {
                let value = id.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                guard value.count == 10, value.unicodeScalars.allSatisfy(Self.isTeamIdScalar) else {
                    refuse("expectedTeamId: '\(id)' is not an Apple team id (10 letters and digits)")
                    return self
                }
                accepted.append(value)
            }
            expectedTeamIds = accepted.distinctPreservingOrder()
            return self
        }

        /// Keep using a config for `amount` `unit` after its `expiresAt`.
        /// Default zero (fail closed): a blocked Config API cannot hold the device on old pins.
        @discardableResult public func expiredConfigGrace(_ amount: Int64, _ unit: TimeUnit) -> Builder {
            guard amount >= 0 else {
                refuse("expiredConfigGrace must not be negative")
                return self
            }
            expiredConfigGraceMs = unit.toMillis(amount)
            return self
        }

        /// For these hosts the server's certificate must ALSO be trusted by
        /// the platform's CAs, besides matching a pin — so a stolen config
        /// signing key alone cannot pin an attacker's certificate. Patterns use
        /// the pin syntax (`api.example.com`, `*.example.com`, optional `:port`).
        @discardableResult public func requireCaTrust(_ hostPatterns: String...) -> Builder { requireCaTrust(hostPatterns) }

        @discardableResult public func requireCaTrust(_ hostPatterns: [String]) -> Builder {
            for pattern in hostPatterns {
                let host = pattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !host.isEmpty, !host.contains("://"), !host.contains("/") else {
                    refuse("requireCaTrust: '\(pattern)' is not a host pattern (use api.example.com, *.example.com or host:port)")
                    return self
                }
                let wildcard = host.hasPrefix("*.")
                let rest = wildcard ? String(host.dropFirst(2)) : host
                let restHost = rest.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
                guard !rest.contains("*"), !wildcard || restHost.contains(".") else {
                    refuse("requireCaTrust: '\(pattern)' — a wildcard must be '*.' followed by a domain with at least one dot")
                    return self
                }
                caTrustHosts.append(host)
            }
            return self
        }

        /// Delete every vault file of a Config API when that API says this
        /// device's identity is revoked (`403 reenroll_required` about this
        /// device's certificate). Off by default.
        @discardableResult public func wipeVaultFilesOnRevocation() -> Builder { wipeOnRevocation = true; return self }

        /// The default offline lifetime of every vault file (a file's own
        /// `maxOfflineAge` wins). Not set: no limit.
        @discardableResult public func vaultFileMaxOfflineAge(_ amount: Int64, _ unit: TimeUnit) -> Builder {
            guard amount >= 0 else {
                refuse("vaultFileMaxOfflineAge must not be negative")
                return self
            }
            vaultFileMaxOfflineAgeMs = unit.toMillis(amount)
            return self
        }

        /// Make the library's keys and stores usable only while the device is
        /// unlocked (`…WhenUnlockedThisDeviceOnly`, `NSFileProtectionComplete`).
        /// Work behind a locked screen then fails until the user unlocks.
        @discardableResult public func requireUnlockedDevice() -> Builder { unlockedDeviceRequired = true; return self }

        /// Refuse a key made outside secure hardware (the Secure Enclave): such
        /// a key is deleted again and the operation fails with
        /// ``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``. Not for simulator builds.
        @discardableResult public func requireHardwareBackedKeys() -> Builder { hardwareKeysRequired = true; return self }

        /// Managed trust roots: a host without a pin entry is accepted when the
        /// platform validates its chain to a root the signed config lists in `trustRoots`.
        @discardableResult public func managedTrustRoots() -> Builder { managedRootsEnabled = true; return self }

        /// Ask `guard` before every ``GuardedOperation`` and refuse on `false`.
        @discardableResult public func environmentGuard(_ guard: any EnvironmentGuard) -> Builder {
            environmentGuard = `guard`
            return self
        }

        /// ``environmentGuard(_:)-(EnvironmentGuard)`` with a closure.
        @discardableResult public func environmentGuard(
            _ allows: @escaping @Sendable (GuardedOperation) throws -> Bool
        ) -> Builder {
            environmentGuard(ClosureEnvironmentGuard(allows))
        }

        /// Send an integrity token with every enrollment request, bound to it.
        @discardableResult public func integrityTokenProvider(_ provider: any IntegrityTokenProvider) -> Builder {
            integrityTokenProvider = provider
            return self
        }

        /// ``integrityTokenProvider(_:)-(IntegrityTokenProvider)`` with a closure.
        @discardableResult public func integrityTokenProvider(
            _ token: @escaping @Sendable (String) async throws -> String?
        ) -> Builder {
            integrityTokenProvider(ClosureIntegrityTokenProvider(token))
        }

        /// Register a Config API. The same id twice replaces the earlier block
        /// (keeping its place in the order).
        @discardableResult public func configApi(
            _ id: String,
            url: String,
            _ configure: (ConfigApiBlock.Builder) throws -> Void = { _ in }
        ) rethrows -> Builder {
            let builder = ConfigApiBlock.Builder(id, url: url)
            try configure(builder)
            do {
                let block = try builder.build()
                if blocks[id] == nil { blockIds.append(id) }
                blocks[id] = block
            } catch {
                refuse(error)
            }
            return self
        }

        @discardableResult public func maxRetryCount(_ count: Int) -> Builder { maxRetryCount = count; return self }
        @discardableResult public func updateIntervalHours(_ hours: Int64) -> Builder { updateIntervalHours = hours; return self }
        @discardableResult public func updateIntervalMinutes(_ minutes: Int64) -> Builder { updateIntervalMinutes = minutes; return self }
        @discardableResult public func deviceAlias(_ alias: String) -> Builder { deviceAlias = alias; return self }
        @discardableResult public func staticPins(_ config: CertificateConfig) -> Builder { staticPins = config; return self }

        /// Register a vault file. The same key twice replaces the earlier one.
        @discardableResult public func vaultFile(
            _ key: String,
            _ configure: (VaultFileConfig.Builder) throws -> Void
        ) rethrows -> Builder {
            let builder = VaultFileConfig.Builder(key)
            try configure(builder)
            do {
                let file = try builder.build()
                if files[key] == nil { fileKeys.append(key) }
                files[key] = file
            } catch {
                refuse(error)
            }
            return self
        }

        /// A callback for every ``PinVaultConnectionEvent`` (pinned handshakes,
        /// config updates, renewals, attestations). The library never reports anywhere on its own.
        @discardableResult public func onConnectionEvent(_ listener: @escaping PinVaultConnectionListener) -> Builder {
            connectionListener = listener
            return self
        }

        /// iOS (OkHttp `Dns` counterpart): connections to `host` go to
        /// `address` (an IP or another name; the port stays the request's),
        /// while pin lookup, hostname verification and client-certificate
        /// selection use `host`. The sample app maps `mock-tls.sample` this way.
        @discardableResult public func resolve(host: String, to address: String) -> Builder {
            let name = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let target = address.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, !name.contains("/"), !name.contains("*"), !name.contains(where: \.isWhitespace) else {
                refuse("resolve: '\(host)' is not a host name")
                return self
            }
            guard !target.isEmpty, !target.contains("/"), !target.contains(where: \.isWhitespace) else {
                refuse("resolve: '\(address)' is not an address")
                return self
            }
            resolvedHosts[name] = target
            return self
        }

        public func build() throws -> PinVaultConfig {
            if let firstError { throw firstError }
            // Each block keeps its config and watermarks in a namespace named
            // after its id (anything but [A-Za-z0-9_-] becomes `_`): ids that
            // would share one are refused instead of silently merged.
            var groups: [String: [String]] = [:]
            var namespaces: [String] = []
            for id in blockIds {
                let namespace = ConfigStoreNaming.namespaceFor(id)
                if groups[namespace] == nil { namespaces.append(namespace) }
                groups[namespace, default: []].append(id)
            }
            if let clash = namespaces.lazy.compactMap({ groups[$0] }).first(where: { $0.count > 1 }) {
                throw PinVaultError.invalidConfiguration(
                    "Config API ids \(clash.map { "'\($0)'" }.joined(separator: ", ")) would share one config store (characters " +
                        "other than letters, digits, '_' and '-' are stored as '_'); give them distinct ids"
                )
            }
            if staticPins == nil {
                guard !blockIds.isEmpty else {
                    throw PinVaultError.invalidConfiguration("At least one Config API (or staticPins for offline mode) is required")
                }
                for id in blockIds {
                    guard let block = blocks[id] else { continue }
                    guard !block.bootstrapPins.isEmpty || block.allowUnpinnedConfigApi else {
                        throw PinVaultError.invalidConfiguration(
                            "bootstrapPins must not be empty for Config API '\(block.id)' (or use staticPins for offline mode)"
                        )
                    }
                }
                for key in fileKeys {
                    guard let file = files[key] else { continue }
                    guard blocks[file.configApiId] != nil else {
                        throw PinVaultError.invalidConfiguration(
                            "VaultFile '\(file.key)' references unknown configApi '\(file.configApiId)'. " +
                                "Registered: [\(blockIds.joined(separator: ", "))]"
                        )
                    }
                }
            }

            for key in fileKeys { if let file = files[key] { PinVaultConfig.warnIfPolicyUnusableFromDevice(file) } }

            return PinVaultConfig(
                configApis: blockIds.compactMap { blocks[$0] },
                maxRetryCount: maxRetryCount,
                updateIntervalHours: updateIntervalHours,
                updateIntervalMinutes: updateIntervalMinutes,
                deviceAlias: deviceAlias,
                vaultFiles: fileKeys.compactMap { files[$0] },
                staticPins: staticPins,
                connectionListener: connectionListener,
                expiredConfigGraceMs: expiredConfigGraceMs,
                caTrustHosts: caTrustHosts.distinctPreservingOrder(),
                wipeVaultFilesOnRevocation: wipeOnRevocation,
                vaultFileMaxOfflineAgeMs: vaultFileMaxOfflineAgeMs,
                requireUnlockedDevice: unlockedDeviceRequired,
                requireHardwareBackedKeys: hardwareKeysRequired,
                integrityVerdictProvider: integrityVerdictProvider,
                expectedSignerSha256: expectedSignerSha256,
                managedTrustRoots: managedRootsEnabled,
                environmentGuard: environmentGuard,
                integrityTokenProvider: integrityTokenProvider,
                resolvedHosts: resolvedHosts,
                expectedBundleIds: expectedBundleIds,
                expectedTeamIds: expectedTeamIds
            )
        }

        private static func isBundleIdScalar(_ scalar: Unicode.Scalar) -> Bool {
            switch scalar {
            case "a"..."z", "A"..."Z", "0"..."9", ".", "-": return true
            default: return false
            }
        }

        private static func isTeamIdScalar(_ scalar: Unicode.Scalar) -> Bool {
            switch scalar {
            case "A"..."Z", "0"..."9": return true
            default: return false
            }
        }
    }

    // MARK: Diagnostics

    private static let warnedApiKeyFiles = Locked(Set<String>())

    /// A vault file with ``VaultFileAccessPolicy/apiKey`` fails with HTTP 401
    /// on every fetch from a device; say so once per file.
    private static func warnIfPolicyUnusableFromDevice(_ file: VaultFileConfig) {
        guard file.accessPolicy == .apiKey else { return }
        let first = warnedApiKeyFiles.withLock { $0.insert("\(file.configApiId)/\(file.key)").inserted }
        guard first else { return }
        PinVaultLog.tag("PinVaultConfig").w(
            "VaultFile '\(file.key)' uses accessPolicy=API_KEY, which CANNOT be satisfied from a device: " +
                "the library never sends the server's admin X-API-Key (it would be extractable " +
                "from the APK), so every fetch of this file will fail with HTTP 401. " +
                "API_KEY is for server-side tooling only — use TOKEN or TOKEN_MTLS for " +
                "device-facing files, or PUBLIC for genuinely public ones."
        )
    }

    // MARK: Offline

    /// Offline / embedded static pins. No Config API. The pins are checked
    /// at start like fetched ones; they carry no signature and no expiry.
    public static func `static`(_ pins: HostPin...) -> PinVaultConfig {
        `static`(pins)
    }

    /// ``static(_:)-(HostPin...)`` for a list.
    public static func `static`(_ pins: [HostPin]) -> PinVaultConfig {
        PinVaultConfig(configApis: [], staticPins: CertificateConfig(pins: pins, forceUpdate: false))
    }

    // MARK: Constants

    public static let defaultConfigEndpoint = "api/v1/certificate-config"
    public static let defaultHealthEndpoint = "health"
    public static let defaultMaxRetry = 3
    public static let defaultUpdateIntervalHours: Int64 = 12
    public static let defaultEnrollmentEndpoint = "api/v1/client-certs/enroll"
    public static let defaultClientCertEndpoint = "api/v1/client-certs"
    public static let defaultVaultReportEndpoint = "api/v1/vault/report"
    public static let defaultCertLabel = "default"
}
