import Foundation

/// One Config API registered on a ``PinVaultConfig``: its own TLS/mTLS
/// pipeline, bootstrap pins and vault endpoints. Each ``VaultFileConfig``
/// binds to a block by ``VaultFileConfig/configApiId``.
///
/// ```swift
/// PinVaultConfig.Builder()
///     .configApi("prod-tls", url: "https://host:8091") { block in
///         block.bootstrapPins([HostPin(hostname: "host:8091", sha256: [p1, p2])])
///         block.wantPinsFor("cdn.example.com", "api.example.com")
///     }
/// ```
///
/// The enrollment token is not part of the block: pass it at the call site
/// (`PinVault.shared.enroll(token:)`).
public struct ConfigApiBlock: Sendable, Equatable, Hashable {
    /// Block identifier used by ``VaultFileConfig/configApiId``.
    public let id: String
    /// Base URL (the builder adds the trailing slash).
    public let configUrl: String
    /// Pins compiled into the app for the first connection.
    public let bootstrapPins: [HostPin]
    /// Relative path of the certificate config endpoint.
    public let configEndpoint: String
    /// Relative path of the health check.
    public let healthEndpoint: String
    /// ECDSA P-256 signing key (Base64 SPKI); the first of ``signaturePublicKeys``. Nil = unsigned accepted.
    public let signaturePublicKey: String?
    /// PKCS12 client keystore bundled with the app (see ``Builder/clientKeystore(_:password:)``).
    public let clientKeystoreBytes: Data?
    /// Password of ``clientKeystoreBytes``. The default "changeit" is a placeholder only.
    public let clientKeyPassword: String
    public let enrollmentEndpoint: String
    /// Client certificate base path.
    public let clientCertEndpoint: String
    /// Vault download report path.
    public let vaultReportEndpoint: String
    /// Label isolating this block's client certificate in storage.
    public let clientCertLabel: String
    /// Pin scoping: sent as `?hosts=…`; the server returns pins for the
    /// intersection with the device's ACL. Empty = whatever the server returns.
    public let wantPinsFor: [String]
    /// Every key a config signature may come from (Base64 SPKI, ECDSA P-256). Empty = just ``signaturePublicKey``.
    public let signaturePublicKeys: [String]
    /// Distinct trusted keys that must sign each config.
    public let requiredSignatures: Int
    /// Offline keys that may authorise a new signing-key set. Empty = disabled.
    public let recoveryPublicKeys: [String]
    /// Distinct recovery keys that must sign a key set.
    public let requiredRecoverySignatures: Int
    /// Where an expired (or refused) client certificate is renewed; nil = ``configUrl``.
    public let renewalUrl: String?
    /// Where first enrollment goes; nil = ``configUrl``.
    public let enrollmentUrl: String?
    /// Renew when the remaining lifetime falls below this fraction.
    public let clientCertRenewalThreshold: Double
    /// False = the library never renews on its own.
    public let clientCertRenewalEnabled: Bool
    /// The server-side Config API id a signed config must name (`configApiId`); nil = not checked.
    public let serverScope: String?
    /// The app called ``Builder/allowUnsigned()``.
    public let allowUnsigned: Bool
    /// The Config API may be reached without bootstrap pins or over `http://`.
    public let allowUnpinnedConfigApi: Bool
    /// A private key the server made may be this block's identity.
    public let allowServerGeneratedKey: Bool
    /// SHA-256 pins (Base64) of the client CA's SPKI; issued chains must be signed by a match.
    public let clientCaPins: [String]
    /// Longest lifetime of a client certificate this block stores (days).
    public let maxClientCertLifetimeDays: Int
    /// Further listeners (`https://host:port/`) the client identity is offered to.
    public let clientCertHosts: [String]
    /// This block attests the device and carries a `PinVault-Token`.
    public let attestationEnabled: Bool
    /// Longest interval between attestations, ms.
    public let attestationIntervalMs: Int64
    /// Hosts whose requests carry the token (pin host patterns, lower case); empty = every pinned host + the Config API.
    public let tokenHosts: [String]
    /// Requests that carry the token also carry a `PinVault-Proof`. See ``Builder/proofOfPossession()``.
    public let tokenProof: Bool
    /// ``allowUnsigned`` and ``allowUnpinnedConfigApi`` apply in a release build too. See ``Builder/allowRelaxationsInRelease()``.
    public let relaxationsInRelease: Bool

    public init(
        id: String,
        configUrl: String,
        bootstrapPins: [HostPin],
        configEndpoint: String = PinVaultConfig.defaultConfigEndpoint,
        healthEndpoint: String = PinVaultConfig.defaultHealthEndpoint,
        signaturePublicKey: String? = nil,
        clientKeystoreBytes: Data? = nil,
        clientKeyPassword: String = "changeit",
        enrollmentEndpoint: String = PinVaultConfig.defaultEnrollmentEndpoint,
        clientCertEndpoint: String = PinVaultConfig.defaultClientCertEndpoint,
        vaultReportEndpoint: String = PinVaultConfig.defaultVaultReportEndpoint,
        clientCertLabel: String = PinVaultConfig.defaultCertLabel,
        wantPinsFor: [String] = [],
        signaturePublicKeys: [String] = [],
        requiredSignatures: Int = 1,
        recoveryPublicKeys: [String] = [],
        requiredRecoverySignatures: Int = 1,
        renewalUrl: String? = nil,
        enrollmentUrl: String? = nil,
        clientCertRenewalThreshold: Double = ConfigApiBlock.defaultRenewalThreshold,
        clientCertRenewalEnabled: Bool = true,
        serverScope: String? = nil,
        allowUnsigned: Bool = false,
        allowUnpinnedConfigApi: Bool = false,
        allowServerGeneratedKey: Bool = false,
        clientCaPins: [String] = [],
        maxClientCertLifetimeDays: Int = ConfigApiBlock.defaultMaxClientCertLifetimeDays,
        clientCertHosts: [String] = [],
        attestationEnabled: Bool = false,
        attestationIntervalMs: Int64 = ConfigApiBlock.defaultAttestationIntervalMs,
        tokenHosts: [String] = [],
        tokenProof: Bool = false,
        relaxationsInRelease: Bool = false
    ) {
        self.id = id
        self.configUrl = configUrl
        self.bootstrapPins = bootstrapPins
        self.configEndpoint = configEndpoint
        self.healthEndpoint = healthEndpoint
        self.signaturePublicKey = signaturePublicKey
        self.clientKeystoreBytes = clientKeystoreBytes
        self.clientKeyPassword = clientKeyPassword
        self.enrollmentEndpoint = enrollmentEndpoint
        self.clientCertEndpoint = clientCertEndpoint
        self.vaultReportEndpoint = vaultReportEndpoint
        self.clientCertLabel = clientCertLabel
        self.wantPinsFor = wantPinsFor
        self.signaturePublicKeys = signaturePublicKeys
        self.requiredSignatures = requiredSignatures
        self.recoveryPublicKeys = recoveryPublicKeys
        self.requiredRecoverySignatures = requiredRecoverySignatures
        self.renewalUrl = renewalUrl
        self.enrollmentUrl = enrollmentUrl
        self.clientCertRenewalThreshold = clientCertRenewalThreshold
        self.clientCertRenewalEnabled = clientCertRenewalEnabled
        self.serverScope = serverScope
        self.allowUnsigned = allowUnsigned
        self.allowUnpinnedConfigApi = allowUnpinnedConfigApi
        self.allowServerGeneratedKey = allowServerGeneratedKey
        self.clientCaPins = clientCaPins
        self.maxClientCertLifetimeDays = maxClientCertLifetimeDays
        self.clientCertHosts = clientCertHosts
        self.attestationEnabled = attestationEnabled
        self.attestationIntervalMs = attestationIntervalMs
        self.tokenHosts = tokenHosts
        self.tokenProof = tokenProof
        self.relaxationsInRelease = relaxationsInRelease
    }

    /// Why this block must not be used, or nil: the Config API (and the
    /// enrollment / renewal URLs) must be `https://` and the block must carry
    /// bootstrap pins, unless ``allowUnpinnedConfigApi``. Checked at start and
    /// by every client built for the block, so a block made with the
    /// initializer is held to the same rules as the builder's.
    ///
    /// iOS: also the Kotlin `HostPin` constructor rule (two pins per entry),
    /// since the Swift initializer cannot throw.
    func configurationError() -> String? {
        for pin in bootstrapPins where pin.sha256.count < 2 {
            return "At least 2 pins required (primary + backup) for hostname: \(pin.hostname)"
        }
        if allowUnpinnedConfigApi { return nil }
        for (name, url) in [("configUrl", configUrl), ("enrollmentUrl", enrollmentUrl), ("renewalUrl", renewalUrl)] {
            if let url, !url.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("https://") {
                return "Config API '\(id)': \(name) must be an https:// URL — a config fetched over plain HTTP can be " +
                    "replaced by anyone on the network. Call allowUnpinnedConfigApi() to accept that (tests, demos)."
            }
        }
        if bootstrapPins.isEmpty {
            return "Config API '\(id)': bootstrapPins must not be empty — without them the first config fetch trusts " +
                "every certificate authority on the device. Call allowUnpinnedConfigApi() to accept that (tests, demos)."
        }
        return nil
    }

    /// The keys config signatures are checked against when no signing-key set
    /// has been applied: ``signaturePublicKeys``, or ``signaturePublicKey`` alone.
    func effectiveSignatureKeys() -> [String] {
        signaturePublicKeys.isEmpty ? [signaturePublicKey].compactMap { $0 } : signaturePublicKeys
    }

    // MARK: Constants

    public static let defaultId = "default"
    /// Re-attest every 5 minutes unless the server or the token say sooner.
    public static let defaultAttestationIntervalMs: Int64 = 5 * 60 * 1000
    /// Shortest ``Builder/attestationInterval(_:_:)``.
    public static let minAttestationIntervalMs: Int64 = 60 * 1000
    /// Renew with a third of the lifetime left.
    public static let defaultRenewalThreshold: Double = 1.0 / 3
    /// Longest client-certificate lifetime accepted unless the block says otherwise (days).
    public static let defaultMaxClientCertLifetimeDays = 825

    /// Strips PEM armour and whitespace so a key pasted as PEM, or with a
    /// trailing newline, is one key and not two.
    static func normalizeKeyText(_ key: String) -> String {
        key.components(separatedBy: CharacterSet.newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
            .filter { !$0.isWhitespace }
    }

    // MARK: Builder

    /// The DSL builder. Methods record the first invalid argument (Kotlin's
    /// `require`); ``PinVaultConfig/Builder/build()`` throws it.
    public final class Builder {
        private let id: String
        private let configUrl: String
        private var bootstrapPins: [HostPin] = []
        private var configEndpoint = PinVaultConfig.defaultConfigEndpoint
        private var healthEndpoint = PinVaultConfig.defaultHealthEndpoint
        private var signaturePublicKeys: [String] = []
        private var requiredSignatures = 1
        private var recoveryPublicKeys: [String] = []
        private var requiredRecoverySignatures = 1
        private var unsignedAllowed = false
        private var clientKeystoreBytes: Data?
        private var clientKeyPassword = "changeit"
        private var enrollmentEndpoint = PinVaultConfig.defaultEnrollmentEndpoint
        private var clientCertEndpoint = PinVaultConfig.defaultClientCertEndpoint
        private var vaultReportEndpoint = PinVaultConfig.defaultVaultReportEndpoint
        private var clientCertLabel = PinVaultConfig.defaultCertLabel
        private var wantPinsFor: [String] = []
        private var renewalUrl: String?
        private var enrollmentUrl: String?
        private var clientCertRenewalThreshold = ConfigApiBlock.defaultRenewalThreshold
        private var clientCertRenewalEnabled = true
        private var serverScope: String?
        private var unpinnedAllowed = false
        private var serverKeyAllowed = false
        private var clientCaPins: [String] = []
        private var maxClientCertLifetimeDays = ConfigApiBlock.defaultMaxClientCertLifetimeDays
        private var clientCertHosts: [String] = []
        private var attestationEnabled = false
        private var attestationIntervalMs = ConfigApiBlock.defaultAttestationIntervalMs
        private var tokenHosts: [String] = []
        private var tokenProof = false
        private var relaxationsInRelease = false
        private var firstError: PinVaultError?

        public init(_ id: String, url configUrl: String) {
            self.id = id
            self.configUrl = configUrl
        }

        private func refuse(_ message: String) {
            if firstError == nil { firstError = .invalidConfiguration(message) }
        }

        @discardableResult public func bootstrapPins(_ pins: [HostPin]) -> Builder {
            // Kotlin refuses such a HostPin when it is constructed.
            for pin in pins {
                do { try pin.validate() } catch { refuse((error as? PinVaultError)?.message ?? "\(error)") }
            }
            bootstrapPins = pins
            return self
        }

        @discardableResult public func configEndpoint(_ endpoint: String) -> Builder { configEndpoint = endpoint; return self }
        @discardableResult public func healthEndpoint(_ endpoint: String) -> Builder { healthEndpoint = endpoint; return self }

        /// The config-signing public key: X.509 SubjectPublicKeyInfo, Base64, ECDSA P-256 (PEM accepted).
        @discardableResult public func signaturePublicKey(_ key: String) -> Builder {
            signaturePublicKeys = [ConfigApiBlock.normalizeKeyText(key)].filter { !$0.isEmpty }
            return self
        }

        /// Several config-signing keys, any of which may sign (unless
        /// ``requiredSignatures(_:)`` asks for more). Replaces an earlier ``signaturePublicKey(_:)``.
        @discardableResult public func signaturePublicKeys(_ keys: String...) -> Builder { signaturePublicKeys(keys) }

        /// ``signaturePublicKeys(_:)-(String...)`` for a list.
        @discardableResult public func signaturePublicKeys(_ keys: [String]) -> Builder {
            signaturePublicKeys = keys.map(ConfigApiBlock.normalizeKeyText).filter { !$0.isEmpty }.distinctPreservingOrder()
            return self
        }

        /// How many distinct keys of ``signaturePublicKeys(_:)-(String...)`` must sign every config (and vault file). Default 1.
        @discardableResult public func requiredSignatures(_ count: Int) -> Builder { requiredSignatures = count; return self }

        /// Offline recovery keys that may authorise a new set of signing keys
        /// (rotation and revocation without an app update). Never signing keys too.
        @discardableResult public func recoveryPublicKeys(_ keys: String...) -> Builder { recoveryPublicKeys(keys) }

        @discardableResult public func recoveryPublicKeys(_ keys: [String]) -> Builder {
            recoveryPublicKeys = keys.map(ConfigApiBlock.normalizeKeyText).filter { !$0.isEmpty }.distinctPreservingOrder()
            return self
        }

        /// How many distinct recovery keys must sign a key set. Default 1.
        @discardableResult public func requiredRecoverySignatures(_ count: Int) -> Builder {
            requiredRecoverySignatures = count
            return self
        }

        /// Explicit opt-out from signed configs. SECURITY: also disables replay
        /// protection, expiry and downgrade rejection — tests and demos only.
        /// With signing keys and a custom ``CertificateConfigApi`` that is not a
        /// ``SignedConfigSource``, accepts that API's configs unverified.
        @discardableResult public func allowUnsigned() -> Builder { unsignedAllowed = true; return self }

        /// The server-side Config API id (e.g. `default-tls`) a signed payload
        /// must name in `configApiId`. No effect on an unsigned block.
        @discardableResult public func serverScope(_ id: String) -> Builder {
            guard !id.isBlank else {
                refuse("serverScope must not be blank")
                return self
            }
            serverScope = id.trimmingCharacters(in: .whitespacesAndNewlines)
            return self
        }

        /// Opt-out from `https://` and bootstrap pins for the Config API.
        /// SECURITY: tests against a local plain-HTTP server and demos only.
        @discardableResult public func allowUnpinnedConfigApi() -> Builder { unpinnedAllowed = true; return self }

        /// Keep ``allowUnsigned()`` and ``allowUnpinnedConfigApi()`` in a release
        /// build (compiled without `DEBUG`). Without this call `start` and
        /// enrollment with this config fail there: both are test relaxations,
        /// and a release build that still has one usually forgot to remove it.
        /// Call it only when the release app really talks to an unsigned or
        /// unpinned Config API, and know what it gives away.
        @discardableResult public func allowRelaxationsInRelease() -> Builder { relaxationsInRelease = true; return self }

        /// mTLS client keystore (PKCS12) bundled with the app; imported into
        /// the Keychain on first use. The same for every install: use it to
        /// reach an mTLS Config API before enrollment, not as a device identity.
        @discardableResult public func clientKeystore(_ bytes: Data, password: String = "changeit") -> Builder {
            clientKeystoreBytes = bytes
            clientKeyPassword = password
            return self
        }

        /// Accept a private key the SERVER generated as this block's identity
        /// (a PKCS12 answer to enrollment, or P12 enrollment when the device
        /// cannot make its own key). Such an identity is not renewed.
        @discardableResult public func allowServerGeneratedKey() -> Builder { serverKeyAllowed = true; return self }

        /// Pins the client CA: Base64 SHA-256 of a CA certificate's SPKI
        /// (`sha256/` prefix accepted). Issued chains must be signed by a match.
        @discardableResult public func clientCaPins(_ pins: String...) -> Builder { clientCaPins(pins) }

        @discardableResult public func clientCaPins(_ pins: [String]) -> Builder {
            var accepted: [String] = []
            for pin in pins {
                var value = pin.trimmingCharacters(in: .whitespacesAndNewlines)
                if value.hasPrefix("sha256/") { value.removeFirst("sha256/".count) }
                guard let decoded = Base64.decodeLenient(value), decoded.count == 32 else {
                    refuse("clientCaPins: '\(pin)' is not a Base64 SHA-256 hash (44 characters)")
                    return self
                }
                accepted.append(Base64.encode(decoded))
            }
            clientCaPins = accepted.distinctPreservingOrder()
            return self
        }

        /// Longest lifetime of a client certificate this block stores. Default 825 days.
        @discardableResult public func maxClientCertLifetimeDays(_ days: Int) -> Builder {
            guard days >= 1 else {
                refuse("maxClientCertLifetimeDays must be at least 1")
                return self
            }
            maxClientCertLifetimeDays = days
            return self
        }

        /// Further listeners the client identity may be presented to, as
        /// `https://host:port/` or `host:port` (port required). Once set it is the whole list.
        @discardableResult public func clientCertHosts(_ hosts: String...) -> Builder { clientCertHosts(hosts) }

        @discardableResult public func clientCertHosts(_ hosts: [String]) -> Builder {
            var accepted: [String] = []
            for host in hosts {
                let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
                let url = host.contains("://") ? trimmed : "https://\(trimmed)/"
                let afterScheme = url.range(of: "://").map { String(url[$0.upperBound...]) } ?? url
                let authority = afterScheme.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
                let parsed = URLComponents(string: url)
                let isHttps = parsed?.scheme?.lowercased() == "https" && !(parsed?.host ?? "").isEmpty
                guard isHttps, authority.range(of: ":[0-9]+", options: .regularExpression) != nil else {
                    refuse("clientCertHosts: '\(host)' must be https://host:port/ or host:port")
                    return self
                }
                accepted.append(url)
            }
            clientCertHosts = accepted.distinctPreservingOrder()
            return self
        }

        @discardableResult public func enrollmentEndpoint(_ endpoint: String) -> Builder { enrollmentEndpoint = endpoint; return self }
        @discardableResult public func clientCertEndpoint(_ endpoint: String) -> Builder { clientCertEndpoint = endpoint; return self }
        @discardableResult public func vaultReportEndpoint(_ endpoint: String) -> Builder { vaultReportEndpoint = endpoint; return self }
        @discardableResult public func clientCertLabel(_ label: String) -> Builder { clientCertLabel = label; return self }

        /// Which hosts this device wants pins for; the server answers the
        /// intersection with the device's ACL.
        @discardableResult public func wantPinsFor(_ hosts: String...) -> Builder { wantPinsFor(hosts) }

        @discardableResult public func wantPinsFor(_ hosts: [String]) -> Builder { wantPinsFor = hosts; return self }

        /// Where an expired (or refused) client certificate is renewed: a
        /// plain-TLS listener of the same backend, covered by the bootstrap pins.
        @discardableResult public func renewalUrl(_ url: String) -> Builder {
            guard !url.isBlank else {
                refuse("renewalUrl must not be blank")
                return self
            }
            renewalUrl = url.hasSuffix("/") ? url : url + "/"
            return self
        }

        /// Where `enroll` / `autoEnroll` send the first enrollment: a plain-TLS
        /// listener (an mTLS Config API refuses a device without a certificate).
        @discardableResult public func enrollmentUrl(_ url: String) -> Builder {
            guard !url.isBlank else {
                refuse("enrollmentUrl must not be blank")
                return self
            }
            enrollmentUrl = url.hasSuffix("/") ? url : url + "/"
            return self
        }

        /// Renew once the remaining lifetime drops below this fraction. Default 1/3.
        @discardableResult public func clientCertRenewalThreshold(_ fraction: Double) -> Builder {
            guard fraction > 0.0, fraction < 1.0 else {
                refuse("clientCertRenewalThreshold must be between 0 and 1 (exclusive)")
                return self
            }
            clientCertRenewalThreshold = fraction
            return self
        }

        /// No automatic renewal; `renewClientCertIfNeeded(force: true)` still works.
        @discardableResult public func disableClientCertRenewal() -> Builder { clientCertRenewalEnabled = false; return self }

        /// Attest this device with the block's server (`ATTESTATION.md`) and
        /// carry the `PinVault-Token` on requests to the ``tokenHosts(_:)-(String...)``.
        @discardableResult public func attestation() -> Builder { attestationEnabled = true; return self }

        /// Longest interval between attestations. Default 5 minutes, at least 1 minute.
        @discardableResult public func attestationInterval(_ amount: Int64, _ unit: TimeUnit) -> Builder {
            let ms = unit.toMillis(amount)
            guard ms >= ConfigApiBlock.minAttestationIntervalMs else {
                refuse("attestationInterval must be at least 1 minute")
                return self
            }
            attestationIntervalMs = ms
            return self
        }

        /// Which hosts' requests carry the `PinVault-Token`: pin host patterns.
        /// Not set: every host pinned by this block's live config, and its Config API.
        @discardableResult public func tokenHosts(_ patterns: String...) -> Builder { tokenHosts(patterns) }

        @discardableResult public func tokenHosts(_ patterns: [String]) -> Builder {
            var accepted: [String] = []
            for pattern in patterns {
                let host = pattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if let error = PinConfigValidator.hostPatternError(host) {
                    refuse("tokenHosts: \(error)")
                    return self
                }
                accepted.append(host)
            }
            tokenHosts = accepted.distinctPreservingOrder()
            return self
        }

        /// Prove, on every request that carries the `PinVault-Token`, that it
        /// comes from this device (`ATTESTATION.md` §5.1): the library adds a
        /// `PinVault-Proof` header, a DPoP proof (RFC 9449) of the request's
        /// method and URL signed by the block's device key — the key the
        /// token's `cnf.jkt` names. A backend that checks it refuses a token
        /// used without the key. One signature per request (Secure Enclave:
        /// a few ms). Needs ``attestation()``. Off by default.
        @discardableResult public func proofOfPossession() -> Builder { tokenProof = true; return self }

        func build() throws -> ConfigApiBlock {
            if let firstError { throw firstError }
            guard !id.isBlank else { throw PinVaultError.invalidConfiguration("ConfigApi id must not be blank") }
            guard !configUrl.isBlank else { throw PinVaultError.invalidConfiguration("ConfigApi configUrl must not be blank") }
            guard !tokenProof || attestationEnabled else {
                throw PinVaultError.invalidConfiguration("ConfigApi '\(id)': proofOfPossession() proves the attestation token, so it needs attestation().")
            }
            guard !signaturePublicKeys.isEmpty || unsignedAllowed else {
                throw PinVaultError.invalidConfiguration(
                    "ConfigApi '\(id)': signaturePublicKey is required. Pass the ECDSA P-256 " +
                        "public key (X.509-encoded, Base64) via signaturePublicKey(...) — this " +
                        "is what guards against config tampering and replay attacks. If you are " +
                        "intentionally running without signed configs (tests, demos, transitional " +
                        "setup), call allowUnsigned() to opt out explicitly."
                )
            }
            if !signaturePublicKeys.isEmpty, !(1...signaturePublicKeys.count).contains(requiredSignatures) {
                throw PinVaultError.invalidConfiguration(
                    "ConfigApi '\(id)': requiredSignatures(\(requiredSignatures)) must be between 1 and " +
                        "the number of signing keys (\(signaturePublicKeys.count))."
                )
            }
            if !recoveryPublicKeys.isEmpty {
                guard !signaturePublicKeys.isEmpty else {
                    throw PinVaultError.invalidConfiguration(
                        "ConfigApi '\(id)': recoveryPublicKeys(...) rotates signing keys, so it needs " +
                            "signaturePublicKey(...) / signaturePublicKeys(...) as the starting set."
                    )
                }
                guard !recoveryPublicKeys.contains(where: signaturePublicKeys.contains) else {
                    throw PinVaultError.invalidConfiguration(
                        "ConfigApi '\(id)': a recovery key must not also be a signing key — keep the two " +
                            "roles on separate keys."
                    )
                }
                guard (1...recoveryPublicKeys.count).contains(requiredRecoverySignatures) else {
                    throw PinVaultError.invalidConfiguration(
                        "ConfigApi '\(id)': requiredRecoverySignatures(\(requiredRecoverySignatures)) must be " +
                            "between 1 and the number of recovery keys (\(recoveryPublicKeys.count))."
                    )
                }
            }
            let normalizedUrl = configUrl.hasSuffix("/") ? configUrl : configUrl + "/"
            return ConfigApiBlock(
                id: id,
                configUrl: normalizedUrl,
                bootstrapPins: bootstrapPins,
                configEndpoint: configEndpoint.trimmingLeading("/"),
                healthEndpoint: healthEndpoint.trimmingLeading("/"),
                // The first key keeps the single-key field meaningful.
                signaturePublicKey: signaturePublicKeys.first,
                clientKeystoreBytes: clientKeystoreBytes,
                clientKeyPassword: clientKeyPassword,
                enrollmentEndpoint: enrollmentEndpoint,
                clientCertEndpoint: clientCertEndpoint.trimmingLeading("/"),
                vaultReportEndpoint: vaultReportEndpoint.trimmingLeading("/"),
                clientCertLabel: clientCertLabel,
                wantPinsFor: wantPinsFor,
                signaturePublicKeys: signaturePublicKeys,
                requiredSignatures: requiredSignatures,
                recoveryPublicKeys: recoveryPublicKeys,
                requiredRecoverySignatures: requiredRecoverySignatures,
                renewalUrl: renewalUrl,
                enrollmentUrl: enrollmentUrl,
                clientCertRenewalThreshold: clientCertRenewalThreshold,
                clientCertRenewalEnabled: clientCertRenewalEnabled,
                serverScope: serverScope,
                allowUnsigned: unsignedAllowed,
                allowUnpinnedConfigApi: unpinnedAllowed,
                allowServerGeneratedKey: serverKeyAllowed,
                clientCaPins: clientCaPins,
                maxClientCertLifetimeDays: maxClientCertLifetimeDays,
                clientCertHosts: clientCertHosts,
                attestationEnabled: attestationEnabled,
                attestationIntervalMs: attestationIntervalMs,
                tokenHosts: tokenHosts,
                tokenProof: tokenProof,
                relaxationsInRelease: relaxationsInRelease
            )
        }
    }
}

extension Array where Element: Hashable {
    /// Kotlin `distinct()`: first occurrences, in order.
    func distinctPreservingOrder() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
