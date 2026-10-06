import Foundation

/// The pin configuration served by the Config API (the signed payload, or the
/// unsigned body):
///
/// ```json
/// { "version": 3,
///   "pins": [ { "hostname": "api.example.com", "sha256": ["AAAA…", "BBBB…"] } ],
///   "forceUpdate": false, "issuedAt": 1759660801234, "expiresAt": 1759747201234 }
/// ```
///
/// Decoding is lenient the way Gson is: absent fields take their defaults and
/// `null` list elements become empty strings, so ``PinConfigValidator`` (not
/// the decoder) refuses a malformed config with its own message.
public struct CertificateConfig: Sendable, Equatable, Hashable {
    /// Global config version; see ``computedVersion()``.
    public var version: Int
    /// Pin entries per host.
    public var pins: [HostPin]
    /// The client must update immediately regardless of schedule.
    public var forceUpdate: Bool
    /// Unix epoch ms when the server signed the config; 0 = not populated
    /// (refused for a signed config, no replay protection for an unsigned one).
    public var issuedAt: Int64
    /// Unix epoch ms after which the config must not be applied; 0 = never
    /// (unsigned only). At most 30 days ahead.
    public var expiresAt: Int64
    /// Managed trust roots: SPKI pins (Base64 SHA-256) of root CAs, used with
    /// `managedTrustRoots()`. At most 64, each a valid pin, no duplicates.
    public var trustRoots: [String]

    public init(
        version: Int = 0,
        pins: [HostPin],
        forceUpdate: Bool = false,
        issuedAt: Int64 = 0,
        expiresAt: Int64 = 0,
        trustRoots: [String] = []
    ) {
        self.version = version
        self.pins = pins
        self.forceUpdate = forceUpdate
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.trustRoots = trustRoots
    }

    /// The highest per-host version, or ``version`` without pins.
    public func computedVersion() -> Int {
        pins.map(\.version).max() ?? version
    }
}

extension CertificateConfig: Codable {
    enum CodingKeys: String, CodingKey {
        case version, pins, forceUpdate, issuedAt, expiresAt, trustRoots
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 0
        let entries = try container.decodeIfPresent([HostPin?].self, forKey: .pins) ?? []
        if entries.contains(where: { $0 == nil }) {
            throw PinVaultError.invalidPinFormat(message: "Config has an empty pin entry")
        }
        pins = entries.compactMap { $0 }
        forceUpdate = try container.decodeIfPresent(Bool.self, forKey: .forceUpdate) ?? false
        issuedAt = try container.decodeIfPresent(Int64.self, forKey: .issuedAt) ?? 0
        expiresAt = try container.decodeIfPresent(Int64.self, forKey: .expiresAt) ?? 0
        trustRoots = (try container.decodeIfPresent([String?].self, forKey: .trustRoots) ?? []).map { $0 ?? "" }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(pins, forKey: .pins)
        try container.encode(forceUpdate, forKey: .forceUpdate)
        try container.encode(issuedAt, forKey: .issuedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(trustRoots, forKey: .trustRoots)
    }
}

/// SHA-256 pins for one host: at least two (primary + backup) for safe rotation.
///
/// For mTLS hosts ``mtls`` is true and ``clientCertVersion`` tracks the host's
/// client certificate.
///
/// Kotlin refuses fewer than two pins in the constructor; here the
/// constructor never throws (so the builder DSL needs no `try`) and the rule
/// is checked by ``validate()``, which every builder and `PinVault.start` apply.
public struct HostPin: Sendable, Equatable, Hashable {
    /// `api.example.com`, `*.example.com` (exactly one label, never directly
    /// under a public suffix), either with an optional `:port`.
    public var hostname: String
    /// SHA-256 of the SubjectPublicKeyInfo, Base64 (44 characters each).
    public var sha256: [String]
    /// Per-host version, incremented when this host's pins change.
    public var version: Int
    /// Per-host force-update flag.
    public var forceUpdate: Bool
    /// The host requires mutual TLS (a client certificate).
    public var mtls: Bool
    /// Client certificate version for this host; nil = none available.
    public var clientCertVersion: Int?

    public init(
        hostname: String,
        sha256: [String],
        version: Int = 0,
        forceUpdate: Bool = false,
        mtls: Bool = false,
        clientCertVersion: Int? = nil
    ) {
        self.hostname = hostname
        self.sha256 = sha256
        self.version = version
        self.forceUpdate = forceUpdate
        self.mtls = mtls
        self.clientCertVersion = clientCertVersion
    }

    /// The rule of the Kotlin constructor: at least two pins.
    public func validate() throws {
        guard sha256.count >= 2 else {
            throw PinVaultError.invalidConfiguration("At least 2 pins required (primary + backup) for hostname: \(hostname)")
        }
    }
}

extension HostPin: Codable {
    enum CodingKeys: String, CodingKey {
        case hostname, sha256, version, forceUpdate, mtls, clientCertVersion
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hostname = try container.decodeIfPresent(String.self, forKey: .hostname) ?? ""
        sha256 = (try container.decodeIfPresent([String?].self, forKey: .sha256) ?? []).map { $0 ?? "" }
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 0
        forceUpdate = try container.decodeIfPresent(Bool.self, forKey: .forceUpdate) ?? false
        mtls = try container.decodeIfPresent(Bool.self, forKey: .mtls) ?? false
        clientCertVersion = try container.decodeIfPresent(Int.self, forKey: .clientCertVersion)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(hostname, forKey: .hostname)
        try container.encode(sha256, forKey: .sha256)
        try container.encode(version, forKey: .version)
        try container.encode(forceUpdate, forKey: .forceUpdate)
        try container.encode(mtls, forKey: .mtls)
        // Gson leaves out nulls.
        try container.encodeIfPresent(clientCertVersion, forKey: .clientCertVersion)
    }
}
