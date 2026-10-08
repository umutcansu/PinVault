import Foundation

/// Configuration of one vault file.
///
/// ```swift
/// .vaultFile("ml-model") { file in
///     file.configApi("secure-mtls")
///     file.endpoint("api/v1/vault/ml-model")
///     file.storage(.encryptedFile)
///     file.accessPolicy(.token)
///     file.accessToken { tokens["ml-model"] ?? "" }
///     file.encryption(.endToEnd)
/// }
/// ```
public struct VaultFileConfig: Sendable {
    /// The server's rule for a vault file key (`VaultRoutes.VAULT_KEY_REGEX`), minus all-dot names.
    static func isValidKey(_ key: String) -> Bool {
        let allowed = key.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) ||
                byte == 0x2E || byte == 0x5F || byte == 0x2D
        }
        return !key.isEmpty && key.utf8.count <= 64 && allowed && !key.allSatisfy { $0 == "." }
    }

    public let key: String
    /// Path relative to the block's Config API URL (no leading `/`).
    public let endpoint: String
    public let signaturePublicKey: String?
    /// Sync with every periodic pin update (`syncAllFiles`).
    public let updateWithPins: Bool
    public let storageStrategy: StorageStrategy
    /// A custom store; wins over ``storageStrategy``.
    public let storageProvider: (any VaultStorageProvider)?
    /// Which ``ConfigApiBlock`` handles the file.
    public let configApiId: String
    /// The server-side policy the library satisfies on fetch.
    public let accessPolicy: VaultFileAccessPolicy
    /// Called on every fetch for `token` / `token_mtls` files (`X-Vault-Token`).
    public let accessTokenProvider: (@Sendable () -> String)?
    /// Local decryption strategy.
    public let encryption: VaultFileEncryption
    /// Whether reading the stored copy needs the passcode / biometrics.
    public let userAuth: UserAuth
    /// Offline lifetime in ms; nil = the config's default, 0 = no limit.
    public let maxOfflineAgeMs: Int64?
    /// Delete the stored copy once it is older than ``maxOfflineAgeMs``.
    public let wipeWhenStale: Bool

    public init(
        key: String,
        endpoint: String,
        signaturePublicKey: String? = nil,
        updateWithPins: Bool = false,
        storageStrategy: StorageStrategy = .encryptedPrefs,
        storageProvider: (any VaultStorageProvider)? = nil,
        configApiId: String = ConfigApiBlock.defaultId,
        accessPolicy: VaultFileAccessPolicy = .public,
        accessTokenProvider: (@Sendable () -> String)? = nil,
        encryption: VaultFileEncryption = .plain,
        userAuth: UserAuth = .none,
        maxOfflineAgeMs: Int64? = nil,
        wipeWhenStale: Bool = false
    ) {
        self.key = key
        self.endpoint = endpoint
        self.signaturePublicKey = signaturePublicKey
        self.updateWithPins = updateWithPins
        self.storageStrategy = storageStrategy
        self.storageProvider = storageProvider
        self.configApiId = configApiId
        self.accessPolicy = accessPolicy
        self.accessTokenProvider = accessTokenProvider
        self.encryption = encryption
        self.userAuth = userAuth
        self.maxOfflineAgeMs = maxOfflineAgeMs
        self.wipeWhenStale = wipeWhenStale
    }

    /// The DSL builder. Methods record the first invalid argument; ``build()`` throws it.
    public final class Builder {
        private let key: String
        private var endpoint = ""
        private var signaturePublicKey: String?
        private var updateWithPins = false
        private var storageStrategy: StorageStrategy = .encryptedPrefs
        private var storageProvider: (any VaultStorageProvider)?
        private var configApiId = ConfigApiBlock.defaultId
        private var accessPolicy: VaultFileAccessPolicy = .public
        private var accessTokenProvider: (@Sendable () -> String)?
        private var encryption: VaultFileEncryption = .plain
        private var userAuth: UserAuth = .none
        private var maxOfflineAgeMs: Int64?
        private var wipeStale = false
        private var firstError: PinVaultError?

        public init(_ key: String) {
            self.key = key
        }

        private func refuse(_ message: String) {
            if firstError == nil { firstError = .invalidConfiguration(message) }
        }

        @discardableResult public func endpoint(_ endpoint: String) -> Builder { self.endpoint = endpoint; return self }
        @discardableResult public func signaturePublicKey(_ key: String) -> Builder { signaturePublicKey = key; return self }
        @discardableResult public func updateWithPins(_ value: Bool) -> Builder { updateWithPins = value; return self }
        @discardableResult public func storage(_ strategy: StorageStrategy) -> Builder { storageStrategy = strategy; return self }
        @discardableResult public func storage(_ provider: any VaultStorageProvider) -> Builder { storageProvider = provider; return self }

        /// Bind this file to a Config API by id.
        @discardableResult public func configApi(_ id: String) -> Builder { configApiId = id; return self }

        /// Per-file access policy. The default ``VaultFileAccessPolicy/public`` is demo-only.
        @discardableResult public func accessPolicy(_ policy: VaultFileAccessPolicy) -> Builder { accessPolicy = policy; return self }

        /// A lazy token provider, called on every fetch.
        @discardableResult public func accessToken(_ provider: @escaping @Sendable () -> String) -> Builder {
            accessTokenProvider = provider
            return self
        }

        @discardableResult public func encryption(_ encryption: VaultFileEncryption) -> Builder { self.encryption = encryption; return self }

        /// Lock the stored copy behind the passcode / biometrics; read it with `PinVault.unlockFile`.
        @discardableResult public func userAuth(_ policy: UserAuth) -> Builder { userAuth = policy; return self }

        /// How long the stored copy may be read without the server confirming
        /// it; past that `loadFile` returns nil and `unlockFile` `.stale`. `0` = no limit.
        @discardableResult public func maxOfflineAge(_ amount: Int64, _ unit: TimeUnit) -> Builder {
            guard amount >= 0 else {
                refuse("maxOfflineAge must not be negative")
                return self
            }
            maxOfflineAgeMs = unit.toMillis(amount)
            return self
        }

        /// Delete the stored copy when it is found older than ``maxOfflineAge(_:_:)``.
        @discardableResult public func wipeWhenStale() -> Builder { wipeStale = true; return self }

        public func build() throws -> VaultFileConfig {
            if let firstError { throw firstError }
            // The key names the stored copy's file (`<key>.enc`) and its
            // preference entries, so it is held to the server's own rule: no
            // path separators, no "." / ".." names.
            guard VaultFileConfig.isValidKey(key) else {
                throw PinVaultError.invalidConfiguration("vault file key must match [A-Za-z0-9._-]{1,64} and not be only dots: \(key)")
            }
            guard !endpoint.isBlank else {
                throw PinVaultError.invalidConfiguration("endpoint must not be blank for vault file: \(key)")
            }
            guard encryption != .userAuth || userAuth != .none else {
                throw PinVaultError.invalidConfiguration(
                    "encryption(USER_AUTH) needs userAuth(UserAuth.REQUIRED) or userAuth(UserAuth.IF_SCREEN_LOCK) (key: \(key))"
                )
            }
            if accessPolicy == .token || accessPolicy == .tokenMtls, accessTokenProvider == nil {
                throw PinVaultError.invalidConfiguration(
                    "accessToken { … } required when accessPolicy is TOKEN or TOKEN_MTLS (key: \(key))"
                )
            }
            return VaultFileConfig(
                key: key,
                endpoint: endpoint.trimmingLeading("/"),
                signaturePublicKey: signaturePublicKey,
                updateWithPins: updateWithPins,
                storageStrategy: storageStrategy,
                storageProvider: storageProvider,
                configApiId: configApiId,
                accessPolicy: accessPolicy,
                accessTokenProvider: accessTokenProvider,
                encryption: encryption,
                userAuth: userAuth,
                maxOfflineAgeMs: maxOfflineAgeMs,
                wipeWhenStale: wipeStale
            )
        }
    }
}

/// Built-in storage strategies for vault files.
public enum StorageStrategy: String, Sendable, Equatable, Hashable, CaseIterable {
    /// Encrypted preferences (AES-256-GCM, keys in the Keychain). Small/medium files (default).
    case encryptedPrefs = "ENCRYPTED_PREFS"
    /// AES-256-GCM encrypted file on disk. Large files.
    case encryptedFile = "ENCRYPTED_FILE"
}

/// The access policy the server enforces on a vault file (server
/// `vault_files.access_policy`); the library sends the matching headers.
public enum VaultFileAccessPolicy: String, Sendable, Equatable, Hashable, CaseIterable {
    /// No auth. Demo/test only.
    case `public` = "PUBLIC"
    /// The server's admin `X-API-Key`: NOT usable from a device — the library
    /// never sends the admin key, so every fetch fails with HTTP 401. Server-side tooling only.
    case apiKey = "API_KEY"
    /// Per-device, per-file token: `X-Device-Id` + `X-Vault-Token`.
    case token = "TOKEN"
    /// ``token`` plus an mTLS certificate whose CN must match `X-Device-Id`.
    case tokenMtls = "TOKEN_MTLS"

    /// The `authMethod` of the distribution report.
    var authMethod: String {
        switch self {
        case .public: return "public"
        case .apiKey: return "api_key"
        case .token: return "token"
        case .tokenMtls: return "token_mtls"
        }
    }
}

/// Local decryption strategy for vault file content.
public enum VaultFileEncryption: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The server returns the content verbatim.
    case plain = "PLAIN"
    /// Same wire format as ``plain``; the server keeps it encrypted at rest.
    case atRest = "AT_REST"
    /// Wrapped with the device's registered RSA key (server `end_to_end`);
    /// opened with ``VaultFileDecryptor``.
    case endToEnd = "END_TO_END"
    /// Like ``endToEnd`` with the user-auth key; opened only in `unlockFile`
    /// after the prompt. Needs `userAuth(.required)` or `.ifScreenLock` (server `user_auth`).
    case userAuth = "USER_AUTH"

    /// The server's `X-Vault-Encryption` value.
    public var wireName: String {
        switch self {
        case .plain: return "plain"
        case .atRest: return "at_rest"
        case .endToEnd: return "end_to_end"
        case .userAuth: return "user_auth"
        }
    }
}

extension String {
    /// Kotlin `isBlank()`: empty or whitespace only.
    var isBlank: Bool {
        allSatisfy(\.isWhitespace)
    }

    /// Kotlin `trimStart(char)`.
    func trimmingLeading(_ character: Character) -> String {
        String(drop { $0 == character })
    }
}
