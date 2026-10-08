import Foundation

/// Result of a vault file fetch / sync.
public enum VaultFileResult: Sendable {
    /// Downloaded and stored. `bytes` is the content — empty for a file locked
    /// with `userAuth` (only `unlockFile` hands that out, after the prompt).
    case updated(key: String, version: Int, bytes: Data)
    /// Already at the latest version.
    case alreadyCurrent(key: String, version: Int)
    /// The fetch failed. `reason` is for the app and the local log; `code` is
    /// a fixed class (``FailureCode``, or `http_<status>`) — the only thing the
    /// distribution report sends to the server.
    case failed(key: String, reason: String, exception: (any Error)? = nil, code: String = FailureCode.other)

    /// The file key, whatever the case.
    public var key: String {
        switch self {
        case .updated(let key, _, _), .alreadyCurrent(let key, _), .failed(let key, _, _, _): return key
        }
    }

    /// The fixed failure classes of ``failed(key:reason:exception:code:)`` (`VaultFileResult.Failed.CODE_*`).
    public enum FailureCode {
        /// Anything not classified below.
        public static let other = "other"
        /// Unknown Config API, a missing key provider or user-auth setup.
        public static let notConfigured = "not_configured"
        /// The server refused; the HTTP status follows: `http_401`, `http_404`, …
        public static let httpPrefix = "http_"
        /// The request did not complete (connection, TLS, timeout).
        public static let network = "network_error"
        /// The response body was longer than the library reads.
        public static let responseTooLarge = "response_too_large"
        /// A locked file needs a passcode the device has not got.
        public static let screenLock = "screen_lock_required"
        /// The user-auth key could not be registered with the Config API.
        public static let userAuthKey = "user_auth_key_rejected"
        /// The server answered with another encryption than the file declares.
        public static let encryptionMismatch = "encryption_mismatch"
        /// An end_to_end envelope did not open; one code whatever the step.
        public static let decryptFailed = "decrypt_failed"
        /// A verifying key is configured and the answer carries no signature.
        public static let signatureMissing = "signature_missing"
        /// The signature does not verify.
        public static let signatureInvalid = "signature_invalid"
        /// An older version than the stored one, or a jump beyond the bound.
        public static let versionRejected = "version_rejected"

        /// The code for a refused request with HTTP `status`.
        public static func http(_ status: Int) -> String { "\(httpPrefix)\(status)" }
    }
}

extension VaultFileResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.updated(k1, v1, b1), .updated(k2, v2, b2)): return k1 == k2 && v1 == v2 && b1 == b2
        case let (.alreadyCurrent(k1, v1), .alreadyCurrent(k2, v2)): return k1 == k2 && v1 == v2
        case let (.failed(k1, r1, e1, c1), .failed(k2, r2, e2, c2)):
            return k1 == k2 && r1 == r2 && c1 == c2 && errorsEqual(e1, e2)
        default: return false
        }
    }
}

/// A vault file download with its metadata (headers): `X-Vault-Version`,
/// `X-Vault-Encryption` (`plain` | `at_rest` | `end_to_end` | `user_auth`),
/// 304 = ``notModified``, and the signature headers (`X-Vault-Signature`,
/// `X-Vault-Signatures`, `X-Vault-Signature-V2`, `X-Vault-Signatures-V2`).
public struct VaultFetchResponse: Sendable, Equatable, Hashable, Codable {
    /// Body bytes (the RSA+AES envelope for `end_to_end`); empty for 304.
    public var content: Data
    public var version: Int
    public var encryption: String
    public var notModified: Bool
    /// Base64 ECDSA-SHA256 over `pinvault-vault-file:v1:<key>:<version>:<sha256 hex>`; nil when unsigned.
    public var signature: String?
    /// One entry per signing key (m-of-n); wins over ``signature``.
    public var signatures: [SignatureEntry]?
    /// The v2 signature, which also names the Config API; required with `serverScope`.
    public var signatureV2: String?
    public var signaturesV2: [SignatureEntry]?

    public init(
        content: Data,
        version: Int,
        encryption: String = "plain",
        notModified: Bool = false,
        signature: String? = nil,
        signatures: [SignatureEntry]? = nil,
        signatureV2: String? = nil,
        signaturesV2: [SignatureEntry]? = nil
    ) {
        self.content = content
        self.version = version
        self.encryption = encryption
        self.notModified = notModified
        self.signature = signature
        self.signatures = signatures
        self.signatureV2 = signatureV2
        self.signaturesV2 = signaturesV2
    }
}

/// The report sent after a vault file download attempt
/// (``CertificateConfigApi/reportVaultDownload(_:)``, `POST api/v1/vault/report`).
public struct VaultDownloadReport: Sendable, Equatable, Hashable, Codable {
    public var key: String
    public var version: Int
    /// `downloaded` | `cached` | `failed`.
    public var status: String
    public var deviceManufacturer: String
    public var deviceModel: String
    public var enrollmentLabel: String
    public var deviceId: String
    public var deviceAlias: String
    /// For `failed`: the fixed ``VaultFileResult/FailureCode``, never an error text.
    public var failureReason: String?
    /// `public` | `token` | `token_mtls` | `api_key`.
    public var authMethod: String?

    public init(
        key: String,
        version: Int,
        status: String,
        deviceManufacturer: String,
        deviceModel: String,
        enrollmentLabel: String,
        deviceId: String,
        deviceAlias: String,
        failureReason: String? = nil,
        authMethod: String? = nil
    ) {
        self.key = key
        self.version = version
        self.status = status
        self.deviceManufacturer = deviceManufacturer
        self.deviceModel = deviceModel
        self.enrollmentLabel = enrollmentLabel
        self.deviceId = deviceId
        self.deviceAlias = deviceAlias
        self.failureReason = failureReason
        self.authMethod = authMethod
    }
}
