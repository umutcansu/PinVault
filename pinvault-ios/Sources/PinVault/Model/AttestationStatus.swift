import Foundation

/// What the last attestation of a Config API block came to (`ATTESTATION.md`).
public enum AttestationResult: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The server passed the device and issued a `PinVault-Token`.
    case pass = "PASS"
    /// The server refused the device: no token, no config through this channel.
    case reject = "REJECT"
    /// The attestation could not be completed (network, server error, a refused key). Retried with backoff.
    case failed = "FAILED"
    /// No attestation has run yet for this block.
    case notAttested = "NOT_ATTESTED"
    /// This block cannot attest: no `attestation()` on it, or a custom ``CertificateConfigApi``.
    case unsupported = "UNSUPPORTED"
}

/// The state of attestation for one Config API block, held in memory only
/// (`PinVault.attestationStatus(configApiId:)`).
public struct AttestationStatus: Sendable, Equatable, Hashable {
    /// The block.
    public var configApiId: String
    /// The last outcome.
    public var result: AttestationResult
    /// Attestation result code of the last verdict (8 hex characters an operator looks up), or nil.
    public var arc: String?
    /// The server's reasons for a `REJECT`, when the policy reveals them.
    public var rejectionReasons: [String]
    /// Flags the policy marked `warn` on the last verdict.
    public var warnings: [String]
    /// When the held token expires, epoch ms (device clock); nil without a token.
    public var tokenExpiresAt: Int64?
    /// When the server last answered (pass or reject), epoch ms.
    public var lastAttestedAt: Int64?
    /// When the library re-attests next, epoch ms; nil when nothing is scheduled.
    public var nextAttestAt: Int64?
    /// `serverTime − device time` from the last challenge, ms; informational.
    public var clockSkewMs: Int64?
    /// Why the last attempt failed, or nil.
    public var lastError: String?
    /// The server policy version of the last verdict, or nil.
    public var policyVersion: Int?

    public init(
        configApiId: String,
        result: AttestationResult,
        arc: String? = nil,
        rejectionReasons: [String] = [],
        warnings: [String] = [],
        tokenExpiresAt: Int64? = nil,
        lastAttestedAt: Int64? = nil,
        nextAttestAt: Int64? = nil,
        clockSkewMs: Int64? = nil,
        lastError: String? = nil,
        policyVersion: Int? = nil
    ) {
        self.configApiId = configApiId
        self.result = result
        self.arc = arc
        self.rejectionReasons = rejectionReasons
        self.warnings = warnings
        self.tokenExpiresAt = tokenExpiresAt
        self.lastAttestedAt = lastAttestedAt
        self.nextAttestAt = nextAttestAt
        self.clockSkewMs = clockSkewMs
        self.lastError = lastError
        self.policyVersion = policyVersion
    }

    /// True when the last verdict was a pass and the token has not expired by `now` (epoch ms).
    public func hasValidToken(now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        result == .pass && (tokenExpiresAt ?? 0) > now
    }
}

/// Outcome of `PinVault.fetchAttestationToken(host:)`: the token for the
/// `PinVault-Token` header, or why there is none.
public enum AttestationTokenResult: Sendable, Equatable {
    /// A token valid until `expiresAt` (epoch ms, device clock).
    case token(value: String, expiresAt: Int64)
    /// The server rejected the device; `status` carries the ARC and the reasons the policy reveals.
    case rejected(status: AttestationStatus)
    /// The attestation could not be completed; retried later.
    case failed(message: String)
    /// No attesting block covers the host (see ``AttestationResult/unsupported``).
    case unsupported
}

extension AttestationTokenResult: CustomStringConvertible, CustomDebugStringConvertible {
    /// Never prints the token.
    public var description: String {
        switch self {
        case .token(_, let expiresAt): return "Token(expiresAt=\(expiresAt), value=***)"
        case .rejected(let status): return "Rejected(status=\(status))"
        case .failed(let message): return "Failed(message=\(message))"
        case .unsupported: return "Unsupported"
        }
    }

    public var debugDescription: String { description }
}
