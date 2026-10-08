import Foundation

// ClientCertRenewalResponse.kt and ClientCertRenewalResult.kt.

/// What a backend answers to a client-certificate renewal request
/// (``CertificateConfigApi/renewClientCert(clientId:csrDer:recoveryUrl:)``).
public enum ClientCertRenewalResponse: Sendable, Equatable, Hashable {
    /// A new certificate was issued over the device's key: PEM chain, leaf first.
    case issued(certificateChainPem: [String])
    /// The server refuses to renew this identity; the device must enroll again.
    case reenrollRequired(reason: String)
    /// The backend has no renewal endpoint.
    case unsupported
}

extension ClientCertRenewalResponse: CustomStringConvertible {
    public var description: String {
        switch self {
        case .issued(let chain): return "Issued(certificateChainPem=\(chain.count) certificates)"
        case .reenrollRequired(let reason): return "ReenrollRequired(reason=\(reason))"
        case .unsupported: return "Unsupported"
        }
    }
}

/// Which door a renewal went through.
public enum ClientCertRenewalVia: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The certificate was still valid: renewed over the block's own (mTLS) connection.
    case mtls = "MTLS"
    /// Expired or refused: renewed over the recovery URL, which asks for no
    /// client certificate and checks the CSR signature against the registered key.
    case recovery = "RECOVERY"
}

/// Outcome of `PinVault.renewClientCertIfNeeded` and of the renewal check at
/// start and on every periodic update.
public enum ClientCertRenewalResult: Sendable {
    /// A new certificate is stored and presented from now on.
    case renewed(notAfterEpochMs: Int64, via: ClientCertRenewalVia)
    /// The current certificate still has enough lifetime left.
    case notNeeded(notAfterEpochMs: Int64)
    /// The server will not renew this identity; the stored certificate stays,
    /// the app should enroll again.
    case reenrollRequired(reason: String)
    /// Renewal was attempted and failed; retried next time.
    case failed(reason: String, exception: (any Error)? = nil)
    /// Nothing to renew: not enrolled, a server-made key, static pins, renewal
    /// disabled, or a backend without renewal.
    case notApplicable
}

extension ClientCertRenewalResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.renewed(a1, b1), .renewed(a2, b2)): return a1 == a2 && b1 == b2
        case let (.notNeeded(a), .notNeeded(b)): return a == b
        case let (.reenrollRequired(a), .reenrollRequired(b)): return a == b
        case let (.failed(a, e1), .failed(b, e2)): return a == b && errorsEqual(e1, e2)
        case (.notApplicable, .notApplicable): return true
        default: return false
        }
    }
}
