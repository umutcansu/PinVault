import Foundation

/// What an enrollment came to, from `PinVault.enrollForResult` and
/// `autoEnrollForResult`. The `Bool` `enroll` / `autoEnroll` return `true`
/// exactly for ``enrolled(alreadyEnrolled:keySecurityLevel:)``.
public enum ClientCertEnrollmentResult: Sendable {

    /// A certificate was issued and stored, or one was already stored
    /// (`alreadyEnrolled`). `keySecurityLevel` is where the private key lives,
    /// for an enrollment made now; nil for one already stored (read it with
    /// `PinVault.identityKeySecurityLevel`).
    case enrolled(alreadyEnrolled: Bool = false, keySecurityLevel: KeySecurityLevel? = nil)

    /// The server answered and refused. `reason` says what to do next;
    /// `serverError` and `message` are the server's own words, for logs.
    case refused(reason: EnrollmentRefusal, httpStatus: Int, serverError: String? = nil, message: String? = nil)

    /// An administrator has to approve this device first. The device keeps
    /// its key and the `requestId`; `PinVault.checkPendingEnrollment` asks
    /// again (start and the periodic update do too). `clientId` is the
    /// identity it will get; `retryAfterSeconds` how long the server asks it
    /// to wait between tries; `verificationCode` (`4F7K-2QXM-9D3T-H6WP`) is
    /// what to show the user — the administrator sees the same next to the request.
    case pending(
        requestId: String,
        clientId: String? = nil,
        message: String? = nil,
        retryAfterSeconds: Int? = nil,
        verificationCode: String? = nil
    )

    /// No usable answer: unreachable server, pin mismatch, key store failure,
    /// or an answer that did not check out.
    case failed(message: String, cause: (any Error)? = nil)

    /// True for ``enrolled(alreadyEnrolled:keySecurityLevel:)``.
    public var isEnrolled: Bool {
        if case .enrolled = self { return true }
        return false
    }
}

extension ClientCertEnrollmentResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.enrolled(a1, b1), .enrolled(a2, b2)):
            return a1 == a2 && b1 == b2
        case let (.refused(a1, b1, c1, d1), .refused(a2, b2, c2, d2)):
            return a1 == a2 && b1 == b2 && c1 == c2 && d1 == d2
        case let (.pending(a1, b1, c1, d1, e1), .pending(a2, b2, c2, d2, e2)):
            return a1 == a2 && b1 == b2 && c1 == c2 && d1 == d2 && e1 == e2
        case let (.failed(a1, c1), .failed(a2, c2)):
            return a1 == a2 && errorsEqual(c1, c2)
        default:
            return false
        }
    }
}

/// Why a server refused an enrollment.
public enum EnrollmentRefusal: String, Sendable, Equatable, Hashable, CaseIterable {
    /// The token is unknown, already used or expired (401). Ask for a new one.
    case invalidToken = "INVALID_TOKEN"
    /// The server enrolls only with a token, so a token-less `autoEnroll` was refused.
    case tokenRequired = "TOKEN_REQUIRED"
    /// This device is enrolled under another client id (409 `device_already_enrolled`),
    /// or this client id over another key (409 `identity_already_enrolled`).
    case deviceAlreadyEnrolled = "DEVICE_ALREADY_ENROLLED"
    /// The client id the token is for was revoked (403 `revoked`).
    case revoked = "REVOKED"
    /// An administrator turned this device away (403 `enrollment_rejected`).
    case rejected = "REJECTED"
    /// The enrollment code has no device left (403 `enrollment_limit_reached`).
    case limitReached = "LIMIT_REACHED"
    /// Nobody decided on the request in time (410 `enrollment_request_expired`).
    case expired = "EXPIRED"
    /// The server wants a key attestation / integrity verdict it did not get or
    /// refused (`attestation_required`, `attestation_invalid`,
    /// `integrity_required`, `integrity_invalid`).
    case attestationFailed = "ATTESTATION_FAILED"
    /// The server issues certificates only over a CSR (`csr_required`) and the request carried none.
    case csrRequired = "CSR_REQUIRED"
    /// Anything else; see the `serverError` of the refusal.
    case other = "OTHER"

    /// `EnrollmentRefusedException.refusal`: the refusal for an HTTP status and the server's `error`.
    public static func from(httpStatus: Int, serverError: String?) -> EnrollmentRefusal {
        if httpStatus == 401 { return .invalidToken }
        switch serverError {
        case "device_already_enrolled", "identity_already_enrolled": return .deviceAlreadyEnrolled
        case "revoked": return .revoked
        case "enrollment_rejected": return .rejected
        case "enrollment_limit_reached": return .limitReached
        case "enrollment_request_expired": return .expired
        // The server issues this enrollment only over a CSR.
        case "csr_required": return .csrRequired
        case "attestation_required", "attestation_invalid", "integrity_required", "integrity_invalid":
            return .attestationFailed
        default:
            // The reference server answers a token-less enrollment in token mode
            // with 403 and a sentence in `error` ("Token required for enrollment…").
            if httpStatus == 403, serverError?.hasPrefix("Token required") == true { return .tokenRequired }
            return .other
        }
    }
}

/// Errors compared for the `Equatable` conformances of the result types:
/// both absent, or both present with the same type and description.
func errorsEqual(_ lhs: (any Error)?, _ rhs: (any Error)?) -> Bool {
    switch (lhs, rhs) {
    case (nil, nil): return true
    case let (a?, b?): return type(of: a) == type(of: b) && String(reflecting: a) == String(reflecting: b)
    default: return false
    }
}
