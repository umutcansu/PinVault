import Foundation

/// Supplies an integrity verdict for an enrollment request, made by a service
/// the server can check (App Attest, or a RASP product's attestation).
///
/// PinVault calls ``token(requestHash:)`` once per enrollment request. The
/// `requestHash` binds the token to the request — 43 characters of unpadded
/// Base64url:
///
/// ```
/// requestHash = base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))
/// ```
///
/// where `deviceId` is the request's `deviceUid`, or its `deviceId` without
/// one (empty with neither). Return nil when no token can be had: the request
/// goes without one, and a server that requires it refuses
/// (``EnrollmentRefusal/attestationFailed``, `integrity_required`). A thrown
/// error is treated the same way and logged.
public protocol IntegrityTokenProvider: Sendable {
    /// An integrity token bound to `requestHash`, or nil when none can be had.
    func token(requestHash: String) async throws -> String?
}

/// An ``IntegrityTokenProvider`` made from a closure
/// (`PinVaultConfig.Builder.integrityTokenProvider { hash in … }`).
public struct ClosureIntegrityTokenProvider: IntegrityTokenProvider {
    private let body: @Sendable (String) async throws -> String?

    public init(_ body: @escaping @Sendable (String) async throws -> String?) {
        self.body = body
    }

    public func token(requestHash: String) async throws -> String? {
        try await body(requestHash)
    }
}
