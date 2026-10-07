import Foundation

/// Apple App Attest as the enrollment integrity token (`ATTESTATION.md` §12
/// "Enrollment", `PORTING.md` §6): every enrollment request gets a fresh App
/// Attest key and its attestation, bound to the request with the client data
/// hash `SHA-256(UTF-8(requestHash))`. The PinVault server verifies it
/// (`INTEGRITY_VERIFICATION`, `APP_ATTEST_APP_IDS`).
///
/// ```swift
/// .integrityTokenProvider(AppAttestIntegrityTokenProvider())
/// ```
///
/// Returns nil where `DCAppAttestService.isSupported` is false (the
/// simulator): the request goes without a token. An App Attest error is
/// thrown, and PinVault sends the request without a token and logs it.
public final class AppAttestIntegrityTokenProvider: IntegrityTokenProvider, Sendable {

    private let service: any AppAttestService

    /// The provider over `DCAppAttestService.shared`.
    public convenience init() {
        self.init(service: DeviceCheckAppAttestService())
    }

    init(service: any AppAttestService) {
        self.service = service
    }

    /// `{"provider":"app-attest","keyId":"…","attestation":"…"}` for a new key
    /// attested over `SHA-256(UTF-8(requestHash))`, or nil without App Attest.
    public func token(requestHash: String) async throws -> String? {
        guard service.isSupported else { return nil }
        let keyId = try await service.generateKey()
        let attestation = try await service.attestKey(
            keyId, clientDataHash: AppAttestToken.enrollmentClientDataHash(requestHash: requestHash)
        )
        return AppAttestToken.attestation(keyId: keyId, object: attestation)
    }
}
