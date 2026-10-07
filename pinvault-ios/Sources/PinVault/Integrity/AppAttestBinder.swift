import Foundation

/// App Attest in place of Android Key Attestation (`PORTING.md` §6): an
/// attestation of a FRESH App Attest key whose client data hash binds it to
/// what is being registered — an enrollment (`appAttestation`,
/// ``enrollmentClientDataHash(integrityRequestHash:)``), a screen-lock key
/// (``userAuthKeyClientDataHash(deviceId:spkiDer:)``). The attestation
/// rounds use ``AppAttestVerdictProvider`` instead (one key per block,
/// assertions after the first round).
///
/// The token is the JSON of §6, `{"provider":"app-attest","keyId":…,"attestation":…}`;
/// nil where App Attest is unsupported (the simulator) or fails — the
/// request then goes without one, and a server that requires it refuses.
struct AppAttestBinder: Sendable {

    /// Over `DCAppAttestService.shared`.
    static let shared = AppAttestBinder()

    private let service: any AppAttestService
    private let log = PinVaultLog.tag("AppAttestBinder")

    init(service: any AppAttestService = DeviceCheckAppAttestService()) {
        self.service = service
    }

    /// ``attestation(clientDataHash:)`` over `DCAppAttestService.shared`.
    static func attestation(clientDataHash: Data) async -> String? {
        await shared.attestation(clientDataHash: clientDataHash)
    }

    /// A new App Attest key attested over `clientDataHash`, as the token JSON;
    /// nil when App Attest is unsupported or the attestation failed (logged).
    func attestation(clientDataHash: Data) async -> String? {
        guard service.isSupported else { return nil }
        do {
            let keyId = try await service.generateKey()
            let object = try await service.attestKey(keyId, clientDataHash: clientDataHash)
            return AppAttestToken.attestation(keyId: keyId, object: object)
        } catch {
            log.w("App Attest: no attestation for this registration — sending none", error)
            return nil
        }
    }

    /// Enrollment: `SHA-256(UTF-8(integrityRequestHash))`, the 43-character request hash of the CSR and device id.
    static func enrollmentClientDataHash(integrityRequestHash: String) -> Data {
        AppAttestToken.enrollmentClientDataHash(requestHash: integrityRequestHash)
    }

    /// Screen-lock key registration:
    /// `SHA-256(UTF-8("pinvault-user-auth-key:v1:" + deviceId + ":" + base64(SHA-256(SPKI DER))))`.
    static func userAuthKeyClientDataHash(deviceId: String, spkiDer: Data) -> Data {
        Hashing.sha256("pinvault-user-auth-key:v1:\(deviceId):\(Hashing.sha256Base64(spkiDer))")
    }
}
