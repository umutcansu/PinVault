import Foundation

/// App Attest in place of Android Key Attestation at enrollment (PORTING.md §6).
///
/// An iOS identity key carries no attestation chain. Instead, the first
/// request of an enrollment (and the one retry after an attestation refusal)
/// carries `appAttestation`: the App Attest token JSON
/// `{"provider":"app-attest","keyId":"<base64>","attestation":"<base64 CBOR>"}`
/// of a fresh App Attest key, made with
/// `clientDataHash = SHA256(UTF8(integrityRequestHash))` — the 43-character
/// ``IntegrityRequestHash`` of the request's CSR and device id. The server
/// (`ENROLLMENT_ATTESTATION=warn|enforce`) takes a verified one in place of
/// `attestationChain`. Not sent when a pending request asks again by its
/// `requestId`, and never with a renewal (the server binds a renewal to the
/// certificate it issued).
enum EnrollmentAppAttestation {

    /// Makes the token for a client data hash; nil when there is none
    /// (simulator, App Attest unsupported, a failure). L5's
    /// `AppAttestBinder.attestation(clientDataHash:)`; the integration wires it.
    typealias Source = @Sendable (_ clientDataHash: Data) async -> String?

    /// `SHA256(UTF8(requestHash))`: what the attestation binds.
    static func clientDataHash(requestHash: String) -> Data {
        Hashing.sha256(requestHash)
    }
}

/// A Config API that sends `appAttestation` in the CSR enrollment body. The
/// library's own API client adopts it (L2); a custom ``CertificateConfigApi``
/// that does not gets the eight-argument call, without the attestation.
///
/// Wire form: the token JSON goes into the body as a JSON **string** value,
/// exactly like `integrityToken` — `"appAttestation":"{\"provider\":\"app-attest\",…}"`,
/// never a nested object (the server parses that form; the vault layer sends
/// the user-auth key registration's the same way).
protocol AppAttestedEnrollmentApi: CertificateConfigApi {

    /// The eight-argument `enrollWithCsr` with the App Attest token JSON for
    /// the body's `appAttestation` (a string value, see above).
    func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?,
        attestationChain: [String],
        integrityToken: String?,
        appAttestation: String
    ) async throws -> EnrollmentResult?
}
