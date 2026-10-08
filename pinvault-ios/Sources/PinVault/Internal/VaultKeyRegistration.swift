import Foundation

/// The device's token for one of its `end_to_end` / `user_auth` files (Kotlin
/// `DeviceKeyProof`): over a TLS Config API the server replaces a registered
/// key only for a request that carries it (`X-Vault-Key` + `X-Vault-Token`).
/// ``vaultKey`` is the server-side key, the last segment of the file's endpoint.
struct VaultDeviceKeyProof: Sendable, Equatable, CustomStringConvertible {
    let vaultKey: String
    let token: String

    /// Never prints the token.
    var description: String { "DeviceKeyProof(vaultKey=\(vaultKey), token=***)" }

    /// The request headers that carry it.
    var headers: [String: String] { ["X-Vault-Key": vaultKey, "X-Vault-Token": token] }
}

/// What PinVault's own API client adds to ``CertificateConfigApi`` (Kotlin: the
/// internal overloads of `DefaultCertificateConfigApi`): key registration that
/// carries a ``VaultDeviceKeyProof`` and, for the screen-lock key, an App Attest
/// attestation (PORTING.md §6). Custom APIs register through the protocol's
/// plain methods, without either. The body is ``VaultKeyRegistrationBody``.
protocol VaultKeyProofRegistering: Sendable {
    func registerDevicePublicKey(deviceId: String, publicKeyPem: String, proof: VaultDeviceKeyProof?) async throws

    /// `appAttestation`: the App Attest token JSON for this key, or nil (the field is then omitted).
    func registerUserAuthPublicKey(
        deviceId: String,
        publicKeyPem: String,
        attestationChain: [String],
        proof: VaultDeviceKeyProof?,
        appAttestation: String?
    ) async throws
}

/// The JSON body of `POST {configUrl}api/v1/vault/devices/{deviceId}/public-key`:
///
///     {"publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…", "algorithm": "RSA-OAEP-SHA256-MGF1-SHA256",
///      "purpose": "user_auth", "attestationChain": [...], "appAttestation": "{\"provider\":\"app-attest\",…}"}
///
/// `purpose` only for the screen-lock key (absent = the E2E key);
/// `attestationChain` only when non-empty (never on iOS); `appAttestation` only
/// for the screen-lock key and only when App Attest produced a token: the token
/// JSON as a string, like the enrollment's `integrityToken`.
enum VaultKeyRegistrationBody {
    static let userAuthPurpose = "user_auth"

    static func json(
        publicKeyPem: String,
        purpose: String? = nil,
        attestationChain: [String] = [],
        appAttestation: String? = nil
    ) throws -> Data {
        var body: [String: Any] = [
            "publicKeyPem": publicKeyPem,
            "algorithm": DeviceKeys.registrationAlgorithm,
        ]
        if let purpose { body["purpose"] = purpose }
        if !attestationChain.isEmpty { body["attestationChain"] = attestationChain }
        if purpose == userAuthPurpose, let appAttestation { body["appAttestation"] = appAttestation }
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}

/// What the App Attest attestation of the screen-lock key is bound to (PORTING.md §6).
enum UserAuthKeyAppAttest {

    /// `SHA256(UTF8("pinvault-user-auth-key:v1:" + deviceId + ":" + base64(SHA256(SPKI DER))))`.
    static func clientDataHash(deviceId: String, spki: Data) -> Data {
        Hashing.sha256(clientDataInput(deviceId: deviceId, spki: spki))
    }

    /// The string the client data hash is taken over.
    static func clientDataInput(deviceId: String, spki: Data) -> String {
        "pinvault-user-auth-key:v1:\(deviceId):\(Hashing.sha256Base64(spki))"
    }
}
