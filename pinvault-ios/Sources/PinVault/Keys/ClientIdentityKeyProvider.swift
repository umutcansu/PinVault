import Foundation
import Security

/// The device's mTLS identity: a permanent EC P-256 signing key (Secure
/// Enclave when available, else a Keychain software key reporting
/// ``KeySecurityLevel/software``). The client certificate is a short-lived
/// credential issued over it and renewed by signing a CSR with it; the key
/// never leaves the device. One key per client-cert label, Keychain
/// application tag ``ClientIdentityKeys/aliasFor(_:)``.
///
/// Implementations come in L3 (`ClientIdentityKeys.secureEnclave(label:)` /
/// `.software(label:)`); this file declares the contract.
public protocol ClientIdentityKeyProvider: Sendable {

    /// Generate the key pair if missing. Idempotent.
    func ensureKeyPair() throws

    /// ``ensureKeyPair()`` with an attestation challenge. iOS keys carry no
    /// key attestation, so the challenge is ignored by default.
    func ensureKeyPair(attestationChallenge: Data?) throws

    /// The key's attestation chain (DER, leaf first); always empty on iOS.
    func attestationChain() -> [Data]

    /// True when the key exists (without generating it).
    func exists() -> Bool

    func publicKey() throws -> SecKey

    /// Opaque for Secure Enclave keys: usable only through ``sign(_:)`` and TLS identities.
    func privateKey() throws -> SecKey

    /// ECDSA-SHA256 over `data`, DER `ECDSA-Sig-Value`.
    func sign(_ data: Data) throws -> Data

    /// Base64 SHA-256 of the SubjectPublicKeyInfo — what the server keeps in its registry.
    func spkiSha256() throws -> String

    /// Where the key lives (``KeySecurityLevel/secureEnclave`` or ``KeySecurityLevel/software``);
    /// ``KeySecurityLevel/unknown`` when it cannot be told.
    func securityLevel() -> KeySecurityLevel

    /// Delete the key; the next ``ensureKeyPair()`` makes a new identity.
    func clear() throws
}

extension ClientIdentityKeyProvider {
    public func ensureKeyPair(attestationChallenge: Data?) throws { try ensureKeyPair() }
    public func attestationChain() -> [Data] { [] }
    public func securityLevel() -> KeySecurityLevel { .unknown }

    public func spkiSha256() throws -> String {
        SPKI.pin(try SPKI.der(for: publicKey()))
    }
}

/// Names and constants of the client identity keys (the Kotlin
/// `ClientIdentityKeyProvider.Companion`).
public enum ClientIdentityKeys {
    private static let aliasPrefix = "pinvault_client_identity_ec_"

    /// Keychain application tag of the identity behind the client cert stored under `label`.
    public static func aliasFor(_ label: String) -> String {
        aliasPrefix + label
    }

    /// OID of the Android key attestation extension (unused on iOS; kept for parity).
    public static let attestationExtensionOID = "1.3.6.1.4.1.11129.2.1.17"

    /// SHA-256 of `pinvault-identity-key:v1:<deviceUid>` (UTF-8): the challenge
    /// an identity key is generated with on Android.
    public static func attestationChallenge(deviceUid: String) -> Data {
        Hashing.sha256("pinvault-identity-key:v1:\(deviceUid)")
    }
}
