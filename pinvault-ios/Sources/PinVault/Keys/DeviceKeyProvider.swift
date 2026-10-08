import Foundation
import Security

/// The device's RSA-2048 key pair for `end_to_end` vault files: the server
/// wraps each file's AES key with the public half (registered with
/// `"algorithm": "RSA-OAEP-SHA256-MGF1-SHA256"`), only the device can unwrap
/// it. Keychain (software: the Secure Enclave holds no RSA), ThisDeviceOnly,
/// application tag ``DeviceKeys/defaultAlias``.
///
/// Implementations come in L4 (`DeviceKeys.keychain(alias:)` / `.software(alias:)`).
public protocol DeviceKeyProvider: Sendable {

    /// Generate the key pair if missing. Idempotent.
    func ensureKeyPair() throws

    /// `-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----` (SPKI).
    func getPublicKeyPem() throws -> String

    /// The private key; used through `SecKeyCreateDecryptedData` only.
    func getPrivateKey() throws -> SecKey

    /// Remove the key pair; the next ``ensureKeyPair()`` makes a new one.
    func clear() throws
}

/// Names of the device keys (the Kotlin `DeviceKeyProvider.Companion`).
public enum DeviceKeys {
    /// Keychain application tag of the `end_to_end` RSA key.
    public static let defaultAlias = "pinvault_vault_e2e_rsa"

    /// The algorithm iOS registers its RSA keys with (PORTING.md §3: Apple's
    /// OAEP-SHA256 uses MGF1-SHA256; Android's `RSA-OAEP-SHA256` is MGF1-SHA1).
    public static let registrationAlgorithm = "RSA-OAEP-SHA256-MGF1-SHA256"
}
