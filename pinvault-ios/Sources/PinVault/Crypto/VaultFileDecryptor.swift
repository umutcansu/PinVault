import CryptoKit
import Foundation
import Security

/// Opens the envelopes the server's VaultEncryptionService makes for
/// `end_to_end` (and, through the unwrap closure, `user_auth`) vault files.
///
/// Layout (big-endian):
///
///     [4 bytes: wrappedKey length][wrappedKey][12 bytes: GCM IV][AES-GCM ciphertext + 16-byte tag]
///
/// The wrapped key is RSA-OAEP with SHA-256 and — for keys iOS registered —
/// MGF1-SHA256 (`.rsaEncryptionOAEPSHA256`; PORTING.md §3). AES-256-GCM
/// authenticates the ciphertext: tampering fails with
/// ``PinVaultError/crypto(message:cause:)``, never with corrupt plaintext.
public enum VaultFileDecryptor {

    static let gcmIVBytes = 12
    static let gcmTagBytes = 16

    /// Opens `envelope` with the device's RSA private key.
    /// - Throws: ``PinVaultError/illegalArgument(_:)`` for a malformed
    ///   envelope, ``PinVaultError/crypto(message:cause:)`` when the key does
    ///   not unwrap it or the ciphertext was tampered with.
    public static func decrypt(_ envelope: Data, privateKey: SecKey) throws -> Data {
        try decrypt(envelope) { wrappedKey in
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, wrappedKey as CFData, &error) as Data? else {
                throw PinVaultError.crypto(message: "The session key does not unwrap", cause: error?.takeRetainedValue())
            }
            return key
        }
    }

    /// Opens `envelope` with `unwrapKey` doing the RSA step (a `user_auth`
    /// envelope is unwrapped with the key the unlock prompt authorised).
    /// Errors of `unwrapKey` propagate unchanged.
    public static func decrypt(_ envelope: Data, unwrapKey: (Data) throws -> Data) throws -> Data {
        let parts = try parse(envelope)
        let sessionKey = try unwrapKey(parts.wrappedKey)
        return try openContent(parts, sessionKey: sessionKey)
    }

    /// The parts of an envelope.
    struct Parts: Equatable {
        let wrappedKey: Data
        let iv: Data
        let ciphertext: Data
    }

    /// Splits an envelope; throws ``PinVaultError/illegalArgument(_:)`` when it is malformed.
    static func parse(_ envelope: Data) throws -> Parts {
        let bytes = [UInt8](envelope)
        guard bytes.count > 4 + gcmIVBytes else {
            throw PinVaultError.illegalArgument("Envelope too short (\(bytes.count) bytes)")
        }
        let wrappedKeyLength = Int(Int32(bitPattern:
            UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])))
        guard (64...1024).contains(wrappedKeyLength) else {
            throw PinVaultError.illegalArgument("Implausible wrappedKey length: \(wrappedKeyLength)")
        }
        guard bytes.count >= 4 + wrappedKeyLength + gcmIVBytes else {
            throw PinVaultError.illegalArgument("Envelope truncated at wrappedKey/IV boundary")
        }
        var offset = 4
        let wrappedKey = Data(bytes[offset..<(offset + wrappedKeyLength)])
        offset += wrappedKeyLength
        let iv = Data(bytes[offset..<(offset + gcmIVBytes)])
        offset += gcmIVBytes
        return Parts(wrappedKey: wrappedKey, iv: iv, ciphertext: Data(bytes[offset...]))
    }

    /// AES-GCM open (tag verified) once the session key is unwrapped.
    static func openContent(_ parts: Parts, sessionKey: Data) throws -> Data {
        guard [16, 24, 32].contains(sessionKey.count) else {
            throw PinVaultError.crypto(message: "Invalid AES key length: \(sessionKey.count) bytes", cause: nil)
        }
        guard parts.ciphertext.count >= gcmTagBytes else {
            throw PinVaultError.crypto(message: "Input too short - need tag", cause: nil)
        }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: parts.iv),
                ciphertext: parts.ciphertext.prefix(parts.ciphertext.count - gcmTagBytes),
                tag: parts.ciphertext.suffix(gcmTagBytes)
            )
            return try AES.GCM.open(box, using: SymmetricKey(data: sessionKey))
        } catch {
            throw PinVaultError.crypto(message: "Tag mismatch", cause: error)
        }
    }
}
