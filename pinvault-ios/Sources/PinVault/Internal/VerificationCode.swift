import Foundation
import Security

/// The code a device shows while its enrollment waits for approval, so the
/// administrator can match it with the request in the dashboard: the first 80
/// bits (10 bytes) of the SHA-256 of the device key (SubjectPublicKeyInfo, DER)
/// in Crockford's base32, 16 characters in groups of four —
/// `4F7K-2QXM-9D3T-H6WP`. The server computes the same from the key it
/// received (demo-server `VerificationCode`); keep the two in step.
///
/// The first eight characters are the 40-bit code library 2.1.x showed.
enum VerificationCode {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Bytes of the digest the code is made of.
    static let bytes = 10

    /// The code of `publicKey`.
    static func of(publicKey: SecKey) throws -> String {
        try of(spki: SPKI.der(for: publicKey))
    }

    /// The code of the key whose SubjectPublicKeyInfo is `spki`.
    static func of(spki: Data) throws -> String {
        try ofDigest(Hashing.sha256(spki))
    }

    static func ofDigest(_ digest: Data) throws -> String {
        guard digest.count >= bytes else { throw PinVaultError.illegalArgument("digest too short") }
        let bytes = [UInt8](digest)
        var chars: [Character] = []
        chars.reserveCapacity(16)
        // 5 bytes = 40 bits = 8 characters, twice.
        for half in 0..<2 {
            var bits: UInt64 = 0
            for i in 0..<5 { bits = (bits << 8) | UInt64(bytes[half * 5 + i]) }
            for i in 0..<8 { chars.append(alphabet[Int((bits >> UInt64(35 - 5 * i)) & 31)]) }
        }
        return stride(from: 0, to: 16, by: 4).map { String(chars[$0..<$0 + 4]) }.joined(separator: "-")
    }
}
