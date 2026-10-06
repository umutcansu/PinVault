import CryptoKit
import Foundation

/// SHA-256 helpers over CryptoKit.
enum Hashing {

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// SHA-256 of the UTF-8 bytes of `text`.
    static func sha256(_ text: String) -> Data {
        sha256(Data(text.utf8))
    }

    /// Lowercase hex of the SHA-256.
    static func sha256Hex(_ data: Data) -> String {
        Hex.encode(sha256(data))
    }

    /// Standard Base64 of the SHA-256 (44 characters) — the pin / key-id format.
    static func sha256Base64(_ data: Data) -> String {
        Base64.encode(sha256(data))
    }

    /// Compares two byte strings in time that depends only on their lengths
    /// (`MessageDigest.isEqual`).
    static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for (x, y) in zip(a, b) { difference |= x ^ y }
        return difference == 0
    }
}
