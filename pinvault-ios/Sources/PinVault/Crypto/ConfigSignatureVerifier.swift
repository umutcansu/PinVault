import CryptoKit
import Foundation

/// Verifies ECDSA-SHA256 signatures on config payloads.
///
/// The public key is compiled into the app (`signaturePublicKey`); the
/// private key lives on the config backend.
enum ConfigSignatureVerifier {

    private static let log = PinVaultLog.tag("ConfigSignatureVerifier")

    /// True when `signature` (Base64 DER) is a valid ECDSA-SHA256 signature
    /// of the UTF-8 bytes of `payload` by `publicKeyBase64` (Base64 SPKI).
    static func verify(payload: String, signature: String, publicKeyBase64: String) -> Bool {
        do {
            let valid = try verifyOrThrow(payload: payload, signature: signature, publicKeyBase64: publicKeyBase64)
            if valid {
                log.d("Config signature verified ✓")
            } else {
                log.e("Config signature verification FAILED")
            }
            return valid
        } catch {
            log.e("Config signature verification error", error)
            return false
        }
    }

    /// ``verify(payload:signature:publicKeyBase64:)`` without logging. Used
    /// when several keys are tried in turn (multi-key trust, m-of-n): a key
    /// that does not match is the expected case there.
    static func verifyQuietly(payload: String, signature: String, publicKeyBase64: String) -> Bool {
        (try? verifyOrThrow(payload: payload, signature: signature, publicKeyBase64: publicKeyBase64)) ?? false
    }

    private static func verifyOrThrow(payload: String, signature: String, publicKeyBase64: String) throws -> Bool {
        guard let keyBytes = AndroidBase64.decode(publicKeyBase64) else { throw SignatureError.malformed("key is not Base64") }
        let key = try ECPublicKey(spki: keyBytes)
        guard let signatureBytes = AndroidBase64.decode(signature) else {
            throw SignatureError.malformed("signature is not Base64")
        }
        return try key.isValid(derSignature: signatureBytes, over: Data(payload.utf8))
    }

    /// One canonical text form per EC public key: accepts Base64 (line breaks
    /// and PEM armour allowed), parses it, and re-encodes the parsed key as
    /// single-line Base64 SPKI. Two spellings of the same key map to the same
    /// string, so key lists can be de-duplicated and compared safely. nil when
    /// it is not an EC key.
    static func canonicalKey(_ key: String) -> String? {
        guard let der = AndroidBase64.decode(ConfigApiBlock.normalizeKeyText(key)),
              let parsed = try? ECPublicKey(spki: der) else { return nil }
        return Base64.encode(parsed.spki)
    }

    /// Key id of a Base64 SPKI public key: Base64 of SHA-256 over the SPKI
    /// bytes — the shape of a TLS SPKI pin. nil when `publicKeyBase64` is not Base64.
    static func keyIdOf(_ publicKeyBase64: String) -> String? {
        AndroidBase64.decode(publicKeyBase64).map(Hashing.sha256Base64)
    }

    /// Verifies a vault file's content signature: the signed canonical binds
    /// key + version + SHA-256(plaintext), as the server's `signVaultFile`.
    /// The device verifies the plaintext it ends up with (after any E2E
    /// decrypt), so one signature covers every encryption mode.
    static func verifyVaultFile(key: String, version: Int, plaintext: Data, signature: String, publicKeyBase64: String) -> Bool {
        verify(payload: vaultCanonical(key: key, version: version, plaintext: plaintext), signature: signature, publicKeyBase64: publicKeyBase64)
    }

    /// The string a v1 vault file signature covers. It does not say which Config API the file belongs to.
    static func vaultCanonical(key: String, version: Int, plaintext: Data) -> String {
        "pinvault-vault-file:v1:\(key):\(version):\(Hashing.sha256Hex(plaintext))"
    }

    /// The string a v2 vault file signature covers: v1 plus the server-side
    /// Config API id, so a file signed for one Config API does not verify for
    /// another that shares the signing key.
    static func vaultCanonicalV2(configApiId: String, key: String, version: Int, plaintext: Data) -> String {
        "pinvault-vault-file:v2:\(configApiId):\(key):\(version):\(Hashing.sha256Hex(plaintext))"
    }

    enum SignatureError: Error, CustomStringConvertible {
        case malformed(String)

        var description: String {
            switch self {
            case .malformed(let reason): return "InvalidKeyException: \(reason)"
            }
        }
    }

    /// An EC public key on a named curve (what Java's `KeyFactory("EC")`
    /// reads from an SPKI), verifying SHA-256 ECDSA signatures in DER form.
    private struct ECPublicKey {
        private enum Key {
            case p256(P256.Signing.PublicKey)
            case p384(P384.Signing.PublicKey)
            case p521(P521.Signing.PublicKey)
        }

        private let key: Key

        init(spki: Data) throws {
            let parsed = try SPKI.parse(spki)
            guard case .ec(let curve) = parsed.algorithm else { throw SignatureError.malformed("not an EC key") }
            // Uncompressed points only, as the JDK reads them.
            guard parsed.keyBytes.first == 0x04 else { throw SignatureError.malformed("not an uncompressed EC point") }
            switch curve {
            case KeyAlgorithmOID.prime256v1: key = .p256(try P256.Signing.PublicKey(x963Representation: parsed.keyBytes))
            case KeyAlgorithmOID.secp384r1: key = .p384(try P384.Signing.PublicKey(x963Representation: parsed.keyBytes))
            case KeyAlgorithmOID.secp521r1: key = .p521(try P521.Signing.PublicKey(x963Representation: parsed.keyBytes))
            default: throw SignatureError.malformed("unsupported EC curve \(curve)")
            }
        }

        /// The key re-encoded as an X.509 SubjectPublicKeyInfo (Java `PublicKey.getEncoded()`).
        var spki: Data {
            switch key {
            case .p256(let key): return key.derRepresentation
            case .p384(let key): return key.derRepresentation
            case .p521(let key): return key.derRepresentation
            }
        }

        /// `SHA256withECDSA` over `message`, whatever the curve.
        func isValid(derSignature: Data, over message: Data) throws -> Bool {
            let digest = SHA256.hash(data: message)
            switch key {
            case .p256(let key):
                return key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: derSignature), for: digest)
            case .p384(let key):
                return key.isValidSignature(try P384.Signing.ECDSASignature(derRepresentation: derSignature), for: digest)
            case .p521(let key):
                return key.isValidSignature(try P521.Signing.ECDSASignature(derRepresentation: derSignature), for: digest)
            }
        }
    }
}

/// `android.util.Base64.decode(text, NO_WRAP)`, which the Kotlin verifier
/// uses for keys and signatures: the standard alphabet, characters outside it
/// skipped, padding optional; nil where Android throws "bad base-64".
enum AndroidBase64 {
    static func decode(_ text: String) -> Data? {
        var out = Data()
        var state = 0
        var value: UInt32 = 0
        for byte in text.utf8 {
            let digit = Self.digit(byte)
            switch state {
            case 0, 1:
                if let digit {
                    value = (value << 6) | digit
                    state += 1
                } else if byte == UInt8(ascii: "=") {
                    return nil
                }
            case 2:
                if let digit {
                    value = (value << 6) | digit
                    state = 3
                } else if byte == UInt8(ascii: "=") {
                    out.append(UInt8((value >> 4) & 0xFF))
                    state = 4
                }
            case 3:
                if let digit {
                    value = (value << 6) | digit
                    out.append(UInt8((value >> 16) & 0xFF))
                    out.append(UInt8((value >> 8) & 0xFF))
                    out.append(UInt8(value & 0xFF))
                    value = 0
                    state = 0
                } else if byte == UInt8(ascii: "=") {
                    out.append(UInt8((value >> 10) & 0xFF))
                    out.append(UInt8((value >> 2) & 0xFF))
                    state = 5
                }
            case 4:
                if byte == UInt8(ascii: "=") {
                    state = 5
                } else if digit != nil {
                    return nil
                }
            default:
                // After the padding only skipped characters may follow.
                if digit != nil || byte == UInt8(ascii: "=") { return nil }
            }
        }
        switch state {
        case 1, 4: return nil
        case 2: out.append(UInt8((value >> 4) & 0xFF))
        case 3:
            out.append(UInt8((value >> 10) & 0xFF))
            out.append(UInt8((value >> 2) & 0xFF))
        default: break
        }
        return out
    }

    private static func digit(_ c: UInt8) -> UInt32? {
        switch c {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): return UInt32(c - UInt8(ascii: "A"))
        case UInt8(ascii: "a")...UInt8(ascii: "z"): return UInt32(c - UInt8(ascii: "a")) + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return UInt32(c - UInt8(ascii: "0")) + 52
        case UInt8(ascii: "+"): return 62
        case UInt8(ascii: "/"): return 63
        default: return nil
        }
    }
}
