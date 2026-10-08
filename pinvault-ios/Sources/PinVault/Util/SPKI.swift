import Foundation
import Security

/// Object identifiers of the key algorithms the library handles.
enum KeyAlgorithmOID {
    static let ecPublicKey = "1.2.840.10045.2.1"
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let prime256v1 = "1.2.840.10045.3.1.7"
    static let secp384r1 = "1.3.132.0.34"
    static let secp521r1 = "1.3.132.0.35"
}

/// X.509 SubjectPublicKeyInfo: building, reading and pinning it.
///
/// Apple's `SecKeyCopyExternalRepresentation` gives the bare key — the X9.63
/// point `04‖X‖Y` for EC, PKCS#1 `RSAPublicKey` for RSA — while every pin and
/// key id of PinVault is over the SPKI (`PublicKey.getEncoded()` on Android).
enum SPKI {

    enum Algorithm: Equatable, Sendable {
        /// EC key on the named curve.
        case ec(curveOID: String)
        case rsa
        /// Anything else, by algorithm OID.
        case other(String)
    }

    struct Parsed: Equatable, Sendable {
        let algorithm: Algorithm
        /// X9.63 point (EC) or PKCS#1 `RSAPublicKey` (RSA); the BIT STRING bytes otherwise.
        let keyBytes: Data
    }

    /// SPKI of an uncompressed P-256 point (65 bytes, `04‖X‖Y`).
    static func ecP256(x963Point point: Data) throws -> Data {
        guard point.count == 65, point.first == 0x04 else {
            throw DERError.invalidValue("not an uncompressed P-256 point (\(point.count) bytes)")
        }
        return try ec(x963Point: point, curveOID: KeyAlgorithmOID.prime256v1)
    }

    /// SPKI of an uncompressed EC point on the curve `curveOID`.
    static func ec(x963Point point: Data, curveOID: String) throws -> Data {
        let algorithm = DER.sequence([
            try DER.objectIdentifier(KeyAlgorithmOID.ecPublicKey),
            try DER.objectIdentifier(curveOID),
        ])
        return DER.sequence([algorithm, DER.bitString(point)])
    }

    /// SPKI of a PKCS#1 `RSAPublicKey` (rsaEncryption with NULL parameters).
    static func rsa(pkcs1 publicKey: Data) throws -> Data {
        let algorithm = DER.sequence([try DER.objectIdentifier(KeyAlgorithmOID.rsaEncryption), DER.null()])
        return DER.sequence([algorithm, DER.bitString(publicKey)])
    }

    /// The algorithm and key bytes of an SPKI.
    static func parse(_ spki: Data) throws -> Parsed {
        let parts = try DER.parse(spki).expect(ASN1Tag.sequence).children()
        guard parts.count == 2 else { throw DERError.invalidValue("SubjectPublicKeyInfo must have two parts") }
        let algorithm = try parts[0].expect(ASN1Tag.sequence).children()
        guard let oidElement = algorithm.first else { throw DERError.invalidValue("empty AlgorithmIdentifier") }
        let oid = try oidElement.expect(ASN1Tag.objectIdentifier).objectIdentifier()
        let key = try parts[1].expect(ASN1Tag.bitString).bitStringBytes()
        switch oid {
        case KeyAlgorithmOID.ecPublicKey:
            guard algorithm.count == 2, algorithm[1].tag == ASN1Tag.objectIdentifier else {
                throw DERError.invalidValue("EC key without a named curve")
            }
            return Parsed(algorithm: .ec(curveOID: try algorithm[1].objectIdentifier()), keyBytes: key)
        case KeyAlgorithmOID.rsaEncryption:
            return Parsed(algorithm: .rsa, keyBytes: key)
        default:
            return Parsed(algorithm: .other(oid), keyBytes: key)
        }
    }

    /// Base64(SHA-256(SPKI)): the pin of a certificate key and the key id of a
    /// signing key — 44 characters, as Android computes it.
    static func pin(_ spkiDer: Data) -> String {
        Hashing.sha256Base64(spkiDer)
    }

    /// The modulus length in bits of a PKCS#1 `RSAPublicKey`.
    static func rsaModulusBits(pkcs1 publicKey: Data) throws -> Int {
        let parts = try DER.parse(publicKey).expect(ASN1Tag.sequence).children()
        guard parts.count == 2 else { throw DERError.invalidValue("RSAPublicKey must have two integers") }
        let modulus = try parts[0].expect(ASN1Tag.integer).unsignedIntegerBytes()
        guard let first = modulus.first else { return 0 }
        return (modulus.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }

    // MARK: SecKey

    /// The SPKI of `key` (a private key yields its public half's).
    static func der(for key: SecKey) throws -> Data {
        let publicKey = try publicKeyOf(key)
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw PinVaultError.crypto(message: "The public key cannot be exported", cause: error?.takeRetainedValue())
        }
        let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any] ?? [:]
        let type = attributes[kSecAttrKeyType] as? String
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) || type == (kSecAttrKeyTypeEC as String) {
            let bits = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
            let curve: String
            switch bits {
            case 256: curve = KeyAlgorithmOID.prime256v1
            case 384: curve = KeyAlgorithmOID.secp384r1
            case 521: curve = KeyAlgorithmOID.secp521r1
            default: throw PinVaultError.crypto(message: "Unsupported EC key size \(bits)", cause: nil)
            }
            return try ec(x963Point: external, curveOID: curve)
        }
        if type == (kSecAttrKeyTypeRSA as String) {
            return try rsa(pkcs1: external)
        }
        throw PinVaultError.crypto(message: "Unsupported key type \(type ?? "nil")", cause: nil)
    }

    /// A public `SecKey` from an SPKI (EC P-256/384/521 or RSA).
    static func secKey(fromSPKI spki: Data) throws -> SecKey {
        let parsed = try parse(spki)
        var attributes: [CFString: Any] = [kSecAttrKeyClass: kSecAttrKeyClassPublic]
        switch parsed.algorithm {
        case .ec(let curve):
            let bits: Int
            switch curve {
            case KeyAlgorithmOID.prime256v1: bits = 256
            case KeyAlgorithmOID.secp384r1: bits = 384
            case KeyAlgorithmOID.secp521r1: bits = 521
            default: throw PinVaultError.crypto(message: "Unsupported EC curve \(curve)", cause: nil)
            }
            attributes[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            attributes[kSecAttrKeySizeInBits] = bits
        case .rsa:
            attributes[kSecAttrKeyType] = kSecAttrKeyTypeRSA
            attributes[kSecAttrKeySizeInBits] = try rsaModulusBits(pkcs1: parsed.keyBytes)
        case .other(let oid):
            throw PinVaultError.crypto(message: "Unsupported key algorithm \(oid)", cause: nil)
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(parsed.keyBytes as CFData, attributes as CFDictionary, &error) else {
            throw PinVaultError.crypto(message: "The public key cannot be read", cause: error?.takeRetainedValue())
        }
        return key
    }

    /// `PUBLIC KEY` PEM of `key` (what the vault key registration sends).
    static func pem(for key: SecKey) throws -> String {
        PEM.encode(try der(for: key), label: "PUBLIC KEY")
    }

    /// The public half of `key`, or `key` itself when it is public.
    static func publicKeyOf(_ key: SecKey) throws -> SecKey {
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] ?? [:]
        if let keyClass = attributes[kSecAttrKeyClass] as? String, keyClass == (kSecAttrKeyClassPublic as String) {
            return key
        }
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw PinVaultError.crypto(message: "The key has no public half", cause: nil)
        }
        return publicKey
    }
}
