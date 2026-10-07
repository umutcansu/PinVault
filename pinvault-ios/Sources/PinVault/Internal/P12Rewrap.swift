import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Re-encrypts a PKCS12 bundle from the one-off password a server sent it with
/// (`X-P12-Password`) to the block's own `clientKeyPassword`, so storing and
/// reloading it works exactly as before — and no app has to know a
/// server-side password (Kotlin `P12Rewrap`).
///
/// Apple's Security framework reads PKCS12 (`SecPKCS12Import`) but writes it
/// only on macOS, so the bundle is written here: the identity's key as a
/// PKCS#8 `pkcs8ShroudedKeyBag` under `pbeWithSHAAnd3-KeyTripleDES-CBC`, the
/// certificates as plain cert bags, and an HMAC-SHA1 integrity MAC — the
/// classic PKCS#12 profile every importer (Apple, Java, OpenSSL) reads. The key
/// never leaves process memory.
enum P12Rewrap {

    /// Request header value asking the server for a per-response P12 password.
    static let feature = "p12password"
    static let passwordHeader = "X-P12-Password"

    private static let iterations = 2048

    /// `p12` (opened with `from`) wrapped with `to`.
    /// - Throws: ``PinVaultError/crypto(message:cause:)`` when the bundle does not open or its key cannot be read.
    static func rewrap(_ p12: Data, from: String, to: String) throws -> Data {
        let identity = try ClientIdentity.fromPKCS12(p12, password: from)
        var key: SecKey?
        SecIdentityCopyPrivateKey(identity.identity, &key)
        guard let key else { throw PinVaultError.crypto(message: "PKCS12 key cannot be read") }
        let certificates = identity.chain.map { SecCertificateCopyData($0) as Data }
        return try write(privateKey: key, certificates: certificates, password: to)
    }

    /// A PKCS12 holding `privateKey` and `certificates` (leaf first), protected by `password`.
    static func write(privateKey: SecKey, certificates: [Data], password: String) throws -> Data {
        guard let leaf = certificates.first else { throw PinVaultError.crypto(message: "PKCS12 needs a certificate") }
        let pkcs8 = try privateKeyInfo(privateKey)
        let localKeyId = Hashing.sha256(leaf).prefix(20)
        let bmp = bmpPassword(password)

        // pkcs8ShroudedKeyBag: EncryptedPrivateKeyInfo under pbeWithSHAAnd3-KeyTripleDES-CBC.
        let keySalt = randomBytes(8)
        let encryptedKey = try tripleDESEncrypt(
            pkcs8,
            key: kdf(bmp, salt: keySalt, id: 1, count: 24),
            iv: kdf(bmp, salt: keySalt, id: 2, count: 8)
        )
        let pbeParams = DER.sequence([DER.octetString(keySalt), DER.integer(iterations)])
        let encryptedPrivateKeyInfo = DER.sequence([
            DER.sequence([try DER.objectIdentifier(OID.pbeWithSHAAnd3KeyTripleDESCBC), pbeParams]),
            DER.octetString(encryptedKey),
        ])
        let keyBag = DER.sequence([
            try DER.objectIdentifier(OID.pkcs8ShroudedKeyBag),
            DER.explicit(0, encryptedPrivateKeyInfo),
            try attributes(localKeyId: localKeyId),
        ])

        var certBags: [Data] = []
        for (index, certificate) in certificates.enumerated() {
            let certBag = DER.sequence([try DER.objectIdentifier(OID.x509Certificate), DER.explicit(0, DER.octetString(certificate))])
            var bag = [try DER.objectIdentifier(OID.certBag), DER.explicit(0, certBag)]
            if index == 0 { bag.append(try attributes(localKeyId: localKeyId)) }
            certBags.append(DER.sequence(bag))
        }

        let authenticatedSafe = DER.sequence([
            try dataContentInfo(DER.sequence(certBags)),
            try dataContentInfo(DER.sequence([keyBag])),
        ])

        let macSalt = randomBytes(8)
        let macKey = kdf(bmp, salt: macSalt, id: 3, count: 20)
        let mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: authenticatedSafe, using: SymmetricKey(data: macKey)))
        let macData = DER.sequence([
            DER.sequence([DER.sequence([try DER.objectIdentifier(OID.sha1), DER.null()]), DER.octetString(mac)]),
            DER.octetString(macSalt),
            DER.integer(iterations),
        ])
        return DER.sequence([DER.integer(3), try dataContentInfo(authenticatedSafe), macData])
    }

    // MARK: Pieces

    private enum OID {
        static let data = "1.2.840.113549.1.7.1"
        static let pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2"
        static let certBag = "1.2.840.113549.1.12.10.1.3"
        static let x509Certificate = "1.2.840.113549.1.9.22.1"
        static let localKeyId = "1.2.840.113549.1.9.21"
        static let pbeWithSHAAnd3KeyTripleDESCBC = "1.2.840.113549.1.12.1.3"
        static let sha1 = "1.3.14.3.2.26"
        static let rsaEncryption = "1.2.840.113549.1.1.1"
        static let ecPublicKey = "1.2.840.10045.2.1"
        static let prime256v1 = "1.2.840.10045.3.1.7"
        static let secp384r1 = "1.3.132.0.34"
        static let secp521r1 = "1.3.132.0.35"
    }

    private static func dataContentInfo(_ content: Data) throws -> Data {
        DER.sequence([try DER.objectIdentifier(OID.data), DER.explicit(0, DER.octetString(content))])
    }

    private static func attributes(localKeyId: Data) throws -> Data {
        DER.set([DER.sequence([try DER.objectIdentifier(OID.localKeyId), DER.set([DER.octetString(localKeyId)])])])
    }

    /// The key as PKCS#8 `PrivateKeyInfo` (RSA, or EC P-256 / P-384 / P-521).
    static func privateKeyInfo(_ key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw PinVaultError.crypto(message: "PKCS12 key cannot be exported", cause: error?.takeRetainedValue())
        }
        let attributes = SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
        let type = attributes[kSecAttrKeyType as String] as? String
        if type == (kSecAttrKeyTypeRSA as String) {
            return DER.sequence([
                DER.integer(0),
                DER.sequence([try DER.objectIdentifier(OID.rsaEncryption), DER.null()]),
                DER.octetString(external),
            ])
        }
        // EC: 04 || X || Y || K.
        let curve: String
        let size: Int
        switch external.count {
        case 97: curve = OID.prime256v1; size = 32
        case 145: curve = OID.secp384r1; size = 48
        case 199: curve = OID.secp521r1; size = 66
        default: throw PinVaultError.crypto(message: "PKCS12 key has an unsupported type")
        }
        let publicPoint = external.prefix(1 + 2 * size)
        let scalar = external.suffix(size)
        let ecPrivateKey = DER.sequence([
            DER.integer(1),
            DER.octetString(Data(scalar)),
            DER.explicit(1, DER.bitString(Data(publicPoint))),
        ])
        return DER.sequence([
            DER.integer(0),
            DER.sequence([try DER.objectIdentifier(OID.ecPublicKey), try DER.objectIdentifier(curve)]),
            DER.octetString(ecPrivateKey),
        ])
    }

    /// The password as a BMPString with its terminating NUL (RFC 7292 B.1).
    static func bmpPassword(_ password: String) -> Data {
        var out = Data()
        for unit in password.utf16 {
            out.append(UInt8(unit >> 8))
            out.append(UInt8(unit & 0xFF))
        }
        out.append(contentsOf: [0, 0])
        return out
    }

    /// The PKCS#12 key derivation (RFC 7292 Appendix B.2) with SHA-1.
    static func kdf(_ password: Data, salt: Data, id: UInt8, count: Int, iterations: Int = P12Rewrap.iterations) -> Data {
        let u = 20, v = 64
        let d = Data(repeating: id, count: v)
        func stretch(_ input: Data) -> Data {
            guard !input.isEmpty else { return Data() }
            let length = v * ((input.count + v - 1) / v)
            var out = Data(capacity: length)
            while out.count < length { out.append(input.prefix(length - out.count)) }
            return out
        }
        var i = [UInt8](stretch(salt) + stretch(password))
        var result = Data()
        let blocks = (count + u - 1) / u
        for _ in 0..<blocks {
            var a = Data(Insecure.SHA1.hash(data: d + Data(i)))
            for _ in 1..<iterations { a = Data(Insecure.SHA1.hash(data: a)) }
            result.append(a)
            let b = [UInt8](stretch(a).prefix(v))
            // I_j = (I_j + B + 1) mod 2^(v·8) for every v-byte block of I.
            var offset = 0
            while offset < i.count {
                var carry: UInt16 = 1
                for k in stride(from: v - 1, through: 0, by: -1) {
                    let sum = UInt16(i[offset + k]) + UInt16(b[k]) + carry
                    i[offset + k] = UInt8(sum & 0xFF)
                    carry = sum >> 8
                }
                offset += v
            }
        }
        return result.prefix(count)
    }

    private static func tripleDESEncrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        var out = Data(count: plaintext.count + kCCBlockSize3DES)
        var written = 0
        let outCapacity = out.count
        let status = out.withUnsafeMutableBytes { outBytes in
            plaintext.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithm3DES), CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            inBytes.baseAddress, plaintext.count,
                            outBytes.baseAddress, outCapacity, &written
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw PinVaultError.crypto(message: "PKCS12 key encryption failed (\(status))") }
        return out.prefix(written)
    }

    private static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
