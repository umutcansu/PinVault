import Foundation
import Security

/// Minimal PKCS#10 (RFC 2986) encoder for the device's certificate signing
/// request, plus the PEM helpers the CSR flow needs (Kotlin `Pkcs10Csr`).
///
/// The request is always the same shape, byte for byte what the Android
/// library sends:
///
/// ```
/// CertificationRequest ::= SEQUENCE {
///   certificationRequestInfo  SEQUENCE {
///     version        INTEGER 0,
///     subject        Name (a single CN, UTF8String),
///     subjectPKInfo  SubjectPublicKeyInfo (the key's X.509 encoding),
///     attributes     [0] IMPLICIT SET (empty) },
///   signatureAlgorithm  ecdsa-with-SHA256 (no parameters),
///   signature           BIT STRING }
/// ```
///
/// The server ignores the subject anyway (it names the certificate after the
/// enrolled client id). `Pkcs10CsrTests` checks the bytes; the demo server's
/// `IosCsrInteropTest` parses a request this encoder made from a Secure Enclave key.
enum Pkcs10Csr {

    /// ecdsa-with-SHA256, 1.2.840.10045.4.3.2
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    /// id-at-commonName, 2.5.4.3
    private static let commonNameOID: [UInt8] = [0x55, 0x04, 0x03]
    private static let ecdsaWithSHA256OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]

    private static let tagInteger: UInt8 = 0x02
    private static let tagBitString: UInt8 = 0x03
    private static let tagOID: UInt8 = 0x06
    private static let tagUTF8String: UInt8 = 0x0C
    private static let tagSequence: UInt8 = 0x30
    private static let tagSet: UInt8 = 0x31
    private static let tagContext0: UInt8 = 0xA0

    /// A CSR for the key whose SubjectPublicKeyInfo is `spki`, subject `CN=<commonName>`.
    ///
    /// - Parameter signer: signs the DER CertificationRequestInfo with the
    ///   key's private half (SHA256withECDSA) and returns the DER
    ///   `ECDSA-Sig-Value`; a closure, so the key never has to leave the Secure Enclave.
    static func encode(commonName: String, spki: Data, signer: (_ tbs: Data) throws -> Data) throws -> Data {
        guard !commonName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PinVaultError.illegalArgument("commonName must not be blank")
        }
        do {
            _ = try SPKI.parse(spki)
        } catch {
            throw PinVaultError.illegalArgument("Public key must encode as X.509 SubjectPublicKeyInfo")
        }
        let subject = der(tagSequence, der(tagSet, der(tagSequence,
            der(tagOID, Data(commonNameOID)) + der(tagUTF8String, Data(commonName.utf8))
        )))
        let info = der(tagSequence,
            der(tagInteger, Data([0])) + subject + spki + der(tagContext0, Data())
        )
        let signature = try signer(info)
        let algorithm = der(tagSequence, der(tagOID, Data(ecdsaWithSHA256OID)))
        // BIT STRING: one leading byte for the count of unused bits (0).
        let bitString = der(tagBitString, Data([0]) + signature)
        return der(tagSequence, info + algorithm + bitString)
    }

    /// ``encode(commonName:spki:signer:)`` for `publicKey`.
    static func encode(commonName: String, publicKey: SecKey, signer: (_ tbs: Data) throws -> Data) throws -> Data {
        try encode(commonName: commonName, spki: SPKI.der(for: publicKey), signer: signer)
    }

    /// A CSR over the identity key `key`, signed by it.
    static func encode(commonName: String, key: any ClientIdentityKeyProvider) throws -> Data {
        try encode(commonName: commonName, publicKey: key.publicKey(), signer: { try key.sign($0) })
    }

    /// SHA-256 of the key's SubjectPublicKeyInfo, Base64 — the same form pins are written in.
    static func spkiSha256Base64(_ publicKey: SecKey) throws -> String {
        SPKI.pin(try SPKI.der(for: publicKey))
    }

    /// `-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----`, 64-character lines.
    static func toPem(_ certificate: X509Certificate) -> String {
        toPem(der: certificate.der)
    }

    static func toPem(der: Data) -> String {
        PEM.encode(der, label: "CERTIFICATE")
    }

    /// Parses PEM certificates, one per entry, in order. Throws on anything unreadable.
    static func parsePemChain(_ pems: [String]) throws -> [X509Certificate] {
        try pems.map { pem in
            let body = pem.split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
                .joined()
            guard !body.isEmpty else { throw PinVaultError.illegalArgument("Empty PEM certificate") }
            guard let der = Base64.decode(body) else { throw PinVaultError.illegalArgument("bad base-64") }
            do {
                return try X509Certificate(der: der)
            } catch {
                throw PinVaultError.certificate(message: "Could not parse certificate: \(error)", cause: error)
            }
        }
    }

    // MARK: DER

    private static func der(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    private static func length(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var bytes: [UInt8] = []
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
