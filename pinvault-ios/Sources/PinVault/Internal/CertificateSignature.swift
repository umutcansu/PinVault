import Foundation
import Security

/// Checks a certificate's signature against an issuer's key (Java
/// `X509Certificate.verify(PublicKey)`), for the issued-chain checks of
/// enrollment and renewal.
enum CertificateSignature {

    /// Signature algorithms by OID.
    private static let algorithms: [String: SecKeyAlgorithm] = [
        "1.2.840.10045.4.3.2": .ecdsaSignatureMessageX962SHA256,
        "1.2.840.10045.4.3.3": .ecdsaSignatureMessageX962SHA384,
        "1.2.840.10045.4.3.4": .ecdsaSignatureMessageX962SHA512,
        "1.2.840.113549.1.1.11": .rsaSignatureMessagePKCS1v15SHA256,
        "1.2.840.113549.1.1.12": .rsaSignatureMessagePKCS1v15SHA384,
        "1.2.840.113549.1.1.13": .rsaSignatureMessagePKCS1v15SHA512,
        "1.2.840.113549.1.1.5": .rsaSignatureMessagePKCS1v15SHA1,
    ]

    /// Throws unless `certificate` is signed by the key whose SubjectPublicKeyInfo is `issuerSPKI`.
    static func verify(_ certificate: X509Certificate, issuerSPKI: Data) throws {
        guard certificate.signatureAlgorithmOID == certificate.tbsSignatureAlgorithmOID,
              let algorithm = algorithms[certificate.signatureAlgorithmOID] else {
            throw PinVaultError.crypto(message: "Unsupported signature algorithm \(certificate.signatureAlgorithmOID)")
        }
        let key = try SPKI.secKey(fromSPKI: issuerSPKI)
        var error: Unmanaged<CFError>?
        let valid = SecKeyVerifySignature(
            key, algorithm, certificate.tbsCertificate as CFData, certificate.signature as CFData, &error
        )
        error?.release()
        if !valid { throw PinVaultError.crypto(message: "Signature does not match.") }
    }

    /// ``verify(_:issuerSPKI:)`` as a Bool.
    static func isSigned(_ certificate: X509Certificate, by issuerSPKI: Data) -> Bool {
        (try? verify(certificate, issuerSPKI: issuerSPKI)) != nil
    }
}
