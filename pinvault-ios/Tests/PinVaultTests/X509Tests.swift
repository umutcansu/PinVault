import Security
import XCTest
@testable import PinVault

final class X509Tests: XCTestCase {

    private func expected(_ name: String) throws -> [String: Any] {
        try XCTUnwrap(try Fixture.expected()[name])
    }

    func testTheLeafCertificateIsReadAsOpenSSLPrintsIt() throws {
        let der = try Fixture.data("leaf", "der")
        let cert = try X509Certificate(der: der)
        let values = try expected("leaf")
        XCTAssertEqual(cert.version, 3)
        XCTAssertEqual(Hex.encode(cert.serialNumber), values["serialHex"] as? String, "leading 0x00 kept")
        XCTAssertEqual(cert.notBefore.timeIntervalSince1970, values["notBefore"] as? TimeInterval)
        XCTAssertEqual(cert.notAfter.timeIntervalSince1970, values["notAfter"] as? TimeInterval)
        XCTAssertEqual(cert.subject.rfc2253, values["subject"] as? String)
        XCTAssertEqual(cert.issuer.rfc2253, values["issuer"] as? String)
        XCTAssertEqual(cert.subject.commonName, "mock-tls.sample")
        XCTAssertEqual(cert.issuer.commonName, "PinVault Test CA")
        XCTAssertEqual(cert.dnsNames, values["dnsNames"] as? [String])
        XCTAssertEqual(cert.ipAddressStrings, values["ipAddresses"] as? [String])
        XCTAssertEqual(cert.ipAddresses.map(\.count), [4, 16])
        XCTAssertEqual(cert.spkiPin, values["spkiPin"] as? String)
        XCTAssertEqual(cert.subjectPublicKeyInfo, try Fixture.data("leaf-spki", "der"))
        XCTAssertEqual(cert.basicConstraints?.isCA, false)
        XCTAssertFalse(cert.isCA)
        XCTAssertEqual(cert.keyUsage, [.digitalSignature, .keyEncipherment])
        XCTAssertEqual(cert.extendedKeyUsage, ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"])
        XCTAssertEqual(cert.signatureAlgorithmOID, X509OID.ecdsaWithSHA256)
        XCTAssertEqual(cert.tbsSignatureAlgorithmOID, X509OID.ecdsaWithSHA256)
        XCTAssertEqual(cert.extension(X509OID.basicConstraints)?.critical, true)
        XCTAssertEqual(cert.extension(X509OID.subjectAltName)?.critical, false)
        XCTAssertTrue(cert.isValid(at: cert.notBefore.addingTimeInterval(1)))
        XCTAssertFalse(cert.isValid(at: cert.notAfter.addingTimeInterval(1)))
        XCTAssertEqual(cert.der, der)
    }

    func testTheCACertificateUsesGeneralizedTimeAndIsACA() throws {
        let cert = try X509Certificate(der: try Fixture.data("ca", "der"))
        let values = try expected("ca")
        XCTAssertEqual(Hex.encode(cert.serialNumber), values["serialHex"] as? String)
        XCTAssertEqual(cert.notAfter.timeIntervalSince1970, values["notAfter"] as? TimeInterval, "2056: GeneralizedTime")
        XCTAssertEqual(cert.subject, cert.issuer, "self-signed")
        XCTAssertEqual(cert.subject.rfc2253, values["subject"] as? String)
        XCTAssertEqual(cert.basicConstraints?.isCA, true)
        XCTAssertEqual(cert.basicConstraints?.pathLength, 0)
        XCTAssertEqual(cert.keyUsage, [.keyCertSign, .cRLSign])
        XCTAssertTrue(cert.dnsNames.isEmpty)
        XCTAssertEqual(cert.spkiPin, values["spkiPin"] as? String)
    }

    func testAnRSACertificateWithNamesThatNeedEscaping() throws {
        let cert = try X509Certificate(der: try Fixture.data("rsa", "der"))
        let values = try expected("rsa")
        XCTAssertEqual(Hex.encode(cert.serialNumber), values["serialHex"] as? String)
        XCTAssertEqual(cert.subject.rfc2253, values["subject"] as? String)
        XCTAssertEqual(cert.subject.commonName, values["commonName"] as? String)
        XCTAssertEqual(cert.signatureAlgorithmOID, X509OID.sha256WithRSAEncryption)
        XCTAssertEqual(cert.spkiPin, values["spkiPin"] as? String)
        XCTAssertEqual(try SPKI.parse(cert.subjectPublicKeyInfo).algorithm, .rsa)
    }

    func testTheSignatureCoversTheTbsBytes() throws {
        let ca = try X509Certificate(der: try Fixture.data("ca", "der"))
        let leaf = try X509Certificate(der: try Fixture.data("leaf", "der"))
        let caKey = try SPKI.secKey(fromSPKI: ca.subjectPublicKeyInfo)
        var error: Unmanaged<CFError>?
        XCTAssertTrue(SecKeyVerifySignature(
            caKey, .ecdsaSignatureMessageX962SHA256, leaf.tbsCertificate as CFData, leaf.signature as CFData, &error
        ))
        XCTAssertTrue(SecKeyVerifySignature(
            caKey, .ecdsaSignatureMessageX962SHA256, ca.tbsCertificate as CFData, ca.signature as CFData, &error
        ), "self-signed")
        var tampered = leaf.tbsCertificate
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertFalse(SecKeyVerifySignature(
            caKey, .ecdsaSignatureMessageX962SHA256, tampered as CFData, leaf.signature as CFData, &error
        ))
    }

    func testSecCertificateAndPEMForms() throws {
        let der = try Fixture.data("leaf", "der")
        let fromDER = try X509Certificate(der: der)
        let sec = try XCTUnwrap(fromDER.secCertificate())
        XCTAssertEqual(try X509Certificate(certificate: sec), fromDER)
        XCTAssertEqual(SecCertificateCopySubjectSummary(sec) as String?, "mock-tls.sample")

        let leafPEM = try Fixture.text("leaf", "pem")
        let caPEM = try Fixture.text("ca", "pem")
        XCTAssertEqual(try X509Certificate(pem: leafPEM), fromDER)
        let chain = try X509Certificate.parsePEMChain([leafPEM + "\n" + caPEM])
        XCTAssertEqual(chain.map(\.subject.commonName), ["mock-tls.sample", "PinVault Test CA"])
        XCTAssertEqual(try X509Certificate.parsePEMChain([leafPEM, caPEM]).count, 2)
        XCTAssertThrowsError(try X509Certificate(pem: "not a certificate"))
    }

    func testMalformedCertificatesAreRefused() throws {
        let der = try Fixture.data("leaf", "der")
        XCTAssertThrowsError(try X509Certificate(der: der.prefix(der.count - 1)))
        XCTAssertThrowsError(try X509Certificate(der: DER.sequence([DER.null()])))
        XCTAssertThrowsError(try X509Certificate(der: Data()))
    }

    func testIPAddressText() {
        XCTAssertEqual(X509Certificate.ipString(Data([10, 0, 0, 1])), "10.0.0.1")
        XCTAssertEqual(X509Certificate.ipString(Data(hex: "20010db8000000000000000000000001")), "2001:db8::1")
        XCTAssertNil(X509Certificate.ipString(Data([1, 2, 3])))
    }
}
