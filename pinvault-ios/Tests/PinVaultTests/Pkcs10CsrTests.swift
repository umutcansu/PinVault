import Security
import XCTest
@testable import PinVault

/// The hand-rolled PKCS#10 encoder (Kotlin `Pkcs10CsrTest`, which parses with
/// BouncyCastle): here the request is parsed with the library's DER reader and
/// its signature checked with Security; the demo server's `IosCsrInteropTest`
/// parses `Fixtures/enrollment/ios-device.csr` with BouncyCastle.
final class Pkcs10CsrTests: XCTestCase {

    private let keys = TestKeyPair()

    private func encode(_ cn: String, signer: TestKeyPair? = nil) throws -> Data {
        let signing = signer ?? keys
        return try Pkcs10Csr.encode(commonName: cn, publicKey: keys.publicKey) { signing.sign($0) }
    }

    func testTheRequestParsesAndItsSignatureVerifies() throws {
        let csr = try ParsedCsr(encode("device-42"))
        XCTAssertTrue(csr.signatureValid)
        XCTAssertEqual(csr.commonName, "device-42")
        XCTAssertEqual(csr.spki, keys.spki)
        XCTAssertEqual(csr.signatureAlgorithm, "1.2.840.10045.4.3.2")
        XCTAssertTrue(csr.attributesEmpty)
    }

    func testTheBytesAreTheFixedShapeTheAndroidEncoderWrites() throws {
        // A fixed "signature": everything else is determined by CN and key.
        let signature = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        let der = try Pkcs10Csr.encode(commonName: "device-42", spki: keys.spki) { _ in signature }
        let info = DER.sequence([DER.integer(0), ClientCertTestCA.name("device-42"), keys.spki, Data([0xA0, 0x00])])
        let algorithm = DER.sequence([try DER.objectIdentifier("1.2.840.10045.4.3.2")])
        XCTAssertEqual(der, DER.sequence([info, algorithm, DER.bitString(signature)]))
    }

    func testTheSignerSignsExactlyTheRequestInfo() throws {
        var signed: Data?
        let der = try Pkcs10Csr.encode(commonName: "device-42", spki: keys.spki) { tbs in
            signed = tbs
            return keys.sign(tbs)
        }
        let info = try DER.parse(der).children()[0].encoded
        XCTAssertEqual(signed, info)
    }

    func testACommonNameLongerThan127BytesUsesLongFormLengths() throws {
        let cn = String(repeating: "x", count: 300)
        let csr = try ParsedCsr(encode(cn))
        XCTAssertTrue(csr.signatureValid)
        XCTAssertEqual(csr.commonName, cn)
    }

    func testANonAsciiCommonNameSurvivesAsUtf8() throws {
        let csr = try ParsedCsr(encode("cihaz-ğüş"))
        XCTAssertTrue(csr.signatureValid)
        XCTAssertEqual(csr.commonName, "cihaz-ğüş")
    }

    func testTamperingWithTheRequestInfoInvalidatesTheSignature() throws {
        var der = try encode("device-42")
        let needle = Data("device-42".utf8)
        let index = der.range(of: needle)!.lowerBound + 8
        der[index] = der[index] &+ 1
        XCTAssertFalse(try ParsedCsr(der).signatureValid)
    }

    func testASignatureFromADifferentKeyDoesNotVerify() throws {
        XCTAssertFalse(try ParsedCsr(encode("device-42", signer: TestKeyPair())).signatureValid)
    }

    func testABlankCommonNameIsRefused() {
        guard case .illegalArgument? = assertThrowsPinVault({ _ = try encode("  ") }) else {
            return XCTFail("expected IllegalArgumentException")
        }
    }

    func testTheSpkiHashMatchesThePinFormOfTheSameKey() throws {
        XCTAssertEqual(try Pkcs10Csr.spkiSha256Base64(keys.publicKey), Hashing.sha256Base64(keys.spki))
    }

    func testPemRoundTripsACertificateChainInOrder() throws {
        let a = ClientCertTestCA(cn: "leaf").certificate
        let b = ClientCertTestCA(cn: "issuer").certificate
        let pems = [Pkcs10Csr.toPem(a), Pkcs10Csr.toPem(b)]
        XCTAssertTrue(pems[0].hasPrefix("-----BEGIN CERTIFICATE-----\n"))
        XCTAssertTrue(pems[0].hasSuffix("\n-----END CERTIFICATE-----"))
        XCTAssertEqual(try Pkcs10Csr.parsePemChain(pems).map(\.der), [a.der, b.der])
    }

    func testGarbagePemIsRejected() {
        XCTAssertThrowsError(try Pkcs10Csr.parsePemChain(["-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----"]))
        XCTAssertThrowsError(try Pkcs10Csr.parsePemChain(["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"]))
        XCTAssertThrowsError(try Pkcs10Csr.parsePemChain(["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"]))
    }

    // MARK: The request the server-side interop test parses

    /// `Fixtures/enrollment/ios-device.csr` was made by this encoder over a
    /// Secure Enclave key (`IdentityKeychainTests.testWriteTheCsrFixture`);
    /// `ios-device.json` holds what the server must read from it.
    func testTheCommittedSecureEnclaveCsrParsesAndVerifies() throws {
        guard let csrURL = Bundle.module.url(forResource: "ios-device", withExtension: "csr", subdirectory: "Fixtures/enrollment"),
              let jsonURL = Bundle.module.url(forResource: "ios-device", withExtension: "json", subdirectory: "Fixtures/enrollment") else {
            return XCTFail("missing Fixtures/enrollment/ios-device.csr / .json")
        }
        let der = try Data(contentsOf: csrURL)
        let expected = try JSONSerialization.jsonObject(with: Data(contentsOf: jsonURL)) as! [String: Any]
        let csr = try ParsedCsr(der)
        XCTAssertTrue(csr.signatureValid)
        XCTAssertEqual(csr.commonName, expected["commonName"] as? String)
        XCTAssertEqual(SPKI.pin(csr.spki), expected["spkiSha256"] as? String)
        XCTAssertEqual(try VerificationCode.of(spki: csr.spki), expected["verificationCode"] as? String)
        XCTAssertEqual(try SPKI.parse(csr.spki).algorithm, .ec(curveOID: KeyAlgorithmOID.prime256v1))
        let commonName = try XCTUnwrap(expected["commonName"] as? String)
        let requestHash = IntegrityRequestHash.of(deviceId: commonName, csrDer: der)
        XCTAssertEqual(requestHash, expected["integrityRequestHash"] as? String)
        XCTAssertEqual(
            EnrollmentAppAttestation.clientDataHash(requestHash: requestHash).base64EncodedString(),
            expected["appAttestClientDataHash"] as? String
        )
    }
}
