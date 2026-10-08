import Foundation
import Security
import XCTest
@testable import PinVault

/// `P12Rewrap`: a bundle sent with a one-off password comes back under the block's password.
final class P12RewrapTests: XCTestCase {

    private func identity(_ p12: Data, _ password: String) -> ClientIdentity? {
        try? ClientIdentity.fromPKCS12(p12, password: password)
    }

    func testABundleIsRewrappedToTheNewPasswordWithTheSameKeyAndChain() throws {
        let original = TLSFixture.p12("client-a")
        let rewrapped = try P12Rewrap.rewrap(original, from: "changeit", to: "block-pass")

        XCTAssertNil(identity(rewrapped, "changeit"))
        let opened = try XCTUnwrap(identity(rewrapped, "block-pass"))
        let source = try XCTUnwrap(identity(original, "changeit"))
        XCTAssertEqual(opened.leaf?.der, source.leaf?.der)
        XCTAssertEqual(opened.chain.count, source.chain.count)

        var key: SecKey?
        SecIdentityCopyPrivateKey(opened.identity, &key)
        var sourceKey: SecKey?
        SecIdentityCopyPrivateKey(source.identity, &sourceKey)
        XCTAssertEqual(
            SecKeyCopyExternalRepresentation(try XCTUnwrap(key), nil) as Data?,
            SecKeyCopyExternalRepresentation(try XCTUnwrap(sourceKey), nil) as Data?
        )
    }

    func testAWrongSourcePasswordIsRefused() {
        XCTAssertThrowsError(try P12Rewrap.rewrap(TLSFixture.p12("client-a"), from: "wrong", to: "x"))
    }

    func testTheRewrappedBundleSurvivesASecondRewrap() throws {
        let once = try P12Rewrap.rewrap(TLSFixture.p12("client-b"), from: "changeit", to: "one-off-7Qx")
        let twice = try P12Rewrap.rewrap(once, from: "one-off-7Qx", to: "changeit")
        XCTAssertEqual(identity(twice, "changeit")?.leaf?.subject.commonName, "client-b")
    }

    func testAnRSAKeyBecomesAPKCS8PrivateKeyInfo() throws {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
        let key = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        let info = try P12Rewrap.privateKeyInfo(key)
        let parts = try DER.parse(info).expect(ASN1Tag.sequence).children()
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(try parts[1].children()[0].objectIdentifier(), "1.2.840.113549.1.1.1")
        XCTAssertEqual(try parts[2].octetString(), SecKeyCopyExternalRepresentation(key, nil) as Data?)
    }
}
