import CryptoKit
import Security
import XCTest
@testable import PinVault

final class SPKITests: XCTestCase {

    /// `openssl pkey -pubin -inform DER -in leaf-spki.der -outform DER | openssl dgst -sha256 -binary | base64`
    private let leafPin = "lGuEndHp4adDMhXI+fpPwCFvgsXWtocXcVKcy+3QYoI="

    func testThePinOfAKnownSPKIIsWhatOpenSSLComputes() throws {
        let spki = try Fixture.data("leaf-spki", "der")
        XCTAssertEqual(SPKI.pin(spki), leafPin)
        XCTAssertEqual(SPKI.pin(spki).count, 44)
        for name in ["ca", "rsa"] {
            let expected = try Fixture.expected()[name]?["spkiPin"] as? String
            XCTAssertEqual(SPKI.pin(try Fixture.data("\(name)-spki", "der")), expected, name)
        }
    }

    func testAnX963PointBecomesTheSPKIOpenSSLWrites() throws {
        let point = try Fixture.data("leaf-point", "bin")
        let spki = try SPKI.ecP256(x963Point: point)
        XCTAssertEqual(spki, try Fixture.data("leaf-spki", "der"))
        XCTAssertEqual(spki.prefix(26), Data(hex: "3059301306072a8648ce3d020106082a8648ce3d030107034200"))
        let parsed = try SPKI.parse(spki)
        XCTAssertEqual(parsed.algorithm, .ec(curveOID: KeyAlgorithmOID.prime256v1))
        XCTAssertEqual(parsed.keyBytes, point)
        XCTAssertThrowsError(try SPKI.ecP256(x963Point: point.dropFirst()))
        XCTAssertThrowsError(try SPKI.ecP256(x963Point: Data([0x02]) + point.dropFirst()))
    }

    func testAPKCS1KeyBecomesTheRSASPKI() throws {
        let pkcs1 = try Fixture.data("rsa-pkcs1", "der")
        let spki = try SPKI.rsa(pkcs1: pkcs1)
        XCTAssertEqual(spki, try Fixture.data("rsa-spki", "der"))
        let parsed = try SPKI.parse(spki)
        XCTAssertEqual(parsed.algorithm, .rsa)
        XCTAssertEqual(parsed.keyBytes, pkcs1)
        XCTAssertEqual(try SPKI.rsaModulusBits(pkcs1: pkcs1), 2048)
    }

    func testSecKeysRoundTripThroughTheSPKI() throws {
        for name in ["leaf-spki", "ca-spki", "rsa-spki"] {
            let spki = try Fixture.data(name, "der")
            let key = try SPKI.secKey(fromSPKI: spki)
            XCTAssertEqual(try SPKI.der(for: key), spki, name)
        }
        XCTAssertThrowsError(try SPKI.secKey(fromSPKI: Data(hex: "3000")))
    }

    func testAGeneratedKeyMatchesCryptoKitsEncoding() throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ]
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        // A private key yields its public half's SPKI.
        let spki = try SPKI.der(for: privateKey)
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let x963 = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
        XCTAssertEqual(spki, try P256.Signing.PublicKey(x963Representation: x963).derRepresentation)
        XCTAssertTrue(try SPKI.pem(for: publicKey).hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
    }
}
