import CryptoKit
import Foundation
import XCTest
@testable import PinVault

/// Port of ConfigSignatureVerifierTest (D.25: a tampered config is refused),
/// plus the key helpers and Android's Base64 decoding.
final class ConfigSignatureVerifierTests: XCTestCase {

    func testValidSignatureVerifyReturnsTrue() {
        let key = TestSigner()
        let payload = #"{"version":1,"pins":[]}"#
        XCTAssertTrue(ConfigSignatureVerifier.verify(payload: payload, signature: key.sign(payload), publicKeyBase64: key.pub))
    }

    func testTamperedPayloadVerifyReturnsFalse() {
        let key = TestSigner()
        let signature = key.sign(#"{"version":1,"pins":[]}"#)
        XCTAssertFalse(ConfigSignatureVerifier.verify(payload: #"{"version":999,"pins":[]}"#, signature: signature, publicKeyBase64: key.pub))
    }

    func testTamperedSignatureVerifyReturnsFalse() throws {
        let key = TestSigner()
        let payload = #"{"version":1,"pins":[]}"#
        var bytes = try XCTUnwrap(Data(base64Encoded: key.sign(payload)))
        bytes[0] ^= 0xFF
        XCTAssertFalse(ConfigSignatureVerifier.verify(payload: payload, signature: bytes.base64EncodedString(), publicKeyBase64: key.pub))
    }

    func testWrongPublicKeyVerifyReturnsFalse() {
        let payload = #"{"version":1}"#
        XCTAssertFalse(ConfigSignatureVerifier.verify(payload: payload, signature: TestSigner().sign(payload), publicKeyBase64: TestSigner().pub))
    }

    func testInvalidBase64KeyVerifyReturnsFalse() {
        XCTAssertFalse(ConfigSignatureVerifier.verify(payload: "payload", signature: "sig", publicKeyBase64: "not-valid-base64!!!"))
    }

    func testEmptyPayloadStillVerifiable() {
        let key = TestSigner()
        XCTAssertTrue(ConfigSignatureVerifier.verify(payload: "", signature: key.sign(""), publicKeyBase64: key.pub))
    }

    // ── iOS additions ───────────────────────────────────────────────────

    func testTheSignatureCoversTheExactUTF8Bytes() {
        let key = TestSigner()
        let composed = "{\"n\":\"\u{E9}\"}"
        let decomposed = "{\"n\":\"e\u{301}\"}"
        XCTAssertEqual(composed, decomposed, "Swift calls them equal")
        XCTAssertTrue(ConfigSignatureVerifier.verify(payload: composed, signature: key.sign(composed), publicKeyBase64: key.pub))
        XCTAssertFalse(
            ConfigSignatureVerifier.verify(payload: decomposed, signature: key.sign(composed), publicKeyBase64: key.pub),
            "but their bytes differ, and the bytes are what is signed"
        )
    }

    func testP384KeysVerifySHA256SignaturesAsTheJDKDoes() throws {
        let key = P384.Signing.PrivateKey()
        let payload = "p384"
        let signature = try key.signature(for: SHA256.hash(data: Data(payload.utf8))).derRepresentation.base64EncodedString()
        let pub = key.publicKey.derRepresentation.base64EncodedString()
        XCTAssertTrue(ConfigSignatureVerifier.verify(payload: payload, signature: signature, publicKeyBase64: pub))
        XCTAssertEqual(ConfigSignatureVerifier.canonicalKey(pub), pub)
    }

    func testRawRSAAndCompressedKeysAreNotECKeys() throws {
        let rsa = try Fixture.data("rsa-spki", "der").base64EncodedString()
        XCTAssertNil(ConfigSignatureVerifier.canonicalKey(rsa))
        let compressed = try SPKI.ec(x963Point: P256.Signing.PrivateKey().publicKey.compressedRepresentation, curveOID: KeyAlgorithmOID.prime256v1)
        XCTAssertNil(ConfigSignatureVerifier.canonicalKey(compressed.base64EncodedString()))
    }

    func testCanonicalKeyAcceptsPEMAndLineBreaksAndKeyIdIsTheSPKIPin() {
        let key = TestSigner()
        XCTAssertEqual(ConfigSignatureVerifier.canonicalKey(key.pem), key.pub)
        XCTAssertEqual(ConfigSignatureVerifier.canonicalKey(key.pub + "\n"), key.pub)
        XCTAssertEqual(ConfigSignatureVerifier.canonicalKey("  " + key.pub.prefix(20) + "\r\n" + key.pub.dropFirst(20)), key.pub)
        XCTAssertNil(ConfigSignatureVerifier.canonicalKey("not-a-key"))
        XCTAssertEqual(ConfigSignatureVerifier.keyIdOf(key.pub), key.id)
        XCTAssertEqual(ConfigSignatureVerifier.keyIdOf(key.pub)?.count, 44)
    }

    func testVaultCanonicalStrings() {
        let content = Data("bytes".utf8)
        let digest = Hashing.sha256Hex(content)
        XCTAssertEqual(ConfigSignatureVerifier.vaultCanonical(key: "f", version: 4, plaintext: content), "pinvault-vault-file:v1:f:4:\(digest)")
        XCTAssertEqual(
            ConfigSignatureVerifier.vaultCanonicalV2(configApiId: "api", key: "f", version: 4, plaintext: content),
            "pinvault-vault-file:v2:api:f:4:\(digest)"
        )
        let key = TestSigner()
        let signature = key.sign(ConfigSignatureVerifier.vaultCanonical(key: "f", version: 4, plaintext: content))
        XCTAssertTrue(ConfigSignatureVerifier.verifyVaultFile(key: "f", version: 4, plaintext: content, signature: signature, publicKeyBase64: key.pub))
        XCTAssertFalse(ConfigSignatureVerifier.verifyVaultFile(key: "f", version: 5, plaintext: content, signature: signature, publicKeyBase64: key.pub))
    }

    func testAndroidBase64SkipsForeignCharactersAndAcceptsMissingPadding() {
        XCTAssertEqual(AndroidBase64.decode("aGVsbG8="), Data("hello".utf8))
        XCTAssertEqual(AndroidBase64.decode("aGVsbG8"), Data("hello".utf8), "padding optional")
        XCTAssertEqual(AndroidBase64.decode("aGV s\nbG8=\n"), Data("hello".utf8), "whitespace skipped")
        XCTAssertEqual(AndroidBase64.decode("a-GVs_bG8!"), Data("hello".utf8), "characters outside the alphabet skipped")
        XCTAssertEqual(AndroidBase64.decode(""), Data())
        XCTAssertNil(AndroidBase64.decode("a"), "one character is not a byte")
        XCTAssertNil(AndroidBase64.decode("=abc"), "padding first")
        XCTAssertNil(AndroidBase64.decode("aGVsbG8=x"), "data after the padding")
        XCTAssertNil(AndroidBase64.decode("aGVsbA="), "one padding character where two are due")
        XCTAssertEqual(AndroidBase64.decode("aGVsbA=="), Data("hell".utf8))
    }
}
