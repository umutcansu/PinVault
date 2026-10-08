import CryptoKit
import Security
import XCTest
@testable import PinVault

/// Port of VaultFileDecryptorTest: server-style envelopes round-trip.
final class VaultFileDecryptorTests: XCTestCase {

    private func newKeyPair() throws -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        return (privateKey, try XCTUnwrap(SecKeyCopyPublicKey(privateKey)))
    }

    /// `[4-byte wrappedKey length BE][wrappedKey][12-byte IV][AES-GCM ciphertext+tag]`, RSA-OAEP-SHA256 (MGF1-SHA256).
    private func buildEnvelope(_ plaintext: Data, _ publicKey: SecKey) throws -> Data {
        let sessionKey = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: sessionKey, nonce: nonce)
        var error: Unmanaged<CFError>?
        let rawKey = sessionKey.withUnsafeBytes { Data($0) }
        let wrapped = try XCTUnwrap(SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, rawKey as CFData, &error) as Data?)
        var envelope = Data()
        let length = UInt32(wrapped.count).bigEndian
        withUnsafeBytes(of: length) { envelope.append(contentsOf: $0) }
        envelope.append(wrapped)
        envelope.append(contentsOf: nonce)
        envelope.append(sealed.ciphertext)
        envelope.append(sealed.tag)
        return envelope
    }

    func testDecryptsAServerStyleEnvelope() throws {
        let keys = try newKeyPair()
        let plaintext = Data("hello decryptor world".utf8)
        XCTAssertEqual(try VaultFileDecryptor.decrypt(try buildEnvelope(plaintext, keys.publicKey), privateKey: keys.privateKey), plaintext)
    }

    func testEmptyPlaintextRoundTrips() throws {
        let keys = try newKeyPair()
        XCTAssertEqual(try VaultFileDecryptor.decrypt(try buildEnvelope(Data(), keys.publicKey), privateKey: keys.privateKey).count, 0)
    }

    func testAWrongPrivateKeyFails() throws {
        let a = try newKeyPair()
        let b = try newKeyPair()
        let envelope = try buildEnvelope(Data("secret".utf8), a.publicKey)
        XCTAssertThrowsError(try VaultFileDecryptor.decrypt(envelope, privateKey: b.privateKey)) { error in
            guard case PinVaultError.crypto = error else { return XCTFail("\(error)") }
        }
    }

    func testTamperedCiphertextIsCaughtByTheTag() throws {
        let keys = try newKeyPair()
        var envelope = try buildEnvelope(Data("original".utf8), keys.publicKey)
        envelope[envelope.count - 1] ^= 0x01
        XCTAssertThrowsError(try VaultFileDecryptor.decrypt(envelope, privateKey: keys.privateKey)) { error in
            guard case PinVaultError.crypto(let message, _) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "Tag mismatch")
        }
    }

    func testATruncatedEnvelopeIsRefusedBeforeDecryption() throws {
        let keys = try newKeyPair()
        XCTAssertThrowsError(try VaultFileDecryptor.decrypt(Data(count: 10), privateKey: keys.privateKey)) { error in
            guard case PinVaultError.illegalArgument(let message) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "Envelope too short (10 bytes)")
        }
    }

    func testAnAbsurdWrappedKeyLengthIsRefused() throws {
        let keys = try newKeyPair()
        var malformed = Data([0x00, 0x98, 0x96, 0x80])   // 10 000 000
        malformed.append(Data(count: 96))
        XCTAssertThrowsError(try VaultFileDecryptor.decrypt(malformed, privateKey: keys.privateKey)) { error in
            guard case PinVaultError.illegalArgument(let message) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "Implausible wrappedKey length: 10000000")
        }
        var truncated = Data([0x00, 0x00, 0x01, 0x00])   // 256, but only 100 bytes follow
        truncated.append(Data(count: 100))
        XCTAssertThrowsError(try VaultFileDecryptor.parse(truncated)) { error in
            guard case PinVaultError.illegalArgument(let message) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "Envelope truncated at wrappedKey/IV boundary")
        }
    }

    func testTheUnwrapClosureDoesTheRSAStepAndItsErrorsPassThrough() throws {
        let key = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(Data("user auth".utf8), using: key)
        var envelope = Data([0x00, 0x00, 0x00, 0x40]) + Data(repeating: 7, count: 64)
        envelope.append(contentsOf: sealed.nonce)
        envelope.append(sealed.ciphertext + sealed.tag)
        let opened = try VaultFileDecryptor.decrypt(envelope) { wrapped in
            XCTAssertEqual(wrapped, Data(repeating: 7, count: 64))
            return key.withUnsafeBytes { Data($0) }
        }
        XCTAssertEqual(opened, Data("user auth".utf8))
        struct Cancelled: Error {}
        XCTAssertThrowsError(try VaultFileDecryptor.decrypt(envelope) { _ in throw Cancelled() }) { XCTAssertTrue($0 is Cancelled) }
    }
}
