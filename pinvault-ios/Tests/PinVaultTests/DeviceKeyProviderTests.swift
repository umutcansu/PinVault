import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of DeviceKeyProviderTest, for the software provider everywhere and the
/// Keychain provider where the test process may use the Keychain: hosted by
/// an app on the simulator (`Tests/VaultKeychainHost`); the SwiftPM runner has
/// no Keychain entitlement (macOS and simulator alike) and skips.
///
/// End to end: generate the key pair, export the PEM, have "the server" wrap
/// with the exported PEM (RSA-OAEP SHA-256, MGF1-SHA256), decrypt with the
/// provider's private key.
final class DeviceKeyProviderTests: XCTestCase {

    // MARK: Software provider

    func testEnsureKeyPairIsIdempotent() throws {
        let provider = DeviceKeys.software(alias: "test-idempotent")
        try provider.ensureKeyPair()
        let first = try provider.getPublicKeyPem()
        try provider.ensureKeyPair()
        XCTAssertEqual(try provider.getPublicKeyPem(), first)
    }

    func testClearRemovesTheKeyAndTheNextEnsureKeyPairMakesANewOne() throws {
        let provider = DeviceKeys.software(alias: "test-clear")
        try provider.ensureKeyPair()
        let first = try provider.getPublicKeyPem()
        try provider.clear()
        try provider.ensureKeyPair()
        XCTAssertNotEqual(try provider.getPublicKeyPem(), first, "a fresh key pair has a different PEM")
    }

    func testThePublicKeyAndThePrivateKeyNeedEnsureKeyPairFirst() {
        let provider = DeviceKeys.software(alias: "test-not-ready")
        XCTAssertThrowsError(try provider.getPublicKeyPem())
        XCTAssertThrowsError(try provider.getPrivateKey())
    }

    func testThePemIsAnX509SubjectPublicKeyInfoOfAnRSA2048Key() throws {
        let provider = DeviceKeys.software(alias: "test-pem-format")
        try provider.ensureKeyPair()
        try assertRegistrablePem(provider.getPublicKeyPem())
    }

    func testEndToEndRoundTripEncryptWithTheExportedPemDecryptWithTheProvidersKey() throws {
        try assertRoundTrip(DeviceKeys.software(alias: "test-e2e"))
    }

    func testTwoProvidersHaveIndependentKeyPairs() throws {
        let a = DeviceKeys.software(alias: "alias-a")
        let b = DeviceKeys.software(alias: "alias-b")
        try a.ensureKeyPair()
        try b.ensureKeyPair()
        XCTAssertNotEqual(try a.getPublicKeyPem(), try b.getPublicKeyPem())
    }

    func testTheNamesOfTheContract() {
        XCTAssertEqual(DeviceKeys.defaultAlias, "pinvault_vault_e2e_rsa")
        XCTAssertEqual(DeviceKeys.registrationAlgorithm, "RSA-OAEP-SHA256-MGF1-SHA256")
    }

    func testTheLevelCheckRefusesASoftwareKeyWhenHardwareIsRequired() {
        var cleaned = false
        XCTAssertThrowsError(try DeviceKeyLevelCheck.check("Device RSA key", level: .software, required: true) { cleaned = true }) { error in
            guard case PinVaultError.hardwareBackedKeyRequired(let kind, let level, _) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(kind, "Device RSA key")
            XCTAssertEqual(level, .software)
        }
        XCTAssertTrue(cleaned, "the refused key is deleted")
        XCTAssertEqual(try DeviceKeyLevelCheck.check("Device RSA key", level: .software, required: false), .software)
        XCTAssertEqual(try DeviceKeyLevelCheck.check("Device RSA key", level: .secureEnclave, required: true), .secureEnclave)
    }

    // MARK: Keychain provider

    /// A Keychain provider under a tag of this test only, cleaned up after it; skips where the Keychain refuses the process.
    private func keychainProvider(_ name: String = #function, requireHardwareBacked: Bool = false) throws -> any DeviceKeyProvider {
        let alias = "pinvault_test_\(name.filter(\.isLetter))"
        let provider = DeviceKeys.keychain(alias: alias, requireHardwareBacked: requireHardwareBacked)
        try? provider.clear()
        addTeardownBlock { try? provider.clear() }
        try skipWithoutKeychain(provider)
        return provider
    }

    func testTheKeychainKeyIsPermanentAndIdempotent() throws {
        let provider = try keychainProvider()
        let first = try provider.getPublicKeyPem()
        try provider.ensureKeyPair()
        XCTAssertEqual(try provider.getPublicKeyPem(), first)
        // A second provider over the same tag finds the same key (it lives in the Keychain, not in the object).
        let again = DeviceKeys.keychain(alias: (provider as! KeychainDeviceKeyProvider).alias)
        XCTAssertEqual(try again.getPublicKeyPem(), first)
        try assertRegistrablePem(first)
    }

    func testTheKeychainKeyRoundTripsAServerEnvelope() throws {
        try assertRoundTrip(try keychainProvider())
    }

    func testClearDeletesTheKeychainKey() throws {
        let provider = try keychainProvider()
        let first = try provider.getPublicKeyPem()
        try provider.clear()
        XCTAssertThrowsError(try provider.getPrivateKey())
        try provider.clear()   // nothing there is not an error
        try provider.ensureKeyPair()
        XCTAssertNotEqual(try provider.getPublicKeyPem(), first)
    }

    func testTheKeychainKeyIsThisDeviceOnlyAndNotSynchronised() throws {
        let provider = try keychainProvider()
        var query = DeviceKeyKeychain.query(tag: (provider as! KeychainDeviceKeyProvider).alias)
        query[kSecReturnAttributes] = true
        var item: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &item), errSecSuccess)
        let attributes = try XCTUnwrap(item as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
    }

    func testRequireHardwareBackedKeysRefusesTheKeychainRSAKey() throws {
        let alias = "pinvault_test_hardware_refused"
        let provider = DeviceKeys.keychain(alias: alias, requireHardwareBacked: true)
        try? provider.clear()
        addTeardownBlock { try? provider.clear() }
        do {
            try provider.ensureKeyPair()
            XCTFail("the Secure Enclave holds no RSA key: refused")
        } catch PinVaultError.hardwareBackedKeyRequired(let kind, let level, _) {
            XCTAssertEqual(kind, "Device RSA key")
            XCTAssertEqual(level, .software)
            XCTAssertNil(try DeviceKeyKeychain.privateKey(tag: alias), "the refused key is deleted")
        } catch let error as DeviceKeyKeychainError where error.status == errSecMissingEntitlement {
            throw XCTSkip("no Keychain entitlement in this test process (SwiftPM runner); runs hosted: Tests/VaultKeychainHost")
        }
    }

    // MARK: Helpers

    private func skipWithoutKeychain(_ provider: any DeviceKeyProvider) throws {
        do {
            try provider.ensureKeyPair()
        } catch let error as DeviceKeyKeychainError where error.status == errSecMissingEntitlement {
            throw XCTSkip("no Keychain entitlement in this test process (SwiftPM runner); runs hosted: Tests/VaultKeychainHost")
        }
    }

    private func assertRegistrablePem(_ pem: String, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertTrue(pem.hasPrefix("-----BEGIN PUBLIC KEY-----\n"), file: file, line: line)
        XCTAssertTrue(pem.hasSuffix("\n-----END PUBLIC KEY-----"), file: file, line: line)
        for bodyLine in pem.split(separator: "\n") where !bodyLine.hasPrefix("-----") {
            XCTAssertLessThanOrEqual(bodyLine.count, 64, "line too long: \(bodyLine)", file: file, line: line)
        }
        let der = try XCTUnwrap(PEM.decode(pem, label: "PUBLIC KEY"), file: file, line: line)
        let parsed = try SPKI.parse(der)
        XCTAssertEqual(parsed.algorithm, .rsa, file: file, line: line)
        XCTAssertEqual(try SPKI.rsaModulusBits(pkcs1: parsed.keyBytes), 2048, file: file, line: line)
    }

    /// The server side, from the PEM alone: wrap a session key, seal content; the provider opens it.
    private func assertRoundTrip(_ provider: any DeviceKeyProvider, file: StaticString = #filePath, line: UInt = #line) throws {
        try provider.ensureKeyPair()
        let serverSideKey = try SPKI.secKey(fromSPKI: XCTUnwrap(PEM.decode(provider.getPublicKeyPem(), label: "PUBLIC KEY")))
        let plaintext = Data("end-to-end-round-trip".utf8)
        let envelope = try SoftwareUserAuthKeys.serverEnvelope(plaintext, serverSideKey)
        XCTAssertEqual(try VaultFileDecryptor.decrypt(envelope, privateKey: provider.getPrivateKey()), plaintext, file: file, line: line)
    }
}
