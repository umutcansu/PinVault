import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// The store keys in the Keychain are wrapped by a Secure Enclave key
/// (``SecureEnclaveKeyWrap``): a Keychain dump reads ciphertext, the library
/// reads the key. Needs a Keychain (hosted by `Tests/VaultKeychainHost` on the
/// simulator; the SwiftPM runner skips) and, for the wrapped form, a Secure
/// Enclave (skipped where there is none).
final class StoreKeyWrapKeychainTests: XCTestCase {

    private static let service = KeychainPrefsKeySource.service
    private let vaultKey = "wrap-test-file"

    override func tearDown() {
        deleteItem(KeychainPrefsKeySource.aesAlias)
        deleteItem(KeychainPrefsKeySource.macAlias)
        VaultFileKeychainKeys(requireUnlockedDevice: { false }).remove(vaultKey)
        super.tearDown()
    }

    func testNewStoreKeysAreStoredWrappedAndReadBack() throws {
        try skipWithoutKeychain()
        deleteItem(KeychainPrefsKeySource.aesAlias)
        deleteItem(KeychainPrefsKeySource.macAlias)
        let first = try KeychainPrefsKeySource(requireUnlockedDevice: { false }).keys()
        let stored = try XCTUnwrap(item(KeychainPrefsKeySource.aesAlias))
        try skipWithoutSecureEnclave(stored)
        XCTAssertTrue(SecureEnclaveKeyWrap.isWrapped(stored), "the Keychain holds the wrapped form")
        XCTAssertNotEqual(stored, first.aes.withUnsafeBytes { Data($0) }, "not the key in the clear")

        // A fresh source (no cache) opens the same keys.
        let second = try KeychainPrefsKeySource(requireUnlockedDevice: { false }).keys()
        let cipher = KeyedPrefsCipher(source: StaticKeys(fixed: first))
        let sealed = try cipher.seal(Data("value".utf8), aad: Data("aad".utf8))
        XCTAssertEqual(try KeyedPrefsCipher(source: StaticKeys(fixed: second)).open(sealed, aad: Data("aad".utf8)), Data("value".utf8))
    }

    func testAKeyWrittenBeforeTheWrapIsKeptAndWrappedOnFirstRead() throws {
        try skipWithoutKeychain()
        deleteItem(KeychainPrefsKeySource.aesAlias)
        deleteItem(KeychainPrefsKeySource.macAlias)
        let legacyAes = Data((0..<32).map { UInt8($0) })
        let legacyMac = Data((0..<32).map { UInt8(255 - $0) })
        try addRaw(KeychainPrefsKeySource.aesAlias, legacyAes)
        try addRaw(KeychainPrefsKeySource.macAlias, legacyMac)

        let keys = try KeychainPrefsKeySource(requireUnlockedDevice: { false }).keys()
        XCTAssertEqual(keys.aes.withUnsafeBytes { Data($0) }, legacyAes, "the same key: stores sealed with it still open")
        XCTAssertEqual(keys.mac.withUnsafeBytes { Data($0) }, legacyMac)
        let stored = try XCTUnwrap(item(KeychainPrefsKeySource.aesAlias))
        try skipWithoutSecureEnclave(stored)
        XCTAssertTrue(SecureEnclaveKeyWrap.isWrapped(stored))
        let again = try KeychainPrefsKeySource(requireUnlockedDevice: { false }).keys()
        XCTAssertEqual(again.aes.withUnsafeBytes { Data($0) }, legacyAes)
    }

    func testAnItemThatIsNeitherAKeyNorAWrappedKeyIsReplaced() throws {
        try skipWithoutKeychain()
        deleteItem(KeychainPrefsKeySource.aesAlias)
        deleteItem(KeychainPrefsKeySource.macAlias)
        try addRaw(KeychainPrefsKeySource.aesAlias, SecureEnclaveKeyWrap.magic + Data(repeating: 7, count: 40))
        let keys = try KeychainPrefsKeySource(requireUnlockedDevice: { false }).keys()
        XCTAssertEqual(keys.aes.withUnsafeBytes { $0.count }, 32)
    }

    func testVaultFileKeysAreWrappedToo() throws {
        try skipWithoutKeychain()
        let keys = VaultFileKeychainKeys(requireUnlockedDevice: { false })
        keys.remove(vaultKey)
        let first = try keys.key(for: vaultKey)
        let stored = try XCTUnwrap(item(EncryptedFileStorageProvider.keyAliasPrefix + vaultKey))
        try skipWithoutSecureEnclave(stored)
        XCTAssertTrue(SecureEnclaveKeyWrap.isWrapped(stored))
        XCTAssertEqual(try keys.key(for: vaultKey), first)
    }

    // MARK: Helpers

    private struct StaticKeys: PrefsKeySource {
        let fixed: PrefsKeys
        func keys() throws -> PrefsKeys { fixed }
    }

    private func query(_ account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    private func item(_ account: String) throws -> Data? {
        var lookup = query(account)
        lookup[kSecReturnData] = true
        lookup[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainIdentities.failure("read \(account)", status) }
        return result as? Data
    }

    private func addRaw(_ account: String, _ data: Data) throws {
        var add = query(account)
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainIdentities.failure("add \(account)", status) }
    }

    private func deleteItem(_ account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }

    private func skipWithoutKeychain() throws {
        var probe = query("pinvault_wrap_probe")
        probe[kSecValueData] = Data([1])
        let status = SecItemAdd(probe as CFDictionary, nil)
        deleteItem("pinvault_wrap_probe")
        if status == errSecMissingEntitlement {
            throw XCTSkip("no Keychain entitlement in this test process (SwiftPM runner); runs hosted: Tests/VaultKeychainHost")
        }
    }

    private func skipWithoutSecureEnclave(_ stored: Data) throws {
        if stored.count == 32 && !SecureEnclaveKeyWrap.isWrapped(stored) {
            throw XCTSkip("no Secure Enclave here: keys stay in the clear form, as before 2.4.0")
        }
    }
}
