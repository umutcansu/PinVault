import Foundation
import Security
import XCTest
@testable import PinVault

/// What opening a PKCS12 does to the Keychain (MASVS audit finding 1, 2026-10-07).
///
/// The audit suspected that on iOS 16–17, where `kSecImportToMemoryOnly` does
/// not exist, `SecPKCS12Import` persists the identity in the Keychain with the
/// default accessibility (not ThisDeviceOnly) and refuses a second import with
/// errSecDuplicateItem. It does not: Apple's header says the flag "is already
/// default behavior on iOS", and the open-source implementation adds items to
/// the Keychain only when the caller passes `kSecUseDataProtectionKeychain`
/// (macOS 14+), which the library never does. These tests pin that down on
/// every runtime CI covers: the library's ``ClientIdentity/fromPKCS12(_:password:)``
/// (the flag on iOS 18+) and the bare call the library makes on iOS 16–17
/// (no flag) both leave nothing behind, open the same bundle again and again,
/// and hand back a key that signs.
///
/// Runs hosted by an app (`Tests/IdentityKeychainHost`): the SwiftPM runner has
/// no Keychain entitlement and skips.
final class PKCS12ImportKeychainTests: XCTestCase {

    private let password = "changeit"

    override func setUpWithError() throws {
        try XCTSkipUnless(keychainAvailable(), "no Keychain in this process (unsigned xctest): run IdentityKeychainHost/run-tests.sh")
    }

    func testTheLibraryImportLeavesNothingInTheKeychainAndOpensTheBundleAgain() throws {
        for name in ["client-a", "client-b"] {
            let first = try ClientIdentity.fromPKCS12(TLSFixture.p12(name), password: password)
            let second = try ClientIdentity.fromPKCS12(TLSFixture.p12(name), password: password)
            assertNothingPersisted(for: first, name)
            XCTAssertEqual(first.leaf?.subject.commonName, name)
            XCTAssertEqual(second.leaf?.subject.commonName, name, "the same bundle opens again")
            assertKeySigns(first, name)
        }
        let rsa = try ClientIdentity.fromPKCS12(rsaTestP12, password: password)
        assertNothingPersisted(for: rsa, "rsa")
        assertKeySigns(rsa, "rsa")
    }

    /// The call as the library makes it on iOS 16–17: no `kSecImportToMemoryOnly`.
    func testTheBareImportWithoutTheMemoryOnlyFlagBehavesTheSame() throws {
        let p12 = TLSFixture.p12("client-a")
        let options = [kSecImportExportPassphrase as String: password] as CFDictionary
        var items: CFArray?
        XCTAssertEqual(SecPKCS12Import(p12 as CFData, options, &items), errSecSuccess)
        let entry = try XCTUnwrap((items as? [[String: Any]])?.first)
        let identity = try Self.identityFromImport(entry)
        assertNothingPersisted(for: identity, "bare")

        var again: CFArray?
        XCTAssertEqual(SecPKCS12Import(p12 as CFData, options, &again), errSecSuccess, "no errSecDuplicateItem on a second import")
        XCTAssertEqual((again as? [[String: Any]])?.count, 1)
        assertKeySigns(identity, "bare")
    }

    // MARK: Helpers

    /// Nothing of `identity` is in the data-protection Keychain: no identity
    /// pairing its leaf, no certificate with its bytes, no key with its
    /// public-key hash. Only items the library stores on purpose (under its
    /// own tags) may exist, and these fixtures are never imported that way here.
    private func assertNothingPersisted(for identity: ClientIdentity, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        var leafRef: SecCertificate?
        SecIdentityCopyCertificate(identity.identity, &leafRef)
        guard let leafRef else { return XCTFail("\(name): no leaf", file: file, line: line) }
        let leaf = SecCertificateCopyData(leafRef) as Data
        XCTAssertNil(try? KeychainIdentities.identity(for: leafRef), "\(name): no persisted identity for the leaf", file: file, line: line)

        var certificates = KeychainIdentities.base(kSecClassCertificate)
        certificates[kSecMatchLimit] = kSecMatchLimitAll
        certificates[kSecReturnRef] = true
        var found: CFTypeRef?
        let status = SecItemCopyMatching(certificates as CFDictionary, &found)
        let stored = status == errSecSuccess ? ((found as? [SecCertificate]) ?? []) : []
        XCTAssertFalse(stored.contains { (SecCertificateCopyData($0) as Data) == leaf }, "\(name): the leaf is not stored", file: file, line: line)

        var keyRef: SecKey?
        SecIdentityCopyPrivateKey(identity.identity, &keyRef)
        guard let keyRef, let label = (SecKeyCopyAttributes(keyRef) as? [String: Any])?[kSecAttrApplicationLabel as String] as? Data else {
            return XCTFail("\(name): the private key has no application label", file: file, line: line)
        }
        var keys = KeychainIdentities.base(kSecClassKey)
        keys[kSecAttrApplicationLabel] = label
        keys[kSecMatchLimit] = kSecMatchLimitAll
        keys[kSecReturnAttributes] = true
        var rows: CFTypeRef?
        let keyStatus = SecItemCopyMatching(keys as CFDictionary, &rows)
        XCTAssertEqual(keyStatus, errSecItemNotFound, "\(name): no key with this public-key hash (\(String(describing: rows)))", file: file, line: line)
    }

    private func assertKeySigns(_ identity: ClientIdentity, _ name: String, file: StaticString = #filePath, line: UInt = #line) {
        var keyRef: SecKey?
        SecIdentityCopyPrivateKey(identity.identity, &keyRef)
        guard let key = keyRef else { return XCTFail("\(name): no private key", file: file, line: line) }
        let algorithm: SecKeyAlgorithm = KeyInspector.algorithm(key).hasPrefix("RSA") ? .rsaSignatureMessagePKCS1v15SHA256 : .ecdsaSignatureMessageX962SHA256
        var error: Unmanaged<CFError>?
        XCTAssertNotNil(SecKeyCreateSignature(key, algorithm, Data("probe".utf8) as CFData, &error),
                        "\(name): the in-memory key signs (\(String(describing: error?.takeRetainedValue())))", file: file, line: line)
    }
}

extension PKCS12ImportKeychainTests {
    /// The import entry's identity with the chain it lists (leaf first), as the library builds it.
    static func identityFromImport(_ entry: [String: Any]) throws -> ClientIdentity {
        let identity = entry[kSecImportItemIdentity as String] as! SecIdentity
        var leaf: SecCertificate?
        SecIdentityCopyCertificate(identity, &leaf)
        var chain: [SecCertificate] = []
        if let leaf { chain.append(leaf) }
        for certificate in (entry[kSecImportItemCertChain as String] as? [SecCertificate]) ?? []
        where !chain.contains(where: { CFEqual($0, certificate) }) {
            chain.append(certificate)
        }
        return try ClientIdentity(identity: identity, chain: chain)
    }
}
