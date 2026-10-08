import Foundation
import XCTest
@testable import PinVault

/// Port of VaultFileWipeTest: a revoked (or unenrolled) Config API's vault files leave the device.
final class VaultFileWipeTests: XCTestCase {

    private let inner = MemVaultStore()
    private let keys = SoftwareUserAuthKeys()
    private lazy var locked = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)

    private let revokedPlain = VaultFileConfig(key: "flags", endpoint: "e/flags", configApiId: "mtls")
    private let revokedLocked = VaultFileConfig(key: "statement", endpoint: "e/statement", configApiId: "mtls", userAuth: .required)
    private let otherPlain = VaultFileConfig(key: "public", endpoint: "e/public", configApiId: "tls")
    private let otherLocked = VaultFileConfig(key: "card", endpoint: "e/card", configApiId: "tls", userAuth: .required)

    private func storageFor(_ key: String) -> any VaultStorageProvider {
        key == "statement" || key == "card" ? locked : inner
    }

    func testWipesTheRevokedConfigApisFilesLockedOnesAndTheKeyIncluded() throws {
        try inner.save(key: "flags", bytes: Data("f".utf8), version: 1)
        try locked.save(key: "statement", bytes: Data("s".utf8), version: 1)
        try inner.save(key: "public", bytes: Data("p".utf8), version: 1)
        var keyDeleted = false

        let count = VaultFileWipe.wipe(["mtls"], files: [revokedPlain, revokedLocked, otherPlain], storageFor: storageFor,
                                       userAuthKeys: keys) { keyDeleted = true }

        XCTAssertEqual(count, 2)
        XCTAssertFalse(try inner.exists(key: "flags"))
        XCTAssertFalse(try locked.exists(key: "statement"))
        XCTAssertTrue(try inner.exists(key: "public"), "another Config API's file stays")
        XCTAssertNil(keys.key, "no locked file left: the user-auth key goes too")
        XCTAssertTrue(keyDeleted)
    }

    func testKeepsTheDeviceKeyWhileAnotherConfigApiStillHasALockedFile() throws {
        try locked.save(key: "statement", bytes: Data("s".utf8), version: 1)
        try locked.save(key: "card", bytes: Data("c".utf8), version: 1)

        VaultFileWipe.wipe(["mtls"], files: [revokedLocked, otherLocked], storageFor: storageFor, userAuthKeys: keys)

        XCTAssertFalse(try locked.exists(key: "statement"))
        XCTAssertTrue(try locked.exists(key: "card"))
        XCTAssertNotNil(keys.key)
    }

    func testAStorageErrorDoesNotStopTheRest() throws {
        try inner.save(key: "flags", bytes: Data("f".utf8), version: 1)
        final class Failing: VaultStorageProvider, @unchecked Sendable {
            func save(key: String, bytes: Data, version: Int) throws {}
            func load(key: String) throws -> Data? { nil }
            func getVersion(key: String) throws -> Int { 0 }
            func exists(key: String) throws -> Bool { true }
            func clear(key: String) throws { throw PinVaultError.io(message: "disk") }
        }
        let failing = Failing()
        let inner = self.inner

        let count = VaultFileWipe.wipe(["mtls"], files: [revokedLocked, revokedPlain], storageFor: { $0 == "statement" ? failing as any VaultStorageProvider : inner },
                                       userAuthKeys: nil)

        XCTAssertEqual(count, 2)
        XCTAssertFalse(try inner.exists(key: "flags"))
    }

    func testUnenrollWipesOnlyTheBlocksThatUseTheLabelForMTLS() {
        func block(_ id: String, label: String = "default_cert", enrollmentUrl: String? = nil, renewalUrl: String? = nil,
                   bundled: Data? = nil) -> ConfigApiBlock {
            ConfigApiBlock(id: id, configUrl: "https://\(id).test/", bootstrapPins: [], clientKeystoreBytes: bundled,
                           clientCertLabel: label, renewalUrl: renewalUrl, enrollmentUrl: enrollmentUrl)
        }
        let blocks = [
            block("tls"),                                                   // TLS only, same default label
            block("enrolls", enrollmentUrl: "https://enrolls.test:8091/"),
            block("renews", renewalUrl: "https://renews.test:8093/"),
            block("bundled", bundled: Data([1])),
            block("by-file"),
            block("other-label", label: "other", enrollmentUrl: "https://x.test/"),
        ]
        let files = [
            VaultFileConfig(key: "public", endpoint: "e/public", configApiId: "tls"),
            VaultFileConfig(key: "secret", endpoint: "e/secret", configApiId: "by-file", accessPolicy: .tokenMtls, accessTokenProvider: { "t" }),
        ]

        XCTAssertEqual(VaultFileWipe.mtlsBlocksUsing("default_cert", blocks: blocks, files: files), ["enrolls", "renews", "bundled", "by-file"])
        XCTAssertEqual(VaultFileWipe.mtlsBlocksUsing("other", blocks: blocks, files: files), ["other-label"])
    }
}
