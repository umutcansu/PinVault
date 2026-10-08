import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of EncryptedFileStorageProviderTest: the file store binds a file's
/// name and version into what its GCM tag covers, and reads the version from
/// the file itself. In-memory AES keys stand in for the per-file Keychain keys.
final class EncryptedFileStorageProviderTests: XCTestCase {

    private var directory: URL!
    private var store: EncryptedFileStorageProvider!
    private let keystoreDown = Locked(false)
    private let removedKeys = Locked<[String]>([])
    /// One key for every file: the worst case for swapping copies.
    private let sharedKey = SymmetricKey(size: .bits256)

    override func setUpWithError() throws {
        directory = try temporaryStoreDirectory(self).appendingPathComponent("vault_files", isDirectory: true)
        let down = keystoreDown
        let key = sharedKey
        let removed = removedKeys
        store = EncryptedFileStorageProvider(
            directory: directory,
            keyFor: { _ in
                if down.get() { throw DeviceKeyKeychainError(status: errSecInteractionNotAllowed, operation: "read the vault file key") }
                return key
            },
            removeKey: { name in removed.withLock { $0.append(name) } }
        )
    }

    private func file(_ key: String) -> URL { directory.appendingPathComponent("\(key).enc") }

    func testAFileRoundTripsWithItsVersion() throws {
        var model = Data(count: 200_000)
        _ = model.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 200_000, $0.baseAddress!) }
        try store.save(key: "model", bytes: model, version: 12)

        XCTAssertEqual(try store.load(key: "model"), model)
        XCTAssertEqual(try store.getVersion(key: "model"), 12)
        XCTAssertTrue(try store.exists(key: "model"))
        let raw = try Data(contentsOf: file("model"))
        XCTAssertEqual(raw.prefix(4), Data("PVF2".utf8))
        XCTAssertEqual(Array(raw[4..<8]), [0, 0, 0, 12], "the version is in the file, big-endian")
        XCTAssertEqual(raw[8], 12, "IV length")
        XCTAssertNil(raw.range(of: model.prefix(64)), "not in the clear")
        XCTAssertEqual(try file("model").resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        XCTAssertEqual(try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }

    func testACopyMovedUnderAnotherFilesNameDoesNotOpenAndIsDeleted() throws {
        try store.save(key: "public-notes", bytes: Data("public".utf8), version: 1)
        try store.save(key: "trusted-hosts", bytes: Data("trusted".utf8), version: 1)
        try Data(contentsOf: file("public-notes")).write(to: file("trusted-hosts"))

        XCTAssertNil(try store.load(key: "trusted-hosts"))
        XCTAssertFalse(try store.exists(key: "trusted-hosts"), "it will never open: gone, so the next fetch starts from zero")
        XCTAssertEqual(try store.getVersion(key: "trusted-hosts"), 0)
        XCTAssertEqual(try store.load(key: "public-notes"), Data("public".utf8))
        XCTAssertEqual(removedKeys.get(), ["trusted-hosts"], "the file's key goes with it")
    }

    func testACopyGivenAnotherVersionDoesNotOpenAndIsDeleted() throws {
        try store.save(key: "flags", bytes: Data("flags".utf8), version: 4)
        var bytes = try Data(contentsOf: file("flags"))
        bytes[4] = 0x77   // 4 becomes 2,000,000,004
        try bytes.write(to: file("flags"))
        XCTAssertGreaterThan(try store.getVersion(key: "flags"), 1_000_000)

        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertFalse(try store.exists(key: "flags"))
        XCTAssertEqual(try store.getVersion(key: "flags"), 0)
    }

    func testAnOlderCopyCannotBeGivenTheNewerVersionsLabel() throws {
        try store.save(key: "flags", bytes: Data("old".utf8), version: 1)
        var old = try Data(contentsOf: file("flags"))
        try store.save(key: "flags", bytes: Data("new".utf8), version: 2)

        old[7] = 2   // the old ciphertext with the version field of the new one
        try old.write(to: file("flags"))

        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertFalse(try store.exists(key: "flags"))
    }

    func testARewrittenOrTruncatedCopyIsDeleted() throws {
        try store.save(key: "flags", bytes: Data("flags".utf8), version: 1)
        var bytes = try Data(contentsOf: file("flags"))
        bytes[bytes.count - 1] &+= 1
        try bytes.write(to: file("flags"))
        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertFalse(try store.exists(key: "flags"))

        try store.save(key: "flags", bytes: Data("flags".utf8), version: 1)
        try Data(contentsOf: file("flags")).prefix(9).write(to: file("flags"))
        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertFalse(try store.exists(key: "flags"))
    }

    func testAKeychainFailureKeepsTheCopyOnLoadAndOnSave() throws {
        try store.save(key: "flags", bytes: Data("v1".utf8), version: 1)

        keystoreDown.set(true)
        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertTrue(try store.exists(key: "flags"), "unreadable now is not damaged")
        XCTAssertEqual(try store.getVersion(key: "flags"), 1)
        // A save that cannot encrypt must not take the old copy with it.
        try store.save(key: "flags", bytes: Data("v2".utf8), version: 2)
        XCTAssertTrue(try store.exists(key: "flags"))

        keystoreDown.set(false)
        XCTAssertEqual(try store.load(key: "flags"), Data("v1".utf8))
        XCTAssertEqual(try store.getVersion(key: "flags"), 1)
    }

    func testClearRemovesTheFileAndItsVersion() throws {
        try store.save(key: "flags", bytes: Data("x".utf8), version: 3)
        try store.clear(key: "flags")
        XCTAssertFalse(try store.exists(key: "flags"))
        XCTAssertEqual(try store.getVersion(key: "flags"), 0)
        XCTAssertNil(try store.load(key: "flags"))
    }

    func testThePendingSlotOfAUserAuthFileIsAFileOfItsOwn() async throws {
        let keys = SoftwareUserAuthKeys()
        let locked = UserAuthVaultStorage(inner: store, keys: keys, policy: .required, serverSealedOnly: true)
        try keys.ensureKey()
        try locked.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(Data("v5".utf8), keys.publicKey()), version: 5, signatures: [])
        try locked.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(Data("v6".utf8), keys.publicKey()), version: 6, signatures: [])
        XCTAssertTrue(FileManager.default.fileExists(atPath: file("st.pending").path))

        let result = await locked.unlock("st", authenticate: { _, grant in .succeeded(grant) }, verify: { _, _, _ in nil })
        XCTAssertEqual(result, .unlocked(key: "st", version: 6, bytes: Data("v6".utf8)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file("st.pending").path))
        XCTAssertEqual(try store.getVersion(key: "st"), 6)
    }
}
