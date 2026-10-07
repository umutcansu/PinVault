import Foundation
import XCTest
@testable import PinVault

/// Port of VaultFileStoreTest, over plain in-memory preferences and over the
/// real ``SecurePreferences`` (in-memory keys) the app uses.
final class VaultFileStoreTests: XCTestCase {

    private let prefs = InMemoryPreferences()
    private lazy var store = VaultFileStore(prefs: prefs)

    func testSaveAndLoadRoundTripBinary() throws {
        let bytes = Data([0x00, 0x01, 0x02, 0x50, 0x4B, 0x03, 0x04])
        try store.save(key: "model", bytes: bytes, version: 1)
        XCTAssertEqual(try store.load(key: "model"), bytes)
    }

    func testSaveAndLoadRoundTripText() throws {
        let json = #"{"feature":"enabled","version":3}"#
        try store.save(key: "flags", bytes: Data(json.utf8), version: 2)
        XCTAssertEqual(try store.load(key: "flags").map { String(decoding: $0, as: UTF8.self) }, json)
    }

    func testEmptyStore() throws {
        XCTAssertNil(try store.load(key: "nonexistent"))
        XCTAssertEqual(try store.getVersion(key: "nonexistent"), 0)
        XCTAssertFalse(try store.exists(key: "nonexistent"))
    }

    func testVersionAndExistence() throws {
        try store.save(key: "model", bytes: Data([1, 2, 3]), version: 5)
        XCTAssertEqual(try store.getVersion(key: "model"), 5)
        XCTAssertTrue(try store.exists(key: "model"))
    }

    func testClearRemovesFileAndVersion() throws {
        try store.save(key: "model", bytes: Data([1, 2, 3]), version: 3)
        try store.clear(key: "model")
        XCTAssertFalse(try store.exists(key: "model"))
        XCTAssertNil(try store.load(key: "model"))
        XCTAssertEqual(try store.getVersion(key: "model"), 0)
    }

    func testMultipleFilesAreIndependent() throws {
        try store.save(key: "file-a", bytes: Data([0x0A]), version: 1)
        try store.save(key: "file-b", bytes: Data([0x0B]), version: 2)
        XCTAssertEqual(try store.load(key: "file-a"), Data([0x0A]))
        XCTAssertEqual(try store.load(key: "file-b"), Data([0x0B]))
        XCTAssertEqual(try store.getVersion(key: "file-a"), 1)
        XCTAssertEqual(try store.getVersion(key: "file-b"), 2)
        try store.clear(key: "file-a")
        XCTAssertNil(try store.load(key: "file-a"))
        XCTAssertNotNil(try store.load(key: "file-b"))
    }

    func testOverwriteUpdatesVersionAndContent() throws {
        try store.save(key: "model", bytes: Data([0x01]), version: 1)
        try store.save(key: "model", bytes: Data([0x02]), version: 2)
        XCTAssertEqual(try store.load(key: "model"), Data([0x02]))
        XCTAssertEqual(try store.getVersion(key: "model"), 2)
    }

    func testLargeBinaryContentRoundTrips() throws {
        let large = Data((0..<100_000).map { UInt8($0 % 256) })
        try store.save(key: "big", bytes: large, version: 1)
        XCTAssertEqual(try store.load(key: "big"), large)
    }

    // MARK: Content and version are one entry

    func testContentAndVersionAreStoredAsOneEntry() throws {
        try store.save(key: "flags", bytes: Data("flags".utf8), version: 7)
        XCTAssertEqual(try prefs.all().count, 1, "one entry: the two cannot be taken from different moments")
        XCTAssertEqual(try prefs.getString("vault_data_flags", nil), "2:7:" + Base64.encode(Data("flags".utf8)))
        XCTAssertEqual(try store.getVersion(key: "flags"), 7)
    }

    func testAnEmptyFileKeepsItsVersion() throws {
        try store.save(key: "empty", bytes: Data(), version: 3)
        XCTAssertEqual(try store.getVersion(key: "empty"), 3)
        XCTAssertEqual(try store.load(key: "empty"), Data())
        XCTAssertTrue(try store.exists(key: "empty"))
    }

    func testAMalformedEntryReadsAsNothing() throws {
        try prefs.edit().putString("vault_data_flags", "not-a-record").commit()
        XCTAssertNil(try store.load(key: "flags"))
        XCTAssertEqual(try store.getVersion(key: "flags"), 0)
    }

    // MARK: Over SecurePreferences

    func testOverSecurePreferencesTheEntryIsSealedAndBoundToItsName() throws {
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory)
        let secure = try VaultFileStore.open(environment: environment)
        try secure.save(key: "flags", bytes: Data("secret-flags".utf8), version: 4)

        XCTAssertEqual(try secure.load(key: "flags"), Data("secret-flags".utf8))
        XCTAssertEqual(try secure.getVersion(key: "flags"), 4)
        let file = directory.appendingPathComponent("\(VaultFileStore.fileName).plist")
        let raw = try Data(contentsOf: file)
        XCTAssertNil(raw.range(of: Data("secret-flags".utf8)), "nothing in the clear on disk")
        XCTAssertNil(raw.range(of: Data(Base64.encode(Data("secret-flags".utf8)).utf8)))
        let excluded = try file.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
        XCTAssertEqual(excluded, true)
    }
}

/// The metadata store and the registrations (Kotlin `VaultFileMeta.Persistent`, `UserAuthRegistrations`).
final class VaultFileMetaPersistentTests: XCTestCase {

    func testSignaturesConfirmationAndProblemRoundTrip() throws {
        let meta = VaultFileMetaPersistent(prefs: InMemoryPreferences())
        let signatures = StoredSignatures(version: 3, scheme: 2, entries: [
            SignatureEntry(keyId: "k1", signature: "c2ln"), SignatureEntry(keyId: nil, signature: "c2ln2"),
        ])
        try meta.saveSignatures("flags", signatures)
        try meta.setConfirmedAt("flags", 1_800_000_000_000)
        try meta.setProblem("flags", .integrityFailed)

        XCTAssertEqual(try meta.signatures("flags"), signatures)
        XCTAssertEqual(try meta.confirmedAt("flags"), 1_800_000_000_000)
        XCTAssertEqual(try meta.problem("flags"), .integrityFailed)

        try meta.clear("flags")
        XCTAssertNil(try meta.signatures("flags"))
        XCTAssertEqual(try meta.confirmedAt("flags"), 0)
        XCTAssertEqual(try meta.problem("flags"), .integrityFailed, "clear keeps a recorded problem")
        try meta.setProblem("flags", nil)
        XCTAssertNil(try meta.problem("flags"))
    }

    func testTheStrictStoreThrowsWhenTheKeychainFails() throws {
        let cipher = FlakyCipher()
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory, cipher: cipher)
        let meta = try VaultFileMetaPersistent.open(environment: environment)
        try meta.setConfirmedAt("flags", 42)

        cipher.broken = true
        XCTAssertThrowsError(try meta.confirmedAt("flags")) { error in
            guard case PinVaultError.storeUnreadable = error else { return XCTFail("\(error)") }
        }
        cipher.broken = false
        XCTAssertEqual(try meta.confirmedAt("flags"), 42, "kept, not dropped")
    }

    func testRegistrationsPersistInTheirNamespace() throws {
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory)
        let registrations = try UserAuthRegistrationsPersistent.open(environment: environment)
        registrations.put("default", "0011223344556677")
        registrations.put("other", "8899aabbccddeeff")
        XCTAssertEqual(try UserAuthRegistrationsPersistent.open(environment: environment).get("default"), "0011223344556677")
        registrations.remove("default")
        XCTAssertNil(registrations.get("default"))
        // The vault store shares the file: clearing the registrations leaves its entries.
        let store = try VaultFileStore.open(environment: environment)
        try store.save(key: "flags", bytes: Data([1]), version: 1)
        registrations.clear()
        XCTAssertNil(registrations.get("other"))
        XCTAssertEqual(try store.load(key: "flags"), Data([1]))
    }
}
