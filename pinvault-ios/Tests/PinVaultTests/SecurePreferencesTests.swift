import Foundation
import XCTest
@testable import PinVault

/// Port of SecurePreferencesTest: the encrypted preferences behind every
/// store. An in-memory key source stands in for the Keychain. The Android
/// 2.0.x migration tests are not ported (iOS has no legacy files); the backup
/// rules test becomes the backup-exclusion test.
final class SecurePreferencesTests: XCTestCase {

    private static let file = "test_secure_prefs"

    private var directory: URL!
    private var environment: SecureStoreEnvironment!
    private var backing: PrefsFile!
    private let cipher = KeyedPrefsCipher(source: InMemoryPrefsKeySource())

    override func setUpWithError() throws {
        directory = try temporaryStoreDirectory(self)
        environment = SecureStoreEnvironment(directory: directory, cipher: cipher)
        backing = environment.file(Self.file)
    }

    private func prefs(_ namespace: String = "ns", cipher: (any PrefsCipher)? = nil) throws -> SecurePreferences {
        try SecurePreferences(backing: backing, fileName: Self.file, namespace: namespace, cipher: cipher ?? self.cipher)
    }

    func testEveryTypeRoundTripsAndAbsentKeysGiveTheDefault() throws {
        try prefs().edit()
            .putString("s", "değer ✓")
            .putInt("i", -7)
            .putLong("l", Int64.max)
            .putFloat("f", 1.5)
            .putBoolean("b", true)
            .putStringSet("set", ["a", "b"])
            .commit()

        let p = try prefs()
        XCTAssertEqual(try p.getString("s", nil), "değer ✓")
        XCTAssertEqual(try p.getInt("i", 0), -7)
        XCTAssertEqual(try p.getLong("l", 0), Int64.max)
        XCTAssertEqual(try p.getFloat("f", 0), 1.5)
        XCTAssertTrue(try p.getBoolean("b", false))
        XCTAssertEqual(try p.getStringSet("set", nil), ["a", "b"])
        XCTAssertEqual(try p.getString("missing", "yok"), "yok")
        XCTAssertEqual(try p.getInt("missing", 42), 42)
        XCTAssertEqual(try p.all().count, 6)
    }

    func testNothingReadableReachesTheFile() throws {
        try prefs().edit().putString("config_pins", "api.example.com|3|pinA,pinB|false").putInt("config_version", 3).commit()

        let raw = String(decoding: try Data(contentsOf: directory.appendingPathComponent("\(Self.file).plist")), as: UTF8.self)
        for secret in ["config_pins", "config_version", "api.example.com", "pinA"] {
            XCTAssertFalse(raw.contains(secret), "'\(secret)' is in the file")
        }
        XCTAssertEqual(try backing.entries().count, 2)
    }

    func testPutStringNilAndRemoveDeleteTheEntry() throws {
        try prefs().edit().putString("a", "1").putString("b", "2").commit()
        try prefs().edit().putString("a", nil).remove("b").commit()
        XCTAssertFalse(try prefs().contains("a"))
        XCTAssertFalse(try prefs().contains("b"))
        XCTAssertTrue(try backing.entries().isEmpty)
    }

    func testNamespacesShareAFileWithoutSeeingEachOtherAndClearEmptiesOne() throws {
        try prefs("block-a").edit().putString("config_pins", "A").commit()
        try prefs("block-b").edit().putString("config_pins", "B").commit()

        XCTAssertEqual(try prefs("block-a").getString("config_pins", nil), "A")
        XCTAssertEqual(try prefs("block-b").getString("config_pins", nil), "B")

        try prefs("block-a").edit().clear().commit()
        XCTAssertNil(try prefs("block-a").getString("config_pins", nil))
        XCTAssertEqual(try prefs("block-b").getString("config_pins", nil), "B")
        XCTAssertEqual(try prefs("block-b").all(), ["config_pins": .string("B")])
    }

    func testClearAppliesBeforeThePutsOfTheSameEdit() throws {
        try prefs().edit().putString("old", "x").commit()
        try prefs().edit().putString("new", "y").clear().commit()
        XCTAssertEqual(try prefs().all(), ["new": .string("y")])
    }

    // An entry copied onto another key's name, or another file's, does not
    // open: the value is bound to its stored name and file.
    func testAnEntryMovedToAnotherKeyReadsAsAbsentAndIsDropped() throws {
        try prefs().edit().putString("pins_host_a", "attacker").putString("pins_host_b", "genuine").commit()
        // Swap the two sealed values under their stored names.
        let entries = try backing.entries()
        let names = Array(entries.keys)
        try backing.write(setting: [names[0]: entries[names[1]]!, names[1]: entries[names[0]]!])

        XCTAssertNil(try prefs().getString("pins_host_a", nil))
        XCTAssertNil(try prefs().getString("pins_host_b", nil))
        XCTAssertTrue(try backing.entries().isEmpty, "unopenable entries are removed")
    }

    func testAnEntryCopiedToAnotherFileDoesNotOpen() throws {
        try prefs().edit().putString("k", "v").commit()
        let other = environment.file("other_file")
        try other.write(setting: try backing.entries())
        let elsewhere = try SecurePreferences(backing: other, fileName: "other_file", namespace: "ns", cipher: cipher)
        XCTAssertNil(try elsewhere.getString("k", nil))
        XCTAssertTrue(try other.entries().isEmpty)
    }

    func testATamperedValueReadsAsAbsent() throws {
        try prefs().edit().putString("k", "v").commit()
        let (name, sealed) = try XCTUnwrap(try backing.entries().first)
        var chars = Array(sealed)
        chars[20] = chars[20] == "A" ? "B" : "A"
        try backing.write(setting: [name: String(chars)])

        XCTAssertEqual(try prefs().getString("k", "fallback"), "fallback")
        XCTAssertFalse(try backing.contains(name))
    }

    func testAnotherAppsKeyCannotOpenTheFile() throws {
        try prefs().edit().putString("k", "v").commit()
        XCTAssertNil(try prefs(cipher: KeyedPrefsCipher(source: InMemoryPrefsKeySource())).getString("k", nil))
    }

    func testReadingWithTheWrongTypeThrowsLikePlatformPreferences() throws {
        try prefs().edit().putString("k", "text").commit()
        XCTAssertThrowsError(try prefs().getInt("k", 0)) { error in
            guard case PinVaultError.illegalState(let message) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "k is a String")
        }
    }

    func testListenersHearTheLogicalKey() throws {
        let heard = Locked<[String]>([])
        let p = try prefs()
        let token = p.addChangeListener { key in heard.withLock { $0.append(key) } }
        try p.edit().putInt("config_version", 5).commit()
        p.removeChangeListener(token)
        try p.edit().putInt("config_version", 6).commit()
        XCTAssertEqual(heard.get(), ["config_version"])
    }

    func testStoresWorkUnchangedOnTopTwoBlocksInOneFile() throws {
        let a = CertificateConfigStore(prefs: try prefs("ssl_cert_config_block-a"))
        let b = CertificateConfigStore(prefs: try prefs("ssl_cert_config_block-b"))
        let config = CertificateConfig(version: 4, pins: [HostPin(hostname: "api.example.com", sha256: ["p1", "p2"], version: 4)], issuedAt: 7)
        try a.save(config)
        var other = config
        other.version = 9
        other.pins = [HostPin(hostname: "cdn.example.com", sha256: ["p3", "p4"], version: 9)]
        try b.save(other)

        let loaded = try XCTUnwrap(try CertificateConfigStore(prefs: try prefs("ssl_cert_config_block-a")).load())
        XCTAssertEqual(loaded.version, 4)
        XCTAssertEqual(loaded.pins, config.pins)
        XCTAssertEqual(loaded.issuedAt, 7)
        try a.clearActive() // PinVault.reset() on block a
        XCTAssertNil(try CertificateConfigStore(prefs: try prefs("ssl_cert_config_block-a")).load())
        XCTAssertEqual(try CertificateConfigStore(prefs: try prefs("ssl_cert_config_block-b")).load()?.version, 9)
    }

    // ── iOS: the file on disk ───────────────────────────────────────────

    func testEntriesSurviveANewProcessReadingTheFile() throws {
        try prefs().edit().putLong("watermark", 42).putString("text", "kept").commit()

        // A new process: a fresh environment over the same directory and keys.
        let reopened = SecureStoreEnvironment(directory: directory, cipher: cipher)
        let p = try SecurePreferences.openStrict(fileName: Self.file, namespace: "ns", environment: reopened)
        XCTAssertEqual(try p.getLong("watermark", 0), 42)
        XCTAssertEqual(try p.getString("text", nil), "kept")
    }

    // The counterpart of the Android backup rules (audit M-07): every store
    // file and the folder they live in are excluded from backup.
    func testStoreFilesAreExcludedFromBackup() throws {
        let nested = directory.appendingPathComponent("pinvault", isDirectory: true)
        let env = SecureStoreEnvironment(directory: nested, cipher: cipher)
        for fileName in [CertificateConfigStore.fileName, SigningKeyStore.fileName] {
            let p = try SecurePreferences.openStrict(fileName: fileName, namespace: "ns", environment: env)
            XCTAssertTrue(try p.edit().putString("k", "v").commit())
            let url = nested.appendingPathComponent("\(fileName).plist")
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "\(fileName).plist")
            XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true, fileName)
        }
        XCTAssertEqual(try nested.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        XCTAssertEqual(CertificateConfigStore.fileName, "pinvault_secure_config")
        XCTAssertEqual(SigningKeyStore.fileName, "pinvault_secure_signing_keys")
    }

    func testAFileThatCannotBeReadIsNotAnEmptyStoreAndIsNotOverwritten() throws {
        try prefs().edit().putLong("watermark", 42).commit()
        let url = directory.appendingPathComponent("\(Self.file).plist")
        let before = try Data(contentsOf: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: url.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path) }

        // A new process meets the file while it cannot be read (a locked device).
        let locked = SecureStoreEnvironment(directory: directory, cipher: cipher)
        let strict = try SecurePreferences.openStrict(fileName: Self.file, namespace: "ns", environment: locked)
        assertStoreUnreadable("strict read") { _ = try strict.getLong("watermark", 0) }
        assertStoreUnreadable("strict all") { _ = try strict.all() }
        let lenient = try SecurePreferences.open(fileName: Self.file, namespace: "ns", environment: locked)
        XCTAssertEqual(try lenient.getLong("watermark", 7), 7)
        assertStoreUnreadable("a write must not replace what it could not read") {
            try lenient.edit().putLong("other", 1).commit()
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        XCTAssertEqual(try Data(contentsOf: url), before)
        XCTAssertEqual(try strict.getLong("watermark", 0), 42)
    }

    func testACorruptFileReadsAsEmpty() throws {
        let url = directory.appendingPathComponent("\(Self.file).plist")
        try Data("not a property list".utf8).write(to: url)
        let p = try prefs()
        XCTAssertNil(try p.getString("k", nil))
        try p.edit().putString("k", "v").commit()
        XCTAssertEqual(try prefs().getString("k", nil), "v")
    }

    func testKotlinIntsAreClampedTo32Bits() throws {
        try prefs().edit().putInt("big", Int(Int32.max) + 10).putInt("small", Int(Int32.min) - 10).commit()
        XCTAssertEqual(try prefs().getInt("big", 0), Int(Int32.max))
        XCTAssertEqual(try prefs().getInt("small", 0), Int(Int32.min))
    }

    func testTheValueEncodingRoundTripsAndRefusesDamage() {
        let values: [PrefValue] = [.string("ü"), .int(-1), .long(.min), .float(-0.5), .bool(false), .stringSet(["x", ""])]
        for value in values {
            let encoded = SecurePreferences.encode("key", value)
            let decoded = SecurePreferences.decode(encoded)
            XCTAssertEqual(decoded?.0, "key")
            XCTAssertEqual(decoded?.1, value)
        }
        XCTAssertNil(SecurePreferences.decode(Data()))
        XCTAssertNil(SecurePreferences.decode(Data([9, 0, 0, 0, 0])), "unknown type")
        XCTAssertNil(SecurePreferences.decode(Data([2, 0, 0, 0, 1, 0x41, 0])), "int cut short")
        XCTAssertNil(SecurePreferences.decode(Data([1, 0x7F, 0xFF, 0xFF, 0xFF])), "key length beyond the value")
        XCTAssertNil(SecurePreferences.decode(Data([6, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF])), "negative set size")
    }
}
