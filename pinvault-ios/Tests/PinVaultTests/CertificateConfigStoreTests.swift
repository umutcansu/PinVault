import Foundation
import XCTest
@testable import PinVault

/// Port of CertificateConfigStoreTest. Plain in-memory preferences stand in
/// for the encrypted file, as the Kotlin test uses plain SharedPreferences.
final class CertificateConfigStoreTests: XCTestCase {

    private typealias S = CertificateConfigStore

    private var prefs: InMemoryPreferences!
    private var store: CertificateConfigStore!

    override func setUp() {
        prefs = InMemoryPreferences()
        store = CertificateConfigStore(prefs: prefs)
    }

    private func pin(_ hostname: String, _ hashes: [String], version: Int = 0, forceUpdate: Bool = false) -> HostPin {
        HostPin(hostname: hostname, sha256: hashes, version: version, forceUpdate: forceUpdate)
    }

    func testManagedTrustRootsAreStoredWithTheConfigClearedWithItAndMalformedEntriesDropped() throws {
        let rootA = String(repeating: "A", count: 43) + "="
        let rootB = String(repeating: "B", count: 43) + "="
        let config = CertificateConfig(
            version: 1, pins: [pin("api.example.com", ["hash1aaa", "hash2bbb"], version: 1)], trustRoots: [rootA, rootB]
        )
        try store.save(config)
        XCTAssertEqual(try store.load()?.trustRoots, [rootA, rootB])

        // A config without roots removes them.
        var noRoots = config
        noRoots.trustRoots = []
        try store.save(noRoots)
        XCTAssertEqual(try store.load()?.trustRoots, [])

        // Something that is not a pin in the stored list is ignored, not returned.
        try store.save(config)
        try prefs.edit().putString(S.keyTrustRootsJson, "[\"\(rootA)\",\"garbage\"]").apply()
        XCTAssertEqual(try store.load()?.trustRoots, [rootA])

        try store.clearActive()
        XCTAssertNil(try store.load())
        XCTAssertFalse(try prefs.contains(S.keyTrustRootsJson))
    }

    func testSaveAndLoadRoundTripSingleHost() throws {
        try store.save(CertificateConfig(version: 1, pins: [pin("api.example.com", ["hash1aaa", "hash2bbb"], version: 1)]))
        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded.pins.count, 1)
        XCTAssertEqual(loaded.pins[0].hostname, "api.example.com")
        XCTAssertEqual(loaded.pins[0].sha256, ["hash1aaa", "hash2bbb"])
        XCTAssertEqual(loaded.pins[0].version, 1)
    }

    func testSaveAndLoadRoundTripMultipleHosts() throws {
        try store.save(CertificateConfig(version: 3, pins: [
            pin("api.example.com", ["h1", "h2"], version: 1),
            pin("cdn.example.com", ["h3", "h4"], version: 2),
            pin("auth.example.com", ["h5", "h6"], version: 3),
        ]))
        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded.pins.map(\.hostname), ["api.example.com", "cdn.example.com", "auth.example.com"])
    }

    func testLoadReturnsNilWhenNothingSaved() throws {
        XCTAssertNil(try store.load())
    }

    func testGetCurrentVersionReturns0WhenEmpty() throws {
        XCTAssertEqual(try store.getCurrentVersion(), 0)
    }

    func testGetCurrentVersionReflectsSavedConfigVersion() throws {
        try store.save(CertificateConfig(version: 5, pins: [pin("api.example.com", ["h1", "h2"], version: 5)]))
        XCTAssertEqual(try store.getCurrentVersion(), 5)
    }

    func testWipeAllRemovesAllData() throws {
        try store.save(CertificateConfig(version: 1, pins: [pin("api.example.com", ["h1", "h2"], version: 1)]))
        XCTAssertNotNil(try store.load())
        try store.wipeAll()
        XCTAssertNil(try store.load())
        XCTAssertEqual(try store.getCurrentVersion(), 0)
    }

    func testSaveOverwritesPreviousConfig() throws {
        try store.save(CertificateConfig(version: 1, pins: [pin("old.example.com", ["h1", "h2"], version: 1)]))
        try store.save(CertificateConfig(version: 2, pins: [pin("new.example.com", ["h3", "h4"], version: 2)]))
        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded.pins.map(\.hostname), ["new.example.com"])
        XCTAssertEqual(try store.getCurrentVersion(), 2)
    }

    func testBackwardCompatibleParsingOldFormat() throws {
        // Old format: hostname|hash1,hash2 (no version field)
        try prefs.edit().putInt(S.keyVersion, 1).putString(S.keyPins, "api.example.com|hashA,hashB").apply()
        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded.pins.count, 1)
        XCTAssertEqual(loaded.pins[0].hostname, "api.example.com")
        XCTAssertEqual(loaded.pins[0].sha256, ["hashA", "hashB"])
        XCTAssertEqual(loaded.pins[0].version, 0) // old format defaults to version 0
    }

    func testMalformedDataReturnsNil() throws {
        try prefs.edit().putInt(S.keyVersion, 1).putString(S.keyPins, "").apply()
        XCTAssertNil(try store.load())
    }

    func testSingleHashHostIsFilteredOut() throws {
        try prefs.edit().putInt(S.keyVersion, 1).putString(S.keyPins, "api.example.com|1|singlehash").apply()
        XCTAssertNil(try store.load())
    }

    func testForceUpdateFlagSurvivesSaveAndLoad() throws {
        // Regression: save() used to drop forceUpdate; a restart then defeated
        // the backend's revocation guarantee.
        try store.save(CertificateConfig(version: 1, pins: [pin("api.example.com", ["h1", "h2"], version: 1)], forceUpdate: true))
        XCTAssertEqual(try store.load()?.forceUpdate, true, "forceUpdate=true lost on round-trip — restart bypass regression")
    }

    func testForceUpdateDefaultsToFalseWhenAbsentFromPrefs() throws {
        try prefs.edit().putInt(S.keyVersion, 1).putString(S.keyPins, "api.example.com|1|h1,h2").apply()
        XCTAssertEqual(try store.load()?.forceUpdate, false, "legacy entries without KEY_FORCE_UPDATE should load with false")
    }

    func testPerHostForceUpdateFlagSurvivesSaveAndLoad() throws {
        try store.save(CertificateConfig(version: 2, pins: [
            pin("forced.example.com", ["h1", "h2"], version: 2, forceUpdate: true),
            pin("normal.example.com", ["h3", "h4"], version: 1, forceUpdate: false),
        ]))
        let byHost = Dictionary(uniqueKeysWithValues: try XCTUnwrap(try store.load()).pins.map { ($0.hostname, $0) })
        XCTAssertEqual(byHost["forced.example.com"]?.forceUpdate, true, "per-host forceUpdate=true lost on round-trip")
        XCTAssertEqual(byHost["normal.example.com"]?.forceUpdate, false, "per-host forceUpdate=false must stay false")
        XCTAssertEqual(byHost["forced.example.com"]?.sha256, ["h1", "h2"])
        XCTAssertEqual(byHost["forced.example.com"]?.version, 2)
    }

    func testEntriesWrittenBeforeTheForceUpdateFieldStillLoad() throws {
        try prefs.edit()
            .putInt(S.keyVersion, 2)
            .putString(S.keyPins, "legacy.example.com|2|oldA,oldB\nfresh.example.com|1|newA,newB|true")
            .apply()
        let byHost = Dictionary(uniqueKeysWithValues: try XCTUnwrap(try store.load()).pins.map { ($0.hostname, $0) })
        XCTAssertEqual(byHost.count, 2)
        XCTAssertEqual(byHost["legacy.example.com"]?.sha256, ["oldA", "oldB"])
        XCTAssertEqual(byHost["legacy.example.com"]?.forceUpdate, false, "3-field legacy row must default to false")
        XCTAssertEqual(byHost["fresh.example.com"]?.forceUpdate, true, "4-field row must keep its flag")
    }

    func testSingleMalformedEntryDoesNotPoisonTheRestOfTheCache() throws {
        try prefs.edit()
            .putInt(S.keyVersion, 5)
            .putString(S.keyPins,
                "good.example.com|2|goodPinA,goodPinB\n" +
                    "bad.example.com|3|loneHash\n" +
                    "another.example.com|4|anotherA,anotherB")
            .apply()
        let hostnames = try XCTUnwrap(try store.load(), "good rows must still load even if one entry is malformed").pins.map(\.hostname)
        XCTAssertTrue(hostnames.contains("good.example.com"), "good.example.com lost: \(hostnames)")
        XCTAssertTrue(hostnames.contains("another.example.com"), "another.example.com lost: \(hostnames)")
        XCTAssertFalse(hostnames.contains("bad.example.com"), "malformed bad.example.com must be dropped: \(hostnames)")
    }

    func testComputedVersionUsesMaxOfHostVersions() throws {
        try store.save(CertificateConfig(version: 0, pins: [
            pin("a.com", ["h1", "h2"], version: 2), pin("b.com", ["h3", "h4"], version: 7), pin("c.com", ["h5", "h6"], version: 3),
        ]))
        XCTAssertEqual(try store.getCurrentVersion(), 7)
    }

    // ── expiresAt and watermarks (Y1) ───────────────────────────────────

    private func hostConfig(_ version: Int, issuedAt: Int64, expiresAt: Int64 = 0, hosts: [String] = ["a.com"]) -> CertificateConfig {
        CertificateConfig(version: version, pins: hosts.map { pin($0, ["h1", "h2"], version: version) }, issuedAt: issuedAt, expiresAt: expiresAt)
    }

    func testExpiresAtSurvivesSaveAndLoad() throws {
        try store.save(hostConfig(1, issuedAt: 1_000, expiresAt: 9_000))
        XCTAssertEqual(try store.load()?.expiresAt, 9_000)
        try store.save(hostConfig(2, issuedAt: 2_000, expiresAt: 0))
        XCTAssertEqual(try store.load()?.expiresAt, 0, "0 = no expiry, kept as such")
    }

    func testConfigStoredBeforeExpiresAtWasKeptGetsSevenDaysFromItsFirstLoadWhateverItsIssuedAt() throws {
        // 2.1.1 never wrote issuedAt back for unchanged pins: it is often weeks old.
        try prefs.edit()
            .putInt(S.keyVersion, 3)
            .putString(S.keyPins, "a.com|3|h1,h2|false")
            .putLong(S.keyIssuedAt, 1_000_000)
            .apply()
        let firstLoad: Int64 = 1_000_000 + 30 * 24 * 3_600_000
        store.clock = { firstLoad }

        XCTAssertEqual(S.legacyLifetimeMs, 7 * 24 * 3_600_000)
        XCTAssertEqual(try store.load()?.expiresAt, firstLoad + S.legacyLifetimeMs)
        store.clock = { firstLoad + 3_600_000 }
        XCTAssertEqual(try store.load()?.expiresAt, firstLoad + S.legacyLifetimeMs, "a restart does not extend it")
        XCTAssertEqual(try store.load()?.issuedAt, 1_000_000, "issuedAt itself is kept")
    }

    func testConfigStoredBeforeExpiresAtWithoutIssuedAtGetsSevenDaysFromItsFirstLoad() throws {
        try prefs.edit().putInt(S.keyVersion, 3).putString(S.keyPins, "a.com|3|h1,h2|false").apply()
        store.clock = { 5_000_000 }
        XCTAssertEqual(try store.load()?.expiresAt, 5_000_000 + S.legacyLifetimeMs)
        store.clock = { 9_000_000 }
        XCTAssertEqual(try store.load()?.expiresAt, 5_000_000 + S.legacyLifetimeMs, "a restart does not extend it")
    }

    func testSavingAnOlderConfigWithoutLoweringTheWatermarks() throws {
        try store.save(hostConfig(5, issuedAt: 2_000, hosts: ["a.com", "b.com"]))
        try store.save(hostConfig(4, issuedAt: 1_000))

        XCTAssertEqual(try store.load()?.pins.map(\.version), [4])
        XCTAssertEqual(try store.getCurrentIssuedAt(), 2_000)
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 5, "b.com": 5])
    }

    func testAHostTheServerDroppedKeepsItsVersionWatermark() throws {
        try store.save(hostConfig(5, issuedAt: 2_000, hosts: ["a.com", "b.com"]))
        try store.save(hostConfig(6, issuedAt: 3_000))
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 6, "b.com": 5])
    }

    func testClearActiveKeepsTheWatermarksWipeAllDoesNot() throws {
        try store.save(hostConfig(5, issuedAt: 2_000))
        try store.clearActive()

        XCTAssertNil(try store.load())
        XCTAssertEqual(try store.getCurrentIssuedAt(), 2_000)
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 5])

        try store.wipeAll()
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
        XCTAssertTrue(try store.getVersionWatermarks().isEmpty)
    }

    func testWatermarksBeyond32BitsAreKept() throws {
        try store.save(hostConfig(5_000_000_000, issuedAt: 2_000))
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 5_000_000_000])
        try store.clearActive()
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 5_000_000_000])
    }

    // ── JSON format, legacy format read once ────────────────────────────

    func testPinsAreStoredAsJSONPortsAndWildcardsIncluded() throws {
        let odd = ["a.com", "b.com:8443", "*.c.example.com"]
        try store.save(hostConfig(3, issuedAt: 10, hosts: odd))

        XCTAssertEqual(try store.load()?.pins.map(\.hostname), odd)
        XCTAssertEqual(try store.getVersionWatermarks(), Dictionary(uniqueKeysWithValues: odd.map { ($0, 3) }))
        XCTAssertNil(try prefs.getString(S.keyPins, nil), "the pre-JSON key is gone")
        XCTAssertTrue(try prefs.getString(S.keyPinsJson, "")!.hasPrefix("["))
    }

    func testMtlsAndClientCertVersionSurviveSaveAndLoad() throws {
        try store.save(CertificateConfig(version: 2, pins: [
            HostPin(hostname: "mtls.example.com", sha256: ["h1", "h2"], version: 2, mtls: true, clientCertVersion: 7),
            HostPin(hostname: "plain.example.com", sha256: ["h1", "h2"], version: 1),
        ]))
        let loaded = try XCTUnwrap(try store.load()).pins
        XCTAssertTrue(loaded[0].mtls)
        XCTAssertEqual(loaded[0].clientCertVersion, 7)
        XCTAssertFalse(loaded[1].mtls)
        XCTAssertNil(loaded[1].clientCertVersion)
    }

    func testThePreJSONFormatIsReadOnceAndRewritten() throws {
        try prefs.edit()
            .putInt(S.keyVersion, 4)
            .putString(S.keyPins, "a.com|4|h1,h2|false\nb.com|2|h3,h4|true")
            .putString(S.keyWatermarkVersions, "a.com=4\nb.com=9")
            .putLong(S.keyExpiresAt, 0)
            .apply()

        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded.pins.map(\.hostname), ["a.com", "b.com"])
        XCTAssertTrue(loaded.pins[1].forceUpdate)
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 4, "b.com": 9])

        XCTAssertNil(try prefs.getString(S.keyPins, nil))
        XCTAssertNil(try prefs.getString(S.keyWatermarkVersions, nil))
        XCTAssertNotNil(try prefs.getString(S.keyPinsJson, nil))
        XCTAssertNotNil(try prefs.getString(S.keyWatermarkVersionsJson, nil))
        // A second read finds the JSON and the same content.
        XCTAssertEqual(try CertificateConfigStore(prefs: prefs).load()?.pins, loaded.pins)
    }

    func testEntriesThePreJSONFormatWasTrickedIntoAreDroppedOnMigration() throws {
        // What a host named "x y|1|h1,h2" + line break + "z=5" left behind:
        // rows whose host is not a host name.
        try prefs.edit()
            .putInt(S.keyVersion, 4)
            .putString(S.keyPins, "good.example.com|4|h1,h2|false\nnot a host|1|h1,h2|false\n*.com|1|h1,h2")
            .putString(S.keyWatermarkVersions, "good.example.com=4\nnot a host=2147483647\n=7")
            .putLong(S.keyExpiresAt, 0)
            .apply()

        XCTAssertEqual(try store.load()?.pins.map(\.hostname), ["good.example.com"])
        XCTAssertEqual(try store.getVersionWatermarks(), ["good.example.com": 4])
    }

    func testCorruptPinsJSONClearsTheActiveConfigButKeepsTheWatermarks() throws {
        try store.save(hostConfig(5, issuedAt: 2_000))
        try prefs.edit().putString(S.keyPinsJson, "{not json").apply()
        XCTAssertNil(try store.load())
        XCTAssertFalse(try prefs.contains(S.keyVersion))
        XCTAssertEqual(try store.getCurrentIssuedAt(), 2_000)
    }

    // ── Envelope, key-set marker, clock reference ───────────────────────

    func testTheSignedEnvelopeIsStoredWithTheConfigAndGoesWithIt() throws {
        let envelope = StoredEnvelope(
            payload: #"{"version":5,"pins":[],"note":"quotes \" and | , = survive","ünicode":"✓ \n"}"#,
            signatures: [SignatureEntry(keyId: "key-1", signature: "c2ln"), SignatureEntry(keyId: nil, signature: "c2lnMg==")]
        )
        try store.save(hostConfig(5, issuedAt: 2_000), envelope: envelope)
        XCTAssertEqual(try store.loadEnvelope(), envelope)

        // A save without an envelope (an unsigned config) leaves none behind.
        try store.save(hostConfig(6, issuedAt: 3_000))
        XCTAssertNil(try store.loadEnvelope())

        try store.save(hostConfig(7, issuedAt: 4_000), envelope: envelope)
        try store.clearActive()
        XCTAssertNil(try store.loadEnvelope())
    }

    func testTheEnvelopePayloadSurvivesByteForByte() throws {
        // Characters a JSON writer might normalise or escape differently.
        let payload = "{\"a\":\"\u{0}\u{1F}\\u00e9\u{E9}e\u{301}\u{1F600}/\"}  \n"
        try store.save(hostConfig(1, issuedAt: 1), envelope: StoredEnvelope(payload: payload, signatures: []))
        XCTAssertEqual(Array(try XCTUnwrap(try store.loadEnvelope()).payload.utf8), Array(payload.utf8))
    }

    func testResetWatermarksForgetsTheWatermarksAndRecordsTheKeySetItWasFor() throws {
        try store.save(hostConfig(5, issuedAt: 2_000, hosts: ["a.com", "b.com"]))
        try store.markRolledBack(hostConfig(9, issuedAt: 9_000))
        try store.clearActive()
        XCTAssertNil(try store.keySetVersionSeen())

        try store.resetWatermarks(keySetVersion: 3, anchors: nil)

        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
        XCTAssertTrue(try store.getVersionWatermarks().isEmpty)
        XCTAssertFalse(try store.isRolledBack(hostConfig(9, issuedAt: 9_000)))
        XCTAssertEqual(try store.keySetVersionSeen(), 3)
    }

    func testTheClockReferenceSurvivesClearActive() throws {
        try store.setHighestSeenTime(123_456)
        try store.save(hostConfig(5, issuedAt: 2_000))
        try store.clearActive()
        XCTAssertEqual(try store.highestSeenTime(), 123_456)
    }

    func testRolledBackConfigIsRecognisedByIssuedAtAndPins() throws {
        let rejected = hostConfig(5, issuedAt: 2_000)
        try store.markRolledBack(rejected)

        XCTAssertTrue(try store.isRolledBack(rejected))
        var later = rejected
        later.issuedAt = 2_001
        XCTAssertFalse(try store.isRolledBack(later))
        XCTAssertFalse(try store.isRolledBack(hostConfig(6, issuedAt: 2_000)))
        // Order does not matter.
        var reordered = rejected
        reordered.pins[0].sha256 = ["h2", "h1"]
        XCTAssertTrue(try store.isRolledBack(reordered))
    }

    func testTrustAnchorsAndKeySetVersionSeenAreRecorded() throws {
        XCTAssertNil(try store.trustAnchorsSeen())
        try store.setTrustAnchorsSeen("abc")
        XCTAssertEqual(try store.trustAnchorsSeen(), "abc")
        try store.setKeySetVersionSeen(4)
        XCTAssertEqual(try store.keySetVersionSeen(), 4)
    }

    // ── One namespace per server (origin) ───────────────────────────────

    private func originEnvironment() throws -> (PrefsFile, KeyedPrefsCipher) {
        let directory = try temporaryStoreDirectory(self)
        let cipher = KeyedPrefsCipher(source: InMemoryPrefsKeySource())
        return (SecureStoreEnvironment(directory: directory, cipher: cipher).file("test_cert_config"), cipher)
    }

    /// The block's store for `origin`, over the test file, the way ConfigApiClient opens it.
    private func storeFor(_ origin: String, _ file: PrefsFile, _ cipher: KeyedPrefsCipher) throws -> CertificateConfigStore {
        try CertificateConfigStore.forOrigin(namespace: "ssl_cert_config_default", origin: origin) { namespace in
            try SecurePreferences(backing: file, fileName: "test_cert_config", namespace: namespace, cipher: cipher)
        }
    }

    private func mtlsConfig(_ version: Int, issuedAt: Int64) -> CertificateConfig {
        CertificateConfig(version: version, pins: [pin("10.0.2.2", ["hash1aaa", "hash2bbb"], version: version)], issuedAt: issuedAt)
    }

    func testEachServerKeepsItsOwnConfigAndWatermarksAndSwitchingBackFindsThemAgain() throws {
        let (file, cipher) = try originEnvironment()
        let tls = try storeFor("scope:default-tls", file, cipher)
        try tls.save(mtlsConfig(39, issuedAt: 5_000))
        try tls.setHighestSeenTime(9_000)

        // The same block pointed at another server: nothing of the first one's
        // version space, nothing wiped either.
        let mtls = try storeFor("scope:sample-mtls", file, cipher)
        XCTAssertNil(try mtls.load())
        XCTAssertNil(try mtls.getVersionWatermarks()["10.0.2.2"], "no cross-server refusal")
        XCTAssertEqual(try mtls.getCurrentIssuedAt(), 0)
        XCTAssertEqual(try mtls.highestSeenTime(), 9_000, "the trusted clock is the block's, not the server's")
        try mtls.save(mtlsConfig(3, issuedAt: 6_000))

        // Back to the first server: its watermarks are where they were.
        let back = try storeFor("scope:default-tls", file, cipher)
        XCTAssertEqual(try back.getVersionWatermarks()["10.0.2.2"], 39)
        XCTAssertEqual(try back.getCurrentIssuedAt(), 5_000)
        XCTAssertEqual(try back.load()?.version, 39)
        // And the second server's are kept too.
        XCTAssertEqual(try storeFor("scope:sample-mtls", file, cipher).getVersionWatermarks()["10.0.2.2"], 3)
    }

    func testResetAndASwitchAwayAndBackDoNotLowerTheReplayGuard() throws {
        let (file, cipher) = try originEnvironment()
        let first = try storeFor("url:https://a.test", file, cipher)
        try first.save(mtlsConfig(7, issuedAt: 8_000))
        try first.clearActive()                                      // PinVault.reset()
        try storeFor("url:https://b.test", file, cipher).clearActive() // init against another URL, reset again
        let again = try storeFor("url:https://a.test", file, cipher)
        XCTAssertEqual(try again.getCurrentIssuedAt(), 8_000)
        XCTAssertEqual(try again.getVersionWatermarks()["10.0.2.2"], 7)
    }

    func testAStoreWithoutAnOriginIsClaimedByTheBlocksOriginNothingDropped() throws {
        let (file, cipher) = try originEnvironment()
        let legacy = CertificateConfigStore(prefs: try SecurePreferences(
            backing: file, fileName: "test_cert_config", namespace: "ssl_cert_config_default", cipher: cipher
        ))
        try legacy.save(mtlsConfig(12, issuedAt: 1_000))

        let bound = try storeFor("scope:prod", file, cipher)
        XCTAssertEqual(try bound.origin(), "scope:prod")
        XCTAssertEqual(try bound.load()?.version, 12)
        XCTAssertNotEqual(
            S.originNamespace("ssl_cert_config_default", origin: "scope:a"),
            S.originNamespace("ssl_cert_config_default", origin: "scope:b"),
            "every other origin has a namespace of its own"
        )
    }

    func testTheAppStoreOpensOnTheSharedFile() throws {
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory)
        let store = try CertificateConfigStore.forOrigin(prefsName: S.prefsNameFor("block a"), origin: "scope:x", environment: environment)
        try store.save(mtlsConfig(2, issuedAt: 5))
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pinvault_secure_config.plist").path))
        XCTAssertEqual(try CertificateConfigStore.forOrigin(prefsName: S.prefsNameFor("block a"), origin: "scope:x", environment: environment)
            .load()?.version, 2)
        XCTAssertEqual(S.namespaceFor("block a"), "ssl_cert_config_block_a")
    }

    // ── Watermarks survive clearActive (2.1.x stores have none) ─────────

    func testClearActiveTurnsTheActiveConfigsIssuedAtAndVersionsIntoWatermarks() throws {
        // What 2.1.x left: the config's own fields, no watermark keys.
        try prefs.edit()
            .putInt(S.keyVersion, 4)
            .putLong(S.keyIssuedAt, 7_000)
            .putString(S.keyPins, "a.com|4|h1,h2|false\nb.com|9|h3,h4|false")
            .commit()
        XCTAssertFalse(try prefs.contains(S.keyWatermarkIssuedAt))

        try store.clearActive()   // e.g. a signed block discarding the envelope-less config

        XCTAssertNil(try store.load())
        XCTAssertEqual(try store.getCurrentIssuedAt(), 7_000)
        XCTAssertEqual(try store.getVersionWatermarks(), ["a.com": 4, "b.com": 9])
    }

    func testAConfigDroppedForABadEnvelopeLeavesNoWatermarksOfItsOwn() throws {
        try store.save(hostConfig(5, issuedAt: 2_000))
        try store.resetWatermarks(keySetVersion: 2, anchors: nil)            // a newer key set revoked its signer
        try store.clearActive(keepAsWatermarks: false)
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
        XCTAssertTrue(try store.getVersionWatermarks().isEmpty)
    }
}
