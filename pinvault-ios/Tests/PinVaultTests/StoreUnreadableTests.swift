import Foundation
import XCTest
@testable import PinVault

/// Port of StoreUnreadableTest: a Keychain that fails is not an empty store.
/// The pin config store and the signing-key store report it
/// (`storeUnreadable`); the signature check fails closed for that attempt and
/// works again once the Keychain does.
///
/// Not ported yet (needs the updater, L2): "an update with an unreadable store
/// applies nothing and works again afterwards" and "init with an unreadable
/// store fails and applies no config".
final class StoreUnreadableTests: XCTestCase {

    private let cipher = FlakyCipher()
    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private var file: PrefsFile!

    override func setUpWithError() throws {
        let directory = try temporaryStoreDirectory(self)
        file = SecureStoreEnvironment(directory: directory, cipher: cipher).file("unreadable_test")
    }

    private func prefs(_ namespace: String, strict: Bool) throws -> SecurePreferences {
        try SecurePreferences(backing: file, fileName: "unreadable_test", namespace: namespace, cipher: cipher, strict: strict)
    }

    private func config(_ version: Int, issuedAt: Int64, expiresAt: Int64) -> CertificateConfig {
        CertificateConfig(
            version: version,
            pins: [HostPin(hostname: "api.test", sha256: [pin("A"), pin("B")], version: version)],
            issuedAt: issuedAt,
            expiresAt: expiresAt
        )
    }

    // ── SecurePreferences ───────────────────────────────────────────────

    func testAStrictStoreThrowsOnAKeychainFailureAndKeepsTheEntry() throws {
        let strict = try prefs("ns", strict: true)
        try strict.edit().putLong("watermark", 42).putString("text", "kept").commit()

        cipher.broken = true
        let reads: [(String, () throws -> Void)] = [
            ("getLong", { _ = try strict.getLong("watermark", 0) }),
            ("getString", { _ = try strict.getString("text", nil) }),
            ("all", { _ = try strict.all() }),
        ]
        for (name, read) in reads {
            let cause = assertStoreUnreadable("an unreadable entry must not read as absent (\(name))", read)
            XCTAssertTrue(cause is ProviderException, "\(String(describing: cause))")
        }

        cipher.broken = false
        XCTAssertEqual(try strict.getLong("watermark", 0), 42)
        XCTAssertEqual(try strict.getString("text", nil), "kept")
    }

    func testAStoreThatIsNotStrictReadsTheDefaultAsBefore() throws {
        let lenient = try prefs("ns", strict: false)
        try lenient.edit().putLong("value", 42).commit()

        cipher.broken = true
        XCTAssertEqual(try lenient.getLong("value", 0), 0)
        cipher.broken = false
        XCTAssertEqual(try lenient.getLong("value", 0), 42)
    }

    func testAnAbsentEntryIsStillAbsentInAStrictStoreToo() throws {
        let strict = try prefs("ns", strict: true)
        cipher.broken = true
        XCTAssertEqual(try strict.getLong("never-written", 7), 7)
        XCTAssertNil(try strict.getString("never-written", nil))
    }

    // ── CertificateConfigStore ──────────────────────────────────────────

    func testTheReplayWatermarkAndExpiresAtAreUnreadableNotZero() throws {
        let store = CertificateConfigStore(prefs: try prefs("config", strict: true))
        try store.save(
            config(4, issuedAt: now, expiresAt: now + hour),
            envelope: StoredEnvelope(payload: "{}", signatures: [SignatureEntry(keyId: nil, signature: "c2ln")])
        )
        try store.setHighestSeenTime(now)

        cipher.broken = true
        let reads: [(String, () throws -> Void)] = [
            ("getCurrentIssuedAt", { _ = try store.getCurrentIssuedAt() }),
            ("getVersionWatermarks", { _ = try store.getVersionWatermarks() }),
            ("load", { _ = try store.load() }),
            ("loadEnvelope", { _ = try store.loadEnvelope() }),
            ("getCurrentVersion", { _ = try store.getCurrentVersion() }),
            ("highestSeenTime", { _ = try store.highestSeenTime() }),
        ]
        for (name, read) in reads { assertStoreUnreadable(name, read) }

        cipher.broken = false
        XCTAssertEqual(try store.getCurrentIssuedAt(), now)
        XCTAssertEqual(try store.load()?.expiresAt, now + hour)
    }

    func testABrokenKeychainOnSaveWritesNothing() throws {
        let store = CertificateConfigStore(prefs: try prefs("config", strict: true))
        try store.save(config(4, issuedAt: now, expiresAt: now + hour))
        let before = try file.entries()

        cipher.broken = true
        assertStoreUnreadable("save reads the watermarks first") { try store.save(self.config(5, issuedAt: self.now + 1, expiresAt: self.now + self.hour)) }
        XCTAssertEqual(try file.entries(), before)
    }

    // ── SignatureTrust: no fallback to the compiled-in keys ─────────────

    func testARevokedSigningKeyIsNotTrustedAgainWhileTheKeySetIsUnreadable() throws {
        let revoked = TestSigner()
        let current = TestSigner()
        let recovery = TestSigner()
        let keyStore = SigningKeyStore(prefs: try prefs("keys", strict: true))
        func trust() -> SignatureTrust {
            SignatureTrust(configApiId: "default", builtInKeys: [revoked.pub, current.pub], builtInThreshold: 1,
                           recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: keyStore)
        }

        // Set v2 leaves the stolen key out.
        let setPayload = keySetPayload(version: 2, keys: [current.pub])
        XCTAssertTrue(try trust().applyKeySetUpdate(SignedKeySet(payload: setPayload, signatures: [recovery.entry(setPayload)])))

        let payload = #"{"version":3,"pins":[]}"#
        let byRevoked = [revoked.entry(payload)]

        // A new process whose Keychain fails: the set cannot be read.
        cipher.broken = true
        let restarted = trust()
        for attempt in 1...2 {
            // Expected, and again on the next call: not remembered as "no set".
            assertStoreUnreadable("attempt \(attempt): with the key set unreadable nothing may verify — least of all the revoked key") {
                _ = try restarted.verifyConfig(payload: payload, entries: byRevoked)
            }
        }
        assertStoreUnreadable("the version is unknown, not 0") { _ = try restarted.keySetVersion() }

        // The Keychain works again: the same instance reads the set and the revocation holds.
        cipher.broken = false
        XCTAssertFalse(try restarted.verifyConfig(payload: payload, entries: byRevoked).ok)
        XCTAssertTrue(try restarted.verifyConfig(payload: payload, entries: [current.entry(payload)]).ok)
        XCTAssertEqual(try restarted.keySetVersion(), 2)
    }

    func testAKeySetStoreThatCannotBeOpenedIsNotNoKeySetEither() throws {
        let key = TestSigner()
        let recovery = TestSigner()
        let opens = Locked(0)
        let keyStore = SigningKeyStore(prefs: try prefs("keys", strict: true))
        let trust = SignatureTrust(
            configApiId: "default", builtInKeys: [key.pub], builtInThreshold: 1, recoveryKeys: [recovery.pub], recoveryThreshold: 1
        ) {
            let attempt = opens.withLock { count -> Int in
                count += 1
                return count
            }
            if attempt == 1 { throw ProviderException(message: "Keystore unavailable") }
            return keyStore
        }
        let payload = #"{"version":3,"pins":[]}"#
        let entries = [key.entry(payload)]

        assertStoreUnreadable("the store did not open") { _ = try trust.verifyConfig(payload: payload, entries: entries) }
        // Tried again on the next use.
        XCTAssertTrue(try trust.verifyConfig(payload: payload, entries: entries).ok)
        XCTAssertEqual(opens.get(), 2)
    }

    func testAStoredEnvelopeWhoseKeySetIsUnreadableIsCannotTellNotRejected() throws {
        let key = TestSigner()
        let recovery = TestSigner()
        let keyStore = SigningKeyStore(prefs: try prefs("keys", strict: true))
        try keyStore.save("default", SignedKeySet(payload: "{}", signatures: []))
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [key.pub], builtInThreshold: 1,
                                   recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: keyStore)
        let verifier = SignedConfigVerifier(trust: trust)
        let payload = #"{"version":1,"pins":[{"hostname":"api.test","sha256":["\#(pin("A"))","\#(pin("B"))"],"version":1}],"issuedAt":1,"expiresAt":2}"#

        cipher.broken = true
        assertStoreUnreadable("verifyStored") {
            _ = try verifier.verifyStored(StoredEnvelope(payload: payload, signatures: [key.entry(payload)]))
        }
        cipher.broken = false
        XCTAssertNotNil(try verifier.verifyStored(StoredEnvelope(payload: payload, signatures: [key.entry(payload)])))
    }
}
