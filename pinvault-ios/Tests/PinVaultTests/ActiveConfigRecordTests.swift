import Foundation
import XCTest
@testable import PinVault

/// Which signed config is the active one is recorded outside the container
/// (security review 2026-11-14, I1). A stored envelope proves it was signed
/// for this block and has not expired — an older copy of the container holds
/// an older one that proves the same, and it used to become the active config
/// again until it expired. The updater over a real ``CertificateConfigStore``
/// and a mirror in memory standing in for the Keychain item.
final class ActiveConfigRecordTests: XCTestCase {

    private typealias MemoryMirror = WatermarkMirrorTests.MemoryMirror

    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private let pin1 = pin("A"), pin2 = pin("B")
    private let key = TestSigner()

    private var mirror: MemoryMirror!
    private var prefs: InMemoryPreferences!
    private var store: CertificateConfigStore!
    private var api: SignedFakeApi!
    private var provider: HttpClientProvider!

    override func setUp() {
        mirror = MemoryMirror()
        api = SignedFakeApi()
        open(InMemoryPreferences())
    }

    /// The app starts over the container `prefs`; the Keychain item is the same one.
    private func open(_ prefs: InMemoryPreferences, mirror: (any WatermarkMirror)? = nil) {
        self.prefs = prefs
        store = CertificateConfigStore(prefs: prefs, mirror: mirror ?? self.mirror)
        let now = self.now
        store.clock = { now }
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    /// The container as it is now, to be put back later.
    private func snapshot() throws -> InMemoryPreferences {
        InMemoryPreferences(try prefs.all())
    }

    private func updater() -> SSLCertificateUpdater {
        let now = self.now
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [key.pub], builtInThreshold: 1,
                                   recoveryKeys: [], recoveryThreshold: 1, store: nil)
        return SSLCertificateUpdater(
            configApi: api, configStore: store, httpClientProvider: provider, maxRetryCount: 1,
            clock: { now }, verifier: SignedConfigVerifier(trust: trust, serverScope: nil, clock: { now }), sleep: { _ in }
        )
    }

    private func signed(_ version: Int, issuedAt: Int64) -> SignedConfigResponse {
        let payload = signedPayload(version: version, issuedAt: issuedAt, expiresAt: issuedAt + hour,
                                    pins: [pin1, pin2], hosts: [("api.test", version)])
        return SignedConfigResponse(payload: payload, signature: key.sign(payload), keyId: key.id, signingKeys: nil)
    }

    private func envelopeId(_ response: SignedConfigResponse) -> String {
        CertificateConfigStore.envelopeId(StoredEnvelope(payload: response.payload, signatures: []))
    }

    @discardableResult
    private func apply(_ response: SignedConfigResponse) async -> UpdateResult {
        api.next = response
        api.failure = nil
        return await updater().updateNow()
    }

    private func offline() {
        api.failure = PinVaultError.io(message: "offline")
    }

    // MARK: An older container put back

    func testAnOlderContainerPutBackDoesNotMakeItsOlderSignedConfigActiveAgain() async throws {
        let older = signed(4, issuedAt: now)
        let current = signed(5, issuedAt: now + 1)
        await apply(older)
        let earlier = try snapshot()
        let updated = await apply(current)
        XCTAssertEqual(updated, .updated(newVersion: 5))
        XCTAssertEqual(mirror.values.active, [envelopeId(current)])

        // The container from before the update is put back; the Keychain item is not part of it.
        open(earlier)
        XCTAssertEqual(try store.load()?.version, 4, "the older config is what the container holds")
        offline()
        let started = try await updater().initializeAndUpdate()
        guard case .failed(let reason, let exception) = started else { return XCTFail("\(started)") }
        XCTAssertTrue(reason.contains("it is not the one this device last stored"), reason)
        guard case PinVaultError.noConfigAvailable? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertNil(provider.currentConfig, "the older pins are not applied")
        XCTAssertNil(try store.load(), "discarded: no config until a fetch")

        // The watermarks are where the newest config put them.
        XCTAssertEqual(try store.getCurrentIssuedAt(), now + 1)
        XCTAssertEqual(try store.getVersionWatermarks(), ["api.test": 5])
        let replayed = await apply(older)
        guard case .failed(let why, _) = replayed else { return XCTFail("\(replayed)") }
        XCTAssertTrue(why.contains("Config replay rejected"), why)

        // The config the server has now sits AT the watermark: taken as the
        // newest this device has seen, not refused as a replay.
        let fetched = await apply(current)
        XCTAssertEqual(fetched, .updated(newVersion: 5))
        XCTAssertEqual(provider.currentConfig?.pins.first?.version, 5)
        XCTAssertEqual(mirror.values.active, [envelopeId(current)])
    }

    func testTheNextStartFetchesTheCurrentConfigOverAnOlderContainer() async throws {
        let current = signed(5, issuedAt: now + 1)
        await apply(signed(4, issuedAt: now))
        let earlier = try snapshot()
        await apply(current)

        open(earlier)
        api.next = current
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 5), "online, the device is back on the current config at once")
        XCTAssertEqual(provider.currentConfig?.pins.first?.version, 5)
    }

    func testAfterAResetAnOlderContainerDoesNotBringTheClearedConfigBack() async throws {
        let config = signed(4, issuedAt: now)
        await apply(config)
        let earlier = try snapshot()
        // PinVault.reset(): the active config goes, the watermarks stay.
        try store.clearActive()
        XCTAssertEqual(mirror.values.active, [], "the record says nothing is active")

        open(earlier)
        offline()
        let started = try await updater().initializeAndUpdate()
        guard case .failed = started else { return XCTFail("\(started)") }
        XCTAssertNil(provider.currentConfig)
        // Fetched again, it is the newest config this device has seen.
        let fetched = await apply(config)
        XCTAssertEqual(fetched, .updated(newVersion: 4))
    }

    // MARK: What must keep working

    func testAConfigRolledBackToAfterAFailedHealthCheckIsStillTheActiveOneAfterARestart() async throws {
        let good = signed(4, issuedAt: now)
        let bad = signed(5, issuedAt: now + 1)
        api.next = good
        let first = try await updater().initializeAndUpdate()
        XCTAssertEqual(first, .ready(version: 4))

        // The next config cuts the device off its backend: rolled back to the one before.
        api.next = bad
        api.healthy = false
        let second = try await updater().initializeAndUpdate()
        guard case .failed = second else { return XCTFail("\(second)") }
        XCTAssertEqual(try store.load()?.version, 4)
        XCTAssertEqual(mirror.values.issuedAt, now + 1, "the watermark is not lowered by the rollback")
        XCTAssertEqual(mirror.values.active, [envelopeId(good)], "the rollback's save is the last one on record")

        // The active config is OLDER than the watermark now, and rightly so.
        open(prefs)
        offline()
        let restarted = try await updater().initializeAndUpdate()
        XCTAssertEqual(restarted, .ready(version: 4))
        XCTAssertEqual(provider.currentConfig?.pins.first?.version, 4)
    }

    func testAStoreWrittenBeforeTheRecordExistedIsAcceptedOnceAndRecorded() async throws {
        // 2.10.0: the config is saved, the Keychain copy knows watermarks only.
        let config = signed(4, issuedAt: now)
        open(InMemoryPreferences(), mirror: NoWatermarkMirror())
        await apply(config)
        XCTAssertNil(mirror.values.active)

        // The update: the same container, now with the record.
        open(prefs)
        offline()
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 4))
        XCTAssertEqual(mirror.values.active, [envelopeId(config)], "written down at the first load")

        // From here on an older container is told apart.
        let earlier = try snapshot()
        await apply(signed(5, issuedAt: now + 1))
        open(earlier)
        offline()
        let rolledBack = try await updater().initializeAndUpdate()
        guard case .failed = rolledBack else { return XCTFail("\(rolledBack)") }
    }

    func testTheSameConfigServedAgainAndAFreshnessWriteBackKeepTheRecordInStep() async throws {
        let first = signed(4, issuedAt: now)
        await apply(first)
        let again = await apply(first)
        XCTAssertEqual(again, .alreadyCurrent)
        XCTAssertEqual(mirror.values.active, [envelopeId(first)])

        // The same pins under a newer envelope: written back with that envelope.
        let fresher = signed(4, issuedAt: now + 5)
        let writtenBack = await apply(fresher)
        XCTAssertEqual(writtenBack, .alreadyCurrent)
        XCTAssertEqual(mirror.values.active, [envelopeId(fresher)])

        open(prefs)
        offline()
        let restarted = try await updater().initializeAndUpdate()
        XCTAssertEqual(restarted, .ready(version: 4))
    }

    // MARK: The record itself

    private func envelope(_ text: String) -> StoredEnvelope {
        StoredEnvelope(payload: text, signatures: [SignatureEntry(keyId: "k", signature: "c2ln")])
    }

    private func config(_ version: Int, issuedAt: Int64) -> CertificateConfig {
        CertificateConfig(version: version, pins: [HostPin(hostname: "a.com", sha256: ["h1", "h2"], version: version)],
                          issuedAt: issuedAt, expiresAt: issuedAt + 10_000)
    }

    func testASaveThatDoesNotReachTheStoreLeavesTheConfigItHoldsOnRecord() throws {
        /// Preferences whose writes fail while `failing` is set (a full disk).
        final class FailingPreferences: PreferenceStore, @unchecked Sendable {
            let inner = InMemoryPreferences()
            let failing = Locked(false)
            func value(_ key: String) throws -> PrefValue? { try inner.value(key) }
            func contains(_ key: String) throws -> Bool { try inner.contains(key) }
            func all() throws -> [String: PrefValue] { try inner.all() }
            @discardableResult func write(_ changes: PreferenceChanges, sync: Bool) throws -> Bool {
                if failing.get() { throw PinVaultError.io(message: "disk full") }
                return try inner.write(changes, sync: sync)
            }
        }
        let prefs = FailingPreferences()
        let store = CertificateConfigStore(prefs: prefs, mirror: mirror)
        let held = envelope("held"), lost = envelope("lost"), next = envelope("next")
        try store.save(config(1, issuedAt: 1_000), envelope: held)

        prefs.failing.set(true)
        XCTAssertThrowsError(try store.save(config(2, issuedAt: 2_000), envelope: lost))
        XCTAssertTrue(try store.isActiveEnvelope(held), "the store still holds it, and the record still names it")

        prefs.failing.set(false)
        try store.save(config(3, issuedAt: 3_000), envelope: next)
        XCTAssertEqual(mirror.values.active, [CertificateConfigStore.envelopeId(next)], "one config is active once the save is through")
        XCTAssertFalse(try store.isActiveEnvelope(held))
        XCTAssertFalse(try store.isActiveEnvelope(lost))
    }

    func testTheSamePayloadSignedAgainIsTheSameConfig() {
        let one = StoredEnvelope(payload: "p", signatures: [SignatureEntry(keyId: "a", signature: "czE=")])
        let two = StoredEnvelope(payload: "p", signatures: [SignatureEntry(keyId: "b", signature: "czI=")])
        XCTAssertEqual(CertificateConfigStore.envelopeId(one), CertificateConfigStore.envelopeId(two))
        XCTAssertNotEqual(CertificateConfigStore.envelopeId(one), CertificateConfigStore.envelopeId(envelope("q")))
    }

    func testAnUnreadableRecordIsNoVerdict() throws {
        final class Unreadable: WatermarkMirror, @unchecked Sendable {
            func read() -> MirroredWatermarks? { nil }
            @discardableResult func write(_ values: MirroredWatermarks) -> Bool { false }
        }
        let store = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: Unreadable())
        XCTAssertThrowsError(try store.isActiveEnvelope(envelope("p")), "neither \"active\" nor \"put back\": the start tries again")
    }

    func testWithoutAMirrorEveryStoredEnvelopeCountsAsBefore() throws {
        // No Keychain for the process (unsigned test runs), static pins: nothing is recorded, nothing refused.
        let store = CertificateConfigStore(prefs: InMemoryPreferences())
        try store.save(config(1, issuedAt: 1_000), envelope: envelope("a"))
        XCTAssertTrue(try store.isActiveEnvelope(envelope("a")))
        XCTAssertTrue(try store.isActiveEnvelope(envelope("b")))
    }

    func testAWipeForgetsTheRecordAndAKeySetResetKeepsIt() throws {
        let store = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        try store.setKeySetVersionSeen(1)
        try store.save(config(1, issuedAt: 1_000), envelope: envelope("a"))
        // A newer signing-key set lowers the watermarks; which config is active did not change.
        try store.resetWatermarks(keySetVersion: 2, anchors: nil)
        XCTAssertEqual(mirror.values.issuedAt, 0)
        XCTAssertEqual(mirror.values.active, [CertificateConfigStore.envelopeId(envelope("a"))])

        try store.wipeAll()
        XCTAssertNil(mirror.values.active)
    }

    func testTheKeychainFormKeepsTheRecord() {
        var values = MirroredWatermarks()
        values.issuedAt = 5
        XCTAssertNil(KeychainWatermarkMirror.decode(KeychainWatermarkMirror.encode(values)).active, "no record is not an empty one")
        values.active = []
        XCTAssertEqual(KeychainWatermarkMirror.decode(KeychainWatermarkMirror.encode(values)).active, [])
        values.active = ["ab12", "cd34"]
        XCTAssertEqual(KeychainWatermarkMirror.decode(KeychainWatermarkMirror.encode(values)), values)
    }
}
