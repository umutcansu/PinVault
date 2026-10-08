import Foundation
import XCTest
@testable import PinVault

/// The watermarks and the clock reference are mirrored outside the container
/// (``WatermarkMirror``): putting an older copy of the store's file back does
/// not move them back; the library's own resets still do.
final class WatermarkMirrorTests: XCTestCase {

    /// A mirror in memory, standing in for the Keychain item.
    final class MemoryMirror: WatermarkMirror, @unchecked Sendable {
        private let stored = Locked(MirroredWatermarks())
        var values: MirroredWatermarks { stored.get() }
        func read() -> MirroredWatermarks { stored.get() }
        func write(_ values: MirroredWatermarks) { stored.set(values) }
    }

    private func config(_ version: Int, issuedAt: Int64, hosts: [String] = ["a.com"]) -> CertificateConfig {
        CertificateConfig(
            version: version,
            pins: hosts.map { HostPin(hostname: $0, sha256: ["h1", "h2"], version: version) },
            issuedAt: issuedAt,
            expiresAt: issuedAt + 10_000
        )
    }

    func testAnOlderContainerPutBackDoesNotLowerTheWatermarks() throws {
        let mirror = MemoryMirror()
        let live = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        try live.save(config(1, issuedAt: 1_000))
        try live.save(config(7, issuedAt: 5_000, hosts: ["a.com", "b.com"]))

        // The container as it was after the first config only.
        let earlier = InMemoryPreferences()
        try CertificateConfigStore(prefs: earlier).save(config(1, issuedAt: 1_000))
        let restored = CertificateConfigStore(prefs: earlier, mirror: mirror)
        XCTAssertEqual(try restored.getCurrentIssuedAt(), 5_000)
        XCTAssertEqual(try restored.getVersionWatermarks(), ["a.com": 7, "b.com": 7])
    }

    func testTheMirrorIsNeverLoweredBySavingAnOlderConfig() throws {
        let mirror = MemoryMirror()
        let store = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        try store.save(config(5, issuedAt: 5_000))
        try store.markRolledBack(config(5, issuedAt: 5_000))
        try store.save(config(2, issuedAt: 2_000))
        XCTAssertEqual(mirror.values.issuedAt, 5_000)
        XCTAssertEqual(mirror.values.versions["a.com"], 5)
    }

    func testAKeySetResetLowersTheMirrorToo() throws {
        let mirror = MemoryMirror()
        let store = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        try store.save(config(9, issuedAt: 9_000))
        try store.clearActive()
        try store.resetWatermarks(keySetVersion: 3)
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0, "a revoked key set's watermarks do not hold")
        XCTAssertEqual(try store.getVersionWatermarks(), [:])
        XCTAssertEqual(mirror.values.keySetVersion, 3)
    }

    func testTheClockReferenceSurvivesAContainerPutBackAndFollowsTheLibrarysOwnReset() throws {
        let mirror = MemoryMirror()
        let live = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        try live.setHighestSeenTime(1_000_000)
        try live.setHighestSeenTime(1_030_000)   // less than a step ahead: the copy waits
        XCTAssertEqual(mirror.values.clock, 1_000_000)
        try live.setHighestSeenTime(1_100_000)
        XCTAssertEqual(mirror.values.clock, 1_100_000)

        let restored = CertificateConfigStore(prefs: InMemoryPreferences(), mirror: mirror)
        XCTAssertEqual(try restored.highestSeenTime(), 1_100_000, "an empty or older container does not set the clock back")

        // TrustedClock.resetTo persists a lower reference: the copy follows.
        try live.setHighestSeenTime(900_000)
        XCTAssertEqual(mirror.values.clock, 900_000)
        XCTAssertEqual(try restored.highestSeenTime(), 900_000)
    }

    func testAnotherOriginKeepsItsOwnWatermarksAndSharesTheBlocksClock() throws {
        var mirrors: [String: MemoryMirror] = [:]
        let mirrorFor: (String) -> any WatermarkMirror = { namespace in
            if let existing = mirrors[namespace] { return existing }
            let made = MemoryMirror()
            mirrors[namespace] = made
            return made
        }
        var files: [String: InMemoryPreferences] = [:]
        let open: (String) throws -> any PreferenceStore = { namespace in
            if let existing = files[namespace] { return existing }
            let made = InMemoryPreferences()
            files[namespace] = made
            return made
        }
        let first = try CertificateConfigStore.forOrigin(namespace: "block", origin: "https://one/", mirror: mirrorFor, open: open)
        try first.save(config(4, issuedAt: 4_000))
        try first.setHighestSeenTime(2_000_000)
        let second = try CertificateConfigStore.forOrigin(namespace: "block", origin: "https://two/", mirror: mirrorFor, open: open)
        XCTAssertEqual(try second.getCurrentIssuedAt(), 0, "another server's version space")
        XCTAssertEqual(try second.highestSeenTime(), 2_000_000, "the block's clock")
    }

    func testTheKeychainFormRoundTrips() {
        var values = MirroredWatermarks()
        values.issuedAt = 1_759_660_801_234
        values.versions = ["a.com": 3, "*.b.com": 12]
        values.clock = 1_759_660_900_000
        values.keySetVersion = 2
        XCTAssertEqual(KeychainWatermarkMirror.decode(KeychainWatermarkMirror.encode(values)), values)
        XCTAssertEqual(KeychainWatermarkMirror.decode(Data("not json".utf8)), MirroredWatermarks())
    }
}
