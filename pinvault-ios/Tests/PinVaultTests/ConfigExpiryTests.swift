import Foundation
import XCTest
@testable import PinVault

/// Port of ConfigExpiryTest (Y1/O6): a stored config is bounded by its
/// `expiresAt`, a rollback never lowers the replay watermarks, and values that
/// would lock the device out for good are refused. The updater over a real store.
final class ConfigExpiryTests: XCTestCase {

    private let pin1 = pin("A"), pin2 = pin("B")
    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000

    private var prefs: InMemoryPreferences!
    private var store: CertificateConfigStore!
    private var api: FakeConfigApi!
    private var provider: HttpClientProvider!

    override func setUp() {
        prefs = InMemoryPreferences()
        store = CertificateConfigStore(prefs: prefs)
        let now = self.now
        store.clock = { now }
        api = FakeConfigApi()
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    private func updater(graceMs: Int64 = 0) -> SSLCertificateUpdater {
        let now = self.now
        return SSLCertificateUpdater(
            configApi: api, configStore: store, httpClientProvider: provider, maxRetryCount: 1,
            expiredConfigGraceMs: graceMs, clock: { now }, sleep: { _ in }
        )
    }

    private func config(_ version: Int, issuedAt: Int64, expiresAt: Int64, host: String = "api.test") -> CertificateConfig {
        CertificateConfig(version: version, pins: [HostPin(hostname: host, sha256: [pin1, pin2], version: version)], issuedAt: issuedAt, expiresAt: expiresAt)
    }

    // MARK: Expiry at start

    func testAnExpiredStoredConfigIsRefusedWhenTheBackendIsUnreachable() async throws {
        try store.save(config(4, issuedAt: now - 30 * hour, expiresAt: now - 6 * hour))
        api.fails("blocked")
        let result = try await updater().initializeAndUpdate()
        guard case .failed(_, let exception) = result, case .configExpired(let expiresAt, _, _)? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertEqual(expiresAt, now - 6 * hour)
    }

    func testAnUnexpiredStoredConfigStillStartsOffline() async throws {
        try store.save(config(4, issuedAt: now - hour, expiresAt: now + hour))
        api.fails()
        let result = try await updater().initializeAndUpdate()
        XCTAssertEqual(result, .ready(version: 4))
    }

    func testTheGracePeriodKeepsAnExpiredConfigUsableThatMuchLonger() async throws {
        try store.save(config(4, issuedAt: now - 30 * hour, expiresAt: now - 6 * hour))
        api.fails()
        let within = try await updater(graceMs: 7 * hour).initializeAndUpdate()
        XCTAssertEqual(within, .ready(version: 4))
        let beyond = try await updater(graceMs: 5 * hour).initializeAndUpdate()
        guard case .failed = beyond else { return XCTFail("\(beyond)") }
    }

    func testAnExpiredStoredConfigIsRefusedWithoutAClientCertificateToo() async throws {
        try store.save(config(4, issuedAt: now - 30 * hour, expiresAt: now - 6 * hour))
        let result = try await updater().initializeAndUpdate(needsClientCertificate: true)
        guard case .failed(_, let exception) = result, case .configExpired? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
    }

    func testAFreshEnvelopeWithTheSamePinsMovesExpiresAtForward() async throws {
        try store.save(config(4, issuedAt: now - 30 * hour, expiresAt: now - 6 * hour))
        api.returns(config(4, issuedAt: now - 60_000, expiresAt: now + 24 * hour))

        let result = try await updater().initializeAndUpdate()

        XCTAssertEqual(result, .ready(version: 4))
        XCTAssertEqual(try store.load()?.expiresAt, now + 24 * hour)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - 60_000)
        XCTAssertEqual(provider.currentConfig?.expiresAt, now + 24 * hour, "the live session follows the disk")
    }

    func testTheSameEnvelopeServedAgainReplacesAnEstimatedExpiresAt() async throws {
        // Stored by 2.1.1: no expiresAt kept, so the store estimates first load + 7 days.
        try prefs.edit()
            .putInt(CertificateConfigStore.keyVersion, 4)
            .putString(CertificateConfigStore.keyPins, "api.test|4|\(pin1),\(pin2)|false")
            .putLong(CertificateConfigStore.keyIssuedAt, now - hour)
            .commit()
        // The server caches its signature and serves the same envelope, valid for 7 days.
        api.returns(config(4, issuedAt: now - hour, expiresAt: now + 7 * 24 * hour))

        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertEqual(try store.load()?.expiresAt, now + 7 * 24 * hour)
    }

    func testAConfigStoredBy211WithAnOldIssuedAtStillStartsOfflineAfterTheUpdate() async throws {
        // 2.1.1 never wrote issuedAt back while the pins stayed the same: weeks old.
        try prefs.edit()
            .putInt(CertificateConfigStore.keyVersion, 4)
            .putString(CertificateConfigStore.keyPins, "api.test|4|\(pin1),\(pin2)|false")
            .putLong(CertificateConfigStore.keyIssuedAt, now - 40 * 24 * hour)
            .commit()
        api.fails()
        let result = try await updater().initializeAndUpdate()
        XCTAssertEqual(result, .ready(version: 4))
        XCTAssertEqual(provider.currentConfig?.expiresAt, now + 7 * 24 * hour)
    }

    func testAConfigWithoutExpiresAtNeverExpires() async throws {
        try store.save(config(4, issuedAt: 0, expiresAt: 0))
        api.fails()
        let result = try await updater().initializeAndUpdate()
        XCTAssertEqual(result, .ready(version: 4))
    }

    func testNoStoredConfigAndNoBackendIsStillNoConfigAvailable() async throws {
        api.fails()
        let result = try await updater().initializeAndUpdate()
        guard case .failed(_, let exception) = result, case .noConfigAvailable? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
    }

    // MARK: O6: values that would lock the device out

    func testIssuedAtMoreThanAnHourAheadIsRefused() async throws {
        api.returns(config(1, issuedAt: now + 61 * 60_000, expiresAt: now + 24 * hour))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("ahead of this device's clock"), reason)
        XCTAssertNil(try store.load())
    }

    func testIssuedAtSlightlyAheadIsAccepted() async throws {
        api.returns(config(1, issuedAt: now + 50 * 60_000, expiresAt: now + 24 * hour))
        let result = await updater().updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }
    }

    func testAnAlreadyExpiredConfigFromACustomAPIIsRefusedAndTheStoredOneKept() async throws {
        try store.save(config(4, issuedAt: now - hour, expiresAt: now + hour))
        api.returns(config(5, issuedAt: now - 30 * 60_000, expiresAt: now - 1))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("already expired"), reason)
        XCTAssertEqual(try store.load()?.pins.first?.version, 4)
    }

    func testAValidityWindowOverThirtyDaysIsRefused() async throws {
        api.returns(config(1, issuedAt: now, expiresAt: now + 31 * 24 * hour))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("more than 30 days"), reason)
    }

    func testAPerHostVersionJumpOverAMillionIsRefused() async throws {
        try store.save(config(4, issuedAt: now - hour, expiresAt: now + hour))
        api.returns(config(1_000_005, issuedAt: now, expiresAt: now + hour))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("version jump rejected for api.test"), reason)
        XCTAssertEqual(try store.load()?.pins.first?.version, 4)
    }

    func testANewHostStartsAtAMillionAtMost() async throws {
        api.returns(config(1_000_001, issuedAt: now, expiresAt: now + hour))
        let refused = await updater().updateNow()
        guard case .failed(let reason, _) = refused else { return XCTFail("\(refused)") }
        XCTAssertTrue(reason.contains("first version"), reason)
        XCTAssertNil(try store.load())

        api.returns(config(1_000_000, issuedAt: now, expiresAt: now + hour))
        let accepted = await updater().updateNow()
        guard case .updated = accepted else { return XCTFail("\(accepted)") }
    }

    // MARK: Rollback keeps the watermarks

    func testRollbackRestoresTheOldPinsButNotTheOldWatermarks() async throws {
        let previous = config(4, issuedAt: now - 2 * hour, expiresAt: now + 20 * hour)
        let rejected = config(5, issuedAt: now - hour, expiresAt: now + 23 * hour)
        try store.save(previous)
        api.returns(rejected)
        api.healthy = { false }

        let result = try await updater().initializeAndUpdate()
        guard case .failed = result else { return XCTFail("\(result)") }

        XCTAssertEqual(try store.load()?.pins.first?.version, 4, "previous pins are back")
        XCTAssertEqual(provider.currentConfig, previous)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - hour, "issuedAt watermark stays at the rejected config")
        XCTAssertEqual(try store.getVersionWatermarks()["api.test"], 5)

        // An older signed config between the two, with other content, is now a replay.
        api.returns(config(3, issuedAt: now - 90 * 60_000, expiresAt: now + hour))
        let replay = await updater().updateNow()
        guard case .failed(let reason, _) = replay else { return XCTFail("\(replay)") }
        XCTAssertTrue(reason.contains("replay"), reason)
        // An older copy of exactly the restored config changes nothing: current, not an alarm.
        api.returns(config(4, issuedAt: now - 90 * 60_000, expiresAt: now + hour))
        let current = await updater().updateNow()
        XCTAssertEqual(current, .alreadyCurrent)
        XCTAssertEqual(provider.currentConfig, previous)
    }

    func testTheRolledBackConfigItselfMayBeAppliedAgain() async throws {
        let previous = config(4, issuedAt: now - 2 * hour, expiresAt: now + 20 * hour)
        let rejected = config(5, issuedAt: now - hour, expiresAt: now + 23 * hour)
        try store.save(previous)
        api.returns(rejected)
        api.healthy = { false }
        _ = try await updater().initializeAndUpdate()

        api.healthy = { true }
        let result = try await updater().initializeAndUpdate()
        XCTAssertEqual(result, .ready(version: 5))
        XCTAssertEqual(try store.load(), rejected)
    }

    func testTheSameIssuedAtWithOtherPinsIsStillAReplayAfterARollback() async throws {
        try store.save(config(4, issuedAt: now - 2 * hour, expiresAt: now + 20 * hour))
        api.returns(config(5, issuedAt: now - hour, expiresAt: now + 23 * hour))
        api.healthy = { false }
        _ = try await updater().initializeAndUpdate()

        api.returns(config(6, issuedAt: now - hour, expiresAt: now + 23 * hour))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("replay"), reason)
    }

    func testAFirstConfigThatFailsItsHealthCheckLeavesTheWatermarkInPlace() async throws {
        api.returns(config(5, issuedAt: now - hour, expiresAt: now + 23 * hour))
        api.healthy = { false }

        let result = try await updater().initializeAndUpdate()
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertNil(try store.load())
        XCTAssertNil(provider.currentConfig)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - hour)
    }
}
