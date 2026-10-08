import Foundation
import XCTest
@testable import PinVault

/// Port of SSLCertificateUpdaterTest: change detection, mTLS host
/// certificates, the replay and downgrade guards, the post-update health gate
/// with rollback, and force flags reaching the disk in both directions.
final class SSLCertificateUpdaterTests: XCTestCase {

    private var api: FakeConfigApi!
    private var store: SpyConfigStore!
    private var sslManager: DynamicSSLManager!
    private var provider: HttpClientProvider!
    private var certStore: InMemoryHostCertStore!
    private let password = "changeit"

    private let pin1 = pin("A"), pin2 = pin("B"), pin3 = pin("C")

    override func setUp() {
        api = FakeConfigApi()
        store = SpyConfigStore()
        sslManager = testManager()
        provider = HttpClientProvider(sslManager: sslManager)
        certStore = InMemoryHostCertStore()
    }

    private func updater(maxRetry: Int = 1) -> SSLCertificateUpdater {
        SSLCertificateUpdater(
            configApi: api, configStore: store, httpClientProvider: provider, sslManager: sslManager,
            certStore: certStore, clientKeyPassword: password, maxRetryCount: maxRetry, sleep: { _ in }
        )
    }

    /// What the store holds before the test (the mocks' `configStore.load()`).
    private func stored(_ config: CertificateConfig) throws {
        try store.base.save(config)
    }

    private func config(_ version: Int, pins: [HostPin], forceUpdate: Bool = false, issuedAt: Int64 = 0, expiresAt: Int64 = 0) -> CertificateConfig {
        CertificateConfig(version: version, pins: pins, forceUpdate: forceUpdate, issuedAt: issuedAt, expiresAt: expiresAt)
    }

    private func host(_ name: String, _ version: Int, pins: [String]? = nil, forceUpdate: Bool = false,
                      mtls: Bool = false, clientCertVersion: Int? = nil) -> HostPin {
        HostPin(hostname: name, sha256: pins ?? [pin1, pin2], version: version, forceUpdate: forceUpdate, mtls: mtls, clientCertVersion: clientCertVersion)
    }

    private func host(_ version: Int, pins: [String]? = nil, forceUpdate: Bool = false, mtls: Bool = false, clientCertVersion: Int? = nil) -> HostPin {
        host("api.test", version, pins: pins, forceUpdate: forceUpdate, mtls: mtls, clientCertVersion: clientCertVersion)
    }

    // MARK: No client certificate yet

    func testInitWithoutAClientCertificateDoesNotContactTheBackendAndAsksForEnrollment() async throws {
        let result = try await updater(maxRetry: 3).initializeAndUpdate(needsClientCertificate: true)
        guard case .failed(_, let exception) = result, case .clientCertificateRequired? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertEqual(api.fetches, 0)
        XCTAssertEqual(api.scopedFetches, 0)
    }

    func testInitWithoutAClientCertificateStillAppliesAStoredConfig() async throws {
        try stored(config(7, pins: [host(7)]))
        let result = try await updater(maxRetry: 3).initializeAndUpdate(needsClientCertificate: true)
        XCTAssertEqual(result, .ready(version: 7))
        XCTAssertEqual(provider.getVersion(), 7)
        XCTAssertEqual(api.fetches, 0)
    }

    func testInitWithoutAClientCertificateRefusesAStoredForceUpdateConfig() async throws {
        try stored(config(7, pins: [host(7, forceUpdate: true)], forceUpdate: true))
        let result = try await updater().initializeAndUpdate(needsClientCertificate: true)
        guard case .failed(_, let exception) = result, case .clientCertificateRequired? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
    }

    // MARK: Change detection

    func testANewConfigIsDetectedAndSaved() async throws {
        let remote = config(1, pins: [host(1)])
        api.returns(remote)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .updated(newVersion: 1))
        XCTAssertEqual(store.saves, [remote])
    }

    func testTheSameConfigIsAlreadyCurrent() async throws {
        let same = config(1, pins: [host(1)])
        try stored(same)
        api.returns(same)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
    }

    func testAnMTLSHostsClientCertVersionChangeIsDetected() async throws {
        try stored(config(1, pins: [host(1, mtls: true, clientCertVersion: 1)]))
        api.returns(config(1, pins: [host(2, mtls: true, clientCertVersion: 2)]))
        let p12 = TLSFixture.p12("client-a")
        api.hostCert = { _ in p12 }
        certStore.put("host_api.test", Data([1]))

        let result = await updater().updateNow()

        XCTAssertEqual(result, .updated(newVersion: 2))
        XCTAssertEqual(api.hostCertDownloads, ["api.test"])
        XCTAssertEqual(certStore.saved, ["host_api.test"])
        XCTAssertEqual(certStore.stored["host_api.test"], p12)
        XCTAssertEqual(sslManager.clientIdentity(forHost: "api.test", port: 443, config: { nil })?.owner, .host("api.test"))
    }

    func testAFailedHostCertDownloadFallsBackToTheStore() async throws {
        try stored(config(1, pins: [host(1)]))
        api.returns(config(1, pins: [host(2, mtls: true, clientCertVersion: 1)]))
        api.hostCert = { _ in throw PinVaultError.io(message: "Network error") }
        let cached = TLSFixture.p12("client-b")
        // Not "exists" for the download decision… but loadable as the fallback.
        let store = FallbackOnlyHostCertStore(fallback: cached)
        let updater = SSLCertificateUpdater(
            configApi: api, configStore: self.store, httpClientProvider: provider, sslManager: sslManager,
            certStore: store, clientKeyPassword: password, maxRetryCount: 1, sleep: { _ in }
        )

        let result = await updater.updateNow()

        XCTAssertEqual(result, .updated(newVersion: 2))
        XCTAssertEqual(store.loads.get(), ["host_api.test"])
        XCTAssertNotNil(sslManager.clientIdentity(forHost: "api.test", port: 443, config: { nil }))
    }

    func testANonMTLSHostGetsNoCertificateDownload() async throws {
        api.returns(config(1, pins: [host("tls.host", 1)]))
        _ = await updater().updateNow()
        XCTAssertTrue(api.hostCertDownloads.isEmpty)
    }

    func testANetworkErrorIsAFailedUpdate() async throws {
        api.fetch = { _ in throw PinVaultError.io(message: "Connection refused") }
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(reason, "Connection refused")
    }

    func testAnAddedHostIsDetected() async throws {
        try stored(config(1, pins: [host("old.host", 1)]))
        api.returns(config(2, pins: [host("old.host", 1), host("new.host", 1)]))
        let result = await updater().updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }
    }

    func testARemovedHostIsDetected() async throws {
        try stored(config(1, pins: [host("keep.host", 1), host("remove.host", 1)]))
        api.returns(config(2, pins: [host("keep.host", 1)]))
        let result = await updater().updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }
    }

    func testForceUpdateTriggersAnUpdate() async throws {
        try stored(config(1, pins: [host(1)]))
        api.returns(config(1, pins: [host(1)], forceUpdate: true))
        let result = await updater().updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }
    }

    func testAnEmptyPinListIsRefused() async throws {
        api.returns(config(1, pins: [], forceUpdate: true))
        let result = await updater().updateNow()
        guard case .failed = result else { return XCTFail("Expected Failed but got \(result)") }
    }

    // MARK: An empty config is an error, not "no change"

    func testAnEmptyRemoteConfigWithNothingStoredIsRefused() async throws {
        api.returns(config(0, pins: []))
        let result = await updater().updateNow()
        guard case .failed(let reason, let exception) = result else { return XCTFail("Expected Failed but got \(result)") }
        guard case .invalidPinFormat? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertTrue(reason.contains("at least one pin"), reason)
        XCTAssertTrue(store.saves.isEmpty)
    }

    func testAnEmptyRemoteConfigDoesNotDeleteTheStoredOne() async throws {
        try stored(config(7, pins: [host(7)]))
        api.returns(config(0, pins: []))
        let result = await updater().updateNow()
        guard case .failed(_, let exception) = result, case .invalidPinFormat? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertTrue(store.saves.isEmpty)
        XCTAssertEqual(store.wipeAllCalls, 0)
        XCTAssertEqual(try store.load()?.computedVersion(), 7)
    }

    func testInitWithAnEmptyConfigIsNotReady() async throws {
        api.returns(config(0, pins: []))
        let result = try await updater().initializeAndUpdate()
        guard case .failed = result else { return XCTFail("Expected InitResult.Failed but got \(result)") }
        XCTAssertEqual(api.healthChecks, 0)
    }

    // MARK: Replay & downgrade guards (M-08)

    func testTheSameIssuedAtWithOtherContentIsAReplay() async throws {
        let issuedAt: Int64 = 1_000_000_000_000
        try stored(config(5, pins: [host(5)], issuedAt: issuedAt))
        // A legitimate signer never signs two different configs with one timestamp.
        api.returns(config(6, pins: [host(6, pins: [pin2, pin1])], issuedAt: issuedAt))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("Expected Failed for replay, got \(result)") }
        XCTAssertTrue(reason.lowercased().contains("replay") || reason.contains("issuedAt"), reason)
    }

    func testAnOlderIssuedAtIsAReplay() async throws {
        let issuedAt: Int64 = 1_000_000_000_000
        try stored(config(5, pins: [host(5)], issuedAt: issuedAt))
        // An older envelope with OTHER content (the pins it carried back then).
        api.returns(config(5, pins: [host(5, pins: [pin1, pin3])], issuedAt: issuedAt - 1))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("Expected Failed for replay, got \(result)") }
        XCTAssertTrue(reason.lowercased().contains("replay"), reason)
    }

    func testAnOlderCopyOfTheCurrentConfigIsAlreadyCurrentAndWritesNothing() async throws {
        let issuedAt = Int64(Date().timeIntervalSince1970 * 1000) - 60_000
        let current = config(5, pins: [host(5)], issuedAt: issuedAt, expiresAt: issuedAt + 3_600_000)
        try stored(current)
        var older = current
        older.issuedAt = issuedAt - 5_000
        older.expiresAt = issuedAt + 1_000_000
        api.returns(older)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertTrue(store.saves.isEmpty)
    }

    func testTheSameSignedConfigServedAgainIsAlreadyCurrentNotAReplay() async throws {
        let issuedAt = Int64(Date().timeIntervalSince1970 * 1000) - 60_000
        let current = config(5, pins: [host(5)], issuedAt: issuedAt, expiresAt: issuedAt + 3_600_000)
        try stored(current)
        // Its force flag was honoured on first delivery and cleared on disk since — it must not be re-applied.
        var again = current
        again.forceUpdate = true
        again.pins = current.pins.map { var pin = $0; pin.forceUpdate = true; return pin }
        api.returns(again)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertTrue(store.saves.isEmpty)
    }

    func testAPerHostVersionDowngradeIsRefused() async throws {
        try stored(config(5, pins: [host(5)], issuedAt: 1_000))
        api.returns(config(3, pins: [host(3)], issuedAt: 2_000))
        let result = await updater().updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("Expected Failed for downgrade, got \(result)") }
        XCTAssertTrue(reason.lowercased().contains("downgrade"), reason)
    }

    // MARK: The health gate after an update, and rollback (G08)

    func testAFailedHealthCheckRestoresThePreviousConfig() async throws {
        let previous = config(4, pins: [host(4)], issuedAt: 1_000)
        let remote = config(5, pins: [host(5)], issuedAt: 2_000)
        try stored(previous)
        api.returns(remote)
        // The default API swallows exceptions and answers false.
        api.healthy = { false }

        let result = try await updater().initializeAndUpdate()

        guard case .failed(let reason, _) = result else { return XCTFail("Expected Failed but got \(result)") }
        XCTAssertTrue(reason.lowercased().contains("unhealthy"), reason)
        // The new config was applied first… and then rolled back.
        XCTAssertEqual(store.saves, [remote, previous])
        XCTAssertEqual(store.clearActiveCalls, 0)
        XCTAssertEqual(provider.currentConfig, previous, "the live session must be rebuilt with the previous config")
        XCTAssertEqual(provider.getVersion(), 4)
    }

    func testWithoutAPreviousConfigAFailedHealthCheckClearsTheStore() async throws {
        api.returns(config(1, pins: [host(1)], issuedAt: 2_000))
        api.healthy = { false }

        let result = try await updater().initializeAndUpdate()

        guard case .failed = result else { return XCTFail("Expected Failed but got \(result)") }
        XCTAssertEqual(store.clearActiveCalls, 1)
        XCTAssertEqual(store.wipeAllCalls, 0)
        XCTAssertNil(provider.currentConfig, "with nothing to roll back to the session must be fail-closed again")
        XCTAssertEqual(provider.getVersion(), 0)
    }

    func testAHealthyCheckKeepsTheNewConfig() async throws {
        let previous = config(4, pins: [host(4)], issuedAt: 1_000)
        let remote = config(5, pins: [host(5)], issuedAt: 2_000)
        try stored(previous)
        api.returns(remote)
        api.healthy = { true }

        let result = try await updater().initializeAndUpdate()

        XCTAssertEqual(result, .ready(version: 5))
        XCTAssertEqual(store.saves, [remote])
        XCTAssertEqual(store.wipeAllCalls, 0)
        XCTAssertEqual(provider.currentConfig, remote, "the freshly applied config must stay on the live session")
    }

    func testTheHealthGateRunsOnlyWhenTheConfigChanged() async throws {
        let current = config(4, pins: [host(4)], issuedAt: 1_000)
        try stored(current)
        api.returns(current)

        let result = try await updater().initializeAndUpdate()

        XCTAssertEqual(result, .ready(version: 4))
        XCTAssertEqual(api.healthChecks, 0)
        XCTAssertEqual(store.wipeAllCalls, 0)
    }

    func testAHealthCheckThatThrowsRollsBackToo() async throws {
        let previous = config(4, pins: [host(4)], issuedAt: 1_000)
        try stored(previous)
        api.returns(config(5, pins: [host(5)], issuedAt: 2_000))
        api.healthy = { throw PinVaultError.io(message: "reset by peer") }

        let result = try await updater().initializeAndUpdate()

        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(reason, "Pin verification failed: reset by peer")
        guard case .backendUnreachable? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertEqual(provider.currentConfig, previous)
    }

    // MARK: A cleared forceUpdate must reach the device (D04)

    func testAClearedForceFlagIsWrittenBackAsAlreadyCurrent() async throws {
        let previous = config(3, pins: [host(3, forceUpdate: true)], forceUpdate: true, issuedAt: 1_000)
        let remote = config(3, pins: [host(3)], issuedAt: 2_000)
        try stored(previous)
        api.returns(remote)

        let result = await updater().updateNow()

        // Nothing about the pins changed, so this is NOT an update (E2E scenario 04)…
        XCTAssertEqual(result, .alreadyCurrent)
        // …but the cleared flag reaches the disk (E2E F01 / D04).
        let saved = try XCTUnwrap(store.saves.last)
        XCTAssertFalse(saved.forceUpdate, "global forceUpdate must be cleared on disk")
        XCTAssertFalse(saved.pins.contains { $0.forceUpdate }, "per-host forceUpdate must be cleared on disk")
        XCTAssertEqual(saved.pins.map(\.hostname), previous.pins.map(\.hostname))
        XCTAssertEqual(saved.pins.map(\.version), previous.pins.map(\.version))
        XCTAssertEqual(saved.issuedAt, remote.issuedAt)
        XCTAssertEqual(saved.expiresAt, remote.expiresAt)
        XCTAssertFalse(provider.currentConfig!.forceUpdate, "the live config follows the disk")
    }

    func testAClearedPerHostForceFlagIsWrittenBackToo() async throws {
        try stored(config(3, pins: [host(3, forceUpdate: true)], issuedAt: 1_000))
        api.returns(config(3, pins: [host(3)], issuedAt: 2_000))
        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertFalse(try XCTUnwrap(store.saves.last).pins.contains { $0.forceUpdate })
    }

    func testNothingIsWrittenWhenTheFlagsAlreadyAgree() async throws {
        let current = config(3, pins: [host(3)], issuedAt: 1_000)
        try stored(current)
        api.returns(current)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertTrue(store.saves.isEmpty)
    }

    func testARaisedForceFlagStillUpdates() async throws {
        try stored(config(3, pins: [host(3)], issuedAt: 1_000))
        let remote = config(3, pins: [host(3, forceUpdate: true)], forceUpdate: true, issuedAt: 2_000)
        api.returns(remote)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .updated(newVersion: 3))
        XCTAssertEqual(store.saves, [remote])
    }

    func testTheFirstFetchIsAcceptedWithoutAWatermark() async throws {
        let remote = config(1, pins: [host(1)], issuedAt: 1_000)
        api.returns(remote)
        let result = await updater().updateNow()
        XCTAssertEqual(result, .updated(newVersion: 1))
        XCTAssertEqual(store.saves, [remote])
    }

    // MARK: Retries (E.31)

    func testStartRetriesWithTheKotlinBackoffAndReportsTheLastFailure() async throws {
        api.fails("offline")
        let sleeps = SleepRecorder()
        let updater = SSLCertificateUpdater(
            configApi: api, configStore: store, httpClientProvider: provider, maxRetryCount: 3, sleep: sleeps.sleep
        )
        let result = try await updater.initializeAndUpdate()
        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(reason, "No stored config and backend unreachable: offline")
        guard case .noConfigAvailable? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertEqual(api.fetches, 3)
        XCTAssertEqual(sleeps.recorded, [2_000, 4_000], "retrying in 2000ms, then 4000ms")
    }

    func testAForceUpdateConfigOfflineIsForceUpdateFailed() async throws {
        try stored(config(3, pins: [host(3, forceUpdate: true)], forceUpdate: true))
        api.fails()
        let result = try await updater().initializeAndUpdate()
        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.hasPrefix("Force update required but backend unreachable"), reason)
        guard case .forceUpdateFailed? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
    }

    func testAStoredConfigStartsOfflineWithItsVersion() async throws {
        try stored(config(9, pins: [host(9)]))
        api.fails()
        let result = try await updater().initializeAndUpdate()
        XCTAssertEqual(result, .ready(version: 9))
        XCTAssertEqual(provider.getVersion(), 9)
    }
}

/// A host certificate store where nothing "exists" but a fallback load answers (Kotlin's mock in that test).
private final class FallbackOnlyHostCertStore: HostClientCertStore, @unchecked Sendable {
    let fallback: Data
    let loads = Locked<[String]>([])

    init(fallback: Data) { self.fallback = fallback }

    func exists(_ label: String) -> Bool { false }
    func load(_ label: String) -> Data? {
        loads.withLock { $0.append(label) }
        return fallback
    }
    func save(_ label: String, _ p12: Data) {}
}
