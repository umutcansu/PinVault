import Foundation
import XCTest
@_spi(PinVaultE2E) @testable import PinVault

/// The façade over real Config API blocks (the façade parts of
/// MultiConfigApiConfigTest, and the start / update / session / reset paths of
/// PinVault.kt): a signed config served over pinned TLS by a test server.
final class PinVaultStartTests: XCTestCase {

    private let signer = TestSigner()
    private var server: TestServer!
    private let envelope = Locked("")
    private let healthy = Locked(true)
    private var vault: PinVault!

    override func setUp() async throws {
        server = try await startConfigApiServer()
        let envelope = self.envelope, healthy = self.healthy
        server.setHandler { request in
            if request.path.hasPrefix("/api/v1/certificate-config") { return .ok(envelope.get()) }
            if request.path.hasPrefix("/health") { return .ok(healthy.get() ? #"{"status":"ok"}"# : #"{"status":"down"}"#) }
            return .ok("pinned data")
        }
        serve(version: 3)
        vault = try isolatedPinVault(self)
    }

    override func tearDown() async throws {
        vault.cancelPeriodicUpdates()
        vault.reset()
        server.stop()
    }

    private var now: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// Serves a signed config pinning `localhost` at `version`.
    private func serve(version: Int, issuedAt: Int64? = nil, forceUpdate: Bool = false) {
        let issued = issuedAt ?? now
        let payload = signedPayload(
            version: version, issuedAt: issued, expiresAt: issued + 3_600_000,
            pins: configApiServerPins[0].sha256, hosts: [("localhost", version)], forceUpdate: forceUpdate
        )
        envelope.set(json(SignedConfigResponse(payload: payload, signature: signer.sign(payload))))
    }

    private func config(
        _ configure: ((PinVaultConfig.Builder) -> Void)? = nil,
        block: ((ConfigApiBlock.Builder) -> Void)? = nil
    ) throws -> PinVaultConfig {
        let builder = PinVaultConfig.Builder().configApi("api", url: server.baseURL) { [signer] b in
            b.bootstrapPins(configApiServerPins).signaturePublicKey(signer.pub)
            block?(b)
        }
        configure?(builder)
        return try builder.build()
    }

    private func configRequests() -> Int {
        server.requests.filter { $0.path.hasPrefix("/api/v1/certificate-config") }.count
    }

    // MARK: Start

    func testStartFetchesVerifiesAndServesPinnedSessions() async throws {
        let events = EventRecorder()
        let result = await vault.start(config: try config { $0.onConnectionEvent(events.listener) })

        XCTAssertEqual(result, .ready(version: 3))
        XCTAssertEqual(vault.currentVersion(), 3)
        XCTAssertEqual(vault.pinsForHost("LOCALHOST"), configApiServerPins[0].sha256)
        XCTAssertEqual(vault.hostPinVersions(), ["localhost": 3])
        XCTAssertEqual(vault.currentPins, ["localhost": configApiServerPins[0].sha256])
        XCTAssertFalse(vault.isForceUpdate())
        let signing = try XCTUnwrap(vault.signingStatus())
        XCTAssertEqual(signing.trustedKeyIds, [signer.id])
        XCTAssertNil(vault.signingStatus(configApiId: "nope"))

        for session in [vault.session(), vault.session(settings: HttpConnectionSettings()), vault.applyTo(.ephemeral)] {
            let (data, response) = try await session.data(from: server.url("/data"))
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
            XCTAssertEqual(String(decoding: data, as: UTF8.self), "pinned data")
        }
        let connected = await eventually { events.connections.contains { $0 == ("localhost", true) } }
        XCTAssertTrue(connected, "handshakes reach the app's listener")

        // Every Config API request asked for forbidden-as-409; app requests to a host without an identity did not.
        XCTAssertTrue(server.requests.filter { $0.path.hasPrefix("/api/") || $0.path.hasPrefix("/health") }
            .allSatisfy { $0.features.contains("forbidden-as-409") })
        XCTAssertTrue(server.requests.filter { $0.path == "/data" }.allSatisfy { $0.header("X-PinVault-Features") == nil })
    }

    func testASecondStartReturnsReadyWithoutContactingTheServer() async throws {
        let first = await vault.start(config: try config())
        XCTAssertEqual(first, .ready(version: 3))
        let before = server.requestCount
        let second = await vault.start(config: try config())
        XCTAssertEqual(second, .ready(version: 3))
        XCTAssertEqual(server.requestCount, before, "no network request")
    }

    func testAnUnreachableBackendWithNothingStoredFailsAndLeavesNothingStarted() async throws {
        server.stop()
        let result = await vault.start(config: try config())
        guard case .failed(let reason, let exception) = result, case .noConfigAvailable? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertTrue(reason.hasPrefix("No stored config and backend unreachable"), reason)
        XCTAssertFalse(vault.isInitialized)
        XCTAssertEqual(vault.currentVersion(), 0)
        let update = await vault.updateNow()
        guard case .failed(PinVault.notInitializedMessage, _) = update else { return XCTFail("\(update)") }
    }

    func testAnUnhealthyBackendAfterTheFirstConfigFailsStart() async throws {
        healthy.set(false)
        let result = await vault.start(config: try config())
        guard case .failed(let reason, let exception) = result, case .backendUnreachable? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertEqual(reason, "Backend returned unhealthy status after pin update")
        XCTAssertNil(vault.pinsForHost("localhost"))
    }

    func testTheDefaultBlockDecidesTheStartResult() async throws {
        let other = try await startConfigApiServer()
        other.stop()   // the second Config API is down
        let multi = try PinVaultConfig.Builder()
            .configApi("api", url: server.baseURL) { [signer] in $0.bootstrapPins(configApiServerPins).signaturePublicKey(signer.pub) }
            .configApi("other", url: other.baseURL) { [signer] in $0.bootstrapPins(configApiServerPins).signaturePublicKey(signer.pub) }
            .build()
        let result = await vault.start(config: multi)
        XCTAssertEqual(result, .ready(version: 3), "a failing second block does not fail start")
        XCTAssertEqual(vault.configApiClients.map(\.block.id), ["api", "other"])
        XCTAssertEqual(vault.configApiClient("other")?.clientProvider.currentConfig, nil)
        XCTAssertNotNil(vault.signingStatus(configApiId: "other"))
        // Each block keeps its config in its own store namespace.
        XCTAssertEqual(try vault.configApiClient("api")?.configStore.getCurrentVersion(), 3)
        XCTAssertEqual(try vault.configApiClient("other")?.configStore.getCurrentVersion(), 0)
    }

    func testAFailingDefaultBlockFailsStartEvenWhenAnotherWorks() async throws {
        let other = try await startConfigApiServer()
        other.stop()
        let multi = try PinVaultConfig.Builder()
            .configApi("down", url: other.baseURL) { [signer] in $0.bootstrapPins(configApiServerPins).signaturePublicKey(signer.pub) }
            .configApi("api", url: server.baseURL) { [signer] in $0.bootstrapPins(configApiServerPins).signaturePublicKey(signer.pub) }
            .build()
        let result = await vault.start(config: multi)
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertFalse(vault.isInitialized)
        XCTAssertEqual(try vault.configApiClient("api")?.configStore.getCurrentVersion(), 3, "the other block still started")
    }

    // MARK: Custom APIs

    func testACustomAPIThatCannotHandOverEnvelopesFailsASignedBlock() async throws {
        let custom = FakeConfigApi()
        custom.returns(CertificateConfig(version: 1, pins: configApiServerPins))
        let result = await vault.start(config: try config(), configApi: custom)
        guard case .failed(let reason, let exception) = result, case .illegalState? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertTrue(reason.contains("has signing keys, but its custom CertificateConfigApi cannot hand over signed configs"), reason)
        XCTAssertEqual(custom.fetches, 0)
    }

    func testACustomAPIUnderAllowUnsignedServesTheDefaultBlock() async throws {
        let custom = FakeConfigApi()
        var pins = configApiServerPins[0]
        pins.version = 2
        custom.returns(CertificateConfig(version: 2, pins: [pins]))
        let result = await vault.start(config: try config(block: { $0.allowUnsigned() }), configApi: custom)
        XCTAssertEqual(result, .ready(version: 2))
        XCTAssertEqual(custom.fetches, 1)
        XCTAssertEqual(custom.healthChecks, 1)
        XCTAssertNil(vault.signingStatus(), "its configs are not verified")
        XCTAssertEqual(configRequests(), 0)
    }

    func testACustomSignedConfigSourceIsVerifiedLikeTheLibrarysOwn() async throws {
        let custom = SignedFakeApi()
        let issued = now
        let payload = signedPayload(version: 6, issuedAt: issued, expiresAt: issued + 3_600_000,
                                    pins: configApiServerPins[0].sha256, hosts: [("localhost", 6)])
        custom.next = SignedConfigResponse(payload: payload, signature: signer.sign(payload))
        let result = await vault.start(config: try config(), configApi: custom)
        XCTAssertEqual(result, .ready(version: 6))
        XCTAssertNotNil(vault.signingStatus())
    }

    // MARK: Updates, reset, static pins

    func testUpdateNowAppliesANewConfigAndTheSessionsFollow() async throws {
        _ = await vault.start(config: try config())
        let session = vault.session()
        serve(version: 4)
        let update = await vault.updateNow()
        XCTAssertEqual(update, .updated(newVersion: 4))
        XCTAssertEqual(vault.currentVersion(), 4)
        let (_, response) = try await session.data(from: server.url("/data"))
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        let again = await vault.updateNow()
        XCTAssertEqual(again, .alreadyCurrent)
    }

    func testResetRefusesPinnedTrafficAndKeepsTheWatermarks() async throws {
        _ = await vault.start(config: try config())
        let earlier = vault.session()
        vault.reset()

        XCTAssertFalse(vault.isInitialized)
        XCTAssertEqual(vault.currentVersion(), 0)
        // A session obtained before the reset refuses too: its pin recovery does
        // not fetch a config for a block that was reset.
        for session in [earlier, vault.session()] {
            let error = await assertPinVaultError { _ = try await session.data(from: self.server.url("/data")) }
            XCTAssertEqual(error?.exceptionName, "SSLHandshakeException")
        }
        XCTAssertEqual(server.requests.filter { $0.path == "/data" }.count, 0)
        let store = try XCTUnwrap(vault.configApiClient("api")?.configStore)
        XCTAssertNil(try store.load())
        XCTAssertGreaterThan(try store.getCurrentIssuedAt(), 0, "the replay watermark is kept")

        // An older signed config is refused after the reset; the newest one is taken again.
        serve(version: 3, issuedAt: now - 60_000)
        let older = await vault.start(config: try config())
        guard case .failed = older else { return XCTFail("\(older)") }
        serve(version: 3)
        let again = await vault.start(config: try config())
        XCTAssertEqual(again, .ready(version: 3))
    }

    func testResetAndWipeStoredStateForgetsTheWatermarksToo() async throws {
        _ = await vault.start(config: try config())
        let store = try XCTUnwrap(vault.configApiClient("api")?.configStore)
        vault.resetAndWipeStoredState()
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
    }

    func testStaticPinsStartWithoutTheNetworkAndPinTheirHosts() async throws {
        var pins = configApiServerPins[0]
        pins.version = 1
        let result = await vault.start(config: PinVaultConfig.static(pins))
        XCTAssertEqual(result, .ready(version: 1))
        XCTAssertEqual(server.requestCount, 0)
        let (_, response) = try await vault.session().data(from: server.url("/data"))
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        let update = await vault.updateNow()
        XCTAssertEqual(update, .alreadyCurrent)
        XCTAssertNil(vault.signingStatus())
        XCTAssertEqual(vault.attestationStatus().result, .unsupported)
        vault.reset()
        XCTAssertNil(vault.pinsForHost("localhost"))
    }

    // MARK: Periodic updates and the E2E hooks

    func testPeriodicUpdatesRunTheJobReportTheirStateAndTellTheListeners() async throws {
        _ = await vault.start(config: try config { $0.updateIntervalMinutes(15) })
        let observed = Locked(0)
        vault.e2eSetScheduledTasksObserver { observed.withLock { $0 += 1 } }
        let updates = Locked<[UpdateResult]>([])
        vault.setOnUpdateListener { result in updates.withLock { $0.append(result) } }
        let before = configRequests()

        XCTAssertTrue(vault.schedulePeriodicUpdates())
        let ran = await eventually { updates.get().count == 1 }
        XCTAssertTrue(ran, "the job runs once right away and reports to the update listener")
        XCTAssertEqual(updates.get(), [.alreadyCurrent])
        XCTAssertEqual(configRequests(), before + 1)
        let tasks = await vault.scheduledTasks()
        XCTAssertEqual(tasks.count, 1)
        XCTAssertTrue([ScheduledTaskInfo.State.enqueued, .running].contains(tasks[0].state))

        await vault.e2eRunPeriodicWorkNow()
        XCTAssertEqual(updates.get().count, 2)
        XCTAssertGreaterThan(observed.get(), 0)

        vault.cancelPeriodicUpdates()
        let cancelled = await vault.scheduledTasks()
        XCTAssertEqual(cancelled.map(\.state), [.cancelled])
    }

    func testTheConnectionListenerCanBeReplacedAtRuntime() async throws {
        let first = EventRecorder(), second = EventRecorder()
        _ = await vault.start(config: try config { $0.onConnectionEvent(first.listener) })
        vault.setConnectionListener(second.listener)
        let countBefore = first.all.count
        _ = try await vault.session().data(from: server.url("/data"))
        let heard = await eventually { second.connections.contains { $0.0 == "localhost" } }
        XCTAssertTrue(heard)
        XCTAssertEqual(first.all.count, countBefore)
    }

    func testAnUpdateIsReportedAsAConfigUpdateEvent() async throws {
        let events = EventRecorder()
        _ = await vault.start(config: try config { $0.onConnectionEvent(events.listener) })
        await vault.notifyUpdateResult(.failed(reason: "offline"))
        let reported = await eventually {
            events.all.contains { if case .configUpdate(.failed, 3, "Apple", _, "offline") = $0 { return true } else { return false } }
        }
        XCTAssertTrue(reported)
    }
}
