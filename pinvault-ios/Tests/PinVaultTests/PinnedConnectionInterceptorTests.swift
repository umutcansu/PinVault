import XCTest
@testable import PinVault

/// Real connections: a connection opened under one config must not carry
/// requests once the pins that admitted it are gone or the config has expired
/// (Kotlin `PinnedConnectionInterceptorTest`). URLSession never shows a pooled
/// connection to the delegate again; the per-request config check and the
/// session rebuild on every config / pin change do that job.
final class PinnedConnectionInterceptorTests: XCTestCase {

    private final class Clock: @unchecked Sendable { var now: Int64 = 1_800_000_000_000 }

    private let hour: Int64 = 3_600_000
    private let leafPin = TLSFixture.pin("leaf")
    private let otherPin = TLSFixture.pin("selfsigned")
    private var clock = Clock()
    private var manager = testManager()
    private var server: TestServer!

    override func setUp() async throws {
        clock = Clock()
        manager = testManager()
        let clock = self.clock
        manager.clock = { clock.now }
        server = try TestServer(p12: "server", chain: ["intermediate"])
        try await server.start()
    }

    override func tearDown() {
        server.stop()
    }

    private func matching(expiresAt: Int64 = 0, issuedAt: Int64 = 0) -> CertificateConfig {
        var config = pinConfig("localhost", [leafPin], expiresAt: expiresAt)
        config.issuedAt = issuedAt
        return config
    }

    /// The server's pin has been rotated away: the host is still pinned, to other keys.
    private func rotated() -> CertificateConfig {
        pinConfig("localhost", [otherPin], version: 2)
    }

    private func get(_ session: PinnedSession) async throws -> Int {
        let (_, response) = try await session.data(from: server.url("/"))
        return (response as! HTTPURLResponse).statusCode
    }

    private func refused(_ session: PinnedSession, file: StaticString = #filePath, line: UInt = #line) async -> PinVaultError? {
        await assertPinVaultError(file: file, line: line) { _ = try await self.get(session) }
    }

    /// A session over the app's configuration.
    private func appClient(_ live: Locked<CertificateConfig?>) -> PinnedSession {
        manager.applyTo(.ephemeral, configProvider: { live.get() })
    }

    func testAPooledConnectionIsRefusedOnceItsPinIsGoneAndClosed() async throws {
        let live = Locked<CertificateConfig?>(matching())
        let client = appClient(live)
        let first = try await get(client)
        XCTAssertEqual(first, 200)
        let opened = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(opened.sequenceNumber, 0)

        // The pin is rotated: the pooled connection must not carry the next request.
        live.set(rotated())
        let refusal = await refused(client)
        guard case .sslHandshake(let message, let cause)? = refusal, case .certificate? = cause as? PinVaultError else {
            return XCTFail("same type as a failed handshake: \(String(describing: refusal))")
        }
        XCTAssertTrue(message.contains("Certificate pinning failure"), message)
        XCTAssertEqual(server.requestCount, 1, "nothing reached the server on the old connection")
        let closed = await eventually { self.server.openConnectionCount == 0 }
        XCTAssertTrue(closed, "the old connection was closed, not kept for later")

        // Once the pins match again the next request opens a new connection.
        live.set(matching())
        let again = try await get(client)
        XCTAssertEqual(again, 200)
        let next = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(next.sequenceNumber, 0, "a new connection")
        XCTAssertNotEqual(next.connection, opened.connection)
    }

    func testAPooledConnectionIsRefusedOnceTheHostHasNoPinEntry() async throws {
        let live = Locked<CertificateConfig?>(matching())
        let client = appClient(live)
        _ = try await get(client)

        live.set(pinConfig("elsewhere.test", [otherPin], version: 2))
        guard case .unpinnedHost? = await refused(client)?.pinVaultCause else { return XCTFail("expected UnpinnedHostException") }

        live.set(nil)
        let none = await refused(client)
        XCTAssertTrue(none?.message.contains("No pins configured") == true, "\(String(describing: none))")
        XCTAssertEqual(server.requestCount, 1)
    }

    func testAPooledConnectionIsRefusedOnceTheConfigHasExpired() async throws {
        let live = Locked<CertificateConfig?>(matching(expiresAt: clock.now + hour))
        let client = appClient(live)
        let ok = try await get(client)
        XCTAssertEqual(ok, 200)

        // Same config, later: the per-request check refuses it, no handshake needed.
        clock.now += 2 * hour
        let refusal = await refused(client)
        guard case .sslHandshake? = refusal, case .configExpired? = refusal?.pinVaultCause?.pinVaultCause else {
            return XCTFail("\(String(describing: refusal))")
        }
        XCTAssertEqual(server.requestCount, 1)

        // A fresh config (same pins, later expiresAt) makes requests work again.
        live.set(matching(expiresAt: clock.now + hour))
        let again = try await get(client)
        XCTAssertEqual(again, 200)
    }

    func testGraceKeepsAPooledConnectionUsableThatMuchLonger() async throws {
        manager.expiredConfigGraceMs = 3 * hour
        let config = matching(expiresAt: clock.now + hour)
        let client = manager.applyTo(.ephemeral, configProvider: { config })
        let first = try await get(client)
        XCTAssertEqual(first, 200)
        clock.now += 2 * hour
        let second = try await get(client)
        XCTAssertEqual(second, 200)
    }

    func testAnUnchangedConfigKeepsReusingThePooledConnection() async throws {
        let config = matching()
        let client = manager.applyTo(.ephemeral, configProvider: { config })
        _ = try await get(client)
        _ = try await get(client)
        XCTAssertEqual(server.takeRequest()?.sequenceNumber, 0)
        XCTAssertEqual(server.takeRequest()?.sequenceNumber, 1, "the second request rode the same connection")
        XCTAssertEqual(server.connectionCount, 1)
    }

    func testAnExpiredConfigIsRefreshedByTheRecoveryInterceptorAndTheRequestRetried() async throws {
        let provider = HttpClientProvider(sslManager: manager)
        provider.swap(matching(expiresAt: clock.now + hour))
        let refetches = Counter()
        let clock = self.clock
        let hour = self.hour
        let leafPin = self.leafPin
        provider.recoveryUpdater = { [weak provider] in
            refetches.increment()
            provider?.replaceConfigInPlace(pinConfig("localhost", [leafPin], expiresAt: clock.now + hour))
            return true
        }
        let client = provider.get()
        let first = try await get(client)
        XCTAssertEqual(first, 200)

        clock.now += 2 * hour
        // The per-request check fails; recovery refetches and the retry goes through.
        let second = try await get(client)
        XCTAssertEqual(second, 200)
        XCTAssertEqual(refetches.count, 1)
    }

    func testAPinChangeClosesThePooledConnectionsOfEverySessionTheLibraryBuilt() async throws {
        let provider = HttpClientProvider(sslManager: manager)
        provider.swap(matching())
        let shared = provider.get()
        let custom = manager.buildDynamicClient(configProvider: { [weak provider] in provider?.currentConfig })
        let applied = manager.applyTo(.ephemeral, configProvider: { [weak provider] in provider?.currentConfig })
        _ = try await get(shared)
        _ = try await get(custom)
        _ = try await get(applied)
        XCTAssertEqual(server.openConnectionCount, 3)

        provider.swap(rotated())

        let closed = await eventually { self.server.openConnectionCount == 0 }
        XCTAssertTrue(closed, "session(settings:) and applyTo sessions are retired too (\(server.openConnectionCount) open)")
    }

    func testAfterAPinChangeANewConnectionRunsAFullHandshake() async throws {
        // The delegate reports every handshake it is asked about; a resumed TLS
        // session would not ask it. A new URLSession has no session to resume.
        let events = EventRecorder()
        manager.setConnectionListener(events.listener)
        let config = matching()
        let client = manager.applyTo(.ephemeral, configProvider: { config })
        _ = try await get(client)
        let first = await eventually { events.connections.count == 1 }
        XCTAssertTrue(first)

        manager.onPinsChanged()
        _ = try await get(client)
        let second = await eventually { events.connections.count == 2 }
        XCTAssertTrue(second, "the trust check saw the second connection")
    }

    func testRequireCaTrustIsCheckedForEveryNewConfigNotOnlyAtTheFirstHandshake() async throws {
        let caTrusts = Locked(true)
        manager.caCheck = ClosureCaCheck { _, _ in
            if !caTrusts.get() { throw PinVaultError.certificate(message: "not issued by a trusted CA") }
        }
        manager.requireCaTrust(["localhost"])
        let live = Locked<CertificateConfig?>(matching())
        let client = appClient(live)
        let ok = try await get(client)
        XCTAssertEqual(ok, 200)
        XCTAssertEqual(server.openConnectionCount, 1)

        // The CA verdict changes; a new config (a freshness write-back: same pins,
        // newer issuedAt) makes the session look at the server again.
        caTrusts.set(false)
        live.set(matching(issuedAt: 1))
        let refusal = await refused(client)
        guard case .sslHandshake? = refusal, case .caTrust? = refusal?.pinVaultCause else {
            return XCTFail("\(String(describing: refusal))")
        }
        XCTAssertEqual(server.requestCount, 1, "nothing reached the server on that connection")
    }
}
