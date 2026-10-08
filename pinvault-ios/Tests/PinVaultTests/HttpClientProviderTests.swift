import XCTest
@testable import PinVault

/// HttpClientProvider: swap, reset, version tracking, the fail-closed "no
/// config" state (Kotlin `HttpClientProviderTest`).
final class HttpClientProviderTests: XCTestCase {

    private var manager = testManager()
    private var provider: HttpClientProvider!
    private var servers: [TestServer] = []

    override func setUp() {
        manager = testManager()
        provider = HttpClientProvider(sslManager: manager)
    }

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func server(_ p12: String = "server", chain: [String] = ["intermediate"]) async throws -> TestServer {
        let server = try TestServer(p12: p12, chain: chain)
        try await server.start()
        servers.append(server)
        return server
    }

    private var localhostConfig: CertificateConfig {
        pinConfig("localhost", [TLSFixture.pin("leaf")])
    }

    func testInitialStateIsVersion0WithoutConfig() {
        XCTAssertEqual(provider.getVersion(), 0)
        XCTAssertNil(provider.currentConfig)
    }

    func testSwapUpdatesVersionAndConfig() {
        provider.swap(CertificateConfig(version: 5, pins: [HostPin(hostname: "a.com", sha256: [pin("A"), pin("B")], version: 5)]))
        XCTAssertEqual(provider.getVersion(), 5)
        XCTAssertEqual(provider.currentConfig?.pins.count, 1)
    }

    func testEverySwapUpdatesTheVersion() {
        provider.swap(CertificateConfig(version: 1, pins: [HostPin(hostname: "a.com", sha256: [pin("A"), pin("B")], version: 1)]))
        XCTAssertEqual(provider.getVersion(), 1)
        provider.swap(CertificateConfig(version: 3, pins: [HostPin(hostname: "a.com", sha256: [pin("A"), pin("B")], version: 3)]))
        XCTAssertEqual(provider.getVersion(), 3)
    }

    func testResetGoesBackToVersion0() {
        provider.swap(CertificateConfig(version: 5, pins: [HostPin(hostname: "a.com", sha256: [pin("A"), pin("B")], version: 5)]))
        provider.reset()
        XCTAssertEqual(provider.getVersion(), 0)
        XCTAssertNil(provider.currentConfig)
    }

    func testSwapAndResetMoveTheSessionGeneration() {
        let before = manager.sessionGeneration
        provider.swap(localhostConfig)
        let afterSwap = manager.sessionGeneration
        XCTAssertNotEqual(before, afterSwap)
        provider.reset()
        XCTAssertNotEqual(afterSwap, manager.sessionGeneration)
    }

    func testReplaceConfigInPlaceKeepsTheSessionsWhileThePinsStayTheSame() {
        provider.swap(localhostConfig)
        let generation = manager.sessionGeneration
        var fresher = localhostConfig
        fresher.issuedAt = 42
        fresher.forceUpdate = true
        provider.replaceConfigInPlace(fresher)
        XCTAssertEqual(manager.sessionGeneration, generation, "same pins: no onPinsChanged")
        XCTAssertEqual(provider.currentConfig?.issuedAt, 42)

        provider.replaceConfigInPlace(pinConfig("localhost", [pin("Z")]))
        XCTAssertNotEqual(manager.sessionGeneration, generation, "different pins: treated as a pin change")
    }

    // MARK: Fail-closed "no config" state

    func testBeforeTheFirstSwapTheSessionRefusesTLSNoSystemTrust() async throws {
        let server = try await server()
        let error = await assertPinVaultError { _ = try await self.provider.get().data(from: server.url()) }
        XCTAssertTrue(error?.message.contains("No pins configured") == true, "\(String(describing: error))")
        XCTAssertEqual(server.requestCount, 0)
    }

    func testASessionObtainedBeforeSwapGoesLiveAfterSwapWithoutRebuild() async throws {
        let server = try await server()
        let pending = provider.get()
        provider.swap(localhostConfig)
        let (_, response) = try await pending.data(from: server.url())
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)

        // … and still refuses a certificate that is not pinned.
        let rogue = try await self.server("selfsigned", chain: [])
        let error = await assertPinVaultError { _ = try await pending.data(from: rogue.url()) }
        guard case .certificate? = error?.pinVaultCause else { return XCTFail("pin mismatch expected: \(String(describing: error))") }
    }

    func testResetMakesTheSessionFailClosedAgain() async throws {
        let server = try await server()
        provider.swap(localhostConfig)
        _ = try await provider.get().data(from: server.url())
        provider.reset()
        for session in [provider.get()] {
            let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
            XCTAssertTrue(error?.message.contains("No pins configured") == true, "\(String(describing: error))")
        }
    }

    func testSessionsCarryTheTokenInterceptorOnceItIsSet() async throws {
        struct Source: AttestationTokenSource {
            func handlesHost(_ host: String, port: Int) -> Bool { true }
            func token(host: String, port: Int, forceRefresh: Bool) async -> String? { "tok" }
        }
        let server = try await server()
        provider.swap(localhostConfig)
        provider.tokenInterceptor = AttestationTokenInterceptor { [Source()] }
        _ = try await provider.get().data(from: server.url())
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "tok")
        provider.swap(localhostConfig)
        _ = try await provider.get().data(from: server.url())
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "tok", "kept across swaps")
    }

    func testASessionOutlivingItsProviderRefusesEveryHandshake() async throws {
        let server = try await server()
        var provider: HttpClientProvider? = HttpClientProvider(sslManager: manager)
        provider?.swap(localhostConfig)
        let session = provider!.get()
        provider = nil
        let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
        XCTAssertTrue(error?.message.contains("No pins configured") == true, "\(String(describing: error))")
    }
}
