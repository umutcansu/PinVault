import XCTest
@testable import PinVault

/// The session a Config API block reaches its backend with is pinned,
/// HTTPS-only and follows no redirect unless the block said
/// `allowUnpinnedConfigApi()` (Kotlin `BootstrapClientRulesTest`).
final class BootstrapClientRulesTests: XCTestCase {

    private var servers: [TestServer] = []
    private let pins = [HostPin(hostname: "localhost", sha256: [TLSFixture.pin("leaf"), TLSFixture.backupPin])]

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func server(tls: Bool = true, clientAuth: TestServer.ClientAuth = .none) async throws -> TestServer {
        let server = try TestServer(p12: tls ? "server" : nil, chain: tls ? ["intermediate"] : [], clientAuth: clientAuth)
        try await server.start()
        servers.append(server)
        return server
    }

    private func status(_ session: PinnedSession, _ url: URL) async throws -> Int {
        let (_, response) = try await session.data(from: url)
        return (response as! HTTPURLResponse).statusCode
    }

    func testPlainHTTPIsRefusedBeforeAnythingIsSent() async throws {
        let server = try await server(tls: false)
        let error = await assertPinVaultError { _ = try await testManager().buildBootstrapClient(self.pins).data(from: server.url()) }
        guard case .io(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("plain-HTTP"), message)
        XCTAssertEqual(server.requestCount, 0)
    }

    func testWithoutBootstrapPinsEveryTLSHandshakeIsRefusedNotLeftToTheSystemCAs() async throws {
        let server = try await server()
        let manager = testManager()
        // Even a "platform" that would trust the server does not count.
        manager.caCheck = SecTrustCaCheck(anchors: [TLSFixture.cert("root").der])
        let error = await assertPinVaultError { _ = try await manager.buildBootstrapClient([]).data(from: server.url()) }
        XCTAssertTrue(error?.message.contains("No pins configured") == true, "\(String(describing: error))")
        XCTAssertEqual(server.requestCount, 0)
    }

    func testPinnedBootstrapConnects() async throws {
        let server = try await server()
        let code = try await status(testManager().buildBootstrapClient(pins), server.url())
        XCTAssertEqual(code, 200)
    }

    func testAllowUnpinnedKeepsPlainHTTPAndSystemTrustWorking() async throws {
        let plain = try await server(tls: false)
        let unpinned = try await status(testManager().buildBootstrapClient([], allowUnpinned: true), plain.url())
        XCTAssertEqual(unpinned, 200)
        let pinnedButLax = try await status(testManager().buildBootstrapClient(pins, allowUnpinned: true), plain.url())
        XCTAssertEqual(pinnedButLax, 200)

        // TLS without pins: the platform's CAs decide, for the host the app named.
        let tls = try await server()
        let untrusted = await assertPinVaultError { _ = try await testManager().buildBootstrapClient([], allowUnpinned: true).data(from: tls.url()) }
        guard case .sslHandshake? = untrusted else { return XCTFail("the system does not know the test root: \(String(describing: untrusted))") }
        let manager = testManager()
        manager.caCheck = SecTrustCaCheck(anchors: [TLSFixture.cert("root").der])
        let trusted = try await status(manager.buildBootstrapClient([], allowUnpinned: true), tls.url())
        XCTAssertEqual(trusted, 200)
    }

    func testTheBootstrapSessionFollowsNoRedirect() async throws {
        let server = try await server()
        server.enqueue(.status(307, headers: ["Location": server.url("/elsewhere").absoluteString]))
        let code = try await status(testManager().buildBootstrapClient(pins), server.url("/api"))
        XCTAssertEqual(code, 307, "the Config API never redirects: the 3xx is the answer")
        XCTAssertEqual(server.requestCount, 1)
    }

    func testTheUnpinnedBootstrapSessionPresentsNoClientCertificate() async throws {
        // OkHttp's default socket factory has no key manager: system trust, no identity.
        let server = try await server(clientAuth: .required)
        let manager = testManager()
        manager.caCheck = SecTrustCaCheck(anchors: [TLSFixture.cert("root").der])
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts([server.url().absoluteString])
        _ = await assertPinVaultError { _ = try await manager.buildBootstrapClient([], allowUnpinned: true).data(from: server.url()) }
        XCTAssertEqual(server.requestCount, 0)
        // The pinned one presents it to its own listener.
        let code = try await status(manager.buildBootstrapClient(pins), server.url())
        XCTAssertEqual(code, 200)
        XCTAssertEqual(server.takeRequest()?.clientCertificate?.subject.commonName, "client-a")
    }
}
