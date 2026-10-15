import Foundation
import XCTest
@testable import PinVault

/// `TrustCheckWatch`: a pinned session notices when URLSession never asked
/// its delegate about a server certificate — a connection the library's trust
/// check did not see — refuses the response, and records the host for the
/// attestation report.
final class TrustCheckWatchTests: XCTestCase {

    private var servers: [TestServer] = []

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func server(tls: Bool = true) async throws -> TestServer {
        let server = try TestServer(p12: tls ? "server" : nil, chain: tls ? ["intermediate"] : [])
        try await server.start()
        servers.append(server)
        return server
    }

    private func transport(_ manager: DynamicSSLManager, forgetChallenges: Bool = false) -> (URLSessionTransport, PinnedSession) {
        let config = pinConfig("localhost", [TLSFixture.pin("leaf")])
        let transport = URLSessionTransport(
            manager: manager, configuration: .ephemeral, trust: .pinned({ config }), resolveOverrides: [:], redirects: .sameScheme
        )
        transport.testOnlyForgetChallenges = forgetChallenges
        return (transport, PinnedSession(transport: transport))
    }

    // MARK: The decision

    private func tx(networkLoad: Bool = true, tls: Bool = true, https: Bool = true) -> TrustCheckWatch.Transaction {
        TrustCheckWatch.Transaction(networkLoad: networkLoad, tls: tls, https: https)
    }

    func testATLSConnectionNobodyWasAskedAboutIsUnverified() {
        XCTAssertTrue(TrustCheckWatch.wentUnverified([tx()], serverTrustChallenges: 0))
        XCTAssertTrue(TrustCheckWatch.wentUnverified([tx(tls: false, https: false), tx()], serverTrustChallenges: 0))
    }

    func testOneChallengeInTheSessionVouchesForItsConnections() {
        // A later connection without a challenge is a resumed TLS session (verified
        // against a TLS 1.2 server: URLSession shows a resumed session to nobody).
        XCTAssertFalse(TrustCheckWatch.wentUnverified([tx()], serverTrustChallenges: 1))
        XCTAssertFalse(TrustCheckWatch.wentUnverified([tx(), tx(), tx()], serverTrustChallenges: 1))
    }

    func testPlainHTTPTheCacheAndAProxyLegToAnHTTPOriginAreNotJudged() {
        XCTAssertFalse(TrustCheckWatch.wentUnverified([tx(tls: false, https: false)], serverTrustChallenges: 0))
        XCTAssertFalse(TrustCheckWatch.wentUnverified([tx(networkLoad: false)], serverTrustChallenges: 0))
        XCTAssertFalse(TrustCheckWatch.wentUnverified([tx(https: false)], serverTrustChallenges: 0))
        XCTAssertFalse(TrustCheckWatch.wentUnverified([], serverTrustChallenges: 0))
    }

    func testTheLogKeepsDistinctHostsUpToItsCapAndCountsEveryConnection() {
        let log = UnverifiedConnectionLog()
        XCTAssertEqual(log.evidence(), [])
        log.record(host: "API.example.com")
        log.record(host: "api.example.com")
        log.record(host: "files.example.com")
        XCTAssertEqual(log.evidence(), ["tls-unverified:api.example.com", "tls-unverified:files.example.com"])
        XCTAssertEqual(log.count, 3)
        for index in 0..<40 { log.record(host: "h\(index).example.com") }
        XCTAssertEqual(log.evidence().count, UnverifiedConnectionLog.maxHosts)
        XCTAssertEqual(log.count, 43)
        log.reset()
        XCTAssertEqual(log.evidence(), [])
        XCTAssertEqual(log.count, 0)
    }

    // MARK: Over the wire

    func testAVerifiedConnectionAndItsKeptAliveSuccessorPassAndRecordNothing() async throws {
        let server = try await server()
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        let (_, session) = transport(manager)
        server.enqueue(.ok("one"))
        server.enqueue(.ok("two"))

        let (first, _) = try await session.data(from: server.url("/one"))
        let (second, _) = try await session.data(from: server.url("/two"))
        XCTAssertEqual(String(decoding: first, as: UTF8.self), "one")
        XCTAssertEqual(String(decoding: second, as: UTF8.self), "two")
        // The second request rode the first connection: one handshake, one challenge, nothing recorded.
        XCTAssertEqual(server.connectionCount, 1)
        XCTAssertEqual(log.count, 0)
        XCTAssertEqual(log.evidence(), [])
    }

    func testAConnectionTheDelegateWasNeverAskedAboutIsRefusedAndRecorded() async throws {
        let server = try await server()
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        let (_, session) = transport(manager, forgetChallenges: true)
        server.enqueue(.ok("secret"))

        let error = await assertPinVaultError { _ = try await session.data(from: server.url("/data")) }
        guard case .sslHandshake(let message, let cause)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("without PinVault's trust check"), message)
        XCTAssertTrue(message.contains("localhost:\(server.port)"), message)
        guard case .security? = cause as? PinVaultError else { return XCTFail("\(String(describing: cause))") }
        // No config repairs this: the pin recovery must not refetch and retry.
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(error!))
        XCTAssertEqual(log.count, 1)
        XCTAssertEqual(log.evidence(), ["tls-unverified:localhost"])
    }

    func testPlainHTTPIsNotJudged() async throws {
        let server = try await server(tls: false)
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        let (_, session) = transport(manager, forgetChallenges: true)
        server.enqueue(.ok("plain"))

        let (body, _) = try await session.data(from: server.url("/plain"))
        XCTAssertEqual(String(decoding: body, as: UTF8.self), "plain")
        XCTAssertEqual(log.count, 0)
    }

    // MARK: WebSocket

    private final class Sender: NSObject, URLAuthenticationChallengeSender {
        func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
        func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
        func cancel(_ challenge: URLAuthenticationChallenge) {}
    }

    private func delegate(_ manager: DynamicSSLManager, tls: Bool = true) -> PinnedSessionDelegate {
        PinnedSessionDelegate(manager: manager, context: .init(
            logicalHost: "api.test", logicalPort: tls ? 443 : 80, connectHost: "api.test", connectPort: tls ? 443 : 80,
            trust: .pinned({ nil }), tls: tls
        ))
    }

    func testAWebSocketThatOpenedWithoutAChallengeIsCancelledAndRecorded() {
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        let delegate = delegate(manager)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let socket = session.webSocketTask(with: URL(string: "wss://api.test/socket")!)

        delegate.urlSession(session, webSocketTask: socket, didOpenWithProtocol: nil)
        // Cancelled (a task that was never resumed only leaves `.suspended` for `.canceling` once it ran).
        XCTAssertNotEqual(socket.state, .running)
        XCTAssertNotNil(delegate.takeFailure(socket.taskIdentifier))
        XCTAssertEqual(log.evidence(), ["tls-unverified:api.test"])
    }

    func testAWebSocketOnASessionThatWasAskedStaysOpen() {
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        let delegate = delegate(manager)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        // A server-trust challenge reached the delegate (its answer does not matter here).
        let space = URLProtectionSpace(
            host: "api.test", port: 443, protocol: NSURLProtectionSpaceHTTPS, realm: nil,
            authenticationMethod: NSURLAuthenticationMethodServerTrust
        )
        let challenge = URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil, previousFailureCount: 0, failureResponse: nil, error: nil, sender: Sender()
        )
        let probe = session.dataTask(with: URL(string: "https://api.test/")!)
        delegate.urlSession(session, task: probe, didReceive: challenge) { _, _ in }
        XCTAssertEqual(delegate.serverTrustChallengeCount, 1)
        _ = delegate.takeFailure(probe.taskIdentifier)

        let socket = session.webSocketTask(with: URL(string: "wss://api.test/socket")!)
        delegate.urlSession(session, webSocketTask: socket, didOpenWithProtocol: nil)
        XCTAssertNotEqual(socket.state, .canceling)
        XCTAssertNil(delegate.takeFailure(socket.taskIdentifier))
        XCTAssertEqual(log.count, 0)
        socket.cancel()
    }

    func testAPlainWebSocketIsNotJudged() {
        let manager = testManager()
        let log = UnverifiedConnectionLog()
        manager.unverifiedConnections = log
        // The `ws://` session: its delegate is built for plain connections.
        let delegate = delegate(manager, tls: false)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let socket = session.webSocketTask(with: URL(string: "ws://api.test/socket")!)
        delegate.urlSession(session, webSocketTask: socket, didOpenWithProtocol: nil)
        XCTAssertNotEqual(socket.state, .canceling)
        XCTAssertEqual(log.count, 0)
        socket.cancel()
    }
}
