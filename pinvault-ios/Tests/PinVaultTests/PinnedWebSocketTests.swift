import XCTest
@testable import PinVault

/// The `webSocketTask` path added to `PinnedSession`: fail-closed before start,
/// delegation through the transport chain, and the protocol's default refusal.
final class PinnedWebSocketTests: XCTestCase {

    private let url = URL(string: "wss://api.example.com/socket")!

    func testUnavailableTransportRefusesWebSocket() throws {
        // Before `start` `PinVault.shared.session()` is an UnavailableTransport.
        let session = PinnedSession(transport: UnavailableTransport(reason: "not started"))

        XCTAssertThrowsError(try session.webSocketTask(with: url)) { error in
            guard let pv = error as? PinVaultError, case .sslHandshake = pv else {
                return XCTFail("expected sslHandshake, got \(error)")
            }
        }
    }

    func testDefaultTransportRefusesWebSocket() {
        // A transport that does not override `webSocketTask` gets the default refusal.
        let session = PinnedSession(transport: NoWebSocketTransport())

        XCTAssertThrowsError(try session.webSocketTask(with: url)) { error in
            guard let pv = error as? PinVaultError, case .illegalState = pv else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testTheUpgradeRequestKeepsTheHeadersAndTimeout() throws {
        // ws:// skips the pin re-check, so no config is needed to build the task.
        let session = DynamicSSLManager().buildDynamicClient(configProvider: { nil })
        var request = URLRequest(url: URL(string: "ws://api.example.com/socket")!, timeoutInterval: 7)
        request.setValue("Bearer abc", forHTTPHeaderField: "Authorization")
        request.setValue("1", forHTTPHeaderField: "X-Test")

        let task = try session.webSocketTask(for: request)
        defer { task.cancel() }
        XCTAssertEqual(task.originalRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer abc")
        XCTAssertEqual(task.originalRequest?.value(forHTTPHeaderField: "X-Test"), "1")
        XCTAssertEqual(task.originalRequest?.timeoutInterval, 7)
    }

        func testAResolveEntryForTheHostRefusesTheSocket() {
        let settings = HttpConnectionSettings().resolve(host: "api.example.com", to: "10.0.0.1")
        let session = DynamicSSLManager().buildDynamicClient(configProvider: { nil }, settings: settings)

        XCTAssertThrowsError(try session.webSocketTask(with: URL(string: "ws://api.example.com/socket")!)) { error in
            guard let pv = error as? PinVaultError, case .illegalArgument = pv else {
                return XCTFail("expected illegalArgument, got \(error)")
            }
        }
        // Another host is not affected.
        XCTAssertNoThrow(try session.webSocketTask(with: URL(string: "ws://other.example.com/socket")!).cancel())
    }

    func testInterceptedTransportDelegatesWebSocketToBase() throws {
        let base = RecordingBase()
        let session = PinnedSession(transport: InterceptedTransport(interceptors: [], base: base))

        XCTAssertThrowsError(try session.webSocketTask(with: url))
        XCTAssertTrue(base.webSocketCalled, "the intercepted transport must ask its base for the socket")
    }

    // MARK: Attestation token on the upgrade request

    private func tokenSession(_ source: WebSocketTokenSource, base: RecordingBase) -> PinnedSession {
        PinnedSession(interceptors: [AttestationTokenInterceptor { [source] }], transport: base)
    }

    func testAHeldTokenAndItsProofGoOnTheUpgradeRequest() throws {
        let source = WebSocketTokenSource(held: "t1", proofs: true)
        let base = RecordingBase()
        var request = URLRequest(url: URL(string: "wss://api.example.com:8443/socket?x=1")!)
        request.setValue("caller", forHTTPHeaderField: "PinVault-Proof")

        XCTAssertThrowsError(try tokenSession(source, base: base).webSocketTask(for: request))
        let sent = try XCTUnwrap(base.lastRequest)
        XCTAssertEqual(sent.value(forHTTPHeaderField: "PinVault-Token"), "t1")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "PinVault-Proof"), "proof-t1")
        XCTAssertEqual(sent.url?.scheme, "wss", "the socket still opens its own URL")
        XCTAssertEqual(source.proofFor, ["GET https://api.example.com:8443/socket?x=1"], "the proof names the https URL of the upgrade")
        XCTAssertEqual(source.asked, 0, "the synchronous form never attests")
    }

    func testWithoutAHeldTokenTheSynchronousFormStartsAnAttestationAndSendsNothing() async throws {
        let source = WebSocketTokenSource(held: nil, fetched: "t2")
        let base = RecordingBase()

        XCTAssertThrowsError(try tokenSession(source, base: base).webSocketTask(with: url))
        XCTAssertNil(base.lastRequest?.value(forHTTPHeaderField: "PinVault-Token"))
        for _ in 0..<100 where source.asked == 0 { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(source.asked, 1, "a background attestation is started for the next socket")
    }

    func testTheAsyncFormAttestsFirstAndSendsTheToken() async throws {
        let source = WebSocketTokenSource(held: nil, fetched: "t2", proofs: true)
        let base = RecordingBase()

        do {
            _ = try await tokenSession(source, base: base).makeWebSocketTask(with: url)
            XCTFail("the recording base throws")
        } catch {}
        let sent = try XCTUnwrap(base.lastRequest)
        XCTAssertEqual(sent.value(forHTTPHeaderField: "PinVault-Token"), "t2")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "PinVault-Proof"), "proof-t2")
        XCTAssertEqual(source.asked, 1)
    }

    func testTheAsyncFormWaitsForTheTokenOnlySoLong() async throws {
        let source = WebSocketTokenSource(held: nil, fetched: "late", delayNanos: 3_000_000_000)
        let base = RecordingBase()
        var interceptor = AttestationTokenInterceptor { [source] }
        interceptor.webSocketWaitNanos = 100_000_000
        let session = PinnedSession(interceptors: [interceptor], transport: base)

        let started = Date()
        _ = try? await session.makeWebSocketTask(with: url)
        XCTAssertLessThan(Date().timeIntervalSince(started), 2, "the socket did not wait for the slow attestation")
        XCTAssertNil(base.lastRequest?.value(forHTTPHeaderField: "PinVault-Token"))
        XCTAssertEqual(source.asked, 1)
    }

    func testACleartextSocketOrAnUncoveredHostGetsNoToken() async throws {
        let base = RecordingBase()
        let source = WebSocketTokenSource(held: "t1", fetched: "t1")
        _ = try? await tokenSession(source, base: base).makeWebSocketTask(with: URL(string: "ws://api.example.com/socket")!)
        XCTAssertNil(base.lastRequest?.value(forHTTPHeaderField: "PinVault-Token"), "never over cleartext")

        let other = WebSocketTokenSource(held: "t1", fetched: "t1", handles: false)
        _ = try? await tokenSession(other, base: base).makeWebSocketTask(with: url)
        XCTAssertNil(base.lastRequest?.value(forHTTPHeaderField: "PinVault-Token"))
        XCTAssertEqual(source.asked + other.asked, 0)
    }
}

/// A token source for the upgrade-request tests.
private final class WebSocketTokenSource: AttestationTokenSource, @unchecked Sendable {
    private let held: String?
    private let fetched: String?
    private let handles: Bool
    private let proofs: Bool
    private let delayNanos: UInt64
    private let askedCount = Locked(0)
    private let proofLog = Locked<[String]>([])

    init(held: String?, fetched: String? = nil, proofs: Bool = false, handles: Bool = true, delayNanos: UInt64 = 0) {
        self.delayNanos = delayNanos
        self.held = held
        self.fetched = fetched
        self.proofs = proofs
        self.handles = handles
    }

    var asked: Int { askedCount.withLock { $0 } }
    var proofFor: [String] { proofLog.withLock { $0 } }

    func handlesHost(_ host: String, port: Int) -> Bool { handles }
    func heldToken(host: String, port: Int) -> String? { held }

    func token(host: String, port: Int, forceRefresh: Bool) async -> String? {
        askedCount.withLock { $0 += 1 }
        if delayNanos > 0 { try? await Task.sleep(nanoseconds: delayNanos) }
        return fetched
    }

    func proof(method: String, url: URL, token: String) -> String? {
        guard proofs else { return nil }
        proofLog.withLock { $0.append("\(method) \(url.absoluteString)") }
        return "proof-\(token)"
    }
}

/// A transport that keeps the protocol's default `webSocketTask` (refuses).
private struct NoWebSocketTransport: PinnedTransport {
    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        throw PinVaultError.illegalState("unused")
    }
    func invalidate() {}
}

/// A base that records the WebSocket call and throws a distinctive error.
private final class RecordingBase: PinnedTransport {
    private let called = Locked(false)
    private let request = Locked<URLRequest?>(nil)

    var webSocketCalled: Bool { called.withLock { $0 } }
    var lastRequest: URLRequest? { request.withLock { $0 } }

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        throw PinVaultError.illegalState("unused")
    }

    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        called.withLock { $0 = true }
        self.request.withLock { $0 = request }
        throw PinVaultError.illegalArgument("boom")
    }

    func invalidate() {}
}
