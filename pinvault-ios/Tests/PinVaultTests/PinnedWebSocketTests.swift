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

    var webSocketCalled: Bool { called.withLock { $0 } }

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        throw PinVaultError.illegalState("unused")
    }

    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        called.withLock { $0 = true }
        throw PinVaultError.illegalArgument("boom")
    }

    func invalidate() {}
}
