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
