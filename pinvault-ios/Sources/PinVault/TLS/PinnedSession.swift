import Foundation

/// The iOS counterpart of the pinned OkHttp client: owns a `URLSession` whose
/// delegate is the library's pinning trust check, and runs the Android
/// interceptor chain on every request — attestation token header → send →
/// `403 reenroll_required` sniff → `401` + `PinVault-Token` re-attest-and-retry
/// once → pin-mismatch recovery.
///
/// Get one from `PinVault.shared.session()`, `session(settings:)` or
/// `applyTo(_:)`. Fail-closed: before `start` has applied a config, every
/// request fails instead of falling back to system trust.
public final class PinnedSession: @unchecked Sendable {

    let transport: any PinnedTransport

    init(transport: any PinnedTransport) {
        self.transport = transport
    }

    /// Sends `request` and returns the body and the response (`URLSession.data(for:)`).
    /// HTTP error statuses are responses, not errors.
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await transport.data(for: request)
    }

    /// GET `url` (`URLSession.data(from:)`).
    public func data(from url: URL) async throws -> (Data, URLResponse) {
        try await data(for: URLRequest(url: url))
    }

    /// Cancels outstanding requests and releases the session; later requests fail.
    public func invalidateAndCancel() {
        transport.invalidate()
    }
}

/// What a ``PinnedSession`` delegates to. L2 provides the real one (URLSession +
/// `DynamicSSLManager` delegate + the interceptor chain).
protocol PinnedTransport: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
    func invalidate()
}

/// A transport that refuses every request: before start, and until L2 lands.
struct UnavailableTransport: PinnedTransport {
    let reason: String

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        // TODO(L2): replace with the pinned URLSession transport.
        throw PinVaultError.sslHandshake(message: reason, cause: PinVaultError.illegalState(reason))
    }

    func invalidate() {}
}
