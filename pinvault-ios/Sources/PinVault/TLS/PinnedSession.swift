import Foundation

/// The iOS counterpart of the pinned OkHttp client: owns `URLSession`s whose
/// delegate is the library's pinning trust check, and runs the Android
/// interceptor chain on every request — attestation token header → send →
/// `403 reenroll_required` sniff → `401` + `PinVault-Token` re-attest-and-retry
/// once → pin-mismatch recovery. Which of these a session carries depends on
/// where it comes from, as on Android (see `PinVault.session()`,
/// `session(settings:)`, `applyTo(_:)`).
///
/// Get one from `PinVault.shared.session()`, `session(settings:)` or
/// `applyTo(_:)`. Fail-closed: before `start` has applied a config, every
/// request fails instead of falling back to system trust.
///
/// Errors: a refused peer throws ``PinVaultError/sslHandshake(message:cause:)``
/// whose cause is the trust check's ``PinVaultError`` (the
/// `CertificateException` family: ``PinVaultError/unpinnedHost(message:cause:)``,
/// ``PinVaultError/certificateValidity(message:cause:)``, …), or
/// ``PinVaultError/sslPeerUnverified(message:)`` when the certificate does not
/// name the host; other TLS failures ``PinVaultError/sslHandshake(message:cause:)``
/// with the `URLError` as cause; any other transport failure
/// ``PinVaultError/io(message:cause:)`` with the `URLError` as cause. A
/// cancelled Swift task throws `CancellationError`.
public final class PinnedSession: @unchecked Sendable {

    let transport: any PinnedTransport

    init(transport: any PinnedTransport) {
        self.transport = transport
    }

    /// A session that runs `interceptors` (outermost first) around `transport`.
    convenience init(interceptors: [any PinnedInterceptor], transport: any PinnedTransport) {
        self.init(transport: interceptors.isEmpty ? transport : InterceptedTransport(interceptors: interceptors, base: transport))
    }

    /// Sends `request` and returns the body and the response (`URLSession.data(for:)`).
    /// HTTP error statuses are responses, not errors.
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let response = try await send(PinnedExchange(request: request))
        return (response.data, response.response)
    }

    /// ``data(for:)`` with a bound on the answer: the transport stops reading
    /// once the body passes `maxResponseBytes` — whatever the status — and
    /// throws `ResponseTooLargeException` instead of keeping it; a declared
    /// `Content-Length` over the bound is refused before the body is read.
    /// For answers whose size the app does not control (the React Native
    /// plugin's `fetch`).
    public func data(for request: URLRequest, maxResponseBytes: Int64) async throws -> (Data, URLResponse) {
        guard maxResponseBytes > 0 else { throw PinVaultError.illegalArgument("maxResponseBytes must be positive") }
        let response = try await send(PinnedExchange(request: request, bodyLimit: .always(maxResponseBytes, "response")))
        return (response.data, response.response)
    }

    /// GET `url` (`URLSession.data(from:)`).
    public func data(from url: URL) async throws -> (Data, URLResponse) {
        try await data(for: URLRequest(url: url))
    }

    /// A pinned `wss://` (or `ws://`) WebSocket task over this session's own
    /// TLS machinery — the delegate that answers the server-trust and
    /// client-certificate (mTLS) challenges, so a pinned, mTLS-capable socket.
    /// Fail-closed: before `start` has applied a config (or after a failed one)
    /// this throws. Call `task.resume()`, then `task.send` / `task.receive`;
    /// the task lives as long as this session does.
    ///
    /// The upgrade request of a `wss://` socket to a token host carries the
    /// attestation token (and, with `proofOfPossession()`, a proof made for it)
    /// when one is held. This call does not wait for an attestation: without a
    /// held token it starts one in the background and the socket goes without
    /// — use ``makeWebSocketTask(for:)`` to wait for the token first.
    ///
    /// A `resolve(host:to:)` entry for the host does not apply: the socket would
    /// connect to a different address than the one the delegate pins, so such a
    /// socket is refused (fail closed) rather than silently misrouted.
    public func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        try transport.webSocketTask(for: request)
    }

    /// ``webSocketTask(for:)`` for a URL.
    public func webSocketTask(with url: URL) throws -> URLSessionWebSocketTask {
        try webSocketTask(for: URLRequest(url: url))
    }

    /// ``webSocketTask(for:)`` that first gets what the session's request steps
    /// add to the upgrade request: for a `wss://` socket to a token host, the
    /// attestation token — attesting once when none with enough life is held
    /// (bounded by the attestation's single flight and backoff, as for a data
    /// request) — and its proof. The Android client's `newWebSocket` does the
    /// same. A WebSocket upgrade is not retried after a `401`.
    public func makeWebSocketTask(for request: URLRequest) async throws -> URLSessionWebSocketTask {
        try await transport.preparedWebSocketTask(for: request)
    }

    /// ``makeWebSocketTask(for:)`` for a URL.
    public func makeWebSocketTask(with url: URL) async throws -> URLSessionWebSocketTask {
        try await makeWebSocketTask(for: URLRequest(url: url))
    }

    /// Cancels outstanding requests and releases the session; later requests fail.
    public func invalidateAndCancel() {
        transport.invalidate()
    }

    /// One request through the whole chain, with its tags (library internal).
    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        try await transport.send(exchange)
    }
}

/// A request on its way through the chain, with the marks interceptors leave
/// on it (the counterpart of OkHttp request tags).
struct PinnedExchange: Sendable {
    enum Tag: Hashable, Sendable {
        /// The fallback retry of a pin recovery: it does not start a recovery of its own.
        case recoveryAttempt
        /// The one retry after a forced re-attestation: it is not retried again.
        case attestationRetry
    }

    var request: URLRequest
    var tags: Set<Tag> = []
    /// How much of the response body the transport reads (Kotlin `BoundedBody`);
    /// nil = all of it (sessions handed to the app).
    var bodyLimit: BoundedBody.Limit?
    /// Run by the transport on every request it puts on the wire — the first
    /// one and each redirect it follows — so a per-request credential (the
    /// attestation proof) is made for the URL actually sent, never reused.
    var prepareSend: (@Sendable (inout URLRequest) -> Void)?

    init(request: URLRequest, tags: Set<Tag> = [], bodyLimit: BoundedBody.Limit? = nil) {
        self.request = request
        self.tags = tags
        self.bodyLimit = bodyLimit
    }

    func tagged(_ tag: Tag) -> PinnedExchange {
        var copy = self
        copy.tags.insert(tag)
        return copy
    }

    /// The request's URL host, lower case, no brackets ("" without one).
    var host: String { DynamicSSLManager.bareHost(request.url?.host ?? "").lowercased() }

    /// The request's port, the scheme's default when the URL names none.
    var port: Int {
        if let port = request.url?.port { return port }
        return request.url?.scheme?.lowercased() == "http" ? 80 : 443
    }
}

/// A response on its way back.
struct PinnedResponse: @unchecked Sendable {
    let data: Data
    let response: URLResponse
    /// The client certificate the connection presented; nil when it presented none.
    let presentedClientCertificate: X509Certificate?

    var http: HTTPURLResponse? { response as? HTTPURLResponse }
    var statusCode: Int { http?.statusCode ?? 0 }
}

/// One step of the chain (an OkHttp application interceptor): may change the
/// request, call `proceed` (zero, one or more times) and change the response.
protocol PinnedInterceptor: Sendable {
    func intercept(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse

    /// What this step adds to a WebSocket upgrade request from what it holds
    /// right now (no network). Default: nothing.
    func addWebSocketHeaders(_ request: inout URLRequest)

    /// ``addWebSocketHeaders(_:)`` after fetching what is missing (an
    /// attestation). Default: the synchronous form.
    func fetchWebSocketHeaders(_ request: inout URLRequest) async
}

extension PinnedInterceptor {
    func addWebSocketHeaders(_ request: inout URLRequest) {}

    func fetchWebSocketHeaders(_ request: inout URLRequest) async {
        addWebSocketHeaders(&request)
    }
}

/// What a ``PinnedSession`` delegates to: the URLSession machinery
/// (``URLSessionTransport``), an interceptor chain around it, or a refusal.
protocol PinnedTransport: Sendable {
    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse
    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask
    /// ``webSocketTask(for:)`` after the chain fetched what its steps add to
    /// the upgrade request. Default: ``webSocketTask(for:)``.
    func preparedWebSocketTask(for request: URLRequest) async throws -> URLSessionWebSocketTask
    func invalidate()
}

extension PinnedTransport {
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let response = try await send(PinnedExchange(request: request))
        return (response.data, response.response)
    }

    /// Default: transports that do not open WebSockets (the unavailable one,
    /// test doubles) refuse them. ``URLSessionTransport`` overrides this.
    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        throw PinVaultError.illegalState("This pinned session does not open WebSockets")
    }

    func preparedWebSocketTask(for request: URLRequest) async throws -> URLSessionWebSocketTask {
        try webSocketTask(for: request)
    }
}

/// `interceptors` (outermost first) around `base`.
struct InterceptedTransport: PinnedTransport {
    let interceptors: [any PinnedInterceptor]
    let base: any PinnedTransport

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        try await run(from: 0, exchange)
    }

    private func run(from index: Int, _ exchange: PinnedExchange) async throws -> PinnedResponse {
        guard index < interceptors.count else { return try await base.send(exchange) }
        return try await interceptors[index].intercept(exchange) { next in
            try await self.run(from: index + 1, next)
        }
    }

    /// The upgrade request goes through every step's WebSocket headers
    /// (outermost first), then to `base`: a WebSocket has no response the
    /// steps could act on, so only the request side of the chain runs.
    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        var request = request
        for interceptor in interceptors { interceptor.addWebSocketHeaders(&request) }
        return try base.webSocketTask(for: request)
    }

    func preparedWebSocketTask(for request: URLRequest) async throws -> URLSessionWebSocketTask {
        var request = request
        for interceptor in interceptors { await interceptor.fetchWebSocketHeaders(&request) }
        return try await base.preparedWebSocketTask(for: request)
    }

    func invalidate() {
        base.invalidate()
    }
}

/// A transport that refuses every request: before start (fail-closed).
struct UnavailableTransport: PinnedTransport {
    let reason: String

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        throw PinVaultError.sslHandshake(message: reason, cause: PinVaultError.illegalState(reason))
    }

    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        throw PinVaultError.sslHandshake(message: reason, cause: PinVaultError.illegalState(reason))
    }

    func invalidate() {}
}

/// The bootstrap client's refusal of plain HTTP: a Config API request never
/// leaves the device unencrypted unless the block called `allowUnpinnedConfigApi()`.
struct HTTPSOnlyInterceptor: PinnedInterceptor {
    func intercept(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        guard exchange.request.url?.scheme?.lowercased() == "https" else {
            throw PinVaultError.io(
                message: "Refusing a plain-HTTP request to the Config API (\(exchange.host)): " +
                    "use https://, or allowUnpinnedConfigApi() for tests"
            )
        }
        return try await proceed(exchange)
    }
}
