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
}

/// What a ``PinnedSession`` delegates to: the URLSession machinery
/// (``URLSessionTransport``), an interceptor chain around it, or a refusal.
protocol PinnedTransport: Sendable {
    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse
    func invalidate()
}

extension PinnedTransport {
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let response = try await send(PinnedExchange(request: request))
        return (response.data, response.response)
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
