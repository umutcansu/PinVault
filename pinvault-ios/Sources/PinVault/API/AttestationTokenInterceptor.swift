import Foundation

/// Where the token interceptor gets its tokens: one per attesting Config API
/// block (L5's attestation manager). A protocol so the interceptor can be
/// tested without a manager.
protocol AttestationTokenSource: Sendable {
    /// True when requests to `host:port` carry this source's token.
    func handlesHost(_ host: String, port: Int) -> Bool

    /// The token for `host:port`, or nil when none can be had right now.
    /// Without `forceRefresh` a held token with enough life left is returned as
    /// it is; otherwise the source attests once (bounded by its single flight
    /// and its backoff) and returns what that brought.
    func token(host: String, port: Int, forceRefresh: Bool) async -> String?

    /// The token for `host:port` when one with enough life is held now, with
    /// no attestation (a synchronous WebSocket upgrade); nil otherwise.
    func heldToken(host: String, port: Int) -> String?

    /// The `PinVault-Proof` for `method` `url` carrying `token` (`ATTESTATION.md`
    /// §5.1), or nil when this source sends none (no `proofOfPossession()`, or
    /// the device key cannot sign right now).
    func proof(method: String, url: URL, token: String) -> String?
}

extension AttestationTokenSource {
    func proof(method: String, url: URL, token: String) -> String? { nil }
    func heldToken(host: String, port: Int) -> String? { nil }
}

/// Adds `PinVault-Token` to requests whose host is a token host of an
/// attesting block (`ATTESTATION.md` §8), on every session the library builds
/// or configures (Kotlin `AttestationTokenInterceptor`).
///
/// Without a valid token it attests once and sends the request without the
/// header when that fails — the backend refuses it the way it refuses any
/// request without a token. A `401` that names the token (`WWW-Authenticate`
/// containing `PinVault-Token`, or a body naming `invalid_token`) forces one
/// re-attestation and one retry, tagged so the retry never retries again.
/// Requests whose body can be sent once only (`httpBodyStream`) are not retried.
/// With `proofOfPossession()` each such request also carries a `PinVault-Proof`
/// made for it (§5.1), and the retry a new one.
struct AttestationTokenInterceptor: PinnedInterceptor {

    /// The request header the token travels in.
    static let header = "PinVault-Token"
    /// The request header the proof travels in.
    static let proofHeader = TokenProof.header
    private static let wwwAuthenticate = "WWW-Authenticate"
    private static let invalidToken = "invalid_token"
    static let maxPeekBytes = 8 * 1024

    private static let log = PinVaultLog.tag("AttestationTokenInterceptor")

    let sources: @Sendable () -> [any AttestationTokenSource]

    init(sources: @escaping @Sendable () -> [any AttestationTokenSource]) {
        self.sources = sources
    }

    func intercept(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        if exchange.tags.contains(.attestationRetry) { return try await proceed(exchange) }

        // The token is a bearer credential: never over cleartext.
        guard exchange.request.url?.scheme?.lowercased() == "https" else { return try await proceed(exchange) }
        let host = exchange.host
        let port = exchange.port
        guard let source = sources().first(where: { $0.handlesHost(host, port: port) }) else {
            return try await proceed(exchange)
        }

        let token = await source.token(host: host, port: port, forceRefresh: false)
        var first = exchange
        if let token { Self.attach(token, to: &first, source: source) }
        let response = try await proceed(first)
        guard response.statusCode == 401, Self.namesToken(response) else { return response }

        if exchange.request.httpBodyStream != nil {
            Self.log.w("\(Self.header) refused the token for \(host), but the request body can be sent once only — not retried")
            return response
        }
        guard let fresh = await source.token(host: host, port: port, forceRefresh: true), fresh != token else {
            Self.log.w("\(Self.header) refused for \(host) and no new token could be had — returning the 401")
            return response
        }
        Self.log.d("\(Self.header) refused for \(host) — re-attested, retrying once")
        var retry = exchange.tagged(.attestationRetry)
        Self.attach(fresh, to: &retry, source: source)
        return try await proceed(retry)
    }

    // MARK: WebSocket upgrade requests

    /// A `wss://` upgrade to a token host gets the held token and its proof.
    /// Without a held token the socket goes without and an attestation starts
    /// in the background, so the next socket has one.
    func addWebSocketHeaders(_ request: inout URLRequest) {
        guard let (source, host, port, httpsURL) = webSocketTarget(request) else { return }
        if let token = source.heldToken(host: host, port: port) {
            Self.attach(token, toUpgrade: &request, url: httpsURL, source: source)
        } else {
            Task.detached { _ = await source.token(host: host, port: port, forceRefresh: false) }
        }
    }

    /// ``addWebSocketHeaders(_:)`` after attesting once when no token with
    /// enough life is held (the same single flight and backoff a data request
    /// gets). The socket waits at most ``webSocketWaitNanos`` for it, as an
    /// Android request does; the attestation itself carries on.
    func fetchWebSocketHeaders(_ request: inout URLRequest) async {
        guard let (source, host, port, httpsURL) = webSocketTarget(request) else { return }
        let fetch = Task { await source.token(host: host, port: port, forceRefresh: false) }
        if let token = await Self.value(of: fetch, within: webSocketWaitNanos) {
            Self.attach(token, toUpgrade: &request, url: httpsURL, source: source)
        } else {
            Self.log.w("\(Self.header): no token for the WebSocket to \(host) within the wait — it goes without")
        }
    }

    /// How long a WebSocket waits for an on-demand attestation (Android's `ON_DEMAND_WAIT_MS`).
    var webSocketWaitNanos: UInt64 = 10_000_000_000

    /// `task`'s value, or nil once `nanos` have passed first; `task` is not cancelled.
    static func value(of task: Task<String?, Never>, within nanos: UInt64) async -> String? {
        let timer = Locked<Task<Void, Never>?>(nil)
        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let done = Locked(false)
            let finish: @Sendable (String?) -> Void = { value in
                let first = done.withLock { finished -> Bool in
                    defer { finished = true }
                    return !finished
                }
                guard first else { return }
                timer.withLock { $0?.cancel() }
                continuation.resume(returning: value)
            }
            timer.withLock {
                $0 = Task {
                    try? await Task.sleep(nanoseconds: nanos)
                    if !Task.isCancelled { finish(nil) }
                }
            }
            Task { finish(await task.value) }
        }
    }

    /// The token source of a `wss://` request's host, with the `https://` URL
    /// the upgrade is sent to (the URL a proof's `htu` names, as on Android,
    /// where OkHttp sends the upgrade as an https request); nil for `ws://`
    /// (the token never goes over cleartext) or a host no block covers.
    private func webSocketTarget(_ request: URLRequest) -> (any AttestationTokenSource, String, Int, URL)? {
        guard let url = request.url, url.scheme?.lowercased() == "wss",
              var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        components.scheme = "https"
        guard let httpsURL = components.url else { return nil }
        let host = DynamicSSLManager.bareHost(url.host ?? "").lowercased()
        guard !host.isEmpty else { return nil }
        let port = url.port ?? 443
        guard let source = sources().first(where: { $0.handlesHost(host, port: port) }) else { return nil }
        return (source, host, port, httpsURL)
    }

    /// `token` and, when the source makes proofs, a proof of the upgrade
    /// (`GET` of `url`) on a WebSocket request.
    private static func attach(_ token: String, toUpgrade request: inout URLRequest, url: URL, source: any AttestationTokenSource) {
        request.setValue(token, forHTTPHeaderField: header)
        request.setValue(nil, forHTTPHeaderField: proofHeader)
        if let proof = source.proof(method: "GET", url: url, token: token) {
            request.setValue(proof, forHTTPHeaderField: proofHeader)
        }
    }

    /// `token` on the request and, when the source makes proofs, a fresh
    /// proof on every request the transport sends for it: the first and each
    /// redirect it follows (a redirect to another endpoint loses the token,
    /// so it gets no proof either).
    private static func attach(_ token: String, to exchange: inout PinnedExchange, source: any AttestationTokenSource) {
        exchange.request.setValue(token, forHTTPHeaderField: header)
        exchange.request.setValue(nil, forHTTPHeaderField: proofHeader)
        let earlier = exchange.prepareSend
        exchange.prepareSend = { request in
            earlier?(&request)
            request.setValue(nil, forHTTPHeaderField: proofHeader)
            guard let sent = request.value(forHTTPHeaderField: header), sent == token,
                  request.url?.scheme?.lowercased() == "https", let url = request.url else { return }
            if let proof = source.proof(method: (request.httpMethod ?? "GET").uppercased(), url: url, token: token) {
                request.setValue(proof, forHTTPHeaderField: proofHeader)
            }
        }
    }

    /// True when a 401 is about the token: the challenge header names it, or the body says `invalid_token`.
    static func namesToken(_ response: PinnedResponse) -> Bool {
        if let challenge = response.http?.value(forHTTPHeaderField: wwwAuthenticate),
           challenge.range(of: header, options: .caseInsensitive) != nil {
            return true
        }
        return String(decoding: response.data.prefix(maxPeekBytes), as: UTF8.self).contains(invalidToken)
    }
}
