import Foundation

/// The URLSession machinery under a ``PinnedSession``: one `URLSession` per
/// logical scheme/host/port (each with its own ``PinnedSessionDelegate``),
/// request routing for `resolve(host:to:)` and the E2E redirects, the
/// per-request config check, redirect following and error mapping.
///
/// ## Routing
/// A request for `https://mock-tls.sample/x` that a `resolve` entry sends to
/// `192.168.1.10` goes out as `https://192.168.1.10/x` with
/// `Host: mock-tls.sample`; the session it rides is the one for
/// `mock-tls.sample:443`, whose delegate pins, verifies the hostname and picks
/// the client certificate for `mock-tls.sample`. (URLSession sends the URL's
/// host as SNI, so the server sees the address there — OkHttp with a custom
/// `Dns` would send the logical name.)
///
/// ## Rebuilding
/// Before every request the sessions are compared with the manager's
/// generation (pins, identity, routing, E2E controls) and with the config the
/// provider returns now; when either moved, every session of this transport is
/// retired (`finishTasksAndInvalidate`) and new ones are built — see
/// ``DynamicSSLManager`` for why that replaces OkHttp's per-request
/// connection check.
final class URLSessionTransport: PinnedTransport, @unchecked Sendable {

    /// Which redirects the transport follows (OkHttp `followRedirects` / `followSslRedirects`).
    enum RedirectPolicy: Sendable {
        /// None: the 3xx is the answer (the bootstrap client).
        case none
        /// Not between `http` and `https`, either way: every pinned session
        /// (library-built, `applyTo`, `session(settings:)`) unless the app opts in.
        case sameScheme
        /// All (OkHttp's defaults): the unpinned bootstrap client, and an
        /// app session with `followCleartextRedirects`.
        case all
    }

    static let maxFollowUps = 20

    let manager: DynamicSSLManager
    private let template: URLSessionConfiguration
    let trust: DynamicSSLManager.TrustMode
    let resolveOverrides: [String: String]
    let redirects: RedirectPolicy
    /// Which requests ask for `forbidden-as-409` (see ``ForbiddenAsConflict``).
    let forbiddenAs409: ForbiddenAsConflict.Policy

    /// The configuration every session of this transport is a copy of.
    var configuration: URLSessionConfiguration { template }

    /// One session and its delegate. The transport hands an entry out of its
    /// state lock and creates the task a moment later, while another thread
    /// (a pin update, an identity change, a failed per-request check) may
    /// retire that same session. Creating a task on an invalidated URLSession
    /// raises an Objective-C exception Swift cannot catch — the process
    /// dies — so both go through this entry's own lock: a task is only made
    /// while the session is not retired, and retiring marks it before it
    /// invalidates. A caller that finds the entry retired asks for a new one.
    private final class Entry: @unchecked Sendable {
        let delegate: PinnedSessionDelegate
        private let session: URLSession
        private let lock = NSLock()
        private var retired = false

        init(session: URLSession, delegate: PinnedSessionDelegate) {
            self.session = session
            self.delegate = delegate
        }

        /// A task made by `make` on the session, or nil when it was retired.
        func task<T: URLSessionTask>(_ make: (URLSession) -> T) -> T? {
            lock.lock()
            defer { lock.unlock() }
            return retired ? nil : make(session)
        }

        /// Invalidates the session, once: idle connections close and tasks
        /// already running complete, or with `cancel` they are cancelled.
        func retire(cancel: Bool = false) {
            lock.lock()
            defer { lock.unlock() }
            if retired { return }
            retired = true
            if cancel { session.invalidateAndCancel() } else { session.finishTasksAndInvalidate() }
        }
    }

    /// How many times a request asks for a new session after finding the one
    /// it was handed retired. Each round means the config, the pins or the
    /// identity moved again in between; this many in a row is not a state to
    /// keep spinning in.
    static let maxSessionAttempts = 8

    private struct State {
        var entries: [String: Entry] = [:]
        var generation: DynamicSSLManager.SessionGeneration?
        var config: CertificateConfig?
        var invalidated = false
    }

    private let state = Locked(State())
    /// Tests only: every delegate built from now on forgets the challenges it
    /// was asked (``PinnedSessionDelegate/testOnlyForgetChallenges``).
    var testOnlyForgetChallenges = false

    init(
        manager: DynamicSSLManager,
        configuration: URLSessionConfiguration,
        trust: DynamicSSLManager.TrustMode,
        resolveOverrides: [String: String],
        redirects: RedirectPolicy,
        forbiddenAs409: ForbiddenAsConflict.Policy = .identityHosts
    ) {
        self.manager = manager
        self.template = configuration
        self.trust = trust
        var normalized: [String: String] = [:]
        for (host, address) in resolveOverrides { normalized[host.lowercased()] = address }
        self.resolveOverrides = normalized
        self.redirects = redirects
        self.forbiddenAs409 = forbiddenAs409
        manager.register(self)
    }

    deinit {
        for entry in state.withLock({ $0.entries.values }) { entry.retire() }
    }

    func invalidate() {
        let entries = state.withLock { state -> [Entry] in
            state.invalidated = true
            defer { state.entries = [:] }
            return Array(state.entries.values)
        }
        entries.forEach { $0.retire(cancel: true) }
    }

    /// Invalidates every session now (idle connections close; requests in
    /// flight complete); the next request builds new ones.
    func retireSessions() {
        let entries = state.withLock { state -> [Entry] in
            defer {
                state.entries = [:]
                state.generation = nil
            }
            return Array(state.entries.values)
        }
        entries.forEach { $0.retire() }
    }

    // MARK: Sending

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        var request = exchange.request
        var followUps = 0
        while true {
            var wire = request
            exchange.prepareSend?(&wire)
            let response = try await sendOnce(wire, limit: exchange.bodyLimit)
            guard let next = followUp(response, for: request) else { return response }
            followUps += 1
            if followUps > Self.maxFollowUps {
                throw PinVaultError.io(message: "Too many follow-up requests: \(followUps)")
            }
            request = next
        }
    }

    /// True when a request to the logical `host:port` asks for `forbidden-as-409`.
    private func asksForbiddenAs409(scheme: String, host: String, port: Int) -> Bool {
        switch forbiddenAs409 {
        case .always:
            return true
        case .identityHosts:
            guard scheme == "https", let provider = trust.configProvider else { return false }
            return manager.clientIdentity(forHost: host, port: port, config: provider) != nil
        }
    }

    private func sendOnce(_ request: URLRequest, limit: BoundedBody.Limit?) async throws -> PinnedResponse {
        guard let url = request.url, let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let rawHost = url.host, !rawHost.isEmpty else {
            throw PinVaultError.illegalArgument("Expected an http or https URL with a host: \(request.url?.absoluteString ?? "nil")")
        }
        let host = DynamicSSLManager.bareHost(rawHost).lowercased()
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        // A session retired between being handed out and the task being made
        // (see Entry) is replaced by a new one, with the checks done again.
        for _ in 0..<Self.maxSessionAttempts {
            if let response = try await sendOnce(request, url: url, scheme: scheme, host: host, port: port, limit: limit) {
                return response
            }
        }
        throw PinVaultError.io(message: "The pinned session for \(DynamicSSLManager.hostPort(host, port)) kept being rebuilt; the request was not sent")
    }

    /// One attempt on the current session of `scheme://host:port`; nil when
    /// that session was retired before the task could be made (nothing was sent).
    private func sendOnce(
        _ request: URLRequest, url: URL, scheme: String, host: String, port: Int, limit: BoundedBody.Limit?
    ) async throws -> PinnedResponse? {
        let entry = try session(scheme: scheme, host: host, port: port)

        if scheme == "https", let provider = trust.configProvider {
            do {
                try PinnedConnectionInterceptor.check(manager: manager, config: provider(), host: host)
            } catch {
                retire(key: Self.key(scheme, host, port), entry)
                throw error
            }
        }

        let context = entry.delegate.context
        var wire = request
        let rewritten = context.connectHost != host || context.connectPort != port
        if rewritten {
            var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            if context.connectHost.contains(":") {
                components?.percentEncodedHost = "[\(context.connectHost)]"
            } else {
                components?.host = context.connectHost
            }
            components?.port = context.connectPort
            guard let wireURL = components?.url else {
                throw PinVaultError.illegalArgument("Cannot route \(url.absoluteString) to \(context.connectHost)")
            }
            wire.url = wireURL
            wire.setValue(Self.hostHeader(host, port, scheme: scheme), forHTTPHeaderField: "Host")
        }
        if asksForbiddenAs409(scheme: scheme, host: host, port: port) {
            let features = wire.value(forHTTPHeaderField: ForbiddenAsConflict.featuresHeader)
            wire.setValue(ForbiddenAsConflict.adding(to: features), forHTTPHeaderField: ForbiddenAsConflict.featuresHeader)
        }
        let askedForbiddenAs409 = ForbiddenAsConflict.requested(wire.value(forHTTPHeaderField: ForbiddenAsConflict.featuresHeader))

        guard let outcome = await run(entry, wire, limit: limit) else { return nil }
        if let error = outcome.error {
            if let failure = entry.delegate.takeFailure(outcome.taskIdentifier) { throw failure.thrown }
            if let tooLarge = error as? ResponseTooLargeException { throw tooLarge }
            if Task.isCancelled { throw CancellationError() }
            throw Self.transportError(error)
        }
        // A connection the trust check never saw (TrustCheckWatch) fails the
        // request whatever URLSession reported.
        if let failure = entry.delegate.takeFailure(outcome.taskIdentifier) { throw failure.thrown }
        guard let response = outcome.response else { throw PinVaultError.io(message: "No response for \(url.absoluteString)") }
        var answer: URLResponse = response
        if let http = response as? HTTPURLResponse {
            if askedForbiddenAs409, let forbidden = ForbiddenAsConflict.normalized(http, url: url) {
                // The 403 the server sent as 409 (forbidden-as-409): the interceptors and the API client see a 403.
                answer = forbidden
            } else if rewritten {
                // The app sees the URL it asked for, not the address the connection went to.
                answer = HTTPURLResponse(
                    url: url, statusCode: http.statusCode, httpVersion: nil, headerFields: ForbiddenAsConflict.headerFields(http)
                ) ?? http
            }
        }
        return PinnedResponse(data: outcome.data, response: answer, presentedClientCertificate: entry.delegate.presentedClientCertificate)
    }

    /// A `URLSessionWebSocketTask` on the pinned session for the URL's host and
    /// port (the same delegate that answers the server-trust and client-certificate
    /// challenges, so the socket is pinned and mTLS-capable). `wss` maps to the
    /// `https` session, `ws` to `http`. Before `start` (or after a failed one)
    /// `session(_:_:_:)` fails closed, as does a `resolve` override whose address
    /// would not match the delegate's pinned connect address.
    func webSocketTask(for request: URLRequest) throws -> URLSessionWebSocketTask {
        guard let url = request.url,
              let scheme = url.scheme?.lowercased(), scheme == "wss" || scheme == "ws",
              let rawHost = url.host, !rawHost.isEmpty else {
            throw PinVaultError.illegalArgument("Expected a wss:// or ws:// URL with a host: \(request.url?.absoluteString ?? "nil")")
        }
        let host = DynamicSSLManager.bareHost(rawHost).lowercased()
        let httpScheme = scheme == "wss" ? "https" : "http"
        let port = url.port ?? (scheme == "wss" ? 443 : 80)
        // A WebSocket task connects to its URL's own host; unlike a data task
        // it cannot be pointed at another address. A resolve(host:to:) (or
        // redirect) entry for the host refuses the socket instead of letting
        // it go somewhere other than configured.
        let address = manager.connectAddress(host: host, port: port, overrides: resolveOverrides)
        if address.host != host || address.port != port {
            throw PinVaultError.illegalArgument(
                "WebSocket to \(DynamicSSLManager.hostPort(host, port)): resolve(host:to:) points it at " +
                "\(DynamicSSLManager.hostPort(address.host, address.port)), and a WebSocket connects to its URL's host"
            )
        }
        // A session retired before the task is made is replaced, as for a data task.
        for _ in 0..<Self.maxSessionAttempts {
            let entry = try session(scheme: httpScheme, host: host, port: port)

            // The same per-request re-check a data task gets: a pin set that moved
            // (or a config that expired) refuses the socket before it opens.
            if scheme == "wss", let provider = trust.configProvider {
                do {
                    try PinnedConnectionInterceptor.check(manager: manager, config: provider(), host: host)
                } catch {
                    retire(key: Self.key(httpScheme, host, port), entry)
                    throw error
                }
            }
            // The request, not only its URL: its headers (Authorization, a token)
            // and timeout go into the upgrade request.
            if let task = entry.task({ $0.webSocketTask(with: request) }) { return task }
        }
        throw PinVaultError.io(message: "The pinned session for \(DynamicSSLManager.hostPort(host, port)) kept being rebuilt; the socket was not opened")
    }

    /// Runs one data task whose body the delegate collects under `limit`; the
    /// task identifier says where the delegate recorded a refusal. Nil when
    /// the entry's session was retired: no task was made.
    private func run(_ entry: Entry, _ request: URLRequest, limit: BoundedBody.Limit?) async -> ResponseCollector.Outcome? {
        let delegate = entry.delegate
        let box = TaskBox()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<ResponseCollector.Outcome?, Never>) in
                // Made (not started) and given its collector under the entry's
                // lock, in one step: `invalidate()` cancels a session's tasks
                // through the same lock, and a task cancelled before its
                // collector was registered would complete with nobody
                // listening — this request would wait forever. A session
                // retired without cancelling still lets the task run to its end.
                let task = entry.task { session -> URLSessionDataTask in
                    let task = session.dataTask(with: request)
                    delegate.collect(task.taskIdentifier, ResponseCollector(limit: limit, continuation: continuation))
                    return task
                }
                guard let task else {
                    continuation.resume(returning: nil)
                    return
                }
                box.start(task)
            }
        } onCancel: {
            box.cancel()
        }
    }

    /// The URLSession for `scheme://host:port`, built now when the generation
    /// or the config moved since the current ones were (which are then retired).
    private func session(scheme: String, host: String, port: Int) throws -> Entry {
        let generation = manager.sessionGeneration
        let config = trust.configProvider?()
        var retired: [Entry] = []
        let entry = try state.withLock { state -> Entry in
            if state.invalidated { throw PinVaultError.illegalState("The pinned session was invalidated") }
            if state.generation != generation || state.config != config {
                retired = Array(state.entries.values)
                state.entries = [:]
                state.generation = generation
                state.config = config
            }
            let key = Self.key(scheme, host, port)
            if let entry = state.entries[key] { return entry }
            let address = manager.connectAddress(host: host, port: port, overrides: resolveOverrides)
            let delegate = PinnedSessionDelegate(manager: manager, context: .init(
                logicalHost: host, logicalPort: port, connectHost: address.host, connectPort: address.port, trust: trust,
                tls: scheme == "https"
            ))
            delegate.testOnlyForgetChallenges = testOnlyForgetChallenges
            let configuration = template.copy() as! URLSessionConfiguration
            let entry = Entry(session: URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil), delegate: delegate)
            state.entries[key] = entry
            return entry
        }
        retired.forEach { $0.retire() }
        return entry
    }

    private func retire(key: String, _ entry: Entry) {
        let removed = state.withLock { state -> Bool in
            guard let current = state.entries[key], current === entry else { return false }
            state.entries[key] = nil
            return true
        }
        if removed { entry.retire() }
    }

    private static func key(_ scheme: String, _ host: String, _ port: Int) -> String {
        "\(scheme)://\(DynamicSSLManager.hostPort(host, port))"
    }

    /// OkHttp's `Host` header: the port only when it is not the scheme's default.
    static func hostHeader(_ host: String, _ port: Int, scheme: String) -> String {
        let name = host.contains(":") ? "[\(host)]" : host
        let defaultPort = scheme == "https" ? 443 : 80
        return port == defaultPort ? name : "\(name):\(port)"
    }

    // MARK: Redirects

    /// The next request for a 3xx, or nil when the response is the answer
    /// (OkHttp `RetryAndFollowUpInterceptor.buildRedirectRequest`).
    private func followUp(_ response: PinnedResponse, for request: URLRequest) -> URLRequest? {
        guard redirects != .none, let http = response.http else { return nil }
        let code = http.statusCode
        guard [300, 301, 302, 303, 307, 308].contains(code),
              let location = http.value(forHTTPHeaderField: "Location"),
              let current = request.url,
              let target = URL(string: location, relativeTo: current)?.absoluteURL,
              let scheme = target.scheme?.lowercased(), scheme == "https" || scheme == "http" else { return nil }
        let sameScheme = scheme == current.scheme?.lowercased()
        if !sameScheme, redirects == .sameScheme { return nil }

        var next = request
        next.url = target
        let method = (request.httpMethod ?? "GET").uppercased()
        if method != "GET", method != "HEAD" {
            let maintainBody = method == "PROPFIND" || code == 307 || code == 308
            if method != "PROPFIND", code != 307, code != 308 {
                next.httpMethod = "GET"
                next.httpBody = nil
                next.httpBodyStream = nil
            } else if !maintainBody {
                next.httpBody = nil
                next.httpBodyStream = nil
            }
            if !maintainBody {
                for name in ["Transfer-Encoding", "Content-Length", "Content-Type"] { next.setValue(nil, forHTTPHeaderField: name) }
            }
        }
        // A request for another endpoint (host, port or scheme) carries nothing
        // the caller meant for the first one. OkHttp drops only Authorization;
        // a fixed list of credential names is not enough either — an app's own
        // session or API-key header has any name. So only headers that say
        // nothing about the caller go along, and a body is not sent again: a
        // 307/308 that would repeat it to another endpoint is the answer (an
        // empty body carries nothing and counts as none, as on Android).
        // What the library adds for the new destination (its token for a token
        // host, `Host`, `forbidden-as-409`) is added when that hop is sent.
        let sameEndpoint = target.host?.lowercased() == current.host?.lowercased()
            && (target.port ?? (scheme == "https" ? 443 : 80)) == (current.port ?? (current.scheme?.lowercased() == "https" ? 443 : 80))
            && sameScheme
        if !sameEndpoint {
            if next.httpBody?.isEmpty == false || next.httpBodyStream != nil { return nil }
            for name in (next.allHTTPHeaderFields ?? [:]).keys where !Self.crossEndpointHeaders.contains(name.lowercased()) {
                next.setValue(nil, forHTTPHeaderField: name)
            }
        }
        next.setValue(nil, forHTTPHeaderField: "Host")
        // A body that can be sent once only (a stream, already read) is not sent again: the 3xx is the answer.
        if next.httpBodyStream != nil { return nil }
        return next
    }

    /// The only request headers that follow a redirect to another endpoint
    /// (lower case): what the client accepts and what it is.
    static let crossEndpointHeaders: Set<String> = ["accept", "accept-language", "user-agent"]

    /// Headers that carry a credential: never among ``crossEndpointHeaders``.
    static let credentialHeaders = [
        "Authorization", "Proxy-Authorization", "Cookie",
        AttestationTokenInterceptor.header, AttestationTokenInterceptor.proofHeader, "X-Vault-Token", "X-Vault-Key", "X-API-Key",
    ]

    // MARK: Errors

    /// A transport failure as the library reports it: TLS failures the trust
    /// check did not cause → ``PinVaultError/sslHandshake(message:cause:)``
    /// (not a pin mismatch: the cause is no certificate error), anything else
    /// → ``PinVaultError/io(message:cause:)``.
    static func transportError(_ error: any Error) -> PinVaultError {
        if let pinVault = error as? PinVaultError { return pinVault }
        guard let urlError = error as? URLError else {
            return .io(message: error.localizedDescription, cause: error)
        }
        switch urlError.code {
        case .secureConnectionFailed, .serverCertificateHasBadDate, .serverCertificateUntrusted,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected,
             .clientCertificateRequired:
            return .sslHandshake(message: urlError.localizedDescription, cause: urlError)
        default:
            return .io(message: urlError.localizedDescription, cause: urlError)
        }
    }
}

/// Collects one data task's response and body for ``URLSessionTransport``,
/// fed by the session delegate (``PinnedSessionDelegate``) on its queue.
///
/// The body is read under the exchange's ``BoundedBody/Limit``: a declared
/// length over the ceiling cancels the task at the response head, a counted
/// one as soon as it passes the ceiling (``ResponseTooLargeException``); a body
/// that is only wanted as a prefix stops the task once the prefix is in, and
/// the answer is what was read.
final class ResponseCollector: @unchecked Sendable {

    struct Outcome: Sendable {
        var data = Data()
        var response: URLResponse?
        var taskIdentifier = -1
        var error: (any Error)?
    }

    private let lock = NSLock()
    private var buffer: BoundedBuffer
    private var response: URLResponse?
    /// Why the collector stopped the task itself: a refusal, or nil for a complete prefix.
    private var stoppedEarly = false
    private var refusal: (any Error)?
    /// Optional outcome: the transport answers nil itself when no task was made.
    private var continuation: CheckedContinuation<Outcome?, Never>?

    init(limit: BoundedBody.Limit?, continuation: CheckedContinuation<Outcome?, Never>) {
        self.buffer = BoundedBuffer(limit: limit)
        self.continuation = continuation
    }

    /// The response head: false = cancel the task (refused, or no body wanted).
    func receive(_ response: URLResponse) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        self.response = response
        let status = (response as? HTTPURLResponse)?.statusCode ?? 200
        do {
            try buffer.begin(statusCode: status, declaredLength: response.expectedContentLength)
        } catch {
            refusal = error
            stoppedEarly = true
            return false
        }
        if buffer.isComplete {
            stoppedEarly = true
            return false
        }
        return true
    }

    /// A piece of the body: false = cancel the task (refused, or the prefix is complete).
    func receive(_ data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !stoppedEarly else { return false }
        do {
            try buffer.append(data)
        } catch {
            refusal = error
            stoppedEarly = true
            return false
        }
        if buffer.isComplete {
            stoppedEarly = true
            return false
        }
        return true
    }

    /// The task ended: resumes the waiting request exactly once.
    func complete(taskIdentifier: Int, error: (any Error)?) {
        lock.lock()
        var outcome = Outcome(data: buffer.data, response: response, taskIdentifier: taskIdentifier, error: error)
        if stoppedEarly {
            // The collector cancelled the task itself: the refusal, or a complete prefix.
            outcome.error = refusal
        }
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: outcome)
    }
}

/// Holds a data task for cancellation, whichever comes first.
private final class TaskBox: @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionDataTask?
    private var cancelled = false
    private var taskIdentifier = -1

    var identifier: Int {
        lock.lock()
        defer { lock.unlock() }
        return taskIdentifier
    }

    func start(_ task: URLSessionDataTask) {
        lock.lock()
        self.task = task
        taskIdentifier = task.taskIdentifier
        let cancelled = self.cancelled
        lock.unlock()
        task.resume()
        if cancelled { task.cancel() }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        lock.unlock()
        task?.cancel()
    }
}
