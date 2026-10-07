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
        /// Not between `http` and `https`, either way (library-built clients).
        case sameScheme
        /// All (OkHttp's defaults: `applyTo` and the unpinned bootstrap client).
        case all
    }

    static let maxFollowUps = 20

    let manager: DynamicSSLManager
    private let template: URLSessionConfiguration
    let trust: DynamicSSLManager.TrustMode
    let resolveOverrides: [String: String]
    let redirects: RedirectPolicy

    private struct Entry {
        let session: URLSession
        let delegate: PinnedSessionDelegate
    }

    private struct State {
        var entries: [String: Entry] = [:]
        var generation: DynamicSSLManager.SessionGeneration?
        var config: CertificateConfig?
        var invalidated = false
    }

    private let state = Locked(State())

    init(
        manager: DynamicSSLManager,
        configuration: URLSessionConfiguration,
        trust: DynamicSSLManager.TrustMode,
        resolveOverrides: [String: String],
        redirects: RedirectPolicy
    ) {
        self.manager = manager
        self.template = configuration
        self.trust = trust
        var normalized: [String: String] = [:]
        for (host, address) in resolveOverrides { normalized[host.lowercased()] = address }
        self.resolveOverrides = normalized
        self.redirects = redirects
        manager.register(self)
    }

    deinit {
        for entry in state.withLock({ $0.entries.values }) { entry.session.finishTasksAndInvalidate() }
    }

    func invalidate() {
        let entries = state.withLock { state -> [Entry] in
            state.invalidated = true
            defer { state.entries = [:] }
            return Array(state.entries.values)
        }
        entries.forEach { $0.session.invalidateAndCancel() }
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
        entries.forEach { $0.session.finishTasksAndInvalidate() }
    }

    // MARK: Sending

    func send(_ exchange: PinnedExchange) async throws -> PinnedResponse {
        var request = exchange.request
        var followUps = 0
        while true {
            let response = try await sendOnce(request)
            guard let next = followUp(response, for: request) else { return response }
            followUps += 1
            if followUps > Self.maxFollowUps {
                throw PinVaultError.io(message: "Too many follow-up requests: \(followUps)")
            }
            request = next
        }
    }

    private func sendOnce(_ request: URLRequest) async throws -> PinnedResponse {
        guard let url = request.url, let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let rawHost = url.host, !rawHost.isEmpty else {
            throw PinVaultError.illegalArgument("Expected an http or https URL with a host: \(request.url?.absoluteString ?? "nil")")
        }
        let host = DynamicSSLManager.bareHost(rawHost).lowercased()
        let port = url.port ?? (scheme == "https" ? 443 : 80)
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

        let (data, response, taskIdentifier, error) = await run(entry.session, wire)
        if let error {
            if let failure = entry.delegate.takeFailure(taskIdentifier) { throw failure.thrown }
            if Task.isCancelled { throw CancellationError() }
            throw Self.transportError(error)
        }
        _ = entry.delegate.takeFailure(taskIdentifier)
        guard let response else { throw PinVaultError.io(message: "No response for \(url.absoluteString)") }
        var answer: URLResponse = response
        if rewritten, let http = response as? HTTPURLResponse {
            // The app sees the URL it asked for, not the address the connection went to.
            var fields: [String: String] = [:]
            for (name, value) in http.allHeaderFields {
                if let name = name as? String { fields[name] = "\(value)" }
            }
            answer = HTTPURLResponse(url: url, statusCode: http.statusCode, httpVersion: nil, headerFields: fields) ?? http
        }
        return PinnedResponse(data: data ?? Data(), response: answer, presentedClientCertificate: entry.delegate.presentedClientCertificate)
    }

    /// Runs one data task; the task identifier says where the delegate recorded a refusal.
    private func run(_ session: URLSession, _ request: URLRequest) async -> (Data?, URLResponse?, Int, (any Error)?) {
        let box = TaskBox()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<(Data?, URLResponse?, Int, (any Error)?), Never>) in
                let task = session.dataTask(with: request) { data, response, error in
                    continuation.resume(returning: (data, response, box.identifier, error))
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
                logicalHost: host, logicalPort: port, connectHost: address.host, connectPort: address.port, trust: trust
            ))
            let configuration = template.copy() as! URLSessionConfiguration
            let entry = Entry(session: URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil), delegate: delegate)
            state.entries[key] = entry
            return entry
        }
        retired.forEach { $0.session.finishTasksAndInvalidate() }
        return entry
    }

    private func retire(key: String, _ entry: Entry) {
        let removed = state.withLock { state -> Bool in
            guard let current = state.entries[key], current.session === entry.session else { return false }
            state.entries[key] = nil
            return true
        }
        if removed { entry.session.finishTasksAndInvalidate() }
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
        // A request for another endpoint keeps no credentials. OkHttp drops only
        // Authorization; the library's own secrets (the attestation token, vault
        // tokens, API keys) and cookies must not follow a redirect to another
        // host, port or scheme either.
        let sameEndpoint = target.host?.lowercased() == current.host?.lowercased()
            && (target.port ?? (scheme == "https" ? 443 : 80)) == (current.port ?? (current.scheme?.lowercased() == "https" ? 443 : 80))
            && sameScheme
        if !sameEndpoint {
            for name in Self.credentialHeaders { next.setValue(nil, forHTTPHeaderField: name) }
        }
        next.setValue(nil, forHTTPHeaderField: "Host")
        // A body that can be sent once only (a stream, already read) is not sent again: the 3xx is the answer.
        if next.httpBodyStream != nil { return nil }
        return next
    }

    /// Headers that never follow a redirect to another endpoint.
    static let credentialHeaders = [
        "Authorization", "Proxy-Authorization", "Cookie",
        AttestationTokenInterceptor.header, "X-Vault-Token", "X-Vault-Key", "X-API-Key",
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
