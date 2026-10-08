import Foundation

/// Opt-in connection listener that forwards handshake outcomes and config
/// updates to the PinVault demo-server:
///
/// - `POST api/v1/connection-history/client-report` — handshake reports
/// - `POST api/v1/connection-history/config-update-report` — config swaps
///
/// with the exact JSON the server's route expects. If your backend speaks
/// another format, register your own ``PinVaultConnectionListener``.
///
/// Anomalies (pin mismatch, failed update) are always reported;
/// `reportSuccessEvents = false` drops the healthy stream, `dedupWindowMs > 0`
/// drops repeated healthy handshake reports for the same host/version/pin.
/// Network errors are logged and swallowed.
///
/// SECURITY: a telemetry channel, not part of pinning. The default session is
/// NOT pinned: use an `https://` URL and ``init(managementUrl:pinnedSession:reportSuccessEvents:dedupWindowMs:)``
/// with ``pinnedClient(hostname:pins:)`` in production.
public final class PinVaultBackendReporter: Sendable {

    private enum Transport: Sendable {
        case urlSession(URLSession)
        case pinned(PinnedSession)
    }

    let connectionEndpoint: String
    let configUpdateEndpoint: String
    private let transport: Transport
    private let reportSuccessEvents: Bool
    private let dedupWindowMs: Int64
    /// Last-sent time per `host|pinVersion|cert`.
    private let lastReportedMs = Locked<[String: Int64]>([:])
    private let now: @Sendable () -> Int64
    private static let log = PinVaultLog.tag("PinVaultBackendReporter")

    /// - Parameters:
    ///   - managementUrl: demo-server base URL, e.g. `https://192.168.1.10:6650/`; the paths are appended.
    ///   - session: defaults to an UNPINNED 5-second session (``defaultSession()``).
    ///   - reportSuccessEvents: false = only anomalies are posted.
    ///   - dedupWindowMs: minimum interval between duplicate healthy reports; 0 = none.
    public convenience init(
        managementUrl: String,
        session: URLSession = PinVaultBackendReporter.defaultSession(),
        reportSuccessEvents: Bool = true,
        dedupWindowMs: Int64 = 0
    ) {
        self.init(managementUrl: managementUrl, transport: .urlSession(session),
                  reportSuccessEvents: reportSuccessEvents, dedupWindowMs: dedupWindowMs)
    }

    /// Reports through a pinned session (``pinnedClient(hostname:pins:)`` or `PinVault.shared.session()`).
    public convenience init(
        managementUrl: String,
        pinnedSession: PinnedSession,
        reportSuccessEvents: Bool = true,
        dedupWindowMs: Int64 = 0
    ) {
        self.init(managementUrl: managementUrl, transport: .pinned(pinnedSession),
                  reportSuccessEvents: reportSuccessEvents, dedupWindowMs: dedupWindowMs)
    }

    private init(
        managementUrl: String,
        transport: Transport,
        reportSuccessEvents: Bool,
        dedupWindowMs: Int64,
        now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        connectionEndpoint = Self.buildEndpoint(managementUrl, Self.connectionPath)
        configUpdateEndpoint = Self.buildEndpoint(managementUrl, Self.configUpdatePath)
        self.transport = transport
        self.reportSuccessEvents = reportSuccessEvents
        self.dedupWindowMs = dedupWindowMs
        self.now = now
        // audit L-9: warn loudly when telemetry would travel over cleartext.
        if !managementUrl.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("https://") {
            Self.log.w(
                "PinVaultBackendReporter: managementUrl '\(managementUrl)' is not https — connection/" +
                    "config telemetry (device model, hostname, pin version + hashes) is sent " +
                    "over cleartext and can be read OR forged by an on-path attacker. Use https " +
                    "and a pinned OkHttpClient in production. Pinning itself is unaffected."
            )
        }
    }

    /// The reporter as a listener for `PinVaultConfig.Builder.onConnectionEvent(_:)`.
    public var listener: PinVaultConnectionListener {
        { [self] event in onEvent(event) }
    }

    /// Fire-and-forget: the POST runs on a background task.
    public func onEvent(_ event: PinVaultConnectionEvent) {
        Task.detached { [self] in await handle(event) }
    }

    /// ``onEvent(_:)``, awaitable.
    func handle(_ event: PinVaultConnectionEvent) async {
        switch event {
        case let .connection(hostname, success, pinVersion, manufacturer, model, actualPin, expectedPins):
            if success {
                if !reportSuccessEvents { return }
                if isDuplicateWithinWindow(hostname: hostname, pinVersion: pinVersion, actualPin: actualPin) { return }
            }
            let status = success ? "healthy" : "pin_mismatch"
            let firstExpected = expectedPins.first ?? ""
            // Hand-built JSON in the field order the server's contract test pins.
            var json = "{"
            json += Self.field("hostname", hostname) + ","
            json += Self.field("status", status) + ","
            json += "\"responseTimeMs\":0,"
            json += "\"pinMatched\":\(success),"
            json += "\"pinVersion\":\(pinVersion),"
            json += Self.field("deviceManufacturer", manufacturer) + ","
            json += Self.field("deviceModel", model) + ","
            json += Self.field("serverCertPin", actualPin) + ","
            json += Self.field("storedPin", firstExpected)
            json += "}"
            await post(connectionEndpoint, json)

        case let .configUpdate(status, newVersion, manufacturer, model, failureReason):
            let isFailure = status == .failed
            if !isFailure && !reportSuccessEvents { return }
            let statusString: String
            switch status {
            case .updated: statusString = "config_updated"
            case .unchanged: statusString = "config_unchanged"
            case .failed: statusString = "config_update_failed"
            }
            var json = "{"
            json += Self.field("status", statusString) + ","
            json += "\"pinVersion\":\(newVersion),"
            json += Self.field("deviceManufacturer", manufacturer) + ","
            json += Self.field("deviceModel", model)
            if let failureReason {
                json += "," + Self.field("failureReason", failureReason)
            }
            json += "}"
            await post(configUpdateEndpoint, json)

        case let .clientCertRenewal(status, _, _, configApiId, _, _, _):
            // The server records renewals itself (audit log); nothing to report.
            Self.log.d("Client cert renewal [\(configApiId)]: \(status.rawValue)")

        case let .attestation(configApiId, status, arc, _, _, _, _, _, _):
            // The server made the verdict and keeps it; nothing to report.
            Self.log.d("Attestation [\(configApiId)]: \(status.rawValue) (arc=\(arc ?? "null"))")
        }
    }

    private func post(_ endpoint: String, _ json: String) async {
        guard let url = URL(string: endpoint) else {
            Self.log.w("PinVaultBackendReporter: failed to POST to \(endpoint)")
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(json.utf8)
        do {
            let response: URLResponse
            switch transport {
            case .urlSession(let session): (_, response) = try await session.data(for: request)
            case .pinned(let session): (_, response) = try await session.data(for: request)
            }
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                Self.log.w("PinVaultBackendReporter: \(endpoint) returned HTTP \(http.statusCode)")
            }
        } catch {
            // The reporter must never take down the listener pipeline.
            Self.log.w("PinVaultBackendReporter: failed to POST to \(endpoint)", error)
        }
    }

    private func isDuplicateWithinWindow(hostname: String, pinVersion: Int, actualPin: String) -> Bool {
        guard dedupWindowMs > 0 else { return false }
        let key = "\(hostname)|\(pinVersion)|\(actualPin)"
        let now = now()
        // Check-and-write under one lock, so two callers cannot both be "first".
        return lastReportedMs.withLock { last in
            if let previous = last[key], now - previous < dedupWindowMs { return true }
            last[key] = now
            return false
        }
    }

    /// `"key":"value"` with quotes and backslashes escaped (the Kotlin minimal escaping).
    private static func field(_ key: String, _ value: String) -> String {
        var out = "\"\(key)\":\""
        for character in value {
            switch character {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            default: out.append(character)
            }
        }
        return out + "\""
    }

    static let connectionPath = "api/v1/connection-history/client-report"
    static let configUpdatePath = "api/v1/connection-history/config-update-report"

    static func buildEndpoint(_ managementUrl: String, _ path: String) -> String {
        var base = managementUrl
        while base.hasSuffix("/") { base.removeLast() }
        return "\(base)/\(path)"
    }

    /// UNPINNED fire-and-forget session (5 s timeouts), fine for telemetry to a trusted host.
    public static func defaultSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 5
        return URLSession(configuration: configuration)
    }

    /// A session that accepts only `pins` for `hostname` — for reports to a
    /// backend the app already pins. Its handshakes raise no connection events.
    public static func pinnedClient(hostname: String, pins: [String]) -> PinnedSession {
        pinnedClient(hostname: hostname, pins: pins, manager: DynamicSSLManager())
    }

    /// ``pinnedClient(hostname:pins:)`` over `manager` (tests inject their clock).
    static func pinnedClient(hostname: String, pins: [String], manager: DynamicSSLManager) -> PinnedSession {
        manager.buildBootstrapClient([HostPin(hostname: hostname, sha256: pins)], timeout: pinnedClientTimeout)
    }

    /// Connect / read timeout of ``pinnedClient(hostname:pins:)``, seconds.
    static let pinnedClientTimeout: TimeInterval = 5
}

extension PinVaultBackendReporter {
    /// Test seam: a reporter with an injected clock.
    convenience init(
        managementUrl: String,
        session: URLSession,
        reportSuccessEvents: Bool,
        dedupWindowMs: Int64,
        now: @escaping @Sendable () -> Int64
    ) {
        self.init(managementUrl: managementUrl, transport: .urlSession(session),
                  reportSuccessEvents: reportSuccessEvents, dedupWindowMs: dedupWindowMs, now: now)
    }
}

extension PinVaultConfig.Builder {
    /// One-line opt-in for the demo-server telemetry POST
    /// (``PinVaultBackendReporter``). For any other backend use ``onConnectionEvent(_:)``.
    @discardableResult
    public func reportToPinVaultBackend(
        managementUrl: String,
        reportSuccessEvents: Bool = true,
        dedupWindowMs: Int64 = 0
    ) -> PinVaultConfig.Builder {
        onConnectionEvent(
            PinVaultBackendReporter(
                managementUrl: managementUrl,
                reportSuccessEvents: reportSuccessEvents,
                dedupWindowMs: dedupWindowMs
            ).listener
        )
    }
}
