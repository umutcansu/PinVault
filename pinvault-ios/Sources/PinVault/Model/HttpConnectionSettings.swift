import Foundation

/// Connection settings for `PinVault.session(settings:)`. Timeouts in seconds;
/// 0 = no timeout.
///
/// iOS mapping: `connectTimeout`/`readTimeout`/`writeTimeout` →
/// `URLSessionConfiguration.timeoutIntervalForRequest` (the largest of them),
/// `callTimeout` → `timeoutIntervalForResource`, `maxIdleConnections` →
/// `httpMaximumConnectionsPerHost`; `keepAliveDuration` has no URLSession knob.
public struct HttpConnectionSettings: Sendable, Equatable, Hashable {
    public var connectTimeout: Int64
    public var readTimeout: Int64
    public var writeTimeout: Int64
    public var callTimeout: Int64
    public var maxIdleConnections: Int
    public var keepAliveDuration: Int64
    public var keepAliveDurationUnit: TimeUnit
    /// iOS (OkHttp `Dns` counterpart): logical host (lower case) → the address
    /// the connection goes to. Pin lookup, hostname verification and the
    /// client certificate use the logical host. See ``resolve(host:to:)``.
    public var resolvedHosts: [String: String]

    public init(
        connectTimeout: Int64 = 30,
        readTimeout: Int64 = 30,
        writeTimeout: Int64 = 30,
        callTimeout: Int64 = 0,
        maxIdleConnections: Int = 5,
        keepAliveDuration: Int64 = 5,
        keepAliveDurationUnit: TimeUnit = .seconds,
        resolvedHosts: [String: String] = [:]
    ) {
        self.connectTimeout = connectTimeout
        self.readTimeout = readTimeout
        self.writeTimeout = writeTimeout
        self.callTimeout = callTimeout
        self.maxIdleConnections = maxIdleConnections
        self.keepAliveDuration = keepAliveDuration
        self.keepAliveDurationUnit = keepAliveDurationUnit
        self.resolvedHosts = resolvedHosts
    }

    /// A copy that sends connections for `host` to `address` (an IP address
    /// or another host name; the port stays the request's). Like the sample's
    /// `MockDns`: `mock-tls.sample` → the host machine's IP. Overrides the
    /// config's own ``PinVaultConfig/Builder/resolve(host:to:)`` for that host.
    public func resolve(host: String, to address: String) -> HttpConnectionSettings {
        var copy = self
        copy.resolvedHosts[host.trimmingCharacters(in: .whitespaces).lowercased()] =
            address.trimmingCharacters(in: .whitespaces)
        return copy
    }
}
