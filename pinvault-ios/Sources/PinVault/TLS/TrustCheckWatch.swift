import Foundation

/// The library's check that its own trust check ran.
///
/// URLSession shows every new TLS connection's server certificate to the
/// session's delegate (``PinnedSessionDelegate``) before the first byte goes
/// out: that challenge is where the pins are matched. A tweak that disables
/// certificate validation (the generic "SSL kill switch" family) answers the
/// challenge inside CFNetwork, before the delegate, with the server's own
/// trust — the delegate is never asked, nothing in the library runs, and the
/// connection carries the request as if the pins had matched.
///
/// The library cannot stop code injected into its process from doing that; it
/// can notice. A session's delegate counts the server-trust challenges it was
/// asked; a task that completes over a freshly made TLS connection while that
/// count is still zero rode a connection whose certificate nobody in the
/// library saw. Such a response is refused
/// (`SSLHandshakeException` with a `SecurityException` cause, never a pin
/// mismatch: no config repairs it, so no recovery refetch), a `wss://` socket
/// that opened that way is cancelled, and the host is recorded here, in the
/// process-wide log the attestation report reads: `hooking_framework` carries
/// `tls-unverified:<host>` from then on (`ATTESTATION.md` §3).
///
/// Why per session and not per connection: a resumed TLS session (TLS 1.2
/// session ids; tickets) is a new TCP connection that URLSession does NOT
/// show to the delegate again — verified against a TLS 1.2 server that
/// reports "Reused" (the delegate was asked once for three connections). A
/// `URLSession` has its own TLS session cache, so its first HTTPS connection
/// is always a full handshake with a challenge, and the library builds a new
/// `URLSession` whenever the pins or the identity change; within one
/// session, a later connection without a challenge is a resumption.
///
/// A measurement, like every probe: code that answers the challenge for the
/// delegate can also hook the metrics or this counter. What it buys is that
/// the generic tool, as published, no longer works against the library
/// unnoticed; defeating the check takes work aimed at PinVault.
enum TrustCheckWatch {

    /// Evidence prefix in the `hooking_framework` signal.
    static let evidencePrefix = "tls-unverified:"

    /// The facts of one transaction of a task's metrics that the decision needs.
    struct Transaction: Equatable, Sendable {
        /// `resourceFetchType == .networkLoad` (not the cache, not a server push).
        let networkLoad: Bool
        /// `negotiatedTLSProtocolVersion != nil`.
        let tls: Bool
        /// The request URL's scheme is `https`.
        let https: Bool

        init(networkLoad: Bool, tls: Bool, https: Bool) {
            self.networkLoad = networkLoad
            self.tls = tls
            self.https = https
        }

        init(_ metrics: URLSessionTaskTransactionMetrics) {
            networkLoad = metrics.resourceFetchType == .networkLoad
            tls = metrics.negotiatedTLSProtocolVersion != nil
            https = metrics.request.url?.scheme?.lowercased() == "https"
        }
    }

    /// True when the task's connections were TLS to an https URL, made over
    /// the network, and the session's delegate was never asked about a server
    /// certificate: its trust check did not run for them.
    static func wentUnverified(_ transactions: [Transaction], serverTrustChallenges: Int) -> Bool {
        guard serverTrustChallenges == 0 else { return false }
        return transactions.contains { $0.networkLoad && $0.tls && $0.https }
    }

    /// The message of the refusal.
    static func message(host: String, port: Int) -> String {
        "TLS connection to \(DynamicSSLManager.hostPort(host, port)) was made without PinVault's trust check: " +
            "URLSession never asked the session delegate for the server certificate (a trust-bypass hook?)"
    }
}

/// Hosts whose connections went unverified in this process, for the
/// attestation report. Never cleared: once seen, every later report says so.
final class UnverifiedConnectionLog: @unchecked Sendable {

    static let shared = UnverifiedConnectionLog()

    /// How many distinct hosts are kept (the first ones; the count goes on).
    static let maxHosts = 16

    private let state = Locked<(hosts: [String], count: Int)>(([], 0))

    func record(host: String) {
        state.withLock { state in
            state.count += 1
            let name = host.lowercased()
            if !state.hosts.contains(name), state.hosts.count < Self.maxHosts { state.hosts.append(name) }
        }
    }

    /// How many connections went unverified.
    var count: Int { state.withLock { $0.count } }

    /// `tls-unverified:<host>` per recorded host, in first-seen order.
    func evidence() -> [String] {
        state.withLock { $0.hosts.map { TrustCheckWatch.evidencePrefix + $0 } }
    }

    /// Tests only.
    func reset() {
        state.withLock { $0 = ([], 0) }
    }
}
