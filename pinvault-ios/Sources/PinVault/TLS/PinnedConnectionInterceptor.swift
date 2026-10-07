import Foundation

/// The pin check of the handshake, repeated for every request against the
/// config that is live now (Kotlin `PinnedConnectionInterceptor`, an OkHttp
/// network interceptor).
///
/// The trust check only runs during a full TLS handshake. A connection that
/// stays open (HTTP/2, keep-alive) — or a new one that resumes a cached TLS
/// session — carries requests without it ever being asked again. So after a
/// pin was rotated away, or after the config expired, whoever was on the other
/// end of such a connection kept being trusted.
///
/// On Android the interceptor re-matches the connection's certificates. URLSession
/// shows a request neither its connection nor that connection's certificates,
/// so the iOS port splits the check in two:
///  - here, before every `https` request of a pinned session: the live config
///    must be usable for the request's host — present, with pins, not past its
///    `expiresAt` plus the grace. On failure the request fails the way a failed
///    handshake does (``PinVaultError/sslHandshake(message:cause:)`` whose
///    cause is the trust check's error, so recovery treats both alike), and the
///    host's `URLSession` is retired so its pooled connections serve nobody else;
///  - in ``URLSessionTransport``: a config that differs from the one the
///    sessions were built under, or a pin / identity change
///    (``DynamicSSLManager/onPinsChanged()``), retires them; the next request
///    opens a new connection whose handshake judges the certificates against
///    the new config — leaf and issuer pins, `requireCaTrust`, the hostname.
enum PinnedConnectionInterceptor {

    private static let log = PinVaultLog.tag("PinnedConnectionInterceptor")

    /// Throws the refusal of a request to `host` under `config`.
    static func check(manager: DynamicSSLManager, config: CertificateConfig?, host: String) throws {
        do {
            try manager.requireUsableConfig(config, hostname: host)
        } catch let error as PinVaultError {
            log.w("Connection to \(host) no longer passes the pin check — closing it: \(error.message)")
            throw PinVaultError.sslHandshake(message: error.message, cause: error)
        }
    }
}
