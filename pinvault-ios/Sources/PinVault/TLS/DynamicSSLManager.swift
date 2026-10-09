import Foundation
import Security

/// Builds pinned ``PinnedSession``s from a ``CertificateConfig`` and makes
/// every trust decision their connections need (Kotlin `DynamicSSLManager`).
///
/// ## Trust model
/// Each library-built `URLSession` has a ``PinnedSessionDelegate`` whose
/// task-level authentication handler asks this manager:
///  - **server trust** — ``evaluateServerTrust(_:hostname:port:mode:)``: the
///    Kotlin trust manager (`verifyPin`: a usable config, the host's pin entry,
///    the leaf's validity at the library clock, the leaf or issuer pin,
///    `requireCaTrust`, managed trust roots) followed by OkHttp's hostname
///    verifier, which every Android client the library builds runs after the
///    handshake. Every decision uses the LOGICAL host and port — the URL the app
///    asked for — never the address a `resolve` entry or an E2E redirect sends
///    the connection to. A host without a pin entry is refused (no fallback to
///    system trust), except through managed trust roots or the unpinned
///    bootstrap client of a block that called `allowUnpinnedConfigApi()`.
///  - **client certificates** — ``clientIdentity(forHost:port:config:)``: the
///    composite KeyManager of the Kotlin code (host-specific identities, the
///    default identity for the block's own listeners and `mtls` hosts).
///
/// ## After the handshake
/// URLSession asks the delegate once per new TLS connection. A connection kept
/// alive, or a TLS session it resumes, is never shown to the delegate again,
/// and URLSession offers no way to look at a pooled connection's certificates
/// before a request rides it (OkHttp's network interceptor does that on
/// Android, `PinnedConnectionInterceptor`). Instead:
///  - every request first checks the live config is usable (present, not
///    expired) for its host — the part of the Kotlin per-request check that
///    needs no certificate;
///  - a ``URLSessionTransport`` keeps one `URLSession` per logical host and
///    port, so a pooled connection only ever carries requests for the host its
///    handshake was judged for (no sharing between two names a `resolve` entry
///    sends to the same address, no HTTP/2 coalescing across names);
///  - every change of the pins, of the client identity, of the E2E controls —
///    and every config the session's provider returns that differs from the
///    one its sessions were built under — retires the library's `URLSession`s
///    (``onPinsChanged()`` eagerly, `finishTasksAndInvalidate`: requests in
///    flight complete) and builds new ones on the next request, whose
///    connections run full handshakes against the new state (a new URLSession
///    has its own connection pool and TLS session cache).
///
/// Residual risk, by design of URLSession: between two such changes a pooled
/// connection is not re-checked; the leaf's validity is a handshake-time check
/// and is not repeated (as on Android).
final class DynamicSSLManager: @unchecked Sendable {

    private static let log = PinVaultLog.tag("DynamicSSLManager")

    /// Bootstrap client timeouts (seconds).
    static let defaultTimeout: TimeInterval = 30
    private static let listenerQueueCapacity = 256

    /// What a connection's server trust is judged by.
    enum TrustMode: Sendable {
        /// Pins of the config the provider returns at the handshake (nil = refuse everything).
        case pinned(@Sendable () -> CertificateConfig?)
        /// The platform's CAs for the logical host: the unpinned bootstrap client
        /// of a block with `allowUnpinnedConfigApi()` and no bootstrap pins.
        case system

        var configProvider: (@Sendable () -> CertificateConfig?)? {
            if case .pinned(let provider) = self { return provider }
            return nil
        }
    }

    private struct State {
        var connectionListener: PinVaultConnectionListener?
        var expiredConfigGraceMs: Int64 = 0
        var clock: @Sendable () -> Int64 = LibraryClock.wallMillis
        var wallClock: @Sendable () -> Date = LibraryClock.now
        var caTrustPatterns = PinHostMap<Bool>()
        var caCheck: any ServerCaCheck = SecTrustCaCheck.platform
        var managedTrustRootsEnabled = false
        var anchorResolver: any TrustAnchorResolver = SecTrustCaCheck.platform
        var defaultIdentity: ClientIdentity?
        var hostIdentities = PinHostMap<ClientIdentity>()
        var identityHosts: Set<String> = []
        var identityHostsOnly = false
        var generation = 0
        var resolvedHosts: [String: String] = [:]
        var connectionRedirect: @Sendable (String) -> String? = { PinVault.shared.e2eRedirect(for: $0) }
        var externalGeneration: @Sendable () -> Int = { PinVault.shared.e2eGeneration }
    }

    private let state = Locked(State())

    private struct Delivery: Sendable {
        let listener: PinVaultConnectionListener
        let event: PinVaultConnectionEvent
    }

    /// Listener callbacks run off the TLS callbacks, one at a time, in order.
    /// Bounded: an event that finds 256 waiting is dropped — a listener that
    /// blocks for minutes must not pile handshake events up into an OOM.
    private let events: AsyncStream<Delivery>.Continuation

    /// Transports this manager built, held weakly, so a pin change can retire their sessions.
    private let transports = Locked<[WeakTransport]>([])

    private struct WeakTransport {
        weak var transport: URLSessionTransport?
    }

    /// - Parameter connectionListener: fired on every pin verification (success
    ///   or mismatch); nil keeps the library silent.
    init(connectionListener: PinVaultConnectionListener? = nil) {
        let (stream, continuation) = AsyncStream.makeStream(
            of: Delivery.self,
            bufferingPolicy: .bufferingOldest(Self.listenerQueueCapacity)
        )
        events = continuation
        Task.detached {
            for await delivery in stream { delivery.listener(delivery.event) }
        }
        state.withLock { $0.connectionListener = connectionListener }
    }

    deinit {
        events.finish()
    }

    // MARK: Settings

    /// Updates the listener at runtime (used after start when the config arrives).
    func setConnectionListener(_ listener: PinVaultConnectionListener?) {
        state.withLock { $0.connectionListener = listener }
    }

    /// How long a config may still be used after its `expiresAt`
    /// (`expiredConfigGrace`). Zero: an expired config pins nothing.
    var expiredConfigGraceMs: Int64 {
        get { state.withLock { $0.expiredConfigGraceMs } }
        set { state.withLock { $0.expiredConfigGraceMs = newValue } }
    }

    /// Clock for the config-expiry check: the block's ``TrustedClock`` in
    /// production (it does not go back when the device clock does); tests set their own.
    var clock: @Sendable () -> Int64 {
        get { state.withLock { $0.clock } }
        set { state.withLock { $0.clock = newValue } }
    }

    /// Clock for certificate validity and `SecTrust` verify dates: the library
    /// wall clock (device clock + E2E offset), as `checkValidity()` reads the
    /// system clock on Android. Tests set their own.
    var wallClock: @Sendable () -> Date {
        get { state.withLock { $0.wallClock } }
        set { state.withLock { $0.wallClock = newValue } }
    }

    /// The platform CA check (`requireCaTrust`, and the unpinned bootstrap
    /// client's system trust); tests swap in one over their own anchors.
    var caCheck: any ServerCaCheck {
        get { state.withLock { $0.caCheck } }
        set { state.withLock { $0.caCheck = newValue } }
    }

    /// Managed trust roots (`managedTrustRoots()`): a host with no pin entry is
    /// accepted when the platform validates its chain to a root the signed
    /// config lists in `trustRoots`. Off: such a host is refused.
    var managedTrustRootsEnabled: Bool {
        get { state.withLock { $0.managedTrustRootsEnabled } }
        set { state.withLock { $0.managedTrustRootsEnabled = newValue } }
    }

    /// The platform's validated chain with its anchor, for managed trust roots; tests swap in their own.
    var anchorResolver: any TrustAnchorResolver {
        get { state.withLock { $0.anchorResolver } }
        set { state.withLock { $0.anchorResolver = newValue } }
    }

    /// Hosts (pin syntax: exact, `*.example.com`, optional `:port`) whose
    /// server chain must validate against the platform's trust store in
    /// addition to matching a pin (`requireCaTrust`); nothing the server sends changes it.
    func requireCaTrust(_ hostPatterns: [String]) {
        let map = PinHostMatcher.build(hostPatterns.map { ($0, true) })
        state.withLock { $0.caTrustPatterns = map }
    }

    /// The config's `resolve(host:to:)` entries (logical host → address); a
    /// session's ``HttpConnectionSettings/resolvedHosts`` override them per host.
    var resolvedHosts: [String: String] {
        get { state.withLock { $0.resolvedHosts } }
        set {
            var normalized: [String: String] = [:]
            for (host, address) in newValue { normalized[host.lowercased()] = address }
            state.withLock {
                $0.resolvedHosts = normalized
                $0.generation += 1
            }
        }
    }

    /// The E2E connection-address override for `host:port` (PORTING.md §8),
    /// read for every new session. Default: `PinVault.e2eRedirect(for:)`.
    var connectionRedirect: @Sendable (String) -> String? {
        get { state.withLock { $0.connectionRedirect } }
        set { state.withLock { $0.connectionRedirect = newValue } }
    }

    /// A counter outside this manager whose change retires every session it
    /// built. Default: the E2E control generation (redirects, clock offset).
    var externalGeneration: @Sendable () -> Int {
        get { state.withLock { $0.externalGeneration } }
        set { state.withLock { $0.externalGeneration = newValue } }
    }

    /// The generation sessions are built under: changes with the pins, the
    /// client identity, the routing and the E2E controls.
    var sessionGeneration: SessionGeneration {
        let (own, external) = state.withLock { ($0.generation, $0.externalGeneration) }
        return SessionGeneration(own: own, external: external())
    }

    struct SessionGeneration: Equatable, Sendable {
        let own: Int
        let external: Int
    }

    // MARK: Client identities

    /// Names the listeners the default client identity is for. It is offered
    /// to those, to hosts whose pin entry says `mtls = true` and — through
    /// their own certificate — to hosts with a host-specific client
    /// certificate. Any other pinned host that asks for a client certificate
    /// gets none: the certificate names the device (CN = device id), and a
    /// host the device merely talks to has no business learning it.
    ///
    /// - Parameters:
    ///   - urls: base URLs; anything that is not an http(s) URL is skipped.
    ///   - onlyThese: the app listed its mTLS hosts itself (`clientCertHosts`):
    ///     then `urls` are the ONLY hosts the default identity goes to, and an
    ///     `mtls = true` pin entry — which whoever signs the config writes — adds none.
    func setIdentityHosts(_ urls: [String?], onlyThese: Bool = false) {
        var hosts: Set<String> = []
        for url in urls.compactMap({ $0 }) {
            guard let endpoint = Self.httpEndpoint(url) else { continue }
            hosts.insert("\(endpoint.host):\(endpoint.port)")
        }
        state.withLock {
            $0.identityHosts = hosts
            $0.identityHostsOnly = onlyThese
            $0.generation += 1
        }
    }

    /// Loads a PKCS12 client keystore as the default identity (used for the
    /// block's own listeners and `mtls` hosts).
    /// - Throws: when the bytes or the password are wrong.
    func loadClientKeystore(_ p12: Data, password: String) throws {
        let identity = try ClientIdentity.fromPKCS12(p12, password: password)
        state.withLock {
            $0.defaultIdentity = identity
            $0.generation += 1
        }
        // The subject names the device: say that a certificate is loaded, not whose.
        Self.log.d("Default client keystore loaded — \(identity.chain.count) entr(ies)")
    }

    /// Loads a default client identity whose private key stays where it is
    /// (Secure Enclave / Keychain) with the chain the server issued over it —
    /// the CSR-enrolled counterpart of ``loadClientKeystore(_:password:)``; the two replace each other.
    func loadClientKey(_ identity: ClientIdentity) {
        state.withLock {
            $0.defaultIdentity = identity
            $0.generation += 1
        }
        let notAfter = identity.leaf.map { "\($0.notAfter)" } ?? "unknown"
        Self.log.d("Default client key loaded — notAfter=\(notAfter)")
    }

    /// The leaf the default identity presents, if one is loaded.
    func defaultClientCertificate() -> X509Certificate? {
        state.withLock { $0.defaultIdentity?.leaf }
    }

    /// Drops the in-memory default identity (and with `includeHostCerts` the
    /// host-specific ones) so later handshakes present no client certificate.
    /// `PinVault.unenroll` needs it: deleting the stored credential is not
    /// enough while this process keeps the identity. Sessions built before are
    /// rebuilt on their next request; requests in flight finish on their connection.
    func clearClientKeystore(includeHostCerts: Bool = true) {
        state.withLock {
            $0.defaultIdentity = nil
            if includeHostCerts { $0.hostIdentities = PinHostMap() }
            $0.generation += 1
        }
        Self.log.d("Client keystore cleared — no client cert will be presented (hostCerts=\(includeHostCerts))")
    }

    /// True while a default or host-specific identity is loaded.
    func hasClientKeystore() -> Bool {
        state.withLock { $0.defaultIdentity != nil || !$0.hostIdentities.isEmpty }
    }

    /// Loads host-specific client certificates (hostname → PKCS12), replacing
    /// the ones loaded before. A P12 that cannot be read is logged and skipped.
    func loadHostClientCerts(_ hostCerts: [String: Data], password: String) {
        loadHostClientIdentities([:], hostCerts: hostCerts, password: password)
    }

    /// Loads host-specific client identities, replacing the ones loaded before.
    /// `hostKeys` are identities whose key stays in the Keychain (hostname →
    /// identity); `hostCerts` (hostname → PKCS12) the ones that could not be
    /// imported. A host in both uses its key. Entries follow the pin syntax.
    func loadHostClientIdentities(_ hostKeys: [String: ClientIdentity], hostCerts: [String: Data], password: String) {
        var identities = PinHostMap<ClientIdentity>()
        // Sorted: a stable order for wildcard lookups (Swift dictionaries have none).
        for (hostname, identity) in hostKeys.sorted(by: { $0.key < $1.key }) {
            identities.set(hostname, identity)
            Self.log.d("Host client key loaded: \(hostname)")
        }
        for (hostname, p12) in hostCerts.sorted(by: { $0.key < $1.key }) where identities[hostname.lowercased()] == nil {
            do {
                identities.set(hostname, try ClientIdentity.fromPKCS12(p12, password: password))
                Self.log.d("Host client cert loaded: \(hostname)")
            } catch {
                Self.log.e("Failed to load client cert for host: \(hostname)", error)
            }
        }
        let count = identities.count
        state.withLock {
            $0.hostIdentities = identities
            $0.generation += 1
        }
        Self.log.d("Loaded \(count) host-specific client certs")
    }

    /// Who a handshake presents a client certificate as.
    struct SelectedClientIdentity: @unchecked Sendable {
        enum Owner: Equatable, Sendable {
            /// The block's default identity.
            case defaultIdentity
            /// The host-specific identity of this entry.
            case host(String)
        }
        let owner: Owner
        let identity: ClientIdentity
    }

    /// The decision, per connection, which client certificate the peer gets —
    /// or none. Nil when no identity is loaded at all (Kotlin
    /// `buildCompositeKeyManagers` returning null).
    ///
    ///  1. A host with its own client certificate (``loadHostClientIdentities(_:hostCerts:password:)``)
    ///     gets that certificate. Entries follow the pin syntax (exact,
    ///     `*.domain`, `host:port`), with the pin precedence.
    ///  2. The default identity goes to the block's own listeners
    ///     (``setIdentityHosts(_:onlyThese:)``) and — unless the app listed its
    ///     hosts itself (`clientCertHosts`) — to hosts whose pin entry in the
    ///     live config has `mtls = true`.
    ///  3. Everyone else gets nothing, as does a connection whose host is unknown.
    struct ClientIdentitySelector: @unchecked Sendable {
        fileprivate let defaultIdentity: ClientIdentity?
        fileprivate let hostIdentities: PinHostMap<ClientIdentity>
        fileprivate let identityHosts: Set<String>
        fileprivate let identityHostsOnly: Bool
        fileprivate let configProvider: () -> CertificateConfig?

        func select(host: String?, port: Int?) -> SelectedClientIdentity? {
            guard let host, !host.isEmpty else { return nil }
            let name = host.lowercased()
            if let entry = Self.matchingEntry(hostIdentities, name, port), let identity = hostIdentities[entry] {
                return SelectedClientIdentity(owner: .host(entry), identity: identity)
            }
            guard let defaultIdentity else { return nil }
            let ownListener = port.map { identityHosts.contains("\(name):\($0)") } ?? false
            var mtlsHost = false
            if !ownListener, !identityHostsOnly, let pins = configProvider()?.pins {
                let map = PinHostMatcher.build(pins.map { ($0.hostname, $0) })
                mtlsHost = PinHostMatcher.match(map, name, port: port)?.mtls == true
            }
            return ownListener || mtlsHost ? SelectedClientIdentity(owner: .defaultIdentity, identity: defaultIdentity) : nil
        }

        /// The entry of `map` that `PinHostMatcher` picks for `host`/`port`.
        private static func matchingEntry(_ map: PinHostMap<ClientIdentity>, _ host: String, _ port: Int?) -> String? {
            let names = PinHostMatcher.build(map.keys.map { ($0, $0) })
            return PinHostMatcher.match(names, host, port: port)
        }
    }

    func buildCompositeKeyManagers(configProvider: @escaping () -> CertificateConfig? = { nil }) -> ClientIdentitySelector? {
        let snapshot = state.withLock { ($0.defaultIdentity, $0.hostIdentities, $0.identityHosts, $0.identityHostsOnly) }
        if snapshot.0 == nil, snapshot.1.isEmpty { return nil }
        return ClientIdentitySelector(
            defaultIdentity: snapshot.0,
            hostIdentities: snapshot.1,
            identityHosts: snapshot.2,
            identityHostsOnly: snapshot.3,
            configProvider: configProvider
        )
    }

    /// The identity a handshake with `host:port` presents, under `config`.
    func clientIdentity(forHost host: String, port: Int?, config: @escaping () -> CertificateConfig?) -> SelectedClientIdentity? {
        buildCompositeKeyManagers(configProvider: config)?.select(host: host, port: port)
    }

    // MARK: Pin changes

    /// The pins changed (a new config, a rollback, a reset). From here on
    /// every session this manager built is rebuilt before its next request —
    /// new connections, full handshakes, no TLS session verified against the
    /// old pins — and the current ones are invalidated now, so their idle
    /// pooled connections close (`finishTasksAndInvalidate`: requests in flight complete).
    func onPinsChanged() {
        state.withLock { $0.generation += 1 }
        let live = transports.withLock { list -> [URLSessionTransport] in
            list.removeAll { $0.transport == nil }
            return list.compactMap(\.transport)
        }
        live.forEach { $0.retireSessions() }
    }

    func register(_ transport: URLSessionTransport) {
        transports.withLock { list in
            list.removeAll { $0.transport == nil }
            list.append(WeakTransport(transport: transport))
        }
    }

    // MARK: Session factories

    /// A session pinned to `config` — a frozen snapshot; later config swaps do
    /// not reach it (``buildDynamicClient(configProvider:settings:recovery:extraInterceptors:)``
    /// is the live variant). A nil `config` does NOT fall back to system trust:
    /// every TLS handshake is refused (fail-closed).
    func buildClient(
        _ config: CertificateConfig?,
        settings: HttpConnectionSettings = HttpConnectionSettings(),
        recovery: PinRecoveryInterceptor? = nil
    ) -> PinnedSession {
        buildDynamicClient(configProvider: { config }, settings: settings, recovery: recovery)
    }

    /// A session whose pins are re-read from `configProvider` on every
    /// handshake (and before every request). While the provider returns nil the
    /// session refuses to connect; once a config is published it starts working
    /// without being rebuilt. Used for ``HttpClientProvider`` and `session(settings:)`.
    ///
    /// A pinned session never continues in the clear: a redirect between
    /// `https` and `http` is not followed (OkHttp `followSslRedirects(false)`)
    /// unless the app's `settings` opt in (`followCleartextRedirects`); the
    /// library's own callers pass the defaults.
    /// - Parameter extraInterceptors: added outside `recovery` (the attestation token).
    func buildDynamicClient(
        configProvider: @escaping @Sendable () -> CertificateConfig?,
        settings: HttpConnectionSettings = HttpConnectionSettings(),
        recovery: PinRecoveryInterceptor? = nil,
        extraInterceptors: [any PinnedInterceptor] = []
    ) -> PinnedSession {
        if configProvider() == nil {
            Self.log.d("No config yet — building fail-closed client (TLS refused until a config is applied)")
        }
        let transport = URLSessionTransport(
            manager: self,
            configuration: Self.sessionConfiguration(settings),
            trust: .pinned(configProvider),
            resolveOverrides: settings.resolvedHosts,
            redirects: settings.followCleartextRedirects ? .all : .sameScheme
        )
        logApplied(configProvider())
        return PinnedSession(interceptors: extraInterceptors + [recovery].compactMap { $0 }, transport: transport)
    }

    /// The session a Config API block reaches its own backend with (config
    /// fetch, enrollment, renewal, vault files), pinned to `bootstrapPins`.
    ///
    /// Pinned and HTTPS-only, always — unless the block asked otherwise
    /// (`allowUnpinned`, `allowUnpinnedConfigApi()`): no pins → every TLS
    /// handshake is refused, `http://` → the request fails before it is sent,
    /// and no redirect is followed (the Config API's requests carry device
    /// headers and enrollment bodies; it never redirects).
    ///
    /// - Parameters:
    ///   - timeout: connect/read timeout in seconds (30; the reporter's pinned client uses 5).
    ///   - forbiddenAs409: `.always` for the Config API client (PORTING.md §4).
    func buildBootstrapClient(
        _ bootstrapPins: [HostPin],
        interceptor: (any PinnedInterceptor)? = nil,
        allowUnpinned: Bool = false,
        timeout: TimeInterval = DynamicSSLManager.defaultTimeout,
        forbiddenAs409: ForbiddenAsConflict.Policy = .identityHosts
    ) -> PinnedSession {
        let trust: TrustMode
        if !bootstrapPins.isEmpty {
            let config = CertificateConfig(version: 0, pins: bootstrapPins)
            trust = .pinned({ config })
            Self.log.d("Bootstrap client pinned — \(bootstrapPins.count) hosts")
        } else if allowUnpinned {
            trust = .system
            Self.log.w("Bootstrap client — no pins, using system defaults (allowUnpinnedConfigApi)")
        } else {
            // Fail closed: pinning over "no config" refuses every handshake.
            trust = .pinned({ nil })
            Self.log.e("Bootstrap client has no pins — every TLS handshake is refused (set bootstrapPins)")
        }
        let configuration = Self.sessionConfiguration(HttpConnectionSettings(
            connectTimeout: Int64(timeout), readTimeout: Int64(timeout), writeTimeout: 0
        ))
        let transport = URLSessionTransport(
            manager: self,
            configuration: configuration,
            trust: trust,
            resolveOverrides: [:],
            redirects: allowUnpinned ? .all : .none,
            forbiddenAs409: forbiddenAs409
        )
        var interceptors: [any PinnedInterceptor] = []
        if let interceptor { interceptors.append(interceptor) }
        if !allowUnpinned { interceptors.append(HTTPSOnlyInterceptor()) }
        return PinnedSession(interceptors: interceptors, transport: transport)
    }

    /// Pinning over the app's own `configuration` (its timeouts, headers,
    /// cookies, cache policy): the pins are read from `configProvider` on every
    /// handshake, and the session follows config swaps and identity changes
    /// without being rebuilt by the app. `interceptors` run outside the
    /// transport, in order (the token interceptor, then recovery).
    ///
    /// Forced on the copy: TLS 1.2 or newer, no `URLCache` (a cache shared with
    /// an unpinned session would answer pinned requests with responses that
    /// never crossed a pinned connection), no credential storage (the client
    /// identity is never stored where another session's default handling finds it),
    /// and no redirect from `https` into `http` unless `followCleartextRedirects`
    /// (OkHttp `followSslRedirects`, off here where OkHttp defaults to on).
    func applyTo(
        _ configuration: URLSessionConfiguration,
        configProvider: @escaping @Sendable () -> CertificateConfig?,
        interceptors: [any PinnedInterceptor] = [],
        followCleartextRedirects: Bool = false
    ) -> PinnedSession {
        let copy = configuration.copy() as! URLSessionConfiguration
        Self.harden(copy, libraryOwned: false)
        let transport = URLSessionTransport(
            manager: self,
            configuration: copy,
            trust: .pinned(configProvider),
            resolveOverrides: [:],
            redirects: followCleartextRedirects ? .all : .sameScheme
        )
        logApplied(configProvider())
        return PinnedSession(interceptors: interceptors, transport: transport)
    }

    private func logApplied(_ initial: CertificateConfig?) {
        let (hasDefault, hostCount) = state.withLock { ($0.defaultIdentity != nil, $0.hostIdentities.count) }
        let mtlsHosts = initial?.pins.filter(\.mtls).count ?? 0
        Self.log.d(
            "Applied dynamic pinning — initial v=\(initial?.version ?? -1), \(initial?.pins.count ?? 0) hosts " +
                "(\(mtlsHosts) mTLS), defaultCert=\(hasDefault), hostCerts=\(hostCount)"
        )
    }

    /// A library-owned configuration for `settings`: ephemeral, TLS ≥ 1.2, no
    /// cache, no cookies, no credential storage. Timeouts: the largest of
    /// connect/read/write → `timeoutIntervalForRequest` (0 everywhere = none),
    /// `callTimeout` → `timeoutIntervalForResource`, `maxIdleConnections` →
    /// `httpMaximumConnectionsPerHost`.
    static func sessionConfiguration(_ settings: HttpConnectionSettings) -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        harden(configuration, libraryOwned: true)
        let request = max(settings.connectTimeout, settings.readTimeout, settings.writeTimeout)
        configuration.timeoutIntervalForRequest = request > 0 ? TimeInterval(request) : noTimeout
        configuration.timeoutIntervalForResource = settings.callTimeout > 0 ? TimeInterval(settings.callTimeout) : noTimeout
        if settings.maxIdleConnections > 0 { configuration.httpMaximumConnectionsPerHost = settings.maxIdleConnections }
        return configuration
    }

    /// "No timeout" (URLSession's default resource timeout).
    static let noTimeout: TimeInterval = 7 * 24 * 3600

    /// TLS 1.2 is the floor no configuration can lower: below TLS 1.3 the client
    /// certificate — whose subject names the device — crosses the wire in the clear,
    /// so 1.3 is never capped away either.
    static func harden(_ configuration: URLSessionConfiguration, libraryOwned: Bool) {
        if configuration.tlsMinimumSupportedProtocolVersion.rawValue < tls_protocol_version_t.TLSv12.rawValue {
            configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        }
        let maximum = configuration.tlsMaximumSupportedProtocolVersion
        if maximum.rawValue != 0, maximum.rawValue < tls_protocol_version_t.TLSv13.rawValue {
            configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
        }
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        if libraryOwned {
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.httpCookieStorage = nil
            configuration.httpCookieAcceptPolicy = .never
            configuration.httpShouldSetCookies = false
            // Strip any injected URLProtocol (IOS-7): a custom protocol registered
            // on the template (or globally) would handle the request itself and the
            // pinned delegate would never run. The built-in http(s) handling stays.
            configuration.protocolClasses = []
        }
    }

    // MARK: Routing

    /// Where a connection for the logical `host:port` goes: the session's
    /// resolve entry for the host, else the config's (the port stays), then
    /// the E2E redirect for the resulting `address:port` (or, failing that,
    /// for the logical `host:port`).
    func connectAddress(host: String, port: Int, overrides: [String: String]) -> (host: String, port: Int) {
        let (resolved, redirect) = state.withLock { ($0.resolvedHosts, $0.connectionRedirect) }
        let name = host.lowercased()
        var address = (host: name, port: port)
        if let mapped = overrides[name] ?? resolved[name] {
            address.host = Self.bareHost(mapped).lowercased()
        }
        let target = redirect(Self.hostPort(address.host, address.port))
            ?? (address.host != name ? redirect(Self.hostPort(name, port)) : nil)
        if let target, let parsed = Self.parseHostPort(target) {
            address = parsed
        }
        return address
    }

    /// `host:port`, with brackets around an IPv6 literal.
    static func hostPort(_ host: String, _ port: Int) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// `host:port` / `[v6]:port` → parts; nil without a valid port.
    static func parseHostPort(_ text: String) -> (host: String, port: Int)? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard let colon = trimmed.lastIndex(of: ":") else { return nil }
        let host = bareHost(String(trimmed[..<colon]))
        guard !host.isEmpty, let port = Int(trimmed[trimmed.index(after: colon)...]), (1...65_535).contains(port) else {
            return nil
        }
        return (host.lowercased(), port)
    }

    /// `[::1]` → `::1`.
    static func bareHost(_ host: String) -> String {
        host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
    }

    /// Host (lower case, no brackets) and port of an http(s) URL; nil for anything else.
    static func httpEndpoint(_ text: String) -> (host: String, port: Int)? {
        guard let url = URL(string: text.trimmingCharacters(in: .whitespaces)),
              let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = url.host, !host.isEmpty else { return nil }
        return (bareHost(host).lowercased(), url.port ?? (scheme == "https" ? 443 : 80))
    }

    // MARK: Server trust

    /// Why a connection was refused, recorded per task by the delegate:
    /// URLSession itself only reports `URLError.cancelled`.
    enum PinCheckError: Error, Sendable {
        /// The trust check refused the chain (Kotlin: the trust manager's
        /// `CertificateException`, surfacing as `SSLHandshakeException`).
        case handshake(PinVaultError)
        /// The leaf does not name the host (OkHttp's hostname verifier:
        /// `SSLPeerUnverifiedException`).
        case peerUnverified(String)

        /// What the request throws.
        var thrown: PinVaultError {
            switch self {
            case .handshake(let error): return .sslHandshake(message: error.message, cause: error)
            case .peerUnverified(let message): return .sslPeerUnverified(message: message)
            }
        }
    }

    /// The server-trust decision of a handshake with the logical `hostname:port`.
    func evaluateServerTrust(_ trust: SecTrust, hostname: String, port: Int?, mode: TrustMode) throws {
        let chain = Self.presentedChain(trust)
        switch mode {
        case .pinned(let provider):
            do {
                try checkServerTrusted(chain, hostname: hostname, port: port, config: provider())
            } catch let error as PinVaultError {
                throw PinCheckError.handshake(error)
            }
        case .system:
            do {
                guard !chain.isEmpty else { throw PinVaultError.certificate(message: "No server certificate provided") }
                try caCheck.check(chain, host: hostname, at: wallClock())
            } catch {
                throw PinCheckError.handshake(error as? PinVaultError ?? .certificate(message: "\(error)", cause: error))
            }
        }
        // OkHttp's hostname verifier, after the handshake (the system check above already includes it).
        if case .pinned = mode, let leaf = chain.first, !HostnameVerifier.verify(hostname, leaf) {
            let names = HostnameVerifier.allSubjectAltNames(leaf).joined(separator: ", ")
            throw PinCheckError.peerUnverified(
                "Hostname \(hostname) not verified:\n    certificate: sha256/\(leaf.spkiPin)\n" +
                    "    DN: \(leaf.subject.rfc2253)\n    subjectAltNames: [\(names)]"
            )
        }
    }

    /// The server's certificates as `SecTrust` exposes them: the path it builds
    /// from what the server sent, leaf first (Apple gives no access to the raw
    /// list — certificates off the path are dropped, a locally known issuer may
    /// be appended). No network fetch. A certificate the parser cannot read ends the chain.
    static func presentedChain(_ trust: SecTrust) -> [X509Certificate] {
        SecTrustSetNetworkFetchAllowed(trust, false)
        let certificates = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        var chain: [X509Certificate] = []
        for certificate in certificates {
            guard let parsed = try? X509Certificate(certificate: certificate) else { break }
            chain.append(parsed)
        }
        return chain
    }

    /// The pinning trust check of one handshake (Kotlin `verifyPin`): throws the
    /// reason `chain` is not acceptable for `hostname:port` under `config`.
    ///
    /// Security comes from public-key pinning plus, for the hosts named with
    /// ``requireCaTrust(_:)``, the platform's CA check. A config past its
    /// `expiresAt` (plus the grace) is refused.
    func checkServerTrusted(_ chain: [X509Certificate], hostname: String, port: Int?, config: CertificateConfig?) throws {
        guard let leaf = chain.first else { throw PinVaultError.certificate(message: "No server certificate provided") }
        let config = try requireUsableConfig(config, hostname: hostname)
        let managed = managedTrustRootsEnabled

        // A hostname with no entry (and no matching wildcard) is refused — the
        // alternative is accepting any certificate for unknown hosts, the
        // cross-host pin-reuse attack H-01 closes. The one exception is a host
        // managed trust roots cover (matchPins decides); here the set is only
        // what the connection event reports.
        let acceptedForHost: [String]
        if let pins = pinsForOrNil(config, hostname, port) {
            acceptedForHost = pins
        } else if managed, !config.trustRoots.isEmpty {
            acceptedForHost = config.trustRoots
        } else {
            acceptedForHost = try pinsFor(config, hostname, port)
        }

        // A distinct error: refetching the config cannot repair a certificate
        // outside its validity window, so recovery must not take it for a mismatch.
        let now = wallClock()
        if now < leaf.notBefore {
            throw PinVaultError.certificateValidity(
                message: "Server certificate is expired or not yet valid: NotBefore: \(Self.format(leaf.notBefore))"
            )
        }
        if now > leaf.notAfter {
            throw PinVaultError.certificateValidity(
                message: "Server certificate is expired or not yet valid: NotAfter: \(Self.format(leaf.notAfter))"
            )
        }

        // The leaf, or an issuer the leaf really chains to (ChainPinMatcher).
        let certHash = leaf.spkiPin
        let matchedPin = try matchPins(config, chain, hostname: hostname, port: port)

        try requireCaTrustFor(chain, hostname: hostname, port: port)

        let hasClientCert = state.withLock { $0.defaultIdentity != nil }
        let via = matchedPin == certHash ? "" : " (issuer pin sha256/\(matchedPin.prefix(12))...)"
        // The host and the pin that matched; no certificate subject.
        Self.log.d("Pin verified ✓ — host=\(hostname), sha256/\(certHash.prefix(12))...\(via), clientCert=\(hasClientCert)")
        emitConnectionEvent(hostname, success: true, actualPin: certHash, expectedPins: acceptedForHost, pinVersion: config.version)
    }

    /// `requireCaTrust`: the pins come from whoever signs the config, which on
    /// its own makes that signer a private CA for every pinned host. For the
    /// hosts the app named, the platform's CAs must accept the chain as well —
    /// both checks, not either. Throws ``PinVaultError/caTrust(message:cause:)``;
    /// nothing for other hosts.
    func requireCaTrustFor(_ chain: [X509Certificate], hostname: String, port: Int?) throws {
        let (patterns, check) = state.withLock { ($0.caTrustPatterns, $0.caCheck) }
        guard !patterns.isEmpty, PinHostMatcher.match(patterns, hostname, port: port) != nil else { return }
        do {
            try check.check(chain, host: hostname, at: wallClock())
        } catch {
            let message = ManagedTrustRoots.describe(error)
            Self.log.e("CA check failed for \(hostname) (requireCaTrust): \(message)")
            throw PinVaultError.caTrust(
                message: "Certificate for \(hostname) matches its pins but is not trusted by the platform's " +
                    "certificate authorities, which requireCaTrust asks for: \(message)",
                cause: error
            )
        }
    }

    /// `config` when it may be used right now, else a
    /// ``PinVaultError/certificate(message:cause:)``: no config (or one without
    /// pins), or one past its `expiresAt` plus the grace. Shared by the
    /// handshake check and the per-request check.
    @discardableResult
    func requireUsableConfig(_ config: CertificateConfig?, hostname: String) throws -> CertificateConfig {
        guard let config, !config.pins.isEmpty else {
            throw PinVaultError.certificate(
                message: "No pins configured — refusing connection. Call PinVault.start() before making HTTPS requests."
            )
        }
        // An expired config pins nothing: whoever keeps fresh configs away from
        // the device must not keep it on old pins for good. A plain certificate
        // error on purpose — refetching the config is exactly what repairs this,
        // so recovery should try. Bootstrap and static configs carry no
        // expiresAt (0) and are never refused here.
        let (grace, clock) = state.withLock { ($0.expiredConfigGraceMs, $0.clock) }
        if config.expiresAt > 0, clock() > config.expiresAt + grace {
            throw PinVaultError.certificate(
                message: "Pin config expired at \(config.expiresAt) (Unix ms) — refusing connection to '\(hostname)' " +
                    "until a fresh config is fetched",
                cause: PinVaultError.configExpired(expiresAt: config.expiresAt)
            )
        }
        return config
    }

    /// The pin of `config` that `chain` satisfies for `hostname`: the leaf's
    /// key, or an issuer the leaf really chains to. Throws (and reports the
    /// mismatch to the listener) when there is none.
    @discardableResult
    func matchPins(_ config: CertificateConfig, _ chain: [X509Certificate], hostname: String, port: Int?) throws -> String {
        guard let leaf = chain.first else { throw PinVaultError.certificate(message: "No server certificate provided") }
        let acceptedForHost: [String]
        if let pins = pinsForOrNil(config, hostname, port) {
            acceptedForHost = pins
        } else if managedTrustRootsEnabled, !config.trustRoots.isEmpty {
            // No pin entry, but the config lists managed trust roots: the
            // platform must validate the chain to one of them.
            return try ManagedTrustRoots.match(
                chain, hostname: hostname, trustRoots: Set(config.trustRoots), resolver: anchorResolver, now: wallClock()
            )
        } else {
            acceptedForHost = try pinsFor(config, hostname, port)
        }
        let certHash = leaf.spkiPin
        guard let matchedPin = ChainPinMatcher.match(chain, accepted: Set(acceptedForHost), now: wallClock()) else {
            emitConnectionEvent(hostname, success: false, actualPin: certHash, expectedPins: acceptedForHost, pinVersion: config.version)
            Self.log.e("Pin mismatch for \(hostname) — cert=\(certHash.prefix(12))..., expected \(acceptedForHost.count) pins")
            throw PinVaultError.certificate(
                message: "Certificate pinning failure for \(hostname)!\n" +
                    "  Cert hash: sha256/\(certHash)\n" +
                    "  Accepted pins for this host: \(acceptedForHost.count)"
            )
        }
        // An issuer pin says "a certificate this CA issued": for a public CA that
        // is any site's certificate, so the leaf must also name the host. A leaf
        // pin names one key and needs no name check here — the pin is the identity.
        if matchedPin != certHash, !ChainPinMatcher.leafNamesHost(leaf, hostname) {
            Self.log.e("Issuer pin matched for \(hostname) but the certificate is not issued for that host")
            throw PinVaultError.hostnameMismatch(
                message: "Certificate for \(hostname) chains to a pinned issuer but is not issued for \(hostname) " +
                    "(no matching subjectAltName); an issuer pin vouches for the CA, not for the name"
            )
        }
        return matchedPin
    }

    private func acceptedPins(_ config: CertificateConfig) -> PinHostMap<[String]> {
        PinHostMatcher.build(config.pins.map { pin in
            var seen = Set<String>()
            return (pin.hostname, pin.sha256.filter { seen.insert($0).inserted })
        })
    }

    /// The pins `config` accepts for `hostname` (and `port`); ``PinVaultError/unpinnedHost(message:cause:)`` when it names none.
    private func pinsFor(_ config: CertificateConfig, _ hostname: String, _ port: Int?) throws -> [String] {
        let map = acceptedPins(config)
        guard let pins = PinHostMatcher.match(map, hostname, port: port) else {
            throw PinVaultError.unpinnedHost(
                message: "No pin entry for hostname '\(hostname)'. Configured hosts: \(map.keys.joined(separator: ", "))"
            )
        }
        return pins
    }

    /// The pins `config` accepts for `hostname` (and `port`), or nil when it names none.
    private func pinsForOrNil(_ config: CertificateConfig, _ hostname: String, _ port: Int?) -> [String]? {
        PinHostMatcher.match(acceptedPins(config), hostname, port: port)
    }

    private static func format(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    // MARK: Events

    /// Builds and dispatches a connection event off the TLS callback.
    private func emitConnectionEvent(_ hostname: String, success: Bool, actualPin: String, expectedPins: [String], pinVersion: Int) {
        guard state.withLock({ $0.connectionListener }) != nil else { return }
        dispatchEvent(.connection(
            hostname: hostname,
            success: success,
            pinVersion: pinVersion,
            deviceManufacturer: DeviceInfo.manufacturer,
            deviceModel: DeviceInfo.model,
            actualPin: actualPin,
            expectedPins: expectedPins
        ))
    }

    /// Pushes a non-handshake event (a config update result, a renewal, an
    /// attestation) onto the same listener pipe. Never blocks; a full queue drops the event.
    func dispatchEvent(_ event: PinVaultConnectionEvent) {
        guard let listener = state.withLock({ $0.connectionListener }) else { return }
        events.yield(Delivery(listener: listener, event: event))
    }
}

// MARK: - URLSession delegate

/// The delegate of one library-built `URLSession` (one logical host and port):
/// answers its authentication challenges through the ``DynamicSSLManager``
/// and records, per task, why it refused a peer.
final class PinnedSessionDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {

    /// What this session's connections are for.
    struct Context: Sendable {
        /// The host and port the app asked for: every trust and identity decision uses them.
        let logicalHost: String
        let logicalPort: Int
        /// Where the connections go (`resolve`, E2E redirect); the challenge must come from there.
        let connectHost: String
        let connectPort: Int
        let trust: DynamicSSLManager.TrustMode
    }

    private static let log = PinVaultLog.tag("DynamicSSLManager")

    let manager: DynamicSSLManager
    let context: Context
    private let failures = Locked<[Int: DynamicSSLManager.PinCheckError]>([:])
    private let presented = Locked<X509Certificate?>(nil)
    /// Who receives each running task's response and body.
    private let collectors = Locked<[Int: ResponseCollector]>([:])

    init(manager: DynamicSSLManager, context: Context) {
        self.manager = manager
        self.context = context
    }

    /// Routes the response and body of task `taskIdentifier` to `collector` (before the task is resumed).
    func collect(_ taskIdentifier: Int, _ collector: ResponseCollector) {
        collectors.withLock { $0[taskIdentifier] = collector }
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        guard let collector = collectors.withLock({ $0[dataTask.taskIdentifier] }) else {
            completionHandler(.allow)
            return
        }
        completionHandler(collector.receive(response) ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let collector = collectors.withLock({ $0[dataTask.taskIdentifier] }) else { return }
        if !collector.receive(data) { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let collector = collectors.withLock { $0.removeValue(forKey: task.taskIdentifier) }
        collector?.complete(taskIdentifier: task.taskIdentifier, error: error)
    }

    /// The refusal recorded for `taskIdentifier`, removed.
    func takeFailure(_ taskIdentifier: Int) -> DynamicSSLManager.PinCheckError? {
        failures.withLock { $0.removeValue(forKey: taskIdentifier) }
    }

    /// The client certificate this session's handshakes presented (nil: none
    /// was asked for, or none was given). Sessions are rebuilt whenever the
    /// identity or the config changes, so every connection of one session
    /// presents the same one.
    var presentedClientCertificate: X509Certificate? {
        presented.withLock { $0 }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let space = challenge.protectionSpace
        switch space.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust where !space.isProxy():
            guard let trust = space.serverTrust else {
                refuse(task, .handshake(.certificate(message: "No server certificate provided")), completionHandler)
                return
            }
            guard isConnectAddress(space) else {
                refuse(task, .handshake(.certificate(
                    message: "TLS peer \(space.host):\(space.port) is not the address this session connects to " +
                        "(\(DynamicSSLManager.hostPort(context.connectHost, context.connectPort)))"
                )), completionHandler)
                return
            }
            do {
                try manager.evaluateServerTrust(trust, hostname: context.logicalHost, port: context.logicalPort, mode: context.trust)
                completionHandler(.useCredential, URLCredential(trust: trust))
            } catch let failure as DynamicSSLManager.PinCheckError {
                refuse(task, failure, completionHandler)
            } catch {
                refuse(task, .handshake(.certificate(message: "\(error)", cause: error)), completionHandler)
            }

        case NSURLAuthenticationMethodClientCertificate:
            // The unpinned bootstrap client presents none (OkHttp's default socket factory has no key manager).
            guard let provider = context.trust.configProvider,
                  let selected = manager.clientIdentity(forHost: context.logicalHost, port: context.logicalPort, config: provider) else {
                presented.set(nil)
                completionHandler(.rejectProtectionSpace, nil)
                return
            }
            presented.set(selected.identity.leaf)
            completionHandler(.useCredential, selected.identity.credential())

        case NSURLAuthenticationMethodServerTrust:
            // TLS to an HTTPS proxy: the platform's trust. The origin behind it is judged above.
            completionHandler(.performDefaultHandling, nil)

        default:
            // HTTP authentication (Basic, Digest, NTLM, Negotiate, proxy auth):
            // OkHttp's default authenticators answer none, so the 401/407 goes
            // back to the caller as it is (the token interceptor reads it).
            completionHandler(.rejectProtectionSpace, nil)
        }
    }

    /// Redirects are followed by the transport (it re-routes and re-pins each
    /// hop on the right session), never by URLSession: the 3xx comes back as is.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    private func refuse(
        _ task: URLSessionTask,
        _ failure: DynamicSSLManager.PinCheckError,
        _ completionHandler: @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        failures.withLock { $0[task.taskIdentifier] = failure }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private func isConnectAddress(_ space: URLProtectionSpace) -> Bool {
        let host = DynamicSSLManager.bareHost(space.host).lowercased()
        guard host == context.connectHost else { return false }
        return space.port == context.connectPort || space.port == 0
    }
}
