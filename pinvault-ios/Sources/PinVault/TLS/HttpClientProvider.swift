import Foundation

/// Thread-safe holder for the current pinned session of a Config API block
/// (Kotlin `HttpClientProvider`).
///
/// When the config is updated, ``swap(_:)`` replaces the session; requests in
/// flight complete normally, new requests use the new one. Every change of the
/// pins — ``swap(_:)``, ``reset()``, a ``replaceConfigInPlace(_:)`` whose pins
/// differ — is reported to the SSL manager (``DynamicSSLManager/onPinsChanged()``):
/// the sessions of every client the library handed out are rebuilt, not only
/// the one being replaced.
///
/// Every session built here reads ``currentConfig`` live (weakly: a session
/// that outlives its provider refuses every handshake).
final class HttpClientProvider: @unchecked Sendable {

    private static let log = PinVaultLog.tag("HttpClientProvider")

    private let sslManager: DynamicSSLManager

    private struct State {
        var config: CertificateConfig?
        var version = 0
        var client: PinnedSession?
        var tokenInterceptor: (any PinnedInterceptor)?
        var recoveryUpdater: (@Sendable () async -> Bool)?
    }

    private let state = Locked(State())

    init(sslManager: DynamicSSLManager) {
        self.sslManager = sslManager
        // Starts fail-closed: pinning over the live config, so every handshake is
        // refused until swap publishes the first config — and starts succeeding
        // right after, even for callers still holding this instance.
        let client = build(withRecovery: false, token: nil)
        state.withLock { $0.client = client }
    }

    /// The active config; nil before the first ``swap(_:)`` and after ``reset()``.
    var currentConfig: CertificateConfig? {
        state.withLock { $0.config }
    }

    /// The attestation token interceptor of this block, or nil when it does not
    /// attest. Set once by the block (L5); every session built here from then on
    /// carries it (outside the recovery interceptor), the fail-closed one included.
    var tokenInterceptor: (any PinnedInterceptor)? {
        get { state.withLock { $0.tokenInterceptor } }
        set {
            let withRecovery = state.withLock { state -> Bool in
                state.tokenInterceptor = newValue
                return state.config != nil
            }
            let client = build(withRecovery: withRecovery, token: newValue)
            state.withLock { $0.client = client }
        }
    }

    /// The config refetch pin recovery runs (L2's `SSLCertificateUpdater`);
    /// nil = recovery never fetches (and so never retries).
    var recoveryUpdater: (@Sendable () async -> Bool)? {
        get { state.withLock { $0.recoveryUpdater } }
        set { state.withLock { $0.recoveryUpdater = newValue } }
    }

    /// The interceptor that retries a failed request after refreshing the pins,
    /// also installed by `PinVault.applyTo(_:)` on the app's configuration.
    var recoveryInterceptor: PinRecoveryInterceptor {
        recoveryStorage.withLock { stored in
            if let stored { return stored }
            let made = PinRecoveryInterceptor(
                updater: { [weak self] in
                    guard let updater = self?.recoveryUpdater else { return false }
                    return await updater()
                },
                newClientProvider: { [weak self] in self?.get() }
            )
            stored = made
            return made
        }
    }

    private let recoveryStorage = Locked<PinRecoveryInterceptor?>(nil)

    /// A session over the LIVE config, with this block's token interceptor when
    /// it has one, and the recovery interceptor when asked.
    private func build(withRecovery: Bool, token: (any PinnedInterceptor)?) -> PinnedSession {
        sslManager.buildDynamicClient(
            configProvider: { [weak self] in self?.currentConfig },
            recovery: withRecovery ? recoveryInterceptor : nil,
            extraInterceptors: [token].compactMap { $0 }
        )
    }

    /// The current session.
    func get() -> PinnedSession {
        state.withLock { $0.client! }
    }

    /// ``CertificateConfig/computedVersion()`` of the active config; 0 without one.
    func getVersion() -> Int {
        state.withLock { $0.version }
    }

    /// Publishes `newConfig` and a new session over it (live, so a later
    /// freshness write-back through ``replaceConfigInPlace(_:)`` reaches it too).
    func swap(_ newConfig: CertificateConfig) {
        let token = state.withLock { state -> (any PinnedInterceptor)? in
            state.config = newConfig
            state.version = newConfig.computedVersion()
            return state.tokenInterceptor
        }
        let client = build(withRecovery: true, token: token)
        state.withLock { $0.client = client }
        // Retires the old session's connections (and those of every other session built here).
        sslManager.onPinsChanged()
        Self.log.d("HttpClient swapped — new version: \(newConfig.computedVersion()), \(newConfig.pins.count) pinned hosts")
    }

    /// Replaces the live config WITHOUT a new session, for changes that leave
    /// the pins untouched (a cleared `forceUpdate`, a newer `issuedAt` /
    /// `expiresAt`). Should the pins differ after all, the change is treated as
    /// what it is (``DynamicSSLManager/onPinsChanged()``). Sessions read the
    /// config on every request, so the new object takes effect at once.
    func replaceConfigInPlace(_ newConfig: CertificateConfig) {
        let pinsChanged = state.withLock { state -> Bool in
            let changed = state.config.map { Self.pinShape($0) != Self.pinShape(newConfig) } ?? true
            state.config = newConfig
            state.version = newConfig.computedVersion()
            return changed
        }
        if pinsChanged { sslManager.onPinsChanged() }
    }

    private static func pinShape(_ config: CertificateConfig) -> [String: Set<String>] {
        var shape: [String: Set<String>] = [:]
        for pin in config.pins { shape[pin.hostname.lowercased()] = Set(pin.sha256) }
        return shape
    }

    /// Drops the active config. The replacement session is fail-closed —
    /// pinning is never downgraded to system trust.
    func reset() {
        let token = state.withLock { state -> (any PinnedInterceptor)? in
            state.config = nil
            state.version = 0
            return state.tokenInterceptor
        }
        let client = build(withRecovery: false, token: token)
        state.withLock { $0.client = client }
        sslManager.onPinsChanged()
        Self.log.w("HttpClient reset — no config; TLS refused until the next init/swap")
    }
}
