import Foundation

/// Everything needed to talk to one Config API, one per ``ConfigApiBlock``
/// (Kotlin `ConfigApiClient`):
///  - its own ``DynamicSSLManager`` and ``HttpClientProvider`` (its own pin
///    verification stack and pinned session);
///  - a ``CertificateConfigStore`` namespaced by block and server, so pins do
///    not collide between APIs;
///  - the ``CertificateConfigApi`` bound to the block's URL (the library's
///    ``DefaultCertificateConfigApi`` unless the app passed its own);
///  - the ``SSLCertificateUpdater`` driving start and refresh;
///  - the block's ``TrustedClock`` and ``SignatureTrust``.
///
/// Enrollment (L3), vault files (L4) and attestation (L5) plug in through
/// ``Collaborators`` — see there; without them the block behaves like a TLS
/// block with nothing enrolled and no attestation.
final class ConfigApiClient: @unchecked Sendable {

    private static let log = PinVaultLog.tag("ConfigApiClient")

    // MARK: Collaborators (L3 / L4 / L5)

    /// What the later layers plug into a block. Every member is optional and
    /// its absence is a no-op:
    ///
    /// - ``enrolledIdentity`` (L3): installs the block's enrolled credential
    ///   (`clientCertLabel`) into the client's SSL manager — a chain over the
    ///   device's Secure Enclave key, or an imported server-made key — and says
    ///   what it found. Called at construction and by ``reloadClientIdentity()``.
    ///   `.none` (and a nil hook) falls back to the P12 bundled with the app
    ///   (`clientKeystore(_:password:)`), as Kotlin's `loadClientIdentity`.
    /// - ``hostCertStore`` (L3): where client certificates of `mtls` pin
    ///   entries are kept; nil = they are not synced (Kotlin without a cert store).
    /// - ``renewer`` (L3): builds the block's `ClientCertRenewer`; nil = renewal
    ///   is ``ClientCertRenewalResult/notApplicable``.
    /// - ``attestation`` (L5): builds the block's attestation manager for a
    ///   block with `attestation()`; its token then rides every session of the block.
    /// - ``onIdentityRevoked`` (L3/L4): told once per identity when the server
    ///   refuses the identity loaded now on a connection that presented it
    ///   (`wipeVaultFilesOnRevocation()`).
    /// - ``onReenrollRequired`` (L3): told the server's reason the first time a
    ///   request of the block is refused as `reenroll_required` (per identity).
    struct Collaborators: Sendable {
        var enrolledIdentity: (@Sendable (_ block: ConfigApiBlock, _ sslManager: DynamicSSLManager) -> EnrolledIdentity)?
        var hostCertStore: (any HostClientCertStore)?
        var renewer: (@Sendable (ConfigApiClient) -> any ClientCertRenewing)?
        var attestation: (@Sendable (ConfigApiClient) -> (any BlockAttestation)?)?
        var onIdentityRevoked: (@Sendable (_ configApiId: String) -> Void)?
        var onReenrollRequired: (@Sendable (_ configApiId: String, _ reason: String) -> Void)?

        init(
            enrolledIdentity: (@Sendable (_ block: ConfigApiBlock, _ sslManager: DynamicSSLManager) -> EnrolledIdentity)? = nil,
            hostCertStore: (any HostClientCertStore)? = nil,
            renewer: (@Sendable (ConfigApiClient) -> any ClientCertRenewing)? = nil,
            attestation: (@Sendable (ConfigApiClient) -> (any BlockAttestation)?)? = nil,
            onIdentityRevoked: (@Sendable (_ configApiId: String) -> Void)? = nil,
            onReenrollRequired: (@Sendable (_ configApiId: String, _ reason: String) -> Void)? = nil
        ) {
            self.enrolledIdentity = enrolledIdentity
            self.hostCertStore = hostCertStore
            self.renewer = renewer
            self.attestation = attestation
            self.onIdentityRevoked = onIdentityRevoked
            self.onReenrollRequired = onReenrollRequired
        }

        static let none = Collaborators()
    }

    /// What ``Collaborators/enrolledIdentity`` found (Kotlin `EnrolledChain`, plus "nothing enrolled").
    enum EnrolledIdentity: Sendable {
        /// Presented now.
        case loaded
        /// Kept, but cannot be read right now: present no identity until the next load.
        case unavailable
        /// Nothing enrolled (or dropped): the bundled keystore, if any, is presented.
        case none
    }

    // MARK: Parts

    let block: ConfigApiBlock

    /// The block's store for the server it points at now: each server (scope,
    /// or Config API URL) keeps its own config and watermarks.
    let configStore: CertificateConfigStore

    /// The clock this block's config expiry is decided by; its reference lives
    /// in the block's config store, so setting the device clock back does not
    /// bring an expired config back.
    let trustedClock: TrustedClock

    let sslManager: DynamicSSLManager
    let clientProvider: HttpClientProvider

    /// Which keys this block's configs and vault files must be signed by; nil
    /// when the block runs unsigned. The key-set store is opened only for a
    /// block with recovery keys.
    let signatureTrust: SignatureTrust?

    /// Why this block must not be used, or nil (see ``configurationError(_:customApi:)``).
    let configurationError: String?

    /// Verifies this block's config envelopes; nil when its configs are not verified.
    private let configVerifier: SignedConfigVerifier?

    /// True when the library checks the signatures of this block's configs.
    var configsVerified: Bool { configVerifier != nil }

    let api: any CertificateConfigApi
    let updater: SSLCertificateUpdater
    let collaborators: Collaborators

    /// The block's certificate renewer (L3), or nil.
    private(set) var renewer: (any ClientCertRenewing)?

    /// The block's attestation (`attestation()` on the block), or nil when it
    /// does not attest (L5). With a custom ``CertificateConfigApi`` the
    /// manager exists but reports `UNSUPPORTED` — L5's decision.
    var attestation: (any BlockAttestation)? { attestationBox.get() }
    private let attestationBox = Locked<(any BlockAttestation)?>(nil)

    private let reenrollNotice = ReenrollNotice()
    private let revocation: IdentityRevocation

    /// - Parameters:
    ///   - customApi: the app's ``CertificateConfigApi`` (default block only).
    ///   - recoveryListener: told the result of a pin-mismatch recovery update of THIS block.
    ///   - expiredConfigGraceMs / caTrustHosts / managedTrustRoots / resolvedHosts: from ``PinVaultConfig``.
    ///   - storeEnvironment: where the encrypted stores live (tests pass their own).
    ///   - sleep: the updater's retry wait (tests make it instant).
    /// - Throws: ``PinVaultError/storeUnreadable(message:cause:)`` when the
    ///   block's config store cannot be opened right now.
    init(
        block: ConfigApiBlock,
        customApi: (any CertificateConfigApi)? = nil,
        recoveryListener: @escaping @Sendable (UpdateResult) -> Void = { _ in },
        expiredConfigGraceMs: Int64 = 0,
        caTrustHosts: [String] = [],
        managedTrustRoots: Bool = false,
        resolvedHosts: [String: String] = [:],
        maxRetryCount: Int = SSLCertificateUpdater.defaultMaxRetry,
        collaborators: Collaborators = .none,
        storeEnvironment: SecureStoreEnvironment = .shared,
        configStore injectedStore: CertificateConfigStore? = nil,
        sslManager injectedManager: DynamicSSLManager? = nil,
        sleep: (@Sendable (_ milliseconds: Int64) async -> Void)? = nil
    ) throws {
        self.block = block
        self.collaborators = collaborators
        let store = try injectedStore ?? CertificateConfigStore.forOrigin(
            prefsName: CertificateConfigStore.prefsNameFor(block.id),
            origin: block.serverScope.map { "scope:\($0)" } ?? "url:\(Self.trimTrailingSlashes(block.configUrl).lowercased())",
            environment: storeEnvironment
        )
        configStore = store
        let clock = TrustedClock(
            load: { try store.highestSeenTime() },
            persist: { try store.setHighestSeenTime($0) },
            persistLowered: { try store.lowerHighestSeenTime($0) }
        )
        trustedClock = clock

        let manager = injectedManager ?? DynamicSSLManager()
        manager.expiredConfigGraceMs = expiredConfigGraceMs
        manager.clock = { clock.now() }
        manager.requireCaTrust(caTrustHosts)
        manager.managedTrustRootsEnabled = managedTrustRoots
        manager.resolvedHosts = resolvedHosts
        // The client identity belongs to this block's own listeners (and to
        // hosts the config marks mtls); no other pinned host gets to see it. A
        // block that lists clientCertHosts has named every host itself.
        manager.setIdentityHosts(
            [block.configUrl, block.enrollmentUrl, block.renewalUrl] + block.clientCertHosts,
            onlyThese: !block.clientCertHosts.isEmpty
        )
        sslManager = manager

        signatureTrust = SignatureTrust.forBlock(block) {
            block.recoveryPublicKeys.isEmpty ? nil : try SigningKeyStore.open(environment: storeEnvironment)
        }
        signatureTrust?.setFloorProvider { try store.keySetFloor() }
        configurationError = Self.configurationError(block, customApi: customApi)
        configVerifier = signatureTrust
            .flatMap { trust in customApi == nil || customApi is any SignedConfigSource ? trust : nil }
            .map { trust in
                SignedConfigVerifier(
                    trust: trust,
                    serverScope: block.serverScope,
                    // "Already expired" by the trusted clock, so a clock set back
                    // does not let an expired envelope in (see expiryNow).
                    trustedNow: { clock.now() },
                    issuedAtWatermark: { try store.getCurrentIssuedAt() }
                )
            }

        revocation = IdentityRevocation(currentIdentity: { [weak manager] in manager?.defaultClientCertificate() })
        clientProvider = HttpClientProvider(sslManager: manager)

        // Filled in below once self is complete; the API's reenroll hook reads them.
        let hook = Locked<(@Sendable (String, X509Certificate?) -> Void)?>(nil)
        if let customApi {
            api = customApi
        } else {
            api = DefaultCertificateConfigApi(
                configUrl: block.configUrl,
                configEndpoint: block.configEndpoint,
                healthEndpoint: block.healthEndpoint,
                clientCertEndpoint: block.clientCertEndpoint,
                enrollmentEndpoint: block.enrollmentEndpoint,
                vaultReportEndpoint: block.vaultReportEndpoint,
                bootstrapPins: block.bootstrapPins,
                sslManager: manager,
                signatureTrust: signatureTrust,
                clientKeyPassword: block.clientKeyPassword,
                enrollmentUrl: block.enrollmentUrl,
                onReenrollRequired: { reason, presented in hook.get()?(reason, presented) },
                serverScope: block.serverScope,
                allowUnpinned: block.allowUnpinnedConfigApi,
                allowServerGeneratedKey: block.allowServerGeneratedKey
            )
        }
        if customApi != nil, signatureTrust != nil, configVerifier == nil, block.allowUnsigned {
            Self.log.w(
                "ConfigApiClient[\(block.id)]: custom CertificateConfigApi without SignedConfigSource under allowUnsigned() — " +
                    "its configs are NOT verified and the stored config has no integrity check"
            )
        }

        let deviceIdProvider: @Sendable () -> String? = { DeviceIdentity.deviceId() }
        updater = SSLCertificateUpdater(
            configApi: api,
            configStore: store,
            httpClientProvider: clientProvider,
            sslManager: manager,
            certStore: collaborators.hostCertStore,
            clientKeyPassword: block.clientKeyPassword,
            maxRetryCount: maxRetryCount,
            // Pin scoping: the block's declared host list and the device id the server ACL is keyed on.
            wantPinsFor: block.wantPinsFor,
            deviceIdProvider: deviceIdProvider,
            expiredConfigGraceMs: expiredConfigGraceMs,
            clock: LibraryClock.wallMillis,
            verifier: configVerifier,
            trustedClock: clock,
            sleep: sleep ?? { try? await Task.sleep(nanoseconds: UInt64($0) * 1_000_000) }
        )

        // The identity first: the first fetch of an mTLS Config API presents it.
        loadClientIdentity()

        let blockId = block.id
        hook.set { [weak self] reason, presented in
            guard let self else { return }
            // The files go before the app hears of it.
            if self.revocation.refusedOnConnection(presented) { self.collaborators.onIdentityRevoked?(blockId) }
            if self.claimReenrollNotice() { self.collaborators.onReenrollRequired?(blockId, reason) }
        }

        renewer = collaborators.renewer?(self)
        if block.attestationEnabled, let made = collaborators.attestation?(self) { attach(attestation: made) }

        // Pin mismatch recovery hooks into this block's updater only.
        clientProvider.recoveryUpdater = { [weak self] in
            guard let self else { return false }
            return await self.recoveryUpdate(recoveryListener)
        }

        Self.log.d("ConfigApiClient[\(block.id)] ready → \(block.configUrl)")
    }

    /// Set by `PinVault.reset()`: the block's sessions stay fail-closed until
    /// the next start builds new clients — their pin recovery fetches nothing.
    private let retired = Locked(false)

    /// See ``retired``.
    func retire() {
        retired.set(true)
    }

    /// The refetch pin recovery runs: true when the retry may now succeed.
    private func recoveryUpdate(_ listener: @Sendable (UpdateResult) -> Void) async -> Bool {
        if retired.get() {
            Self.log.w("ConfigApiClient[\(block.id)]: PinVault was reset — no config refetch until it is started again")
            return false
        }
        let before = clientProvider.currentConfig
        let wasExpired = before.map { $0.expiresAt > 0 && trustedClock.now() >= $0.expiresAt + sslManager.expiredConfigGraceMs } ?? false
        let result = await updateNow()
        listener(result)
        // An expired config refreshed in place (same pins, newer expiresAt) is
        // AlreadyCurrent, yet the retry now succeeds: try it too. Only then:
        // every fetch writes a fresher issuedAt back in place, so "the config
        // changed" alone would call a real mismatch repaired and retry for ever.
        switch result {
        case .updated: return true
        case .alreadyCurrent: return wasExpired && clientProvider.currentConfig != before
        case .failed: return false
        }
    }

    /// True the first time the app is to be told that the identity loaded now
    /// must re-enroll. A revoked identity is refused on every request and by
    /// the renewal endpoint; all of those share this one notice.
    func claimReenrollNotice() -> Bool {
        let leaf = sslManager.defaultClientCertificate()
        return reenrollNotice.claim(leaf.map(ReenrollNotice.identityName) ?? "none")
    }

    /// Installs the block's client credentials into the SSL manager: the
    /// enrolled credential (L3's ``Collaborators/enrolledIdentity``) and, only
    /// when nothing is enrolled, the P12 bundled with the app
    /// (`clientKeystore(...)`, the bootstrap identity for an mTLS Config API).
    private func loadClientIdentity() {
        switch collaborators.enrolledIdentity?(block, sslManager) ?? .none {
        case .loaded:
            return
        case .unavailable:
            sslManager.clearClientKeystore(includeHostCerts: false)
        case .none:
            loadBundledKeystore()
        }
    }

    /// The keystore bundled with the app, held in process memory (iOS has no
    /// Keystore import step for it: `SecPKCS12Import` keeps it in memory).
    private func loadBundledKeystore() {
        guard let bundled = block.clientKeystoreBytes else {
            sslManager.clearClientKeystore(includeHostCerts: false)
            return
        }
        do {
            try sslManager.loadClientKeystore(bundled, password: block.clientKeyPassword)
        } catch {
            Self.log.w("ConfigApiClient[\(block.id)]: the bundled client keystore could not be loaded", error)
            sslManager.clearClientKeystore(includeHostCerts: false)
        }
    }

    /// Re-reads the stored credentials and rebuilds every session so the next
    /// handshake presents them. Called after enroll, renew and unenroll (L3).
    func reloadClientIdentity() {
        loadClientIdentity()
        identityChanged()
    }

    /// The identity in the SSL manager changed (enroll, renew, unenroll):
    /// every session — the Config API's bootstrap client included — is rebuilt,
    /// so no request rides a connection made with the previous identity.
    func identityChanged() {
        (api as? DefaultCertificateConfigApi)?.rebuildBootstrapClient()
        if let current = clientProvider.currentConfig { clientProvider.swap(current) }
    }

    /// True when this block's Config API asks for a client certificate the
    /// device does not have yet: the block names an `enrollmentUrl` (its own
    /// URL is an mTLS listener) and no identity is loaded.
    func needsEnrollment() -> Bool {
        block.enrollmentUrl != nil && sslManager.defaultClientCertificate() == nil
    }

    /// Initial config load (from the server or the store). A block that
    /// ``needsEnrollment()`` does not contact its backend.
    func initializeAndUpdate() async throws -> InitResult {
        if let configurationError {
            Self.log.e("ConfigApiClient[\(block.id)] refused: \(configurationError)")
            return .failed(reason: configurationError, exception: PinVaultError.illegalState(configurationError))
        }
        return try await updater.initializeAndUpdate(needsClientCertificate: needsEnrollment())
    }

    func updateNow() async -> UpdateResult {
        if let configurationError {
            return .failed(reason: configurationError, exception: PinVaultError.illegalState(configurationError))
        }
        return await updater.updateNow()
    }

    /// Renewal check (L3's renewer); `notApplicable` without one.
    func renewIfNeeded(force: Bool = false) async -> ClientCertRenewalResult {
        guard let renewer else { return .notApplicable }
        return await renewer.renewIfNeeded(force: force)
    }

    /// Why `block` must not be used with `customApi` (nil = the library's own
    /// HTTP client), or nil. On top of the block's own rules: a block with
    /// signing keys looks signed, so its configs must be verified — a custom
    /// API has to hand over signed envelopes or the block must say `allowUnsigned()`.
    static func configurationError(_ block: ConfigApiBlock, customApi: (any CertificateConfigApi)?) -> String? {
        if let error = block.configurationError() { return error }
        let signed = !block.effectiveSignatureKeys().isEmpty
        if signed, let customApi, !(customApi is any SignedConfigSource), !block.allowUnsigned {
            return "Config API '\(block.id)' has signing keys, but its custom CertificateConfigApi cannot hand over " +
                "signed configs, so nothing would be verified. Implement SignedConfigSource on it (PinVault " +
                "then checks the signatures, issuedAt/expiresAt and key sets itself), or call allowUnsigned() " +
                "on the block to accept unverified configs."
        }
        return nil
    }

    private static func trimTrailingSlashes(_ url: String) -> String {
        var trimmed = url
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        return trimmed
    }

    /// The server refused this block's identity on a connection that showed
    /// `presented` (the renewal over mTLS): the files go when it is the
    /// identity loaded now (``Collaborators/onIdentityRevoked``), once per identity.
    func identityRefused(presented: X509Certificate?) {
        if revocation.refusedOnConnection(presented) { collaborators.onIdentityRevoked?(block.id) }
    }

    /// Attaches the block's attestation (L5's manager, built once every block
    /// exists): every session of this block carries its token from now on.
    func attach(attestation manager: any BlockAttestation) {
        attestationBox.set(manager)
        clientProvider.tokenInterceptor = AttestationTokenInterceptor(sources: { [manager] in [manager] })
    }
}

extension AttestationManager: BlockAttestation {}

/// A block's client-certificate renewal (L3's `ClientCertRenewer`).
protocol ClientCertRenewing: Sendable {
    func renewIfNeeded(force: Bool) async -> ClientCertRenewalResult
}

/// A block's attestation manager (L5's `AttestationManager`), as the façade
/// and the periodic job use it. It is also the token source of the block's sessions.
protocol BlockAttestation: AttestationTokenSource {
    /// The last outcome, from memory.
    var status: AttestationStatus { get }
    /// Attests now (single flight); never throws for a server answer.
    func attestNow() async -> AttestationStatus
    /// The token for the app's own client, attesting first when needed.
    func fetchToken() async -> AttestationTokenResult
    /// Starts the background re-attestation loop (idempotent).
    func start()
    /// Stops the loop and forgets the token (`PinVault.reset()`).
    func reset()
}
