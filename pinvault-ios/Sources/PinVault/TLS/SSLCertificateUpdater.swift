import Foundation

/// The storage the updater works on: ``CertificateConfigStore`` (tests wrap
/// it to see what was written). Every read throws
/// ``PinVaultError/storeUnreadable(message:cause:)`` when the encrypted store
/// cannot be read right now.
protocol UpdaterConfigStore: AnyObject, Sendable {
    func getCurrentVersion() throws -> Int
    func getCurrentIssuedAt() throws -> Int64
    func getVersionWatermarks() throws -> [String: Int]
    func save(_ config: CertificateConfig, envelope: StoredEnvelope?) throws
    func load() throws -> CertificateConfig?
    func loadEnvelope() throws -> StoredEnvelope?
    func markRolledBack(_ config: CertificateConfig) throws
    func isRolledBack(_ config: CertificateConfig) throws -> Bool
    func clearActive(keepAsWatermarks: Bool) throws
    func resetWatermarks(keySetVersion: Int, anchors: String?) throws
    func keySetVersionSeen() throws -> Int?
    func setKeySetVersionSeen(_ version: Int) throws
    func trustAnchorsSeen() throws -> String?
    func setTrustAnchorsSeen(_ fingerprint: String) throws
    func reconcileMirror(keySetVersion: Int, anchors: String)
    func mirroredKeySetVersion() -> Int?
}

extension CertificateConfigStore: UpdaterConfigStore {}

/// Where the client certificates of `mtls` pin entries are kept (Kotlin
/// `ClientCertSecureStore` + `ImportedIdentities`; the implementation is L3's).
/// Labels are `host_<hostname>`. Without one the updater does not sync host
/// certificates (as Kotlin without a cert store).
protocol HostClientCertStore: Sendable {
    /// True when a credential is stored under `label`.
    func exists(_ label: String) -> Bool
    /// The P12 stored under `label` (one whose key could not be imported).
    func load(_ label: String) -> Data?
    /// Stores a P12 under `label`.
    func save(_ label: String, _ p12: Data)
    /// The identity stored under `label` with its key in the Keychain, moving
    /// a P12 stored earlier there now; nil = none (`ImportedIdentities.loadOrMigrate`).
    func loadImportedIdentity(_ label: String, password: String) -> ClientIdentity?
    /// Imports the P12's key into the Keychain under `label` (only its chain
    /// is stored); nil when the platform refuses — the P12 is kept then.
    func importIdentity(_ label: String, p12: Data, password: String) throws -> ClientIdentity?
    /// Deletes a key imported for `label`.
    func deleteImportedKey(_ label: String)
}

extension HostClientCertStore {
    func loadImportedIdentity(_ label: String, password: String) -> ClientIdentity? { nil }
    func importIdentity(_ label: String, p12: Data, password: String) throws -> ClientIdentity? { nil }
    func deleteImportedKey(_ label: String) {}
}

/// Core orchestrator of one Config API block: fetches the config, checks it,
/// persists it and swaps the pinned session (Kotlin `SSLCertificateUpdater`).
///
/// Lifecycle: at start ``initializeAndUpdate(needsClientCertificate:)`` loads
/// the stored config and fetches the latest with retries; afterwards
/// ``updateNow()`` (periodic job, pin recovery, the app) and ``applySigned(_:)``
/// (the config inside an attestation answer). Scheduling lives in `Background/`.
final class SSLCertificateUpdater: @unchecked Sendable {

    private static let log = PinVaultLog.tag("SSLCertificateUpdater")

    static let defaultMaxRetry = 3
    static let retryBaseDelayMs: Int64 = 2000

    /// How far ahead of the device clock a config's issuedAt may be. An hour:
    /// phones whose clock runs a few minutes slow (no network time, a manual
    /// setting) must not lose every config; the bound only has to stop an
    /// issuedAt so far ahead that it locks out the configs after it.
    static let maxClockSkewMs: Int64 = 60 * 60 * 1000
    /// Longest accepted expiresAt - issuedAt.
    static let maxValidityMs: Int64 = 30 * 24 * 60 * 60 * 1000
    /// Largest accepted step of a per-host version over the stored one.
    static let maxVersionJump: Int64 = 1_000_000

    private let configApi: any CertificateConfigApi
    private let configStore: any UpdaterConfigStore
    private let httpClientProvider: HttpClientProvider
    private let sslManager: DynamicSSLManager?
    private let certStore: (any HostClientCertStore)?
    private let clientKeyPassword: String
    private let maxRetryCount: Int
    /// Hostnames the block declared via `wantPinsFor(...)`: when non-empty every
    /// fetch is scoped (`?hosts=a,b` + `X-Device-Id`) so the server can
    /// intersect it with the device ACL. Empty = the unscoped fetch.
    private let wantPinsFor: [String]
    /// `X-Device-Id` of scoped fetches (``DeviceIdentity``); nil → the server's default ACL.
    private let deviceIdProvider: @Sendable () -> String?
    /// How long a stored config may still be used after its `expiresAt`.
    private let expiredConfigGraceMs: Int64
    /// Wall clock; tests set it.
    private let clock: @Sendable () -> Int64
    /// Verifies this block's signed envelopes — fetched ones and the stored one,
    /// every time it is read. Nil = the block's configs are not signed.
    private let verifier: SignedConfigVerifier?
    /// The clock expiry is decided by: it does not go back when the device clock does. Nil = `clock`.
    private let trustedClock: TrustedClock?
    /// Waits between init attempts (2000 ms, 4000 ms …); tests make it instant.
    private let sleep: @Sendable (_ milliseconds: Int64) async -> Void

    /// One fetch-and-apply at a time; a rollback waits for it too.
    private let updateLock = AsyncGate()
    /// The update running now, for callers that arrive meanwhile.
    private let inFlight = Locked<Task<UpdateResult, Never>?>(nil)
    /// Why the stored config was discarded during this init, if it was (see ``loadStored()``).
    private let discardedStoredConfig = Locked<String?>(nil)

    init(
        configApi: any CertificateConfigApi,
        configStore: any UpdaterConfigStore,
        httpClientProvider: HttpClientProvider,
        sslManager: DynamicSSLManager? = nil,
        certStore: (any HostClientCertStore)? = nil,
        clientKeyPassword: String = "",
        maxRetryCount: Int = SSLCertificateUpdater.defaultMaxRetry,
        wantPinsFor: [String] = [],
        deviceIdProvider: @escaping @Sendable () -> String? = { nil },
        expiredConfigGraceMs: Int64 = 0,
        clock: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis,
        verifier: SignedConfigVerifier? = nil,
        trustedClock: TrustedClock? = nil,
        sleep: @escaping @Sendable (_ milliseconds: Int64) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0) * 1_000_000) }
    ) {
        self.configApi = configApi
        self.configStore = configStore
        self.httpClientProvider = httpClientProvider
        self.sslManager = sslManager
        self.certStore = certStore
        self.clientKeyPassword = clientKeyPassword
        self.maxRetryCount = maxRetryCount
        self.wantPinsFor = wantPinsFor
        self.deviceIdProvider = deviceIdProvider
        self.expiredConfigGraceMs = expiredConfigGraceMs
        self.clock = clock
        self.verifier = verifier
        self.trustedClock = trustedClock
        self.sleep = sleep
    }

    /// True when `config` is past its `expiresAt` plus the grace. Configs without one never expire.
    private func isExpired(_ config: CertificateConfig) -> Bool {
        config.expiresAt > 0 && (trustedClock?.now() ?? clock()) > config.expiresAt + expiredConfigGraceMs
    }

    private func expiredResult(_ config: CertificateConfig, _ cause: (any Error)?) -> InitResult {
        let error = PinVaultError.configExpired(expiresAt: config.expiresAt, cause: cause)
        Self.log.e("Init failed — stored config expired at \(config.expiresAt) and no fresh config was fetched")
        return .failed(reason: error.message, exception: error)
    }

    // MARK: Init

    /// Full initialization: load the stored config, fetch the latest with
    /// retries, decide whether the block may run (forceUpdate, expiry).
    ///
    /// - Parameter needsClientCertificate: the Config API asks for a client
    ///   certificate this device does not have yet. The backend is then not
    ///   contacted at all — the handshake would be refused, and retrying it
    ///   only delays the caller. A stored config (from before the certificate
    ///   went away) is still applied; without one the result is
    ///   ``PinVaultError/clientCertificateRequired(message:cause:)``.
    /// - Throws: what Kotlin lets escape (PinVault reports it as the block's failure).
    func initializeAndUpdate(needsClientCertificate: Bool = false) async throws -> InitResult {
        do {
            return try await initialize(needsClientCertificate)
        } catch let error as PinVaultError {
            guard case .storeUnreadable = error else { throw error }
            // The Keychain cannot open the stored config, its watermarks or the
            // signing-key set right now. That is not "nothing stored": applying a
            // config without them would switch the replay checks off. Nothing is
            // applied (pinned sessions keep refusing) and the next start tries again.
            Self.log.e("Init failed — encrypted storage is unreadable", error)
            return .failed(reason: error.message, exception: error)
        }
    }

    private func initialize(_ needsClientCertificate: Bool) async throws -> InitResult {
        // 1. Load the stored config (if any).
        discardedStoredConfig.set(nil)
        let stored = try loadFromStore()
        let storedConfig = stored?.config

        if needsClientCertificate {
            if let storedConfig, !storedConfig.forceUpdate {
                if isExpired(storedConfig) { return expiredResult(storedConfig, nil) }
                Self.log.w("No client certificate yet — using stored config v\(storedConfig.version), backend not contacted")
                return .ready(version: storedConfig.version)
            }
            Self.log.w("No client certificate yet — enroll before init; backend not contacted")
            let error = PinVaultError.clientCertificateRequired()
            return .failed(reason: error.message, exception: error)
        }

        // 2. Fetch the latest from the backend, with retries.
        let updateResult = await updateWithRetry()

        switch updateResult {
        case .updated(let newVersion):
            // 3. A new config was just applied — prove the backend is still
            //    reachable through it, and roll back if it is not. A stored
            //    config discarded during the update is no "previous".
            let verifyResult = try await verifyPinnedConnection(previous: discardedStoredConfig.get() == nil ? stored : nil)
            if case .failed = verifyResult { return verifyResult }
            Self.log.d("Init ready — updated to version: \(newVersion)")
            return .ready(version: newVersion)

        case .alreadyCurrent:
            // A successful fetch refreshes the stored expiresAt; one that could
            // not (a custom backend serving a stale config) leaves an expired
            // config, which must not come up Ready.
            if let active = httpClientProvider.currentConfig, isExpired(active) { return expiredResult(active, nil) }
            let version = try configStore.getCurrentVersion()
            Self.log.d("Init ready — already current version: \(version)")
            return .ready(version: version)

        case .failed(let reason, let exception):
            if let discarded = discardedStoredConfig.get() {
                // The stored config failed its integrity check and no fresh one
                // could be fetched: fail closed, and say why.
                Self.log.e("Init failed — \(discarded) and no fresh config could be fetched")
                return .failed(
                    reason: "No usable config: \(discarded), and no fresh config could be fetched: \(reason)",
                    exception: PinVaultError.noConfigAvailable(
                        message: "No usable config: \(discarded), and the backend could not be reached",
                        cause: exception
                    )
                )
            }
            guard let storedConfig else {
                Self.log.e("Init failed — no stored config and backend unreachable")
                return .failed(
                    reason: "No stored config and backend unreachable: \(reason)",
                    exception: PinVaultError.noConfigAvailable(cause: exception)
                )
            }
            if storedConfig.forceUpdate {
                Self.log.e("Init failed — forceUpdate=true but backend unreachable")
                return .failed(
                    reason: "Force update required but backend unreachable: \(reason)",
                    exception: PinVaultError.forceUpdateFailed(cause: exception)
                )
            }
            if isExpired(storedConfig) {
                // Blocking the Config API must not keep the device on old
                // (possibly compromised) pins forever.
                return expiredResult(storedConfig, exception)
            }
            Self.log.w("Init ready with stored config — version: \(storedConfig.version) (backend unreachable)")
            return .ready(version: storedConfig.version)
        }
    }

    /// Post-update health gate, with rollback. Runs only right after
    /// ``updateNow()`` applied a freshly fetched config: one request to the
    /// Config API's health endpoint (over the bootstrap session — a
    /// reachability check of the backend that just served the config). An
    /// unhealthy answer and a failure are the same outcome, and both roll the
    /// config back to `previous` (or, on a first install, clear it), so a
    /// config that cuts the device off its backend does not survive on disk.
    private func verifyPinnedConnection(previous: StoredConfig?) async throws -> InitResult {
        // The config updateNow just applied, remembered if it gets rolled back.
        let appliedConfig = httpClientProvider.currentConfig
        let healthy: Bool
        do {
            healthy = try await configApi.healthCheck()
        } catch let error as PinVaultError {
            if case .sslPeerUnverified = error {
                // Only reachable with a custom CertificateConfigApi that lets the
                // handshake failure escape; the default one maps it to false.
                Self.log.e("Pin mismatch — hashes do not match server certificate", error)
                try await rollBackAfterFailedHealthCheck(previous, appliedConfig)
                return .failed(reason: "Pin hashes do not match server certificate", exception: PinVaultError.pinMismatch(cause: error))
            }
            return try await verificationFailed(error, previous, appliedConfig)
        } catch {
            return try await verificationFailed(error, previous, appliedConfig)
        }

        if healthy {
            Self.log.d("Pinned connection verified — health check OK")
            return .ready(version: try configStore.getCurrentVersion())
        }
        Self.log.e("Health check unhealthy after config update — rolling the new config back")
        try await rollBackAfterFailedHealthCheck(previous, appliedConfig)
        return .failed(
            reason: "Backend returned unhealthy status after pin update",
            exception: PinVaultError.backendUnreachable(message: "Health check returned unhealthy after pin update")
        )
    }

    private func verificationFailed(_ error: any Error, _ previous: StoredConfig?, _ appliedConfig: CertificateConfig?) async throws -> InitResult {
        Self.log.e("Pinned connection verification failed", error)
        try await rollBackAfterFailedHealthCheck(previous, appliedConfig)
        return .failed(
            reason: "Pin verification failed: \(ErrorMessage.of(error) ?? "null")",
            exception: PinVaultError.backendUnreachable(cause: error)
        )
    }

    /// Undoes the config ``updateNow()`` just applied. The replay watermarks
    /// stay where the rejected config put them (the store never lowers them);
    /// the rejected config itself is remembered (`markRolledBack`) so exactly
    /// that one may be applied again. Without a previous config the active
    /// config is cleared (watermarks kept) and the session reset to fail-closed.
    private func rollBackAfterFailedHealthCheck(_ previous: StoredConfig?, _ appliedConfig: CertificateConfig?) async throws {
        await updateLock.lock()
        defer { updateLock.unlock() }
        // The health check ran outside the lock: a worker's or the pin
        // recovery's updateNow may have applied a newer config meanwhile.
        // That one was not what the check judged; it is not rolled back.
        if httpClientProvider.currentConfig != appliedConfig {
            Self.log.w("Health check failed, but a newer config was applied meanwhile — not rolling back")
            return
        }
        if let appliedConfig { try configStore.markRolledBack(appliedConfig) }
        if let previous {
            // With its envelope: the restored config must pass the same check
            // as any other stored config the next time it is read.
            try configStore.save(previous.config, envelope: previous.envelope)
            httpClientProvider.swap(previous.config)
            Self.log.w("Rolled back to previous config v\(previous.config.computedVersion()) after the post-update health check failed")
        } else {
            try configStore.clearActive(keepAsWatermarks: true)
            httpClientProvider.reset()
            Self.log.w("No previous config to roll back to — config store cleared, TLS refused until re-init")
        }
    }

    private func loadFromStore() throws -> StoredConfig? {
        let stored = try loadStored()
        if let stored {
            httpClientProvider.swap(stored.config)
            Self.log.d("Loaded stored config — version: \(stored.config.version)")
        } else {
            Self.log.d("No stored config — pinned client refuses TLS until the first config is applied")
        }
        return stored
    }

    private func updateWithRetry() async -> UpdateResult {
        var lastResult = UpdateResult.failed(reason: "No attempt made")
        for attempt in 1...max(maxRetryCount, 1) {
            Self.log.d("Update attempt \(attempt)/\(maxRetryCount)")
            lastResult = await updateNow()
            switch lastResult {
            case .updated, .alreadyCurrent:
                return lastResult
            case .failed:
                if attempt < maxRetryCount {
                    let delayMs = Self.retryBaseDelayMs * Int64(attempt)
                    Self.log.w("Attempt \(attempt) failed, retrying in \(delayMs)ms")
                    await sleep(delayMs)
                }
            }
        }
        return lastResult
    }

    // MARK: Updates

    /// Fetches the latest config, checks it and applies it.
    ///
    /// One fetch at a time, and concurrent callers share it: a caller that
    /// arrives while a fetch is running waits for that fetch and gets its
    /// result instead of starting another.
    func updateNow() async -> UpdateResult {
        let (flight, mine) = inFlight.withLock { slot -> (Task<UpdateResult, Never>, Bool) in
            if let running = slot { return (running, false) }
            let task = Task { [self] () -> UpdateResult in
                await updateLock.lock()
                let result = await fetchAndApply()
                updateLock.unlock()
                // Under the slot's lock: it was set before this line can run.
                inFlight.withLock { $0 = nil }
                return result
            }
            slot = task
            return (task, true)
        }
        if !mine { Self.log.d("Config update already running — waiting for its result") }
        return await flight.value
    }

    /// A fetched config and, for a signed block, the verified envelope it came in.
    private struct Fetched {
        let config: CertificateConfig
        let envelope: StoredEnvelope?
    }

    /// Asks the Config API for the latest config. A signed block asks for the
    /// envelope (``SignedConfigSource``) and verifies it here — signatures,
    /// `serverScope`, `issuedAt` / `expiresAt` — so the envelope can be stored
    /// with the config. An unsigned block gets a parsed config nothing vouches for.
    private func fetch(_ currentVersion: Int) async throws -> Fetched {
        // Pin scoping (V2): a block that declared wantPinsFor(...) asks the
        // server for exactly those hosts and identifies itself.
        let scoped = !wantPinsFor.isEmpty
        let deviceId = scoped ? deviceIdProvider() : nil
        if scoped {
            Self.log.d("Scoped config fetch — \(wantPinsFor.count) host(s) requested, deviceId present: \(deviceId != nil)")
        }

        guard let verifier else {
            let config = scoped
                ? try await configApi.fetchScopedConfig(currentVersion: currentVersion, hosts: wantPinsFor, deviceId: deviceId)
                : try await configApi.fetchConfig(currentVersion: currentVersion)
            return Fetched(config: config, envelope: nil)
        }

        guard let source = configApi as? any SignedConfigSource else {
            throw PinVaultError.illegalState(
                "This Config API block has signing keys, but its CertificateConfigApi cannot hand over signed " +
                    "envelopes (it does not implement SignedConfigSource) — refusing unverified configs."
            )
        }
        let signed = scoped
            ? try await source.fetchScopedSignedConfig(currentVersion: currentVersion, hosts: wantPinsFor, deviceId: deviceId)
            : try await source.fetchSignedConfig(currentVersion: currentVersion)

        // The key set riding along goes first: the config in the same response
        // may already be signed by a key that set introduces. A newer set also
        // ends what a revoked key left behind (syncKeySetEpoch) — whether or not
        // the config next to it then verifies.
        try verifier.applyKeySet(signed)
        try syncKeySetEpoch()
        try refuseBelowKeySetFloor(verifier)

        let verified = try verifier.verifyFetched(signed)
        return Fetched(config: verified.config, envelope: verified.envelope)
    }

    /// Brings the replay watermarks in line with the signing-key set in force:
    /// when the set is newer than the one the watermarks were last reset for,
    /// they are cleared, and the stored config is kept only if the new set
    /// still vouches for its signatures. Runs before and after a fetch, so a
    /// process that died between applying the set and resetting finishes the job.
    private func syncKeySetEpoch() throws {
        guard let verifier else { return }
        try syncTrustAnchors(verifier)
        let inForce = try verifier.keySetVersion()
        // The Keychain copy is compared with what is in force on every run, not
        // only when the store's own record moves (a lowering it missed is made now).
        defer { configStore.reconcileMirror(keySetVersion: inForce, anchors: verifier.anchorsFingerprint()) }
        guard let resetFor = try configStore.keySetVersionSeen() else {
            // First time this store meets key sets: nothing to compare with.
            try configStore.setKeySetVersionSeen(inForce)
            return
        }
        if inForce > resetFor {
            Self.log.w("Signing-key set v\(inForce) is newer than v\(resetFor) — replay watermarks reset")
            try configStore.resetWatermarks(keySetVersion: inForce, anchors: nil)
            _ = try loadStored()
        }
    }

    /// True when the signing-key set in force is older than the newest one this
    /// device applied, as its Keychain copy records it (a container put back
    /// from before a rotation would otherwise bring revoked keys back).
    private func keySetBelowFloor(_ verifier: SignedConfigVerifier) throws -> Bool {
        try verifier.keySetBelowFloor()
    }

    /// Refuses to verify a fetched config while the key set in force is below that floor.
    private func refuseBelowKeySetFloor(_ verifier: SignedConfigVerifier) throws {
        if try keySetBelowFloor(verifier) {
            throw PinVaultError.security(message: "The signing-key set in force (v\(try verifier.keySetVersion())) is older than " +
                "one this device applied (v\(configStore.mirroredKeySetVersion() ?? 0)); the answer did not bring a set at least as new")
        }
    }

    /// Resets the replay watermarks when the app itself now trusts other keys
    /// (an update that changed the compiled-in signing keys, their threshold or
    /// the recovery keys — ``SignatureTrust/anchorsFingerprint()``). The first
    /// time a store meets this check it only records the fingerprint.
    private func syncTrustAnchors(_ verifier: SignedConfigVerifier) throws {
        let anchors = verifier.anchorsFingerprint()
        switch try configStore.trustAnchorsSeen() {
        case anchors?:
            return
        case nil:
            try configStore.setTrustAnchorsSeen(anchors)
        default:
            Self.log.w("The app's compiled-in signing keys changed — replay watermarks reset")
            try configStore.resetWatermarks(keySetVersion: try configStore.keySetVersionSeen() ?? verifier.keySetVersion(), anchors: anchors)
            try configStore.setTrustAnchorsSeen(anchors)
            _ = try loadStored()
        }
    }

    /// A stored config that may be used, with its envelope when it has one.
    private struct StoredConfig {
        let config: CertificateConfig
        let envelope: StoredEnvelope?
    }

    /// The stored config, if it may be trusted. For a signed block the envelope
    /// stored next to it is verified again — on every read, against the keys
    /// trusted now — and the config used is the one INSIDE the envelope. A
    /// stored config without an envelope that verifies is discarded: the
    /// device is back to "no config" until the next fetch. Without a verifier
    /// what the store holds is used as it is.
    private func loadStored() throws -> StoredConfig? {
        guard let stored = try configStore.load() else { return nil }
        guard let verifier else { return StoredConfig(config: stored, envelope: nil) }
        if try keySetBelowFloor(verifier) {
            // The signing-key set on disk is older than one this device applied
            // before (an older container put back): nothing it vouches for is
            // used until a fetch brings a set at least as new.
            Self.log.e("Stored config not used — the signing-key set in force is older than one this device applied")
            return nil
        }

        let envelope = try configStore.loadEnvelope()
        let verified = try envelope.flatMap { try verifier.verifyStored($0) }
        guard let envelope, let verified else {
            let reason = envelope == nil ? "it has no signed envelope" : "its signed envelope does not verify"
            Self.log.e("Stored config v\(stored.version) discarded — \(reason)")
            // A config without an envelope was accepted once: its issuedAt and
            // versions stay as watermarks. One whose envelope fails (tampered, or
            // signed by a key revoked since) does not get to leave its values behind.
            try configStore.clearActive(keepAsWatermarks: envelope == nil)
            if httpClientProvider.currentConfig != nil { httpClientProvider.reset() }
            discardedStoredConfig.set("the stored config was discarded because \(reason)")
            return nil
        }
        var config = verified
        config.version = verified.computedVersion()
        return StoredConfig(config: config, envelope: envelope)
    }

    private func fetchAndApply() async -> UpdateResult {
        do {
            trustedClock?.checkpoint()
            let currentVersion = try configStore.getCurrentVersion()
            Self.log.d("Fetching config update — current version: \(currentVersion)")

            try syncKeySetEpoch()
            let fetched = try await fetch(currentVersion)
            return try await applyFetched(fetched, currentVersion)
        } catch is CancellationError {
            return .failed(reason: "Config update was cancelled", exception: CancellationError())
        } catch {
            Self.log.e("Config update failed", error)
            return .failed(reason: ErrorMessage.of(error) ?? "Unknown error", exception: error)
        }
    }

    /// Applies a signed config that arrived by another road than a fetch — the
    /// envelope inside an attestation answer (`ATTESTATION.md` §2.2, "config")
    /// — under exactly the checks a fetched one gets. Serialised with
    /// ``updateNow()`` by the same lock. Only for a signed block: an unsigned
    /// one has nothing to verify the envelope with, and the config is ignored.
    func applySigned(_ signed: SignedConfigResponse) async -> UpdateResult {
        guard let verifier else {
            return .failed(reason: "unsigned block: config inside an attestation response is ignored")
        }
        await updateLock.lock()
        defer { updateLock.unlock() }
        do {
            trustedClock?.checkpoint()
            let currentVersion = try configStore.getCurrentVersion()
            Self.log.d("Applying the config from an attestation answer — current version: \(currentVersion)")

            try syncKeySetEpoch()
            try verifier.applyKeySet(signed)
            try syncKeySetEpoch()
            try refuseBelowKeySetFloor(verifier)
            let verified = try verifier.verifyFetched(signed) { detail in
                "The config inside the attestation answer failed signature verification.\(detail)"
            }
            return try await applyFetched(Fetched(config: verified.config, envelope: verified.envelope), currentVersion)
        } catch is CancellationError {
            return .failed(reason: "Config update was cancelled", exception: CancellationError())
        } catch {
            Self.log.e("Config from an attestation answer not applied", error)
            return .failed(reason: ErrorMessage.of(error) ?? "Unknown error", exception: error)
        }
    }

    /// Everything that happens to a config once it is in hand and (for a
    /// signed block) its envelope has verified: shape, plausibility, the
    /// replay and downgrade guards, change detection, storing, swapping the
    /// session and syncing host client certificates. Throws on refusal.
    private func applyFetched(_ fetched: Fetched, _ currentVersion: Int) async throws -> UpdateResult {
        let remoteConfig = fetched.config

        // Shape (hosts, pins) before anything else looks at it; one bad entry
        // refuses the whole config, an empty pin set too.
        try PinConfigValidator.validate(remoteConfig)

        // Values that would lock the device out for good (O6): the replay
        // guards only ever move forward, so refuse absurd values up front.
        try checkPlausible(remoteConfig, signed: fetched.envelope != nil)

        // Replay & downgrade guards (M-08).
        let storedIssuedAt = try configStore.getCurrentIssuedAt()
        let stored = try loadStored()
        let storedConfig = stored?.config
        // Exactly the config a failed health check rolled back may be applied
        // again: it sits at the watermark, it is not a replay.
        let reapplyingRolledBack = try storedIssuedAt > 0 && remoteConfig.issuedAt == storedIssuedAt &&
            configStore.isRolledBack(remoteConfig)
        // So may a config AT the watermark while nothing is active (after
        // reset(), or after a stored config was discarded): it is the newest
        // config this device has seen, not an older one.
        let atWatermarkWithNothingActive = storedConfig == nil && remoteConfig.issuedAt == storedIssuedAt
        if storedIssuedAt > 0, remoteConfig.issuedAt <= storedIssuedAt, !reapplyingRolledBack, !atWatermarkWithNothingActive {
            // The SAME signed config served again is not a replay — backends that
            // sign once per change serve exactly that until the content changes.
            // Its force flag was honoured on first delivery and is not re-applied.
            if remoteConfig.issuedAt == storedIssuedAt, let storedConfig, storedConfig.issuedAt == storedIssuedAt,
               Self.samePins(storedConfig, remoteConfig) {
                // A config stored before expiresAt was kept carries an estimate; the envelope's own value replaces it.
                if remoteConfig.expiresAt != storedConfig.expiresAt {
                    var refreshed = storedConfig
                    refreshed.expiresAt = remoteConfig.expiresAt
                    try configStore.save(refreshed, envelope: fetched.envelope)
                    httpClientProvider.replaceConfigInPlace(refreshed)
                }
                Self.log.d("Config is already current — the same signed config was served again (issuedAt=\(storedIssuedAt))")
                return .alreadyCurrent
            }
            // An OLDER envelope of the config already applied (same pins and
            // flags): a proxy or cache serving an earlier copy of unchanged
            // content. Nothing is applied or written back — but no alarm either.
            if remoteConfig.issuedAt < storedIssuedAt, let storedConfig, Self.samePins(storedConfig, remoteConfig),
               remoteConfig.forceUpdate == storedConfig.forceUpdate, Self.forceFlags(remoteConfig) == Self.forceFlags(storedConfig) {
                Self.log.d("Config is already current — an older copy of it was served (issuedAt=\(remoteConfig.issuedAt) < \(storedIssuedAt))")
                return .alreadyCurrent
            }
            throw PinVaultError.security(message:
                "Config replay rejected: received issuedAt=\(remoteConfig.issuedAt) " +
                    "<= stored issuedAt=\(storedIssuedAt). Possible MITM or stale-payload replay."
            )
        }

        // Per-host versions are checked against the highest ever accepted,
        // which neither a rollback nor a config that dropped the host lowers.
        var versionWatermarks = try configStore.getVersionWatermarks()
        for pin in storedConfig?.pins ?? [] {
            let host = pin.hostname.lowercased()
            versionWatermarks[host] = max(versionWatermarks[host] ?? 0, pin.version)
        }
        for remotePin in remoteConfig.pins {
            guard let watermark = versionWatermarks[remotePin.hostname.lowercased()] else {
                // A host this device has never seen has nothing to jump from, so
                // its first version is capped instead.
                if Int64(remotePin.version) > Self.maxVersionJump {
                    throw PinVaultError.security(message:
                        "Per-host version rejected for \(remotePin.hostname): first version " +
                            "v\(remotePin.version) is above \(Self.maxVersionJump)."
                    )
                }
                continue
            }
            if remotePin.version < watermark {
                throw PinVaultError.security(message:
                    "Per-host version downgrade rejected for \(remotePin.hostname): " +
                        "remote v\(remotePin.version) < stored v\(watermark)."
                )
            }
            if Int64(remotePin.version) - Int64(watermark) > Self.maxVersionJump {
                throw PinVaultError.security(message:
                    "Per-host version jump rejected for \(remotePin.hostname): " +
                        "remote v\(remotePin.version) is more than \(Self.maxVersionJump) above stored v\(watermark)."
                )
            }
        }

        // Change detection over the whole shape — hosts, versions, pin hashes,
        // the mTLS flags — not the versions alone.
        let hasPinChanges = storedConfig.map { !Self.samePins($0, remoteConfig) } ?? true
        // A raised force flag (global or on any single host) means "re-apply now, even at the same version".
        let remoteForcesUpdate = remoteConfig.forceUpdate || remoteConfig.pins.contains { $0.forceUpdate }

        if !(hasPinChanges || remoteForcesUpdate) {
            // Not an update. But the force flag may have gone the OTHER way —
            // true on disk, false on the wire — and that transition still has to
            // reach the device (start reads the STORED flag and refuses to come
            // up offline while it is set). Likewise freshness: a newer envelope
            // with the same pins moves issuedAt and expiresAt forward.
            if let writeBack = Self.writeBack(storedConfig, remoteConfig) {
                try configStore.save(writeBack, envelope: fetched.envelope)
                acceptedAsNewest(remoteConfig, previousIssuedAt: storedIssuedAt)
                httpClientProvider.replaceConfigInPlace(writeBack)
                Self.log.d(
                    "Config is already current — flags/freshness written back (issuedAt=\(writeBack.issuedAt), " +
                        "expiresAt=\(writeBack.expiresAt), force=\(writeBack.forceUpdate))"
                )
            } else {
                Self.log.d("Config is already current — nothing changed")
            }
            return .alreadyCurrent
        }

        try configStore.save(remoteConfig, envelope: fetched.envelope)
        acceptedAsNewest(remoteConfig, previousIssuedAt: storedIssuedAt)
        httpClientProvider.swap(remoteConfig)

        // Sync host-specific client certs for mTLS hosts.
        await syncHostClientCerts(remoteConfig, storedConfig)

        let newVersion = remoteConfig.computedVersion()
        Self.log.d("Config updated: \(currentVersion) → \(newVersion) (\(remoteConfig.pins.count) hosts pinned)")
        return .updated(newVersion: newVersion)
    }

    /// A config newer than every config accepted before has just been stored:
    /// the one case in which the trusted clock may be moved back.
    private func acceptedAsNewest(_ config: CertificateConfig, previousIssuedAt: Int64) {
        if config.issuedAt > 0, config.issuedAt > previousIssuedAt { trustedClock?.resetTo(issuedAt: config.issuedAt) }
    }

    /// True when both configs pin the same hosts with the same per-host
    /// versions, hash sets, mTLS settings and managed trust roots. Force flags
    /// are left out on purpose.
    static func samePins(_ stored: CertificateConfig, _ remote: CertificateConfig) -> Bool {
        struct Shape: Hashable {
            let version: Int
            let sha256: Set<String>
            let mtls: Bool
            let clientCertVersion: Int?
        }
        func shape(_ config: CertificateConfig) -> [String: Shape] {
            var out: [String: Shape] = [:]
            for pin in config.pins {
                out[pin.hostname.lowercased()] = Shape(
                    version: pin.version, sha256: Set(pin.sha256), mtls: pin.mtls, clientCertVersion: pin.clientCertVersion
                )
            }
            return out
        }
        return shape(stored) == shape(remote) && Set(stored.trustRoots) == Set(remote.trustRoots)
    }

    static func forceFlags(_ config: CertificateConfig) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for pin in config.pins { out[pin.hostname.lowercased()] = pin.forceUpdate }
        return out
    }

    /// `storedConfig` with its force-update flags and its freshness (`issuedAt`,
    /// `expiresAt`) brought in line with `remoteConfig`, or nil when they
    /// already agree (or nothing is stored). Pins and versions are carried over
    /// from the stored config untouched: a write-back, not an update.
    static func writeBack(_ storedConfig: CertificateConfig?, _ remoteConfig: CertificateConfig) -> CertificateConfig? {
        guard let storedConfig else { return nil }
        let remoteForceByHost = forceFlags(remoteConfig)
        let globalDiffers = storedConfig.forceUpdate != remoteConfig.forceUpdate
        let perHostDiffers = storedConfig.pins.contains { $0.forceUpdate != (remoteForceByHost[$0.hostname.lowercased()] ?? false) }
        let fresher = remoteConfig.issuedAt >= storedConfig.issuedAt &&
            (remoteConfig.issuedAt != storedConfig.issuedAt || remoteConfig.expiresAt != storedConfig.expiresAt)
        if !globalDiffers, !perHostDiffers, !fresher { return nil }

        var written = storedConfig
        written.forceUpdate = remoteConfig.forceUpdate
        written.pins = storedConfig.pins.map { pin in
            var copy = pin
            copy.forceUpdate = remoteForceByHost[pin.hostname.lowercased()] ?? false
            return copy
        }
        if fresher {
            written.issuedAt = remoteConfig.issuedAt
            written.expiresAt = remoteConfig.expiresAt
        }
        return written
    }

    /// Refuses configs whose freshness or versions would lock the device out:
    /// an `issuedAt` more than an hour ahead of this device's clock, a validity
    /// window longer than 30 days, an `expiresAt` more than that (plus the
    /// skew) from now, or one that has already passed (by the trusted clock).
    /// A signed config must carry both fields.
    private func checkPlausible(_ config: CertificateConfig, signed: Bool) throws {
        let now = clock()
        if signed, config.issuedAt <= 0 || config.expiresAt <= 0 {
            throw PinVaultError.security(message:
                "Config rejected: a signed config must carry issuedAt and expiresAt " +
                    "(issuedAt=\(config.issuedAt), expiresAt=\(config.expiresAt))."
            )
        }
        if config.issuedAt > now + Self.maxClockSkewMs {
            throw PinVaultError.security(message:
                "Config rejected: issuedAt=\(config.issuedAt) is \((config.issuedAt - now) / 1000)s ahead of this " +
                    "device's clock (now=\(now)); more than \(Self.maxClockSkewMs / 60_000) minutes ahead is refused."
            )
        }
        // "Already expired" by the trusted clock where there is one, except for
        // a config newer than all before (SignedConfigVerifier.expiryNow).
        let trusted = trustedClock
        let expiryNow = try SignedConfigVerifier.expiryNow(
            config: config,
            wall: clock,
            trustedNow: trusted.map { clock in { clock.now() } },
            issuedAtWatermark: { try configStore.getCurrentIssuedAt() }
        )
        if config.expiresAt > 0, config.expiresAt <= expiryNow {
            throw PinVaultError.security(message:
                "Config rejected: already expired (expiresAt=\(config.expiresAt), now=\(expiryNow)); the stored config is kept."
            )
        }
        if config.issuedAt > 0, config.expiresAt > 0, config.expiresAt - config.issuedAt > Self.maxValidityMs {
            throw PinVaultError.security(message:
                "Config rejected: valid for \((config.expiresAt - config.issuedAt) / 3_600_000)h " +
                    "(issuedAt=\(config.issuedAt), expiresAt=\(config.expiresAt)); more than " +
                    "\(Self.maxValidityMs / 86_400_000) days is refused."
            )
        }
        if config.expiresAt > now + Self.maxValidityMs + Self.maxClockSkewMs {
            throw PinVaultError.security(message:
                "Config rejected: expiresAt=\(config.expiresAt) is \((config.expiresAt - now) / 3_600_000)h from now; " +
                    "more than \(Self.maxValidityMs / 86_400_000) days is refused."
            )
        }
    }

    // MARK: Host client certificates

    /// Downloads and stores host-specific client certs for mTLS hosts; only
    /// when `clientCertVersion` changed or nothing is stored yet.
    private func syncHostClientCerts(_ remoteConfig: CertificateConfig, _ storedConfig: CertificateConfig?) async {
        guard let sslManager, let certStore else { return }
        let mtlsHosts = remoteConfig.pins.filter { $0.mtls && $0.clientCertVersion != nil }
        if mtlsHosts.isEmpty { return }

        var storedCertVersions: [String: Int] = [:]
        for pin in storedConfig?.pins ?? [] where pin.mtls {
            if let version = pin.clientCertVersion { storedCertVersions[pin.hostname] = version }
        }

        var hostCerts: [String: Data] = [:]
        var hostKeys: [String: ClientIdentity] = [:]

        // What is stored for a host: its key in the Keychain (a P12 stored
        // earlier is moved there now), else its P12.
        func loadStored(_ hostname: String, _ label: String) {
            if let imported = certStore.loadImportedIdentity(label, password: clientKeyPassword) {
                hostKeys[hostname] = imported
            } else if let p12 = certStore.load(label) {
                hostCerts[hostname] = p12
            }
        }

        for pin in mtlsHosts {
            let label = "host_\(pin.hostname)"
            let storedVersion = storedCertVersions[pin.hostname]
            let needsDownload = storedVersion != pin.clientCertVersion || !certStore.exists(label)
            guard needsDownload else {
                // Already up to date — load from the store.
                loadStored(pin.hostname, label)
                continue
            }
            do {
                let p12 = try await configApi.downloadHostClientCert(hostname: pin.hostname)
                // The key goes into the Keychain; the P12 is stored only where the platform refuses that.
                var imported: ClientIdentity?
                do {
                    imported = try certStore.importIdentity(label, p12: p12, password: clientKeyPassword)
                } catch {
                    Self.log.w("Host client cert for \(pin.hostname) could not be read for import", error)
                }
                if let imported {
                    hostKeys[pin.hostname] = imported
                } else {
                    certStore.save(label, p12)
                    certStore.deleteImportedKey(label)
                    hostCerts[pin.hostname] = p12
                }
                Self.log.d(
                    "Host client cert downloaded: \(pin.hostname) (v\(storedVersion.map(String.init) ?? "null") → " +
                        "v\(pin.clientCertVersion.map(String.init) ?? "null"), key in Keystore: \(imported != nil))"
                )
            } catch {
                // 403 = the device is not enrolled: expected, logged quietly.
                if (error as? HttpException)?.code == 403 {
                    Self.log.d("Host client cert unavailable for \(pin.hostname) (not enrolled / HTTP 403)")
                } else {
                    Self.log.w("Failed to download client cert for \(pin.hostname)", error)
                }
                // Try loading from the store as a fallback.
                loadStored(pin.hostname, label)
            }
        }

        if !hostCerts.isEmpty || !hostKeys.isEmpty {
            sslManager.loadHostClientIdentities(hostKeys, hostCerts: hostCerts, password: clientKeyPassword)
            // Re-swap so every session rebuilds with the new identities.
            if let current = httpClientProvider.currentConfig { httpClientProvider.swap(current) }
            Self.log.d("Host client certs synced: \(hostCerts.count + hostKeys.count) hosts (\(hostKeys.count) with the key in the Keystore)")
        }
    }
}
