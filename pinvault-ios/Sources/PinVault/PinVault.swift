import Foundation
import Security
#if canImport(BackgroundTasks) && os(iOS)
import BackgroundTasks
#endif

/// The entry point of the dynamic certificate pinning library.
///
/// ```swift
/// let config = try PinVaultConfig.Builder()
///     .configApi("api", url: "https://api.example.com/") { block in
///         block.bootstrapPins([HostPin(hostname: "api.example.com", sha256: [hash1, hash2])])
///         block.signaturePublicKey(signingKey)
///     }
///     .build()
///
/// switch await PinVault.shared.start(config: config) {
/// case .ready: let (data, _) = try await PinVault.shared.session().data(from: url)
/// case .failed(let reason, _): print(reason)   // do NOT send pinned traffic
/// }
/// ```
///
/// Kotlin → Swift: `init(context, config)` is ``start(config:)``, `getClient()`
/// is ``session()``, `applyTo(OkHttpClient.Builder)` is ``applyTo(_:)``,
/// suspend functions are `async`, callback overloads and `Context` parameters
/// are gone. Synchronous getters answer from memory; before `start` they
/// return empty values (nil / 0 / false / empty) where Kotlin throws
/// `IllegalStateException`.
public final class PinVault: @unchecked Sendable {

    /// The shared instance (Kotlin `object PinVault`).
    public static let shared = PinVault()

    /// `BGTaskScheduler` identifier of the periodic update; list it under
    /// `BGTaskSchedulerPermittedIdentifiers` in the app's Info.plist.
    public static let backgroundTaskIdentifier = "io.github.umutcansu.pinvault.refresh"

    /// The request header the attestation token travels in.
    static let attestationHeader = "PinVault-Token"

    /// Called with the outcome of every periodic / on-demand config update, on the main actor.
    public typealias OnUpdateListener = @MainActor @Sendable (UpdateResult) -> Void

    /// Called with the outcome of every vault file sync (`syncAllFiles`, the
    /// periodic sync, a stored copy removed by its checks), on the main actor.
    public typealias OnFileUpdateListener = @MainActor @Sendable (_ key: String, _ result: VaultFileResult) -> Void

    /// The default block's parts (Kotlin's "primary mirrors"); in static-pin
    /// mode a stand-alone set over the embedded pins.
    struct Primary: @unchecked Sendable {
        let sslManager: DynamicSSLManager
        let clientProvider: HttpClientProvider
        let updater: SSLCertificateUpdater
        let configStore: CertificateConfigStore
        let api: any CertificateConfigApi
    }

    struct State {
        var config: PinVaultConfig?
        var initialized = false
        /// Per-Config-API clients, by block id; ``clientOrder`` keeps the config's order.
        var clients: [String: ConfigApiClient] = [:]
        var clientOrder: [String] = []
        var primary: Primary?
        var updateListener: OnUpdateListener?
        var fileUpdateListener: OnFileUpdateListener?
        var backgroundTaskRegistered = false
    }

    struct E2EState {
        var clockOffsetSeconds: Int64 = 0
        var redirects: [String: String] = [:]
        /// Bumped on every change, so sessions can tell they must be rebuilt.
        var generation = 0
        var scheduledTasksObserver: (@Sendable () -> Void)?
    }

    let state = Locked(State())
    let e2e = Locked(E2EState())
    let log = PinVaultLog.tag("PinVault")

    /// Where the encrypted stores live; tests use a directory and keys of their own.
    var storeEnvironment: SecureStoreEnvironment {
        get { storeEnvironmentBox.get() }
        set { storeEnvironmentBox.set(newValue) }
    }
    private let storeEnvironmentBox = Locked(SecureStoreEnvironment.shared)

    /// What the later layers plug into each block (``ConfigApiClient/Collaborators``):
    /// enrollment and host certificates (L3), attestation (L5). The integration
    /// step sets this; tests swap in their own.
    var collaboratorsFactory: @Sendable (_ block: ConfigApiBlock, _ vault: PinVault) -> ConfigApiClient.Collaborators {
        get { collaboratorsBox.get() }
        set { collaboratorsBox.set(newValue) }
    }
    private let collaboratorsBox = Locked<@Sendable (ConfigApiBlock, PinVault) -> ConfigApiClient.Collaborators>(
        PinVault.defaultCollaborators
    )

    /// The updater's wait between start attempts (2 s, 4 s); tests make it instant.
    var retrySleep: (@Sendable (_ milliseconds: Int64) async -> Void)? {
        get { retrySleepBox.get() }
        set { retrySleepBox.set(newValue) }
    }
    private let retrySleepBox = Locked<(@Sendable (Int64) async -> Void)?>(nil)

    private let schedulerBox = Locked<PeriodicUpdateScheduler?>(nil)

    init() {}

    static let notInitializedMessage = "PinVault not initialized. Call PinVault.start() first."

    var isInitialized: Bool { state.withLock { $0.initialized } }
    var config: PinVaultConfig? { state.withLock { $0.config } }

    /// The default block's parts while started.
    var primary: Primary? { state.withLock { $0.initialized ? $0.primary : nil } }

    /// The per-block clients in the config's order (empty before start and in static-pin mode).
    var configApiClients: [ConfigApiClient] {
        state.withLock { state in state.clientOrder.compactMap { state.clients[$0] } }
    }

    func configApiClient(_ id: String) -> ConfigApiClient? {
        state.withLock { $0.clients[id] }
    }

    /// The active config of the default block (or the static pins); nil before start.
    var currentConfig: CertificateConfig? { primary?.clientProvider.currentConfig }

    /// The text of a failure result for work a later layer of the port implements.
    static func unavailable(_ what: String, _ layer: String) -> String {
        "PinVault for iOS: \(what) is not available yet (\(layer))"
    }

    // MARK: Listeners

    /// Listener for background pin update events (`setOnUpdateListener`); nil detaches.
    public func setOnUpdateListener(_ listener: OnUpdateListener?) {
        state.withLock { $0.updateListener = listener }
    }

    /// Attach (or with nil detach) a connection listener at runtime, replacing
    /// the one from `onConnectionEvent(...)`, on every block's SSL manager.
    /// Events fired before this call (the bootstrap handshake) are not
    /// delivered. Needs ``start(config:)``.
    public func setConnectionListener(_ listener: PinVaultConnectionListener?) {
        guard isInitialized else {
            log.w(Self.notInitializedMessage)
            return
        }
        for manager in sslManagers() { manager.setConnectionListener(listener) }
    }

    /// Listener for vault file sync results; nil detaches.
    public func setOnFileUpdateListener(_ listener: OnFileUpdateListener?) {
        state.withLock { $0.fileUpdateListener = listener }
    }

    // MARK: Start

    /// Starts the library with `config` (Kotlin `init(context, config)`):
    /// loads the stored config, fetches a fresh one from every Config API,
    /// renews client certificates, attests, registers vault keys. Returns
    /// ``InitResult/ready(version:)`` when pinned traffic may flow.
    public func start(config: PinVaultConfig) async -> InitResult {
        await start(config: config, customApi: nil)
    }

    /// ``start(config:)`` with a custom ``CertificateConfigApi`` for the
    /// default (first) block. A block with signing keys needs the API to adopt
    /// ``SignedConfigSource`` too, or start fails unless the block called `allowUnsigned()`.
    public func start(config: PinVaultConfig, configApi: any CertificateConfigApi) async -> InitResult {
        await start(config: config, customApi: configApi)
    }

    private func start(config: PinVaultConfig, customApi: (any CertificateConfigApi)?) async -> InitResult {
        if let refusal = environmentRefusal(config, .start) {
            return .failed(reason: refusal.message, exception: refusal)
        }
        await DeviceIdentity.warmUp()
        if !isInitialized, let staticConfig = config.staticPins {
            // Compiled-in pins are held to the same rules as fetched ones:
            // host names that are host names, pins that are SHA-256 hashes.
            do {
                try PinConfigValidator.validate(staticConfig)
            } catch {
                let message = (error as? PinVaultError)?.message ?? "\(error)"
                log.e("Static pins refused: \(message)")
                return .failed(reason: "Static pins are not valid: \(message)", exception: error)
            }
        }
        state.withLock { $0.config = config }
        switch setupSafely(config, customApi) {
        case .failed(let result):
            return result
        case .alreadyInitialized:
            return .ready(version: primary?.clientProvider.getVersion() ?? 0)
        case .done:
            return await executeInitSafely()
        }
    }

    private enum SetUp {
        case done
        case alreadyInitialized
        case failed(InitResult)
    }

    /// ``setup(_:_:)``, with a failure of the encrypted storage reported as
    /// ``InitResult/failed(reason:exception:)`` instead of thrown: a Keychain
    /// that cannot be used right now — a hiccup, or a locked device under
    /// `requireUnlockedDevice()` — is no reason to crash the app. Nothing is
    /// started then; call `start` again.
    private func setupSafely(_ config: PinVaultConfig, _ customApi: (any CertificateConfigApi)?) -> SetUp {
        do {
            return try setup(config, customApi) ? .done : .alreadyInitialized
        } catch {
            log.e("PinVault setup failed", error)
            state.withLock { $0.initialized = false }
            let name = (error as? PinVaultError)?.exceptionName ?? String(describing: type(of: error))
            let reason = config.requireUnlockedDevice && Self.isLockedDeviceError(error)
                ? "PinVault's storage is locked while the device is locked (requireUnlockedDevice): init again once it is unlocked"
                : "PinVault could not be set up (\(name): \(ErrorMessage.of(error) ?? "null")); nothing was initialized"
            return .failed(.failed(reason: reason, exception: error))
        }
    }

    /// Builds every block's ``ConfigApiClient`` (or, in static-pin mode, a
    /// stand-alone pinning stack). Returns false when already started.
    private func setup(_ config: PinVaultConfig, _ customApi: (any CertificateConfigApi)?) throws -> Bool {
        if isInitialized {
            log.w("PinVault already initialized — skipping")
            return false
        }
        let environment = storeEnvironment
        // Store files written and Keychain keys made from now on follow the config.
        environment.requireUnlockedDevice = config.requireUnlockedDevice

        var clients: [String: ConfigApiClient] = [:]
        let defaultId = config.defaultConfigApi?.id
        let factory = collaboratorsFactory
        let sleep = retrySleep
        for block in config.orderedConfigApis {
            // The custom API serves the default block only; a multi-API backend
            // implements CertificateConfigApi per block itself.
            clients[block.id] = try ConfigApiClient(
                block: block,
                customApi: block.id == defaultId ? customApi : nil,
                recoveryListener: { [weak self] result in
                    guard let self else { return }
                    Task { await self.notifyUpdateResult(result) }
                },
                expiredConfigGraceMs: config.expiredConfigGraceMs,
                caTrustHosts: config.caTrustHosts,
                managedTrustRoots: config.managedTrustRoots,
                resolvedHosts: config.resolvedHosts,
                collaborators: factory(block, self),
                storeEnvironment: environment,
                sleep: sleep
            )
        }

        // The app's listener on every block's SSL manager, so handshake events
        // of every block reach the same callback.
        if let listener = config.connectionListener {
            clients.values.forEach { $0.sslManager.setConnectionListener(listener) }
        }

        let primary: Primary
        if let defaultId, let client = clients[defaultId] {
            primary = Primary(
                sslManager: client.sslManager, clientProvider: client.clientProvider, updater: client.updater,
                configStore: client.configStore, api: client.api
            )
        } else {
            // Static-pin mode: a stand-alone stack that start fills with the embedded config.
            let manager = DynamicSSLManager(connectionListener: config.connectionListener)
            manager.requireCaTrust(config.caTrustHosts)
            manager.managedTrustRootsEnabled = config.managedTrustRoots
            manager.resolvedHosts = config.resolvedHosts
            let provider = HttpClientProvider(sslManager: manager)
            let store = try CertificateConfigStore.open(environment: environment)
            let api = StaticPinsApi(pins: config.staticPins ?? CertificateConfig(pins: []))
            primary = Primary(
                sslManager: manager,
                clientProvider: provider,
                updater: SSLCertificateUpdater(
                    configApi: api, configStore: store, httpClientProvider: provider, sslManager: manager,
                    clientKeyPassword: "", maxRetryCount: config.maxRetryCount,
                    sleep: sleep ?? { try? await Task.sleep(nanoseconds: UInt64($0) * 1_000_000) }
                ),
                configStore: store,
                api: api
            )
        }

        // TODO(L4): vault file storage providers, device / user-auth keys, the vault guard and router.

        return state.withLock { state -> Bool in
            if state.initialized { return false }
            state.clients = clients
            state.clientOrder = config.orderedConfigApis.map(\.id)
            state.primary = primary
            state.initialized = true
            return true
        }
    }

    /// ``executeInit()`` behind a safety net: an unexpected failure becomes
    /// ``InitResult/failed(reason:exception:)`` (pinning stays fail-closed).
    private func executeInitSafely() async -> InitResult {
        do {
            return try await executeInit()
        } catch {
            log.e("PinVault init failed unexpectedly", error)
            state.withLock { $0.initialized = false }
            return .failed(reason: ErrorMessage.of(error) ?? String(describing: type(of: error)), exception: error)
        }
    }

    private func executeInit() async throws -> InitResult {
        guard let config else { return .failed(reason: Self.notInitializedMessage) }

        // Static pin mode — no server contact.
        if let staticConfig = config.staticPins, let primary {
            log.d("Static pin mode — using embedded config (v\(staticConfig.computedVersion()), \(staticConfig.pins.count) hosts)")
            primary.clientProvider.swap(staticConfig)
            try primary.configStore.save(staticConfig, envelope: nil)
            return .ready(version: staticConfig.computedVersion())
        }

        // Every Config API starts; the default block's result is returned,
        // the others' failures are logged.
        let defaultId = config.defaultConfigApi?.id
        let clients = configApiClients

        // A device whose enrollment waited for approval asks again first: once
        // let in, its certificate is what reaches an mTLS Config API below.
        await pickUpPendingEnrollments()

        // Keep CSR-enrolled client certificates alive BEFORE the first config
        // fetch: an expired certificate would make that fetch fail on an mTLS
        // Config API. The outcome never changes the start result.
        for client in clients {
            emitRenewalEvent(client.block.id, await client.renewIfNeeded())
        }

        var results: [String: InitResult] = [:]
        for client in clients {
            do {
                results[client.block.id] = try await client.initializeAndUpdate()
            } catch {
                log.e("ConfigApi[\(client.block.id)] init failed", error)
                results[client.block.id] = .failed(reason: ErrorMessage.of(error) ?? "init failed", exception: error)
            }
        }

        // Attesting blocks attest once, now that the stored config is loaded,
        // and keep re-attesting in the background. Never fails start.
        for client in clients {
            guard let attestation = client.attestation else { continue }
            let status = await attestation.attestNow()
            log.d("ConfigApi[\(client.block.id)] attestation at init: \(status.result.rawValue)")
            attestation.start()
        }

        // TODO(L4): register the device public key (end_to_end files) and the
        // user-auth key on every Config API that serves such files.

        // Files past their offline lifetime go now (wipeWhenStale).
        await wipeStaleVaultFiles()

        guard let defaultResult = defaultId.flatMap({ results[$0] }) ?? clients.first.flatMap({ results[$0.block.id] }) else {
            return .failed(reason: "No Config APIs configured")
        }
        if case .failed = defaultResult { state.withLock { $0.initialized = false } }
        return defaultResult
    }

    /// True when `error` (or a cause of it) is the Keychain's "the device is
    /// locked" (`errSecInteractionNotAllowed`) or a file the data protection
    /// keeps closed: what `requireUnlockedDevice` stores answer while locked.
    static func isLockedDeviceError(_ error: any Error) -> Bool {
        var next: (any Error)? = error
        var depth = 0
        while let current = next, depth < 8 {
            let ns = current as NSError
            if ns.domain == NSOSStatusErrorDomain, ns.code == Int(errSecInteractionNotAllowed) { return true }
            if ns.domain == NSCocoaErrorDomain, ns.code == NSFileReadNoPermissionError { return true }
            next = (current as? PinVaultError)?.cause ?? ns.userInfo[NSUnderlyingErrorKey] as? any Error
            depth += 1
        }
        return false
    }

    /// Where this device's mTLS identity key lives (Secure Enclave, software),
    /// or nil when no identity key exists yet. Local, no network.
    public func identityKeySecurityLevel(label: String? = nil) -> KeySecurityLevel? {
        // TODO(L3): identityKeyFactory(label ?? defaultCertLabel()) → securityLevel() when the key exists.
        _ = label
        return nil
    }

    /// Diagnostic logging: PinVault's debug and info lines are written at
    /// `.notice`, so `log show` keeps them. Call early, debug / E2E builds only.
    public static func enableDebugLogging() {
        PinVaultLog.enableDebugLogging()
    }

    /// ``enableDebugLogging()-swift.type.method`` on the shared instance.
    public func enableDebugLogging() {
        Self.enableDebugLogging()
    }

    // MARK: Sessions

    /// A pinned session over `configuration` (your timeouts, headers, cache
    /// policy): pinning, the attestation token and pin-mismatch recovery, like
    /// ``session()``. The pins are re-read on every handshake and the session
    /// is rebuilt when they change. Fail-closed until a config is applied.
    public func applyTo(_ configuration: URLSessionConfiguration) -> PinnedSession {
        guard let primary else { return unavailableSession() }
        let provider = primary.clientProvider
        if provider.currentConfig == nil {
            // Started, but no config has reached the provider yet: the dynamic
            // trust check refuses the first handshake (fail-closed) until one does.
            log.w(
                "PinVault.applyTo called before initial config arrived — " +
                    "TLS handshakes will refuse to connect until init completes."
            )
        }
        // The token goes on before (outside) the recovery interceptor, so a
        // request the recovery retries still carries it.
        var interceptors: [any PinnedInterceptor] = []
        if let token = attestationTokenInterceptor() { interceptors.append(token) }
        interceptors.append(provider.recoveryInterceptor)
        return primary.sslManager.applyTo(configuration, configProvider: { provider.currentConfig }, interceptors: interceptors)
    }

    /// The ready-to-use pinned session (`getClient()`): pinning, attestation
    /// token, re-attest on 401, pin-mismatch recovery. Fail-closed: before a
    /// config is applied every request fails. Wait for ``InitResult/ready(version:)``.
    public func session() -> PinnedSession {
        guard let primary else { return unavailableSession() }
        return primary.clientProvider.get()
    }

    /// A pinned session with custom `settings` (`getClient(HttpConnectionSettings)`):
    /// pinning and the attestation token, but NO pin-mismatch recovery — a
    /// mismatch reaches the caller until the next config update.
    public func session(settings: HttpConnectionSettings) -> PinnedSession {
        guard let primary else { return unavailableSession() }
        let provider = primary.clientProvider
        return primary.sslManager.buildDynamicClient(
            configProvider: { provider.currentConfig },
            settings: settings,
            extraInterceptors: [attestationTokenInterceptor()].compactMap { $0 }
        )
    }

    private func unavailableSession() -> PinnedSession {
        log.w(Self.notInitializedMessage)
        return PinnedSession(transport: UnavailableTransport(reason: Self.notInitializedMessage))
    }

    /// The interceptor that adds `PinVault-Token` for the token hosts of every
    /// attesting block (the default block's first), or nil when no block
    /// attests. For sessions the app owns (``applyTo(_:)``, ``session(settings:)``);
    /// each block's own sessions carry their block's interceptor.
    private func attestationTokenInterceptor() -> AttestationTokenInterceptor? {
        guard configApiClients.contains(where: { $0.attestation != nil }) else { return nil }
        return AttestationTokenInterceptor(sources: { [weak self] in
            self?.configApiClients.compactMap { $0.attestation } ?? []
        })
    }

    // MARK: Attestation (ATTESTATION.md)

    /// Attests the device with a block's server now and returns the new
    /// status (single flight per block). Never throws for a server answer.
    /// - Parameter configApiId: the block; nil = the default block.
    /// - Returns: `UNSUPPORTED` for a block without `attestation()`, a custom
    ///   API or an unknown id; `FAILED` before start.
    public func attestNow(configApiId: String? = nil) async -> AttestationStatus {
        let id = configApiId ?? config?.defaultConfigApi?.id ?? ""
        guard isInitialized else {
            return AttestationStatus(configApiId: id, result: .failed, lastError: "PinVault not initialized")
        }
        guard let attestation = configApiClient(id)?.attestation else { return notAttesting(id) }
        return await attestation.attestNow()
    }

    /// The `PinVault-Token` for requests sent through a client of the app's
    /// own (``session()`` / ``applyTo(_:)`` add it themselves): the token of the
    /// block whose token hosts cover `host`, attesting first when none with
    /// enough life is held.
    /// - Parameter host: a host name (optionally `host:port`); nil = the default block.
    public func fetchAttestationToken(host: String? = nil) async -> AttestationTokenResult {
        guard isInitialized else { return .failed(message: "PinVault not initialized") }
        let attestation: (any BlockAttestation)?
        if let host {
            let parts = host.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let name = parts[0].trimmingCharacters(in: .whitespaces)
            let port = parts.count > 1 ? Int(parts[1]) ?? -1 : -1
            attestation = configApiClients.compactMap(\.attestation).first { $0.handlesHost(name, port: port) }
        } else {
            attestation = config?.defaultConfigApi.flatMap { configApiClient($0.id)?.attestation }
        }
        guard let attestation else { return .unsupported }
        return await attestation.fetchToken()
    }

    /// The last attestation outcome of a block, from memory. `NOT_ATTESTED`
    /// before the first round, `UNSUPPORTED` for a block that does not attest
    /// or an unknown id; `FAILED` with "PinVault not initialized" before start.
    public func attestationStatus(configApiId: String? = nil) -> AttestationStatus {
        let id = configApiId ?? config?.defaultConfigApi?.id ?? ""
        guard isInitialized else {
            return AttestationStatus(configApiId: id, result: .failed, lastError: "PinVault not initialized")
        }
        return configApiClient(id)?.attestation?.status ?? notAttesting(id)
    }

    /// The request header the attestation token travels in: `PinVault-Token`.
    public func attestationHeaderName() -> String {
        Self.attestationHeader
    }

    func notAttesting(_ configApiId: String) -> AttestationStatus {
        let known = config?.configApis[configApiId] != nil
        return AttestationStatus(
            configApiId: configApiId,
            result: .unsupported,
            lastError: known
                ? "Config API '\(configApiId)' does not attest: call attestation() on the block"
                : "No Config API block '\(configApiId)'"
        )
    }

    /// Every attesting block attests, for the periodic job. Never throws.
    func attestAll() async {
        guard isInitialized else { return }
        for client in configApiClients {
            guard let attestation = client.attestation else { continue }
            _ = await attestation.attestNow()
            // A process the job woke runs no start: the loop starts here.
            attestation.start()
        }
    }

    // MARK: Updates

    /// Fetches the latest config from the backend, persists it and updates pinning.
    public func updateNow() async -> UpdateResult {
        guard let primary else {
            return .failed(reason: Self.notInitializedMessage, exception: PinVaultError.illegalState(Self.notInitializedMessage))
        }
        if let id = config?.defaultConfigApi?.id, let client = configApiClient(id) {
            return await client.updateNow()
        }
        return await primary.updater.updateNow()
    }

    /// Config fetch for every block but the default one (the periodic job
    /// updates that through ``updateNow()``), so their configs do not run past
    /// `expiresAt` in a long-lived process. Never throws.
    func updateOtherConfigApis() async {
        guard isInitialized else { return }
        let defaultId = config?.defaultConfigApi?.id
        for client in configApiClients where client.block.id != defaultId {
            _ = await client.updateNow()
        }
    }

    /// Schedules the periodic update (`BGTaskScheduler`, or the in-process
    /// scheduler where `submit` is unavailable, e.g. the simulator). A new
    /// schedule replaces the previous one and runs the update once right away.
    /// `updateIntervalMinutes` of the config wins over hours when set.
    /// - Parameter intervalHours: nil = the config's `updateIntervalHours`.
    /// - Returns: whether the task was scheduled.
    @discardableResult
    public func schedulePeriodicUpdates(intervalHours: Int64? = nil) -> Bool {
        guard isInitialized, let config else {
            log.w(Self.notInitializedMessage)
            return false
        }
        let minutes = config.updateIntervalMinutes ?? (intervalHours ?? config.updateIntervalHours) * 60
        return scheduler.schedule(intervalMinutes: minutes)
    }

    /// Cancels the periodic update.
    public func cancelPeriodicUpdates() {
        guard isInitialized else {
            log.w(Self.notInitializedMessage)
            return
        }
        scheduler.cancel()
    }

    /// The scheduled pin update tasks (`getScheduledWorkInfo`): ENQUEUED
    /// between runs, RUNNING during one, CANCELLED once cancelled or replaced.
    public func scheduledTasks() async -> [ScheduledTaskInfo] {
        scheduler.tasks()
    }

    /// The periodic update's scheduler (created on first use).
    var scheduler: PeriodicUpdateScheduler {
        schedulerBox.withLock { slot in
            if let slot { return slot }
            let made = PeriodicUpdateScheduler(
                work: { [weak self] attempts in
                    guard let self else { return .failure }
                    return await self.runPeriodicWork(runAttemptCount: attempts)
                },
                onChange: { [weak self] in self?.notifyScheduledTasksChanged() },
                backgroundSubmitter: { [weak self] in self?.backgroundSubmitter() }
            )
            slot = made
            return made
        }
    }

    /// The BGTaskScheduler road, once the launch handler is registered.
    private func backgroundSubmitter() -> PeriodicUpdateScheduler.BackgroundSubmitter? {
        #if canImport(BackgroundTasks) && os(iOS)
        guard state.withLock({ $0.backgroundTaskRegistered }) else { return nil }
        return .appRefresh(Self.backgroundTaskIdentifier)
        #else
        return nil
        #endif
    }

    /// Registers the periodic update's `BGTaskScheduler` launch handler. Call
    /// it before the app finishes launching (`application(_:didFinishLaunchingWithOptions:)`
    /// or the SwiftUI `App` initializer). The identifier must be listed in
    /// `BGTaskSchedulerPermittedIdentifiers`; without it nothing is registered
    /// and false is returned. Idempotent.
    @discardableResult
    public func registerBackgroundTask() -> Bool {
        #if canImport(BackgroundTasks) && os(iOS)
        let permitted = (Bundle.main.object(forInfoDictionaryKey: "BGTaskSchedulerPermittedIdentifiers") as? [String])?
            .contains(Self.backgroundTaskIdentifier) == true
        guard permitted else {
            log.e("registerBackgroundTask: \(Self.backgroundTaskIdentifier) is not in BGTaskSchedulerPermittedIdentifiers — not registered")
            return false
        }
        let first = state.withLock { state -> Bool in
            defer { state.backgroundTaskRegistered = true }
            return !state.backgroundTaskRegistered
        }
        guard first else { return true }
        let registered = BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.backgroundTaskIdentifier, using: nil) { [self] task in
            handleBackgroundTask(UncheckedSendable(task))
        }
        if !registered { state.withLock { $0.backgroundTaskRegistered = false } }
        return registered
        #else
        return false
        #endif
    }

    #if canImport(BackgroundTasks) && os(iOS)
    private func handleBackgroundTask(_ task: UncheckedSendable<BGTask>) {
        let scheduler = self.scheduler
        let work = Task {
            let succeeded = await scheduler.runFromBackground()
            task.value.setTaskCompleted(success: succeeded && !Task.isCancelled)
        }
        task.value.expirationHandler = { work.cancel() }
    }
    #endif

    /// The periodic job (`CertificateUpdateWorker.doWork`): update the default
    /// block, the others, sync files, wipe stale files, pick up a pending
    /// enrollment, renew certificates, attest.
    func runPeriodicWork(runAttemptCount: Int = 0) async -> CertificateUpdateWorker.Result {
        await CertificateUpdateWorker.doWork(self, runAttemptCount: runAttemptCount)
    }

    // MARK: Enrollment

    /// Enrolls this device with a one-time token or a shared enrollment code
    /// (CSR over a fresh Secure Enclave key; the key never leaves the device).
    /// - Parameter label: nil = the default block's `clientCertLabel`.
    /// - Returns: true when enrolled (or a credential exists); ``enrollForResult(token:label:)`` says why not.
    public func enroll(token: String, label: String? = nil) async -> Bool {
        await enrollForResult(token: token, label: label).isEnrolled
    }

    /// ``enroll(token:label:)`` with the reason when it does not work.
    public func enrollForResult(token: String, label: String? = nil) async -> ClientCertEnrollmentResult {
        await enrollInternal(token: token, deviceId: nil, label: label)
    }

    /// Enrolls with the device id (no token). A server that takes code-less
    /// applications answers ``ClientCertEnrollmentResult/pending(requestId:clientId:message:retryAfterSeconds:verificationCode:)``.
    public func autoEnroll() async -> Bool {
        await autoEnrollForResult().isEnrolled
    }

    /// ``autoEnroll()`` with the reason when it does not work.
    public func autoEnrollForResult() async -> ClientCertEnrollmentResult {
        // SECURITY NOTE (M-02): identifierForVendor is a soft identifier; treat the
        // enrollment as a convenience credential unless the server enforces an integrity verdict.
        let vendorId = DeviceIdentity.deviceId()
        log.d("Auto-enrollment: device id available: \(vendorId != nil)")
        return await enrollInternal(token: nil, deviceId: vendorId ?? "unknown-device", label: nil)
    }

    /// Enrolls before ``start(config:)`` — the first start of an app whose
    /// Config API is an mTLS listener — through the default block's `enrollmentUrl`:
    ///
    /// ```swift
    /// if !PinVault.shared.isEnrolled(config: config) { _ = await PinVault.shared.enroll(config: config, token: token) }
    /// _ = await PinVault.shared.start(config: config)
    /// ```
    public func enroll(config: PinVaultConfig, token: String) async -> Bool {
        await enrollForResult(config: config, token: token).isEnrolled
    }

    /// ``enroll(config:token:)`` with the reason when it does not work.
    public func enrollForResult(config: PinVaultConfig, token: String) async -> ClientCertEnrollmentResult {
        await enrollBeforeStart(config: config, token: token, deviceId: nil)
    }

    /// ``autoEnroll()`` before start.
    public func autoEnroll(config: PinVaultConfig) async -> Bool {
        await autoEnrollForResult(config: config).isEnrolled
    }

    /// ``autoEnroll(config:)`` with the reason when it does not work.
    public func autoEnrollForResult(config: PinVaultConfig) async -> ClientCertEnrollmentResult {
        await enrollBeforeStart(config: config, token: nil, deviceId: DeviceIdentity.deviceId() ?? "unknown-device")
    }

    /// Whether the default block of `config` has an enrolled client certificate. Usable before start.
    public func isEnrolled(config: PinVaultConfig) -> Bool {
        // TODO(L3): ClientCertSecureStore.exists(config.defaultConfigApi?.clientCertLabel ?? default)
        _ = config
        return false
    }

    /// Whether a client certificate is enrolled under `label` (nil = the default block's label).
    public func isEnrolled(label: String? = nil) -> Bool {
        // TODO(L3): ClientCertSecureStore.exists(label ?? defaultCertLabel())
        _ = label
        return false
    }

    /// The verification code of this device's enrollment key
    /// (`4F7K-2QXM-9D3T-H6WP`, 80 bits of the key's SHA-256): show it on the
    /// "waiting for approval" screen. Nil without an enrollment key.
    public func enrollmentVerificationCode(label: String? = nil) -> String? {
        // TODO(L3): VerificationCode.of(identityKey(label ?? defaultCertLabel()).publicKey())
        _ = label
        return nil
    }

    /// Whether an enrollment waits for an administrator's approval and no certificate is stored yet.
    public func isEnrollmentPending(label: String? = nil) -> Bool {
        // TODO(L3): !store.exists(label) && store.loadPendingRequest(label) != nil
        _ = label
        return false
    }

    /// ``isEnrollmentPending(label:)`` for the default block of `config`; usable before start.
    public func isEnrollmentPending(config: PinVaultConfig) -> Bool {
        isEnrollmentPending(label: config.defaultConfigApi?.clientCertLabel ?? PinVaultConfig.defaultCertLabel)
    }

    /// Asks whether a device that was told to wait has been approved:
    /// `enrolled` once it has, `pending` while it waits, `refused(.rejected)`
    /// when turned away. Start and the periodic update ask on their own.
    public func checkPendingEnrollment() async -> ClientCertEnrollmentResult {
        // TODO(L3): pendingCheckShortcut(defaultCertLabel()) then enrollInternal(token: nil, deviceId: nil)
        await enrollInternal(token: nil, deviceId: nil, label: nil)
    }

    /// ``checkPendingEnrollment()`` for the default block of `config`; usable before start.
    public func checkPendingEnrollment(config: PinVaultConfig) async -> ClientCertEnrollmentResult {
        if isInitialized { return await checkPendingEnrollment() }
        guard config.defaultConfigApi != nil else { return Self.noConfigApiBlock }
        // TODO(L3): pendingCheckShortcut(block.clientCertLabel)
        return await enrollBeforeStart(config: config, token: nil, deviceId: nil)
    }

    static let noConfigApiBlock = ClientCertEnrollmentResult.failed(message: "The config has no Config API block")

    private func enrollBeforeStart(config: PinVaultConfig, token: String?, deviceId: String?) async -> ClientCertEnrollmentResult {
        if isInitialized { return await enrollInternal(token: token, deviceId: deviceId, label: nil) }
        if let refusal = environmentRefusal(config, .enroll) {
            return .failed(message: refusal.message, cause: refusal)
        }
        guard let block = config.defaultConfigApi else { return Self.noConfigApiBlock }
        // The same rule start applies: https and bootstrap pins, or an explicit opt-out.
        if let error = block.configurationError() { return .failed(message: error) }
        // TODO(L3): stored credential check, then a ConfigApiClient for the block alone + enrollAndStore.
        _ = (token, deviceId)
        return .failed(message: Self.unavailable("enrollment", "L3"))
    }

    private func enrollInternal(token: String?, deviceId: String?, label: String?) async -> ClientCertEnrollmentResult {
        guard let config else {
            return .failed(message: "PinVault is not initialized: call init first, or enroll with the config before init")
        }
        if let refusal = environmentRefusal(config, .enroll) {
            return .failed(message: refusal.message, cause: refusal)
        }
        guard config.defaultConfigApi != nil else { return Self.noConfigApiBlock }
        // TODO(L3): EnrollmentRequests.send over the default block's API, store, then
        // configApiClient(id)?.reloadClientIdentity() (rebuilds every session).
        _ = (token, deviceId, label)
        return .failed(message: Self.unavailable("enrollment", "L3"))
    }

    /// A device whose enrollment waited for approval asks again (start and the periodic job).
    func pickUpPendingEnrollments() async {
        // TODO(L3): for the default block with a pending request: checkPendingEnrollment().
    }

    /// Renews a block's client certificate when its remaining lifetime is below
    /// the threshold, or always with `force`. Runs on its own at start and on
    /// every periodic update.
    /// - Parameter configApiId: the block; nil = the default block.
    public func renewClientCertIfNeeded(configApiId: String? = nil, force: Bool = false) async -> ClientCertRenewalResult {
        guard isInitialized else { return .failed(reason: "PinVault not initialized") }
        guard let id = configApiId ?? config?.defaultConfigApi?.id, let client = configApiClient(id) else {
            return .notApplicable
        }
        let result = await client.renewIfNeeded(force: force)
        emitRenewalEvent(client.block.id, result)
        return result
    }

    /// Every block's renewal check, for the periodic job. Never throws.
    func renewClientCertsIfNeeded() async {
        guard isInitialized else { return }
        for client in configApiClients {
            emitRenewalEvent(client.block.id, await client.renewIfNeeded())
        }
    }

    private func emitRenewalEvent(_ configApiId: String, _ result: ClientCertRenewalResult) {
        // The refusal that made renewal fail may already have been reported from
        // the request itself; the app hears it once per identity.
        if case .reenrollRequired = result, configApiClient(configApiId)?.claimReenrollNotice() == false { return }
        dispatchRenewalEvent(configApiId, result)
    }

    func dispatchRenewalEvent(_ configApiId: String, _ result: ClientCertRenewalResult) {
        let status: ClientCertRenewalStatus
        var notAfter: Int64 = 0
        var via: ClientCertRenewalVia?
        var failureReason: String?
        switch result {
        case .renewed(let notAfterEpochMs, let renewedVia):
            status = .renewed
            notAfter = notAfterEpochMs
            via = renewedVia
        case .notNeeded(let notAfterEpochMs):
            status = .notNeeded
            notAfter = notAfterEpochMs
        case .reenrollRequired(let reason):
            status = .reenrollRequired
            failureReason = reason
        case .failed(let reason, _):
            status = .failed
            failureReason = reason
        case .notApplicable:
            return
        }
        dispatchEvent(.clientCertRenewal(
            status: status, notAfterEpochMs: notAfter, via: via, configApiId: configApiId,
            deviceManufacturer: DeviceInfo.manufacturer, deviceModel: DeviceInfo.model, failureReason: failureReason
        ))
    }

    /// Removes the enrolled client certificate (and its identity key, and a
    /// pending enrollment) so the next request presents none. With
    /// `wipeVaultFiles` also deletes the vault files of every Config API that
    /// uses that certificate for mTLS (needs start).
    /// - Parameter label: nil = the default block's `clientCertLabel`.
    public func unenroll(label: String? = nil, wipeVaultFiles: Bool = false) {
        let certLabel = label ?? defaultCertLabel()
        // TODO(L3): store.clear(certLabel), identity key + imported key deletion, then
        // reloadClientIdentity() on every block using the label (drops the live key material).
        if wipeVaultFiles {
            if !isInitialized {
                log.w("unenroll: vault files can only be wiped after init — none wiped")
            }
            // TODO(L4): VaultFileWipe.mtlsBlocksUsing(certLabel, …) → wipeVaultFilesOf(ids)
        }
        log.i("Client certificate removed [\(certLabel)] — client cert no longer presented")
    }

    /// The CN of the enrolled client certificate, or nil.
    public func enrolledClientCN(label: String? = nil) -> String? {
        // TODO(L3): enrolledLeaf(label)?.subject.commonName
        _ = label
        return nil
    }

    /// When the enrolled client certificate expires (epoch ms), or nil. Local, no network.
    public func enrolledClientNotAfter(label: String? = nil) -> Int64? {
        // TODO(L3): enrolledLeaf(label)?.notAfter
        _ = label
        return nil
    }

    /// The label enroll / isEnrolled / unenroll use when none is passed.
    func defaultCertLabel() -> String {
        config?.defaultConfigApi?.clientCertLabel ?? PinVaultConfig.defaultCertLabel
    }

    // MARK: Vault files

    /// Fetches a vault file and stores it encrypted. For a `userAuth` file
    /// ``VaultFileResult/updated(key:version:bytes:)`` carries no bytes.
    public func fetchFile(_ key: String) async -> VaultFileResult {
        guard isInitialized else {
            return .failed(key: key, reason: Self.notInitializedMessage, exception: PinVaultError.illegalState(Self.notInitializedMessage))
        }
        guard let config, config.vaultFiles[key] != nil else {
            return .failed(key: key, reason: "Vault file '\(key)' not registered in config")
        }
        if let refusal = environmentRefusal(config, .fetchFile) {
            return .failed(key: key, reason: refusal.message, exception: refusal)
        }
        // TODO(L4): vaultRouter.fetchFile(fileConfig) over configApiClient(file.configApiId).api + reportFileDownload (5 s budget).
        return .failed(key: key, reason: Self.unavailable("vault files", "L4"), code: VaultFileResult.FailureCode.notConfigured)
    }

    /// The stored copy, checked on every read (signature, offline lifetime);
    /// nil when not fetched, for a `userAuth` file (use ``unlockFile(key:prompt:)``),
    /// and when a check fails — ``fileStatus(_:)`` says which.
    public func loadFile(_ key: String) -> Data? {
        // TODO(L4): vaultGuard.load(file, storage, storedVerifier)
        _ = key
        return nil
    }

    /// What ``loadFile(_:)`` / ``unlockFile(key:prompt:)`` would make of the stored copy, without reading it.
    public func fileStatus(_ key: String) -> VaultFileStatus {
        // TODO(L4): guard.status(file, storage, storedVerifier)
        _ = key
        return .notStored
    }

    /// Opens a vault file locked with `userAuth`: shows the passcode /
    /// biometrics prompt and returns the content once the user passes it. A
    /// file without a lock comes back without a prompt.
    public func unlockFile(key: String, prompt: VaultFileUnlockPrompt) async -> VaultFileUnlockResult {
        guard isInitialized else {
            return .failed(key: key, reason: Self.notInitializedMessage, exception: PinVaultError.illegalState(Self.notInitializedMessage))
        }
        // Before the prompt: on a device the app does not trust, the content never reaches memory.
        if let refusal = environmentRefusal(config, .unlockFile) {
            return .failed(key: key, reason: refusal.message, exception: refusal)
        }
        // TODO(L4): guard.beforeUnlock → UserAuthVaultStorage.unlock (LAContext prompt) → guard.check
        _ = prompt
        return .failed(key: key, reason: Self.unavailable("unlockFile", "L4"))
    }

    /// True when the stored copy of `key` opens only through ``unlockFile(key:prompt:)``.
    public func isFileLocked(_ key: String) -> Bool {
        // TODO(L4): (storage as? UserAuthVaultStorage)?.isLocked(key)
        _ = key
        return false
    }

    /// ``loadFile(_:)`` as UTF-8 text (malformed bytes replaced).
    public func loadFileAsString(_ key: String) -> String? {
        loadFile(key).map { String(decoding: $0, as: UTF8.self) }
    }

    /// True when a copy of `key` is stored.
    public func hasFile(_ key: String) -> Bool {
        // TODO(L4): getStorageFor(key).exists(key)
        _ = key
        return false
    }

    /// The version of the stored copy, or 0.
    public func fileVersion(_ key: String) -> Int {
        // TODO(L4): getStorageFor(key).getVersion(key)
        _ = key
        return 0
    }

    /// Deletes the stored copy of `key`.
    public func clearFile(_ key: String) {
        guard isInitialized else {
            log.w(Self.notInitializedMessage)
            return
        }
        // TODO(L4): storage.clear(key); vaultGuard.forget(key)
        log.d("Vault file cleared: \(key)")
    }

    /// Syncs every file with `updateWithPins(true)`; also runs in the periodic update.
    /// - Returns: file key → result.
    public func syncAllFiles() async -> [String: VaultFileResult] {
        guard isInitialized, let config else { return [:] }
        var results: [String: VaultFileResult] = [:]
        for file in config.orderedVaultFiles where file.updateWithPins {
            let result = await fetchFile(file.key)
            results[file.key] = result
            await notifyFileUpdate(file.key, result)
        }
        return results
    }

    /// Files past their offline lifetime go now (`wipeWhenStale`), whether or not anything reads them.
    func wipeStaleVaultFiles() async {
        // TODO(L4): vaultGuard.wipeStale(files, storageFor) + notifyFileUpdate per removed key.
    }

    // MARK: Pins and config state

    /// The current config version, or 0 when none is loaded.
    public func currentVersion() -> Int {
        primary?.clientProvider.getVersion() ?? 0
    }

    /// Per-host pin versions of the current config, by hostname.
    public func hostPinVersions() -> [String: Int] {
        var versions: [String: Int] = [:]
        for pin in currentConfig?.pins ?? [] { versions[pin.hostname] = pin.version }
        return versions
    }

    /// The applied SHA-256 SPKI pins (Base64, no `sha256/` prefix) for
    /// `hostname` (case-insensitive exact entry; wildcards are not expanded),
    /// or nil when the host has no entry. Re-read after every update.
    public func pinsForHost(_ hostname: String) -> [String]? {
        let needle = hostname.lowercased()
        return currentConfig?.pins.first { $0.hostname.lowercased() == needle }?.sha256
    }

    /// Every hostname → pins pair of the active config (wildcards verbatim); empty before a config is applied.
    public var currentPins: [String: [String]] {
        var pins: [String: [String]] = [:]
        for pin in currentConfig?.pins ?? [] { pins[pin.hostname] = pin.sha256 }
        return pins
    }

    /// How a block verifies signatures right now; nil for an unsigned block,
    /// an unknown id, static pins, or while the signing-key store is unreadable.
    /// - Parameter configApiId: nil = the default block.
    public func signingStatus(configApiId: String? = nil) -> SigningStatus? {
        guard isInitialized, let id = configApiId ?? config?.defaultConfigApi?.id,
              let client = configApiClient(id), client.configsVerified else { return nil }
        do {
            return try client.signatureTrust?.status()
        } catch {
            log.w("signingStatus: the signing-key store is unreadable right now", error)
            return nil
        }
    }

    /// True when the current config says `forceUpdate`.
    public func isForceUpdate() -> Bool {
        currentConfig?.forceUpdate ?? false
    }

    /// Clears the active pins and the persisted config of every Config API
    /// and resets the started flag, so the next ``start(config:)`` starts over.
    /// Sessions obtained earlier refuse handshakes until then. Replay
    /// watermarks, the signing-key set, the trusted clock and the client
    /// certificate are kept: reset must not let an older signed config back in.
    public func reset() {
        guard let (clients, primary) = takeForReset() else { return }
        if clients.isEmpty {
            // Static-pin mode.
            primary?.clientProvider.reset()
            clearActive(primary?.configStore)
        } else {
            for client in clients {
                // The refresh loop stops and the token goes; the next start attests again.
                client.attestation?.reset()
                // Sessions handed out earlier stay fail-closed: their recovery fetches nothing.
                client.retire()
                client.clientProvider.reset()
                clearActive(client.configStore)
            }
        }
        log.w("PinVault reset — config cleared (replay watermarks kept), TLS refused until re-init")
    }

    /// ``reset()`` that also wipes the replay watermarks and the trusted clock. Tests only.
    func resetAndWipeStoredState() {
        guard let (clients, primary) = takeForReset() else { return }
        let stacks = clients.isEmpty
            ? [(primary?.clientProvider, primary?.configStore)]
            : clients.map { client -> (HttpClientProvider?, CertificateConfigStore?) in
                client.attestation?.reset()
                client.retire()
                return (client.clientProvider, client.configStore)
            }
        for (provider, store) in stacks {
            provider?.reset()
            do { try store?.wipeAll() } catch { log.e("Config store could not be wiped", error) }
        }
        log.w("PinVault reset — stored config state wiped, TLS refused until re-init")
    }

    /// Flips the started flag off; nil when not started.
    private func takeForReset() -> ([ConfigApiClient], Primary?)? {
        state.withLock { state -> ([ConfigApiClient], Primary?)? in
            guard state.initialized else { return nil }
            state.initialized = false
            return (state.clientOrder.compactMap { state.clients[$0] }, state.primary)
        }
    }

    private func clearActive(_ store: CertificateConfigStore?) {
        do {
            try store?.clearActive(keepAsWatermarks: true)
        } catch {
            log.e("Config store could not be cleared", error)
        }
    }

    // MARK: Internal plumbing

    /// Every SSL manager the library runs: one per block, or the static-pin one.
    func sslManagers() -> [DynamicSSLManager] {
        let clients = configApiClients
        if !clients.isEmpty { return clients.map(\.sslManager) }
        return state.withLock { $0.primary?.sslManager }.map { [$0] } ?? []
    }

    /// The refusal of `config`'s ``EnvironmentGuard`` for `operation`, or nil
    /// when there is no guard or it allows it. A guard that throws refuses.
    func environmentRefusal(_ config: PinVaultConfig?, _ operation: GuardedOperation) -> PinVaultError? {
        guard let environmentGuard = config?.environmentGuard else { return nil }
        let allowed: Bool
        do {
            allowed = try environmentGuard.allows(operation)
        } catch {
            log.e("Environment guard threw for \(operation.rawValue) — refusing", error)
            let kind = (error as? PinVaultError)?.exceptionName ?? String(describing: type(of: error))
            return .untrustedEnvironment(
                operation: operation,
                message: "The app's environment guard failed for \(operation.rawValue) (\(kind)); refused",
                cause: error
            )
        }
        if allowed { return nil }
        log.w("Environment guard refused \(operation.rawValue)")
        return .untrustedEnvironment(operation: operation)
    }

    /// Delivers `event` to the connection listener through the default
    /// block's SSL manager (ordered, bounded, off the caller's task). Never throws.
    func dispatchEvent(_ event: PinVaultConnectionEvent) {
        state.withLock { $0.primary?.sslManager }?.dispatchEvent(event)
    }

    /// Tells the update listener and the connection listener about a config update.
    func notifyUpdateResult(_ result: UpdateResult) async {
        let listener = state.withLock { $0.updateListener }
        if let listener { await listener(result) }
        let version = state.withLock { $0.primary?.clientProvider }?.getVersion() ?? 0
        let status: ConfigUpdateStatus
        let newVersion: Int
        let failureReason: String?
        switch result {
        case .updated(let updated): status = .updated; newVersion = updated; failureReason = nil
        case .alreadyCurrent: status = .unchanged; newVersion = version; failureReason = nil
        case .failed(let reason, _): status = .failed; newVersion = version; failureReason = reason
        }
        dispatchEvent(.configUpdate(
            status: status, newVersion: newVersion,
            deviceManufacturer: DeviceInfo.manufacturer, deviceModel: DeviceInfo.model,
            failureReason: failureReason
        ))
    }

    /// Tells the file update listener about a vault file result.
    func notifyFileUpdate(_ key: String, _ result: VaultFileResult) async {
        guard let listener = state.withLock({ $0.fileUpdateListener }) else { return }
        await listener(key, result)
    }

    /// Wall-clock offset the E2E harness set (ms), for the library clock.
    var e2eClockOffsetMs: Int64 {
        e2e.withLock { $0.clockOffsetSeconds } * 1000
    }

    /// The E2E connection-address override for `hostPort` (`host:port`), if any.
    func e2eRedirect(for hostPort: String) -> String? {
        e2e.withLock { $0.redirects[hostPort.lowercased()] }
    }

    /// The E2E control generation; sessions built under an older one are rebuilt.
    var e2eGeneration: Int {
        e2e.withLock { $0.generation }
    }

    /// Called by the scheduler whenever the scheduled tasks change.
    func notifyScheduledTasksChanged() {
        guard let observer = e2e.withLock({ $0.scheduledTasksObserver }) else { return }
        observer()
    }

    /// The collaborators every block gets until the later layers are wired in: none.
    static let defaultCollaborators: @Sendable (ConfigApiBlock, PinVault) -> ConfigApiClient.Collaborators = { _, _ in .none }
}

extension PinVault: PeriodicWorkTarget {}

// MARK: - E2E control hooks (PORTING.md §8)

extension PinVault {

    /// Adds `seconds` to the library's wall clock (TrustedClock wall source,
    /// certificate validity, `SecTrustSetVerifyDate`). New connections only.
    @_spi(PinVaultE2E)
    public func e2eSetClockOffset(seconds: Int64) {
        let changed = e2e.withLock { state -> Bool in
            guard state.clockOffsetSeconds != seconds else { return false }
            state.clockOffsetSeconds = seconds
            state.generation += 1
            return true
        }
        log.i("E2E: clock offset \(seconds) s")
        // Sessions see the new generation on their next request; idle connections close now.
        if changed { sslManagers().forEach { $0.onPinsChanged() } }
    }

    /// Connection-address overrides `host:port` → `host:port`, applied on top
    /// of the config's `resolve` entries (iptables DNAT/REJECT counterpart).
    @_spi(PinVaultE2E)
    public func e2eSetRedirects(_ redirects: [String: String]) {
        var normalized: [String: String] = [:]
        for (from, to) in redirects { normalized[from.lowercased()] = to }
        let changed = e2e.withLock { state -> Bool in
            guard state.redirects != normalized else { return false }
            state.redirects = normalized
            state.generation += 1
            return true
        }
        log.i("E2E: \(normalized.count) redirect(s)")
        if changed { sslManagers().forEach { $0.onPinsChanged() } }
    }

    /// Runs the periodic job now (`cmd jobscheduler run -f` counterpart); nothing when none is scheduled.
    @_spi(PinVaultE2E)
    public func e2eRunPeriodicWorkNow() async {
        log.i("E2E: running the periodic work now")
        await scheduler.runNow()
    }

    /// The device id the library sends (`X-Device-Id`).
    @_spi(PinVaultE2E)
    public func e2eDeviceId() -> String? {
        DeviceIdentity.deviceId()
    }

    /// Called whenever the scheduled tasks change (to rewrite `report.json`).
    @_spi(PinVaultE2E)
    public func e2eSetScheduledTasksObserver(_ observer: (@Sendable () -> Void)?) {
        e2e.withLock { $0.scheduledTasksObserver = observer }
    }
}

/// The Config API of static-pin mode: always the embedded pins, never a network request.
private struct StaticPinsApi: CertificateConfigApi {
    let pins: CertificateConfig

    func healthCheck() async throws -> Bool { true }
    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { pins }
    func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        EnrollmentResult(p12Bytes: Data())
    }
}

/// Carries a non-Sendable platform object (a `BGTask`) across a task boundary
/// where the platform guarantees it is safe to use.
struct UncheckedSendable<Value>: @unchecked Sendable {
    let value: Value
    init(_ value: Value) { self.value = value }
}
