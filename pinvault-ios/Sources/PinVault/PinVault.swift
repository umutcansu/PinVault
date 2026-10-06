import Foundation
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

    struct State {
        var config: PinVaultConfig?
        var initialized = false
        /// The active pin config (set by L2's client provider).
        var currentConfig: CertificateConfig?
        var currentVersion = 0
        var updateListener: OnUpdateListener?
        var fileUpdateListener: OnFileUpdateListener?
        var connectionListener: PinVaultConnectionListener?
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

    init() {}

    static let notInitializedMessage = "PinVault not initialized. Call PinVault.start() first."

    var isInitialized: Bool { state.withLock { $0.initialized } }
    var config: PinVaultConfig? { state.withLock { $0.config } }

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
    /// the one from `onConnectionEvent(...)`. Events fired before this call
    /// (the bootstrap handshake) are not delivered. Needs ``start(config:)``.
    public func setConnectionListener(_ listener: PinVaultConnectionListener?) {
        let applied = state.withLock { state -> Bool in
            guard state.initialized else { return false }
            state.connectionListener = listener
            return true
        }
        if !applied { log.w(Self.notInitializedMessage) }
        // TODO(L2): hand the listener to every block's DynamicSSLManager.
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
        let alreadyInitialized = state.withLock { state -> Int? in
            state.config = config
            return state.initialized ? state.currentVersion : nil
        }
        if let version = alreadyInitialized {
            log.w("PinVault already initialized — skipping")
            return .ready(version: version)
        }
        if let staticConfig = config.staticPins {
            log.d("Static pin mode — using embedded config (v\(staticConfig.computedVersion()), \(staticConfig.pins.count) hosts)")
            // Compiled-in pins are held to the same rules as fetched ones.
            do {
                try PinConfigValidator.validate(staticConfig)
            } catch {
                let message = (error as? PinVaultError)?.message ?? "\(error)"
                log.e("Static pins refused: \(message)")
                return .failed(reason: "Static pins are not valid: \(message)", exception: error)
            }
        }
        // TODO(L2): setup (stores, per-block ConfigApiClient, DynamicSSLManager, vault router) and
        // executeInit (pending enrollments, renewal, initializeAndUpdate, attestation, key registration).
        _ = customApi
        let reason = Self.unavailable("start", "L2")
        return .failed(reason: reason, exception: PinVaultError.illegalState(reason))
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
        if isInitialized, state.withLock({ $0.currentConfig == nil }) {
            log.w(
                "PinVault.applyTo called before initial config arrived — " +
                    "TLS handshakes will refuse to connect until init completes."
            )
        }
        // TODO(L2): DynamicSSLManager-backed transport over `configuration` + token + recovery interceptors.
        _ = configuration
        return unavailableSession()
    }

    /// The ready-to-use pinned session (`getClient()`): pinning, attestation
    /// token, re-attest on 401, pin-mismatch recovery. Fail-closed: before a
    /// config is applied every request fails. Wait for ``InitResult/ready(version:)``.
    public func session() -> PinnedSession {
        if !isInitialized { log.w(Self.notInitializedMessage) }
        // TODO(L2): the default block's HttpClientProvider session.
        return unavailableSession()
    }

    /// A pinned session with custom `settings` (`getClient(HttpConnectionSettings)`):
    /// pinning and the attestation token, but NO pin-mismatch recovery — a
    /// mismatch reaches the caller until the next config update.
    public func session(settings: HttpConnectionSettings) -> PinnedSession {
        if !isInitialized { log.w(Self.notInitializedMessage) }
        // TODO(L2): DynamicSSLManager.buildDynamicClient(settings, extra: token interceptor).
        _ = settings
        return unavailableSession()
    }

    private func unavailableSession() -> PinnedSession {
        let reason = isInitialized ? Self.unavailable("pinned sessions", "L2") : Self.notInitializedMessage
        return PinnedSession(transport: UnavailableTransport(reason: reason))
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
        // TODO(L5): configApiClients[id]?.attestation?.attestNow()
        return notAttesting(id)
    }

    /// The `PinVault-Token` for requests sent through a client of the app's
    /// own (``session()`` / ``applyTo(_:)`` add it themselves): the token of the
    /// block whose token hosts cover `host`, attesting first when none with
    /// enough life is held.
    /// - Parameter host: a host name (optionally `host:port`); nil = the default block.
    public func fetchAttestationToken(host: String? = nil) async -> AttestationTokenResult {
        guard isInitialized else { return .failed(message: "PinVault not initialized") }
        // TODO(L5): pick the attesting block (handlesHost) and fetchToken().
        _ = host
        return .unsupported
    }

    /// The last attestation outcome of a block, from memory. `NOT_ATTESTED`
    /// before the first round, `UNSUPPORTED` for a block that does not attest
    /// or an unknown id; `FAILED` with "PinVault not initialized" before start.
    public func attestationStatus(configApiId: String? = nil) -> AttestationStatus {
        let id = configApiId ?? config?.defaultConfigApi?.id ?? ""
        guard isInitialized else {
            return AttestationStatus(configApiId: id, result: .failed, lastError: "PinVault not initialized")
        }
        // TODO(L5): configApiClients[id]?.attestation?.status
        return notAttesting(id)
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

    // MARK: Updates

    /// Fetches the latest config from the backend, persists it and updates pinning.
    public func updateNow() async -> UpdateResult {
        guard isInitialized else {
            return .failed(reason: Self.notInitializedMessage, exception: PinVaultError.illegalState(Self.notInitializedMessage))
        }
        // TODO(L2): updater.updateNow()
        let reason = Self.unavailable("updateNow", "L2")
        return .failed(reason: reason, exception: PinVaultError.illegalState(reason))
    }

    /// Schedules the periodic update (`BGTaskScheduler`, or the in-process
    /// scheduler where `submit` is unavailable, e.g. the simulator).
    /// `updateIntervalMinutes` of the config wins over hours when set.
    /// - Parameter intervalHours: nil = the config's `updateIntervalHours`.
    /// - Returns: whether the task was scheduled.
    @discardableResult
    public func schedulePeriodicUpdates(intervalHours: Int64? = nil) -> Bool {
        guard isInitialized else {
            log.w(Self.notInitializedMessage)
            return false
        }
        // TODO(L2): Background scheduler (BGAppRefreshTaskRequest / in-process fallback), then
        // notifyScheduledTasksChanged().
        _ = intervalHours
        return false
    }

    /// Cancels the periodic update.
    public func cancelPeriodicUpdates() {
        guard isInitialized else {
            log.w(Self.notInitializedMessage)
            return
        }
        // TODO(L2): cancel the BGTask request / in-process timer, then notifyScheduledTasksChanged().
    }

    /// The scheduled pin update tasks (`getScheduledWorkInfo`).
    public func scheduledTasks() async -> [ScheduledTaskInfo] {
        // TODO(L2): BGTaskScheduler.pendingTaskRequests() / in-process scheduler state.
        []
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
        let work = Task { [self] in
            await runPeriodicWork()
            task.value.setTaskCompleted(success: !Task.isCancelled)
        }
        task.value.expirationHandler = { work.cancel() }
        // TODO(L2): submit the next BGAppRefreshTaskRequest.
    }
    #endif

    /// The periodic job (`CertificateUpdateWorker.doWork`): update the default
    /// block, the others, renew certificates, pick up a pending enrollment,
    /// attest, wipe stale files, sync `updateWithPins` files.
    func runPeriodicWork() async {
        // TODO(L2): CertificateUpdateWorker port (updateNow, updateOtherConfigApis, renewClientCertsIfNeeded,
        // pickUpPendingEnrollments, attestAll, wipeStaleVaultFiles, syncAllFiles) with retries.
        log.d("Periodic work: nothing to do until L2 lands")
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
        // TODO(L3): EnrollmentRequests.send over the default block's API, store, load the identity, rebuild sessions.
        _ = (token, deviceId, label)
        return .failed(message: Self.unavailable("enrollment", "L3"))
    }

    /// Renews a block's client certificate when its remaining lifetime is below
    /// the threshold, or always with `force`. Runs on its own at start and on
    /// every periodic update.
    /// - Parameter configApiId: the block; nil = the default block.
    public func renewClientCertIfNeeded(configApiId: String? = nil, force: Bool = false) async -> ClientCertRenewalResult {
        guard isInitialized else { return .failed(reason: "PinVault not initialized") }
        guard let id = configApiId ?? config?.defaultConfigApi?.id, config?.configApis[id] != nil else {
            return .notApplicable
        }
        // TODO(L3): client.renewer.renewIfNeeded(force) + emitRenewalEvent
        _ = force
        return .failed(reason: Self.unavailable("certificate renewal", "L3"))
    }

    /// Removes the enrolled client certificate (and its identity key, and a
    /// pending enrollment) so the next request presents none. With
    /// `wipeVaultFiles` also deletes the vault files of every Config API that
    /// uses that certificate for mTLS (needs start).
    /// - Parameter label: nil = the default block's `clientCertLabel`.
    public func unenroll(label: String? = nil, wipeVaultFiles: Bool = false) {
        let certLabel = label ?? defaultCertLabel()
        // TODO(L3): store.clear(certLabel), identity key + imported key deletion, drop live key material.
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
        // TODO(L4): vaultRouter.fetchFile(fileConfig) + reportFileDownload (5 s budget).
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

    // MARK: Pins and config state

    /// The current config version, or 0 when none is loaded.
    public func currentVersion() -> Int {
        state.withLock { $0.currentVersion }
    }

    /// Per-host pin versions of the current config, by hostname.
    public func hostPinVersions() -> [String: Int] {
        state.withLock { state in
            var versions: [String: Int] = [:]
            for pin in state.currentConfig?.pins ?? [] { versions[pin.hostname] = pin.version }
            return versions
        }
    }

    /// The applied SHA-256 SPKI pins (Base64, no `sha256/` prefix) for
    /// `hostname` (case-insensitive exact entry; wildcards are not expanded),
    /// or nil when the host has no entry. Re-read after every update.
    public func pinsForHost(_ hostname: String) -> [String]? {
        let needle = hostname.lowercased()
        return state.withLock { $0.currentConfig?.pins.first { $0.hostname.lowercased() == needle }?.sha256 }
    }

    /// Every hostname → pins pair of the active config (wildcards verbatim); empty before a config is applied.
    public var currentPins: [String: [String]] {
        state.withLock { state in
            var pins: [String: [String]] = [:]
            for pin in state.currentConfig?.pins ?? [] { pins[pin.hostname] = pin.sha256 }
            return pins
        }
    }

    /// How a block verifies signatures right now; nil for an unsigned block,
    /// an unknown id, static pins, or while the signing-key store is unreadable.
    /// - Parameter configApiId: nil = the default block.
    public func signingStatus(configApiId: String? = nil) -> SigningStatus? {
        // TODO(L2): configApiClients[id]?.signatureTrust?.status() when configs are verified.
        _ = configApiId
        return nil
    }

    /// True when the current config says `forceUpdate`.
    public func isForceUpdate() -> Bool {
        state.withLock { $0.currentConfig?.forceUpdate ?? false }
    }

    /// Clears the active pins and the persisted config of every Config API
    /// and resets the started flag, so the next ``start(config:)`` starts over.
    /// Sessions obtained earlier refuse handshakes until then. Replay
    /// watermarks, the signing-key set, the trusted clock and the client
    /// certificate are kept: reset must not let an older signed config back in.
    public func reset() {
        let wasInitialized = state.withLock { state -> Bool in
            guard state.initialized else { return false }
            state.initialized = false
            state.currentConfig = nil
            state.currentVersion = 0
            return true
        }
        guard wasInitialized else { return }
        // TODO(L2/L5): attestation.reset(), clientProvider.reset(), configStore.clearActive() per block.
        log.w("PinVault reset — config cleared (replay watermarks kept), TLS refused until re-init")
    }

    /// ``reset()`` that also wipes the replay watermarks and the trusted clock. Tests only.
    func resetAndWipeStoredState() {
        let wasInitialized = state.withLock { state -> Bool in
            guard state.initialized else { return false }
            state.initialized = false
            state.currentConfig = nil
            state.currentVersion = 0
            return true
        }
        guard wasInitialized else { return }
        // TODO(L4): configStore.wipeAll() per block.
        log.w("PinVault reset — stored config state wiped, TLS refused until re-init")
    }

    // MARK: Internal plumbing for the later layers

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

    /// Delivers `event` to the connection listener (the config's, or the one
    /// set at runtime) off the caller's task. Never throws.
    func dispatchEvent(_ event: PinVaultConnectionEvent) {
        guard let listener = state.withLock({ $0.connectionListener ?? $0.config?.connectionListener }) else { return }
        Task.detached { listener(event) }
    }

    /// Tells the update listener and the connection listener about a config update.
    func notifyUpdateResult(_ result: UpdateResult) async {
        let (listener, version) = state.withLock { ($0.updateListener, $0.currentVersion) }
        if let listener { await listener(result) }
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

    /// Wall-clock offset the E2E harness set (ms), for L2's TrustedClock and certificate checks.
    var e2eClockOffsetMs: Int64 {
        e2e.withLock { $0.clockOffsetSeconds } * 1000
    }

    /// The E2E connection-address override for `hostPort` (`host:port`), if any.
    func e2eRedirect(for hostPort: String) -> String? {
        e2e.withLock { $0.redirects[hostPort.lowercased()] }
    }

    /// The E2E control generation; sessions built under an older one are rebuilt (L2).
    var e2eGeneration: Int {
        e2e.withLock { $0.generation }
    }

    /// Called by the scheduler (L2) whenever the scheduled tasks change.
    func notifyScheduledTasksChanged() {
        guard let observer = e2e.withLock({ $0.scheduledTasksObserver }) else { return }
        observer()
    }
}

// MARK: - E2E control hooks (PORTING.md §8)

extension PinVault {

    /// Adds `seconds` to the library's wall clock (TrustedClock wall source,
    /// certificate validity, `SecTrustSetVerifyDate`). New connections only.
    @_spi(PinVaultE2E)
    public func e2eSetClockOffset(seconds: Int64) {
        e2e.withLock { state in
            guard state.clockOffsetSeconds != seconds else { return }
            state.clockOffsetSeconds = seconds
            state.generation += 1
        }
        log.i("E2E: clock offset \(seconds) s")
        // TODO(L2): rebuild the library's sessions.
    }

    /// Connection-address overrides `host:port` → `host:port`, applied on top
    /// of the config's `resolve` entries (iptables DNAT/REJECT counterpart).
    @_spi(PinVaultE2E)
    public func e2eSetRedirects(_ redirects: [String: String]) {
        var normalized: [String: String] = [:]
        for (from, to) in redirects { normalized[from.lowercased()] = to }
        e2e.withLock { state in
            guard state.redirects != normalized else { return }
            state.redirects = normalized
            state.generation += 1
        }
        log.i("E2E: \(normalized.count) redirect(s)")
        // TODO(L2): rebuild the library's sessions.
    }

    /// Runs the periodic job now (`cmd jobscheduler run -f` counterpart).
    @_spi(PinVaultE2E)
    public func e2eRunPeriodicWorkNow() async {
        log.i("E2E: running the periodic work now")
        await runPeriodicWork()
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

/// Carries a non-Sendable platform object (a `BGTask`) across a task boundary
/// where the platform guarantees it is safe to use.
struct UncheckedSendable<Value>: @unchecked Sendable {
    let value: Value
    init(_ value: Value) { self.value = value }
}
