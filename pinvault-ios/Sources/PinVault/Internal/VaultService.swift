import Foundation

/// The vault-file half of the façade (the vault members of Kotlin `PinVault`):
/// storage per file, the router, the read-time guard, the device keys, the
/// unlock prompt and the distribution report. Everything it talks to is an
/// init parameter, so `PinVault` builds one at `start` (``make(config:clients:now:environmentRefusal:onFileRemoved:deviceIdentity:environment:evaluator:)``)
/// and forwards its vault calls.
///
/// Thread safety: every member may be called from any thread or task; the
/// state lives in the stores and keys, which serialise themselves.
final class VaultService: Sendable {

    /// The device's alias and id (Kotlin `resolveDeviceIdentity`: `deviceAlias`
    /// or "manufacturer model", and the id sent as `X-Device-Id`); nil when the
    /// platform gives no id.
    typealias DeviceIdentityProvider = @Sendable () -> (alias: String, id: String)?

    let config: PinVaultConfig
    let router: VaultFileRouter
    let vaultGuard: VaultFileGuard
    /// The `end_to_end` RSA key; nil when no file uses `END_TO_END`.
    let deviceKeys: (any DeviceKeyProvider)?
    /// The user-auth key; nil when no file uses `userAuth`.
    let userAuthKeys: (any UserAuthKeys)?
    private let defaultStore: any VaultStorageProvider
    private let storages: [String: any VaultStorageProvider]
    private let deviceIdentity: DeviceIdentityProvider
    private let environmentRefusal: @Sendable (GuardedOperation) -> PinVaultError?
    private let evaluator: any UserAuthEvaluator
    /// How long a fetch waits for its distribution report (Kotlin: 5 s).
    private let reportTimeoutNanoseconds: UInt64
    private let log = PinVaultLog.tag("PinVault")

    /// - Parameters:
    ///   - clients: one per Config API block, in configuration order.
    ///   - now: the trusted clock of a Config API (epoch ms), by id.
    ///   - environmentRefusal: the app's environment guard for an operation (nil = allowed).
    ///   - onFileRemoved: told when a stored copy is deleted by its checks (the file-update listener).
    ///   - defaultStore: the `ENCRYPTED_PREFS` store; `fileStore` the `ENCRYPTED_FILE` one.
    init(
        config: PinVaultConfig,
        clients: [VaultFileRouter.Client],
        now: @escaping @Sendable (_ configApiId: String) -> Int64,
        environmentRefusal: @escaping @Sendable (GuardedOperation) -> PinVaultError? = { _ in nil },
        onFileRemoved: @escaping @Sendable (_ key: String, _ result: VaultFileResult) -> Void = { _, _ in },
        deviceIdentity: @escaping DeviceIdentityProvider,
        defaultStore: any VaultStorageProvider,
        fileStore: any VaultStorageProvider,
        deviceKeys: (any DeviceKeyProvider)?,
        userAuthKeys: (any UserAuthKeys)?,
        meta: any VaultFileMeta,
        registrations: any UserAuthRegistrations,
        evaluator: any UserAuthEvaluator = SystemUserAuthEvaluator(),
        appAttestation: (@Sendable (Data) async -> String?)? = nil,
        reportTimeoutNanoseconds: UInt64 = 5_000_000_000
    ) {
        self.config = config
        self.defaultStore = defaultStore
        self.deviceKeys = deviceKeys
        self.userAuthKeys = userAuthKeys
        self.deviceIdentity = deviceIdentity
        self.environmentRefusal = environmentRefusal
        self.evaluator = evaluator
        self.reportTimeoutNanoseconds = reportTimeoutNanoseconds

        // Shared across all Config APIs: file keys are globally unique.
        var storages: [String: any VaultStorageProvider] = [:]
        for file in config.orderedVaultFiles {
            let base = file.storageProvider ?? (file.storageStrategy == .encryptedFile ? fileStore : defaultStore)
            if file.userAuth != .none, let keys = userAuthKeys {
                storages[file.key] = UserAuthVaultStorage(
                    inner: base, keys: keys, policy: file.userAuth, serverSealedOnly: file.encryption == .userAuth
                )
            } else {
                storages[file.key] = base
            }
        }
        self.storages = storages

        let vaultGuard = VaultFileGuard(
            meta: meta, now: now, defaultMaxOfflineAgeMs: config.vaultFileMaxOfflineAgeMs,
            onRemoved: { key, reason in onFileRemoved(key, .failed(key: key, reason: reason)) }
        )
        self.vaultGuard = vaultGuard
        let files = config.orderedVaultFiles
        let storageLookup = storages
        router = VaultFileRouter(
            clients: clients,
            storageFor: { storageLookup[$0] ?? defaultStore },
            deviceKeyProvider: deviceKeys,
            deviceIdProvider: { deviceIdentity()?.id ?? "" },
            userAuthKeys: userAuthKeys,
            files: { files },
            registrations: registrations,
            guard: vaultGuard,
            appAttestation: appAttestation
        )
    }

    /// The production service: SecurePreferences / Keychain stores and keys in
    /// `environment`. The device RSA key is made now when a file uses
    /// `END_TO_END` (Kotlin setup), so this throws what that throws
    /// (``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)`` with
    /// `requireHardwareBackedKeys()`, a Keychain failure) and the start fails.
    static func make(
        config: PinVaultConfig,
        clients: [VaultFileRouter.Client],
        now: @escaping @Sendable (_ configApiId: String) -> Int64,
        environmentRefusal: @escaping @Sendable (GuardedOperation) -> PinVaultError?,
        onFileRemoved: @escaping @Sendable (_ key: String, _ result: VaultFileResult) -> Void,
        deviceIdentity: DeviceIdentityProvider? = nil,
        environment: SecureStoreEnvironment = .shared,
        evaluator: any UserAuthEvaluator = SystemUserAuthEvaluator(),
        appAttestation: (@Sendable (Data) async -> String?)? = nil
    ) throws -> VaultService {
        let files = config.orderedVaultFiles
        let userAuthKeys: (any UserAuthKeys)? = files.contains { $0.userAuth != .none }
            ? KeychainUserAuthKeys(evaluator: evaluator, requireHardwareBacked: config.requireHardwareBackedKeys)
            : nil
        let deviceKeys: (any DeviceKeyProvider)?
        if files.contains(where: { $0.encryption == .endToEnd }) {
            let keys = DeviceKeys.keychain(
                requireUnlockedDevice: config.requireUnlockedDevice, requireHardwareBacked: config.requireHardwareBackedKeys
            )
            try keys.ensureKeyPair()
            deviceKeys = keys
        } else {
            deviceKeys = nil
        }
        let alias = config.deviceAlias
        return VaultService(
            config: config,
            clients: clients,
            now: now,
            environmentRefusal: environmentRefusal,
            onFileRemoved: onFileRemoved,
            deviceIdentity: deviceIdentity ?? {
                DeviceIdentity.deviceId().map { (alias ?? "\(DeviceInfo.manufacturer) \(DeviceInfo.model)", $0) }
            },
            defaultStore: try VaultFileStore.open(environment: environment),
            fileStore: EncryptedFileStorageProvider.keychain(environment: environment),
            deviceKeys: deviceKeys,
            userAuthKeys: userAuthKeys,
            meta: try VaultFileMetaPersistent.open(environment: environment),
            registrations: userAuthKeys != nil
                ? try UserAuthRegistrationsPersistent.open(environment: environment) : UserAuthRegistrationsInMemory(),
            evaluator: evaluator,
            appAttestation: appAttestation
        )
    }

    /// The store of `key` (the default store for a key the config does not name).
    func storageFor(_ key: String) -> any VaultStorageProvider {
        storages[key] ?? defaultStore
    }

    // MARK: Fetch

    /// Kotlin `fetchFile`: download + store, then the distribution report (at
    /// most 5 s). A refusal by the app's environment guard downloads nothing
    /// and is reported like any failed fetch. For a `userAuth` file
    /// `.updated` carries no bytes.
    func fetchFile(_ key: String) async -> VaultFileResult {
        guard let file = config.vaultFiles[key] else {
            return .failed(key: key, reason: "Vault file '\(key)' not registered in config")
        }
        let result: VaultFileResult
        if let refusal = environmentRefusal(.fetchFile) {
            result = .failed(key: key, reason: refusal.message, exception: refusal)
        } else {
            result = await router.fetchFile(file)
        }
        let reported = await Self.withTimeout(reportTimeoutNanoseconds) { await self.reportFileDownload(file, result) }
        if !reported { log.w("Vault file report timed out for: \(key)") }
        return result
    }

    /// Kotlin `syncAllFiles`: every `updateWithPins` file, each result handed to `notify`.
    func syncAllFiles(notify: @Sendable (String, VaultFileResult) async -> Void = { _, _ in }) async -> [String: VaultFileResult] {
        var results: [String: VaultFileResult] = [:]
        for file in config.orderedVaultFiles where file.updateWithPins {
            let result = await fetchFile(file.key)
            results[file.key] = result
            await notify(file.key, result)
        }
        return results
    }

    private func reportFileDownload(_ file: VaultFileConfig, _ result: VaultFileResult) async {
        let identity = deviceIdentity()
        let enrollmentLabel = config.configApis[file.configApiId]?.clientCertLabel
            ?? config.defaultConfigApi?.clientCertLabel
            ?? "default"
        let version: Int
        let status: String
        let failureReason: String?
        switch result {
        case .updated(_, let v, _): version = v; status = "downloaded"; failureReason = nil
        case .alreadyCurrent(_, let v): version = v; status = "cached"; failureReason = nil
        // The fixed class of the failure, never its text.
        case .failed(_, _, _, let code): version = 0; status = "failed"; failureReason = code
        }
        let report = VaultDownloadReport(
            key: file.key,
            version: version,
            status: status,
            deviceManufacturer: DeviceInfo.manufacturer,
            deviceModel: DeviceInfo.model,
            enrollmentLabel: enrollmentLabel,
            deviceId: identity?.id ?? "unknown",
            deviceAlias: identity?.alias ?? DeviceInfo.model,
            failureReason: failureReason,
            authMethod: file.accessPolicy.authMethod
        )
        await router.report(file, report)
    }

    // MARK: Reads

    /// Kotlin `loadFile`: the stored copy, checked on every read; nil when not
    /// fetched, locked, or refused by its checks (``fileStatus(_:)`` says which).
    func loadFile(_ key: String) -> Data? {
        let storage = storageFor(key)
        guard let file = config.vaultFiles[key] else { return (try? storage.load(key: key)) ?? nil }
        if case .content(let bytes) = vaultGuard.load(file, storage, router.storedVerifier(file)) { return bytes }
        return nil
    }

    func loadFileAsString(_ key: String) -> String? {
        loadFile(key).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Kotlin `fileStatus`.
    func fileStatus(_ key: String) -> VaultFileStatus {
        let storage = storageFor(key)
        guard let file = config.vaultFiles[key] else {
            do {
                return try storage.exists(key: key) ? .available : .notStored
            } catch {
                return .storageUnavailable
            }
        }
        return vaultGuard.status(file, storage, router.storedVerifier(file))
    }

    /// Kotlin `unlockFile`: the passcode / biometrics prompt, then the content.
    /// A file without a lock comes back without a prompt. A `USER_AUTH` file is
    /// decrypted here, after the prompt, and its signature checked; a newer copy
    /// in the pending slot is opened first.
    func unlockFile(key: String, prompt: VaultFileUnlockPrompt) async -> VaultFileUnlockResult {
        // Before the prompt: on a device the app does not trust, the content never reaches memory.
        if let refusal = environmentRefusal(.unlockFile) {
            return .failed(key: key, reason: refusal.message, exception: refusal)
        }
        let storage = storageFor(key)
        let file = config.vaultFiles[key]
        // A server-sealed copy carries its signatures and is checked inside
        // unlock; no verifier for such a file = not opened (fail closed).
        let sealedByServer = file?.encryption == .userAuth ? file : nil
        let verifier = sealedByServer.flatMap { router.unlockVerifier($0) }
        // Past its offline lifetime: no prompt for a file that is not handed out.
        if let file, case .refused(let status, let reason)? = vaultGuard.beforeUnlock(file, storage) {
            return status == .stale ? .stale(key: key) : .failed(key: key, reason: reason)
        }
        let hadCopy = (try? storage.exists(key: key)) ?? false
        let result: VaultFileUnlockResult
        if let locked = storage as? UserAuthVaultStorage {
            let evaluator = self.evaluator
            let router = self.router
            let vaultGuard = self.vaultGuard
            result = await locked.unlock(
                key,
                authenticate: { kind, grant in
                    await UserAuthPrompt.authenticate(prompt: prompt, kind: kind, grant: grant, evaluator: evaluator)
                },
                // Sealed for a key the server no longer has: register again before the next fetch.
                onSealedForAnotherKey: { if let sealedByServer { router.forgetUserAuthRegistration(sealedByServer.configApiId) } },
                // A newer server-sealed copy passed its check: only now is it confirmed.
                onPromoted: { version in if let file { vaultGuard.promoted(file, version: version) } },
                verify: verifier
            )
        } else {
            do {
                if let bytes = try storage.load(key: key) {
                    result = .unlocked(key: key, version: try storage.getVersion(key: key), bytes: bytes)
                } else {
                    result = .notFound(key: key)
                }
            } catch {
                result = .failed(key: key, reason: VaultErrorText.message(error), exception: error)
            }
        }
        guard let file else { return result }
        if case .failed(_, let reason, _) = result, hadCopy, !((try? storage.exists(key: key)) ?? true) {
            // The copy failed the check done at unlock and was deleted there.
            vaultGuard.integrityFailed(file, reason: reason)
        }
        guard case .unlocked(_, let version, let bytes) = result else { return result }
        switch vaultGuard.check(file, storage, bytes, version: version, router.storedVerifier(file)) {
        case .content: return result
        case .refused(_, let reason): return .failed(key: key, reason: reason)
        case .absent: return .notFound(key: key)
        }
    }

    /// Kotlin `isFileLocked`: the stored copy opens only through unlock.
    func isFileLocked(_ key: String) -> Bool {
        guard let locked = storageFor(key) as? UserAuthVaultStorage else { return false }
        return (try? locked.isLocked(key)) ?? false
    }

    func hasFile(_ key: String) -> Bool {
        (try? storageFor(key).exists(key: key)) ?? false
    }

    func fileVersion(_ key: String) -> Int {
        (try? storageFor(key).getVersion(key: key)) ?? 0
    }

    /// Kotlin `clearFile`: the copy (and a pending one) and what was remembered about it.
    func clearFile(_ key: String) {
        do {
            try storageFor(key).clear(key: key)
        } catch {
            log.w("Could not clear vault file [\(key)]", error)
        }
        vaultGuard.forget(key)
    }

    // MARK: Start, periodic work, revocation

    /// Kotlin `executeInit`'s vault step: the device RSA key goes to every
    /// Config API (end_to_end files), the user-auth key to every Config API
    /// with a `user_auth` file. Never throws.
    func registerKeysAtStart() async {
        if let deviceKeys {
            let deviceId = deviceIdentity()?.id ?? "unknown"
            do {
                let pem = try deviceKeys.getPublicKeyPem()
                await router.registerDevicePublicKey(deviceId: deviceId, publicKeyPem: pem, files: config.orderedVaultFiles)
            } catch {
                log.w("Device public key registration partially failed", error)
            }
        }
        if userAuthKeys != nil {
            await router.registerUserAuthKeyEverywhere(deviceId: deviceIdentity()?.id ?? "")
        }
    }

    /// Kotlin `wipeStaleVaultFiles`: deletes every copy past its `maxOfflineAge`
    /// that asked for `wipeWhenStale()`. At start and on every periodic update.
    func wipeStaleFiles() {
        vaultGuard.sweep(config.orderedVaultFiles, storageFor: storageFor)
    }

    /// Kotlin `wipeVaultFilesOf`: deletes every stored file of `configApiIds`.
    /// The user-auth key goes only when no locked file is left anywhere; a new
    /// one is made and registered on the next fetch. Never throws.
    func wipeFiles(ofConfigApis configApiIds: Set<String>) {
        if configApiIds.isEmpty { return }
        let router = self.router
        VaultFileWipe.wipe(configApiIds, files: config.orderedVaultFiles, storageFor: storageFor, userAuthKeys: userAuthKeys) {
            router.forgetUserAuthRegistrations()
        }
        // What was remembered about the wiped copies goes with them.
        for file in config.orderedVaultFiles where configApiIds.contains(file.configApiId) { vaultGuard.forget(file.key) }
    }

    /// `wipeVaultFilesOnRevocation()`: the files of a Config API whose server
    /// said this device's identity is revoked.
    func wipeOnRevocation(_ configApiId: String) {
        if config.wipeVaultFilesOnRevocation { wipeFiles(ofConfigApis: [configApiId]) }
    }

    /// `unenroll(label:wipeVaultFiles: true)`: the files of every Config API
    /// that uses the certificate under `label` for mTLS.
    func wipeFiles(usingCertLabel label: String) {
        let ids = VaultFileWipe.mtlsBlocksUsing(label, blocks: config.orderedConfigApis, files: config.orderedVaultFiles)
        if ids.isEmpty { log.w("unenroll: no Config API uses [\(label)] for mTLS — no vault files wiped") }
        wipeFiles(ofConfigApis: ids)
    }

    // MARK: Helpers

    /// Runs `operation`, waiting at most `nanoseconds`; false when the time ran out (the operation is cancelled).
    static func withTimeout(_ nanoseconds: UInt64, _ operation: @escaping @Sendable () async -> Void) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await operation()
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: nanoseconds)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
    }
}
