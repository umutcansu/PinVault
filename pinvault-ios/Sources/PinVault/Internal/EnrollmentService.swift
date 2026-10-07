import Foundation
import Security

/// The enrollment half of the façade (Kotlin `PinVault.enroll*`,
/// `autoEnroll*`, `checkPendingEnrollment`, `isEnrolled*`,
/// `isEnrollmentPending*`, `enrollmentVerificationCode`,
/// `enrolledClientCN` / `enrolledClientNotAfter`, `identityKeySecurityLevel`,
/// the storage part of `unenroll`), apart from the façade's state: whatever it
/// needs is handed in, so `PinVault` only forwards to it.
///
/// - Local calls (no network) need only the ``Storage``.
/// - Enrollment needs a ``Target``: the config, the block, its API and — after
///   `start` — the SSL manager the new identity is loaded into.
///
/// Results, refusal reasons and log lines are the Kotlin ones; "Android
/// Keystore" reads "Keychain".
final class EnrollmentService: Sendable {

    /// Where the credentials live: the stores and the key factories.
    struct Storage: Sendable {
        /// The credential store (non-strict: an unreadable entry reads as absent).
        let openStore: @Sendable () throws -> ClientCertSecureStore
        /// The same store, strict (the enroll paths).
        let openStrictStore: @Sendable () throws -> ClientCertSecureStore
        /// The identity key behind the certificate stored under a label.
        let identityKeys: @Sendable (String) -> any ClientIdentityKeyProvider
        /// Where keys that arrive in a PKCS12 go.
        let importedKeys: any ImportedClientKeys
        /// `requireUnlockedDevice` / `requireHardwareBackedKeys` of the keys made here.
        let options: KeystoreOptions
        /// The encrypted stores the config's `requireUnlockedDevice` also applies to (nil: none).
        let stores: SecureStoreEnvironment?

        init(
            openStore: @escaping @Sendable () throws -> ClientCertSecureStore,
            openStrictStore: @escaping @Sendable () throws -> ClientCertSecureStore,
            identityKeys: @escaping @Sendable (String) -> any ClientIdentityKeyProvider,
            importedKeys: any ImportedClientKeys,
            options: KeystoreOptions,
            stores: SecureStoreEnvironment?
        ) {
            self.openStore = openStore
            self.openStrictStore = openStrictStore
            self.identityKeys = identityKeys
            self.importedKeys = importedKeys
            self.options = options
            self.stores = stores
        }

        /// The app's: `SecureStoreEnvironment.shared`, Secure Enclave keys, the Keychain.
        static let shared = Storage(
            openStore: { try ClientCertSecureStore.open() },
            openStrictStore: { try ClientCertSecureStore.openStrict() },
            identityKeys: { ClientIdentityKeys.secureEnclave(label: $0) },
            importedKeys: ImportedKeys.keychain(),
            options: .shared,
            stores: .shared
        )

        /// The credential stores of `environment` with the given keys (tests).
        static func on(
            _ environment: SecureStoreEnvironment,
            identityKeys: @escaping @Sendable (String) -> any ClientIdentityKeyProvider,
            importedKeys: any ImportedClientKeys,
            options: KeystoreOptions = KeystoreOptions()
        ) -> Storage {
            Storage(
                openStore: { try ClientCertSecureStore.open(environment: environment) },
                openStrictStore: { try ClientCertSecureStore.openStrict(environment: environment) },
                identityKeys: identityKeys,
                importedKeys: importedKeys,
                options: options,
                stores: environment
            )
        }
    }

    /// One Config API block's side of an enrollment.
    struct Target: Sendable {
        let config: PinVaultConfig
        /// The block that enrolls (the config's default block).
        let block: ConfigApiBlock
        /// The block's API. Called only when a request is sent: before start
        /// it builds a client for the block alone, the library's state untouched.
        let api: @Sendable () throws -> any CertificateConfigApi
        /// After start: where the new identity goes. Nil before start (the
        /// credential is stored; the next start loads it).
        let live: Live?
        /// The app's environment guard for ``GuardedOperation/enroll``; nil = allowed.
        let environmentRefusal: @Sendable () -> PinVaultError?

        struct Live: Sendable {
            /// The block's SSL manager: the new identity is loaded into it.
            let sslManager: DynamicSSLManager
            /// Rebuilds the sessions (the bootstrap client, the pinned clients)
            /// so the next handshake presents the new identity.
            let identityChanged: @Sendable () -> Void

            init(sslManager: DynamicSSLManager, identityChanged: @escaping @Sendable () -> Void) {
                self.sslManager = sslManager
                self.identityChanged = identityChanged
            }
        }

        init(
            config: PinVaultConfig,
            block: ConfigApiBlock,
            api: @escaping @Sendable () throws -> any CertificateConfigApi,
            live: Live?,
            environmentRefusal: @escaping @Sendable () -> PinVaultError? = { nil }
        ) {
            self.config = config
            self.block = block
            self.api = api
            self.live = live
            self.environmentRefusal = environmentRefusal
        }
    }

    static let noConfigApiBlock = ClientCertEnrollmentResult.failed(message: "The config has no Config API block")
    static let unknownDevice = "unknown-device"

    let storage: Storage
    private let deviceId: @Sendable () -> String?
    private let deviceModel: String
    private let appAttestation: EnrollmentAppAttestation.Source?
    private static let log = PinVaultLog.tag("PinVault")

    /// - Parameters:
    ///   - deviceId: the device id (`identifierForVendor`, lowercased); nil when the platform gives none.
    ///   - deviceModel: the alias sent when the config names none (`Build.MANUFACTURER + " " + Build.MODEL`).
    ///   - appAttestation: the App Attest attestation of a new enrollment request
    ///     for a client data hash (``EnrollmentAppAttestation``; L5's
    ///     `AppAttestBinder.attestation(clientDataHash:)`); nil = none is sent.
    init(
        storage: Storage = .shared,
        deviceId: @escaping @Sendable () -> String? = { DeviceIdentity.deviceId() },
        deviceModel: String = "\(DeviceInfo.manufacturer) \(DeviceInfo.model)",
        appAttestation: (@Sendable (Data) async -> String?)? = nil
    ) {
        self.storage = storage
        self.deviceId = deviceId
        self.deviceModel = deviceModel
        self.appAttestation = appAttestation
    }

    // MARK: Local (no network)

    /// The device id `autoEnroll` sends: the vendor id, or `unknown-device`.
    func autoEnrollDeviceId() -> String {
        let vendorId = deviceId()
        // The id itself stays out of the log: it identifies the device.
        Self.log.d("Auto-enrollment: device id available: \(vendorId != nil)")
        return vendorId ?? Self.unknownDevice
    }

    /// Whether a client certificate is stored under `label`.
    func isEnrolled(label: String) -> Bool {
        (try? storage.openStore().exists(label)) ?? false
    }

    /// Whether the default block of `config` has an enrolled client certificate. Usable before start.
    func isEnrolled(config: PinVaultConfig) -> Bool {
        applyOptions(config)
        return isEnrolled(label: config.defaultConfigApi?.clientCertLabel ?? PinVaultConfig.defaultCertLabel)
    }

    /// Whether an enrollment under `label` waits for approval and no certificate is stored yet.
    func isEnrollmentPending(label: String) -> Bool {
        guard let store = try? storage.openStore() else { return false }
        return !((try? store.exists(label)) ?? false) && ((try? store.loadPendingRequest(label)) ?? nil) != nil
    }

    /// ``isEnrollmentPending(label:)`` for the default block of `config`; usable before start.
    func isEnrollmentPending(config: PinVaultConfig) -> Bool {
        applyOptions(config)
        return isEnrollmentPending(label: config.defaultConfigApi?.clientCertLabel ?? PinVaultConfig.defaultCertLabel)
    }

    /// The verification code of the enrollment key under `label` (`4F7K-2QXM-9D3T-H6WP`); nil without one.
    func enrollmentVerificationCode(label: String) -> String? {
        let key = storage.identityKeys(label)
        do {
            return key.exists() ? try VerificationCode.of(publicKey: key.publicKey()) : nil
        } catch {
            Self.log.w("Could not read the enrollment key for its verification code", error)
            return nil
        }
    }

    /// Where the identity key under `label` lives; nil when there is none (nothing enrolled).
    func identityKeySecurityLevel(label: String) -> KeySecurityLevel? {
        let key = storage.identityKeys(label)
        return key.exists() ? key.securityLevel() : nil
    }

    /// The CN of the leaf stored under `label`, whichever form it is in.
    /// `p12Password`: what a stored PKCS12 opens with (Kotlin: the first block's `clientKeyPassword`).
    func enrolledClientCN(label: String, p12Password: String?) -> String? {
        guard let cn = enrolledLeaf(label: label, p12Password: p12Password)?.subject.commonName,
              !cn.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return cn
    }

    /// When the leaf stored under `label` expires, epoch ms.
    func enrolledClientNotAfter(label: String, p12Password: String?) -> Int64? {
        enrolledLeaf(label: label, p12Password: p12Password).map { ClientCertRenewer.millis($0.notAfter) }
    }

    /// The enrolled leaf certificate, whichever form it is stored in.
    func enrolledLeaf(label: String, p12Password: String?) -> X509Certificate? {
        do {
            let store = try storage.openStore()
            switch try store.mode(label) {
            case .chain:
                guard let pems = try store.loadChain(label) else { return nil }
                return try Pkcs10Csr.parsePemChain(pems).first
            case .imported:
                guard let pems = try store.loadImported(label) else { return nil }
                return try Pkcs10Csr.parsePemChain(pems).first
            case .p12:
                guard let p12 = try store.load(label), let p12Password else { return nil }
                return try ClientIdentity.fromPKCS12(p12, password: p12Password).leaf
            case .none:
                return nil
            }
        } catch {
            Self.log.w("enrolledLeaf: could not read the stored client certificate", error)
            return nil
        }
    }

    /// The storage part of `unenroll(label:)`: the stored credential (and a
    /// pending request), the identity key behind it — a re-enrollment is a new
    /// identity, not the old key with a new certificate — and a server-made
    /// key imported into the Keychain. Dropping the live identity from the SSL
    /// managers and rebuilding the sessions is the façade's.
    func forgetIdentity(label: String) {
        do {
            try storage.openStore().clear(label)
        } catch {
            Self.log.w("Could not delete the stored client credentials [\(label)]", error)
        }
        do {
            try storage.identityKeys(label).clear()
        } catch {
            Self.log.w("Could not delete the client identity key [\(label)]", error)
        }
        storage.importedKeys.delete(alias: ImportedKeys.aliasFor(label))
    }

    // MARK: Enrollment

    /// Enrollment through the block of a started library (Kotlin
    /// `enrollInternal`): with a one-time token / enrollment code (`token`),
    /// or with the device id (`deviceId`, `autoEnroll`), or neither (a pending
    /// request asking again). Stored under `label` (nil = the block's
    /// `clientCertLabel`), loaded into `target.live`.
    func enroll(token: String?, deviceId: String?, label: String?, target: Target) async -> ClientCertEnrollmentResult {
        if let refusal = target.environmentRefusal() { return .failed(message: refusal.message, cause: refusal) }
        let block = target.block
        let certLabel = label ?? block.clientCertLabel
        let stored: Bool
        do {
            stored = try hasStoredCredential(certLabel)
        } catch {
            return credentialStoreUnreadable(certLabel, error)
        }
        if stored {
            Self.log.d("Client cert already exists [\(certLabel)] — skipping enrollment")
            return .enrolled(alreadyEnrolled: true)
        }
        do {
            let enrolled = try await enrollAndStore(target: target, token: token, deviceId: deviceId, certLabel: certLabel)
            if let live = target.live {
                try load(enrolled, label: certLabel, block: block, into: live.sslManager)
                // Present the new identity on every client, the Config API's included.
                live.identityChanged()
            }
            return .enrolled(keySecurityLevel: enrolled.keySecurityLevel())
        } catch {
            return enrollmentFailure(error)
        }
    }

    /// Enrollment before start (Kotlin `enrollBeforeInit`): the first start of
    /// an app whose Config API is an mTLS listener. Goes to the block's
    /// `enrollmentUrl` through a client for the block alone; the credential is
    /// stored and the next start loads it.
    func enrollBeforeStart(token: String?, deviceId: String?, target: Target) async -> ClientCertEnrollmentResult {
        if let refusal = target.environmentRefusal() { return .failed(message: refusal.message, cause: refusal) }
        applyOptions(target.config)
        let block = target.block
        let certLabel = block.clientCertLabel
        let stored: Bool
        do {
            stored = try hasStoredCredential(certLabel)
        } catch {
            return credentialStoreUnreadable(certLabel, error)
        }
        if stored {
            Self.log.d("Client cert already exists [\(certLabel)] — skipping enrollment")
            return .enrolled(alreadyEnrolled: true)
        }
        // The same rule start applies: https and bootstrap pins, or an explicit opt-out.
        if let error = block.configurationError() { return .failed(message: error) }
        do {
            let enrolled = try await enrollAndStore(target: target, token: token, deviceId: deviceId, certLabel: certLabel)
            return .enrolled(keySecurityLevel: enrolled.keySecurityLevel())
        } catch {
            return enrollmentFailure(error)
        }
    }

    /// Asks whether a device told to wait has been approved (Kotlin
    /// `checkPendingEnrollment`), through a started library.
    func checkPendingEnrollment(target: Target) async -> ClientCertEnrollmentResult {
        if let shortcut = pendingCheckShortcut(target.block.clientCertLabel) { return shortcut }
        return await enroll(token: nil, deviceId: nil, label: nil, target: target)
    }

    /// ``checkPendingEnrollment(target:)`` before start.
    func checkPendingEnrollmentBeforeStart(target: Target) async -> ClientCertEnrollmentResult {
        applyOptions(target.config)
        if let shortcut = pendingCheckShortcut(target.block.clientCertLabel) { return shortcut }
        return await enrollBeforeStart(token: nil, deviceId: nil, target: target)
    }

    /// A device told to wait asks again on its own (Kotlin
    /// `pickUpPendingEnrollments`): at start (before the first config fetch,
    /// so an mTLS Config API is reachable once approved) and on every periodic
    /// update. Never throws.
    func pickUpPendingEnrollment(target: Target) async {
        let certLabel = target.block.clientCertLabel
        let waiting: Bool
        do {
            let store = try storage.openStrictStore()
            waiting = try !store.exists(certLabel) && store.loadPendingRequest(certLabel) != nil
        } catch {
            Self.log.w("Client credential store cannot be read right now [\(certLabel)] — pending enrollment not checked", error)
            return
        }
        guard waiting else { return }
        let result = await enroll(token: nil, deviceId: nil, label: nil, target: target)
        switch result {
        case .enrolled:
            Self.log.i("Enrollment approved — client certificate stored [\(certLabel)]")
        case .pending:
            Self.log.d("Enrollment still waits for approval [\(certLabel)]")
        case .failed(_, let cause?) where Self.isEnvironmentRefusal(cause):
            Self.log.w("Pending enrollment not checked: the environment guard refused it [\(certLabel)]")
        default:
            Self.log.w("Enrollment waiting for approval ended: \(result)")
        }
    }

    // MARK: Internals

    /// What an enrollment stored.
    enum Enrolled {
        /// A chain over the device's identity key.
        case chain(key: any ClientIdentityKeyProvider, certificates: [X509Certificate])
        /// A server-made key (`allowServerGeneratedKey()`), now in the Keychain.
        case imported(ClientIdentity)
        /// A server-made key the Keychain refused: kept as a PKCS12.
        case p12(Data)

        /// Where the private key of this enrollment lives.
        func keySecurityLevel() -> KeySecurityLevel {
            switch self {
            case .chain(let key, _): return key.securityLevel()
            case .imported(let identity): return KeyInspector.securityLevel(identity.identity)
            // A PKCS12 in app storage: software by definition.
            case .p12: return .software
            }
        }
    }

    /// Enrollment through `target`'s API, stored under `certLabel`: a CSR over
    /// a fresh Secure Enclave key answered with a certificate chain. Only a
    /// block that called `allowServerGeneratedKey()` also takes a key the
    /// server made (a P12 answer, or P12 enrollment when no key can be made
    /// here); that key is then imported into the Keychain. Throws on failure;
    /// stores nothing then.
    func enrollAndStore(target: Target, token: String?, deviceId: String?, certLabel: String) async throws -> Enrolled {
        applyOptions(target.config)
        let block = target.block
        // Strict: what EnrollmentRequests reads here decides whether a key may go.
        let certStore = try storage.openStrictStore()
        let identity = resolveDeviceIdentity(target.config)
        let key = storage.identityKeys(certLabel)
        // The device id this request carries: `deviceUid` on every path, and
        // `deviceId` alone when the device has no vendor id to send as one.
        let attestedId = identity?.uid ?? deviceId
        let challenge = attestedId.flatMap { $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0 }
            .map { ClientIdentityKeys.attestationChallenge(deviceUid: $0) }
        let api = try target.api()

        // A device told to wait for approval asks again by its request id (see EnrollmentRequests).
        let result = try await EnrollmentRequests.send(
            api: api, certStore: certStore, key: key, certLabel: certLabel, token: token, deviceId: deviceId,
            deviceAlias: identity?.alias, deviceUid: identity?.uid, allowServerGeneratedKey: block.allowServerGeneratedKey,
            integrity: target.config.integrityTokenProvider, appAttestation: appAttestation
        ) {
            do {
                try key.ensureKeyPair(attestationChallenge: challenge)
                return try Pkcs10Csr.encode(commonName: deviceId ?? identity?.uid ?? "device", key: key)
            } catch {
                // Only a block that asked for it falls back to a key the server makes.
                if !block.allowServerGeneratedKey {
                    throw PinVaultError.illegalState(
                        "This device could not create its key in the Keychain (\(Self.describe(error))), " +
                            "and the Config API block does not accept a key the server generates. Nothing was sent; the " +
                            "token is not spent. Call allowServerGeneratedKey() on the block only if such a key is acceptable."
                    )
                }
                Self.log.w("Could not build a CSR — asking the server for a key (allowServerGeneratedKey)", error)
                return nil
            }
        }

        if let chain = result.certificateChainPem {
            let certificates = try ClientCertRenewer.acceptIssuedChain(
                chain, key: key, expectedIssuer: nil, caPins: block.clientCaPins, maxLifetimeDays: block.maxClientCertLifetimeDays
            )
            try certStore.saveChain(certLabel, pemChain: chain)
            Self.log.d("Enrollment successful — certificate chain stored, valid until \(certificates[0].notAfter)")
            return .chain(key: key, certificates: certificates)
        }

        // Only reached with allowServerGeneratedKey(): the server made the key.
        let password = try acceptEnrolledP12(result, localPassword: block.clientKeyPassword)
        // No orphan identity key next to a server-made one — unless a chain
        // under this label is over it (never deleted then; see EnrollmentRequests).
        if EnrollmentRequests.mayDeleteKey(certStore: certStore, certLabel: certLabel) { try? key.clear() }
        let imported: ClientIdentity?
        do {
            imported = try ImportedIdentities(certStore: certStore, keys: storage.importedKeys)
                .import(label: certLabel, p12: result.p12Bytes, password: password)
        } catch {
            Self.log.w("The enrolled PKCS12 could not be read for import", error)
            imported = nil
        }
        if let imported {
            Self.log.d("Enrollment successful — server-made key imported into the Keychain, chain stored")
            return .imported(imported)
        }
        if result.p12Password != nil {
            // iOS cannot re-wrap a PKCS12 (no export API): one under a one-off
            // password would not open with the block's password later.
            throw PinVaultError.security(
                message: "The Keychain refused the server-made key, and its PKCS12 came with a one-off password, so it " +
                    "cannot be kept. Nothing was stored."
            )
        }
        try certStore.save(certLabel, p12: result.p12Bytes)
        Self.log.w("Enrollment successful — the Keychain refused the server-made key; stored as a PKCS12 (\(result.p12Bytes.count) bytes)")
        return .p12(result.p12Bytes)
    }

    /// Loads what an enrollment stored into `sslManager`.
    func load(_ enrolled: Enrolled, label: String, block: ConfigApiBlock, into sslManager: DynamicSSLManager) throws {
        switch enrolled {
        case .chain(let key, let certificates):
            sslManager.loadClientKey(try EnrolledIdentity.clientIdentity(key: key, label: label, chain: certificates))
        case .imported(let identity):
            sslManager.loadClientKey(identity)
        case .p12(let bytes):
            try sslManager.loadClientKeystore(bytes, password: block.clientKeyPassword)
        }
    }

    /// Checks an enrolled P12 (integrity hash, format) and returns the password
    /// it opens with: the one-off password the server sent (`X-P12-Password`,
    /// used here once and never stored), else the block's `clientKeyPassword`.
    /// (Android re-wraps the bundle to the block's password; iOS imports it
    /// into the Keychain instead.)
    func acceptEnrolledP12(_ result: EnrollmentResult, localPassword: String) throws -> String {
        let password = result.p12Password ?? localPassword
        try Self.validateP12(result.p12Bytes, serverHash: result.p12Hash, password: password)
        return password
    }

    /// Validates P12 bytes: requires the server-supplied SHA-256 and a PKCS12
    /// that opens. The hash header is mandatory — a MITM that drops it could
    /// otherwise inject a P12 with an attacker-controlled certificate (H-05).
    static func validateP12(_ p12: Data, serverHash: String?, password: String) throws {
        guard let serverHash, !serverHash.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PinVaultError.security(
                message: "Server did not provide X-P12-SHA256 header — refusing to install P12. " +
                    "The enrollment endpoint must return the SHA-256 of the P12 bytes so the " +
                    "client can detect transport-level tampering or header stripping."
            )
        }
        guard let expected = Base64.decode(serverHash) else {
            throw PinVaultError.security(message: "Invalid X-P12-SHA256 header — not valid Base64. Refusing to install P12.")
        }
        // Constant time: the header is attacker-controlled.
        guard Hashing.constantTimeEquals(Hashing.sha256(p12), expected) else {
            throw PinVaultError.security(message: "P12 integrity check failed — SHA-256 mismatch (transport corruption or tampering)")
        }
        log.d("P12 SHA-256 hash verified")
        let identity = try ClientIdentity.fromPKCS12(p12, password: password)
        log.d("P12 format validated — \(identity.chain.count) entries")
    }

    /// (deviceAlias, deviceUid): the config's alias or `Apple <model>`, and the
    /// vendor id. Nil when the platform gives no device id.
    private func resolveDeviceIdentity(_ config: PinVaultConfig) -> (alias: String, uid: String)? {
        guard let uid = deviceId() else { return nil }
        return (config.deviceAlias ?? deviceModel, uid)
    }

    /// True when a credential is stored under `certLabel`; throws when that cannot be told right now.
    private func hasStoredCredential(_ certLabel: String) throws -> Bool {
        try storage.openStrictStore().exists(certLabel)
    }

    /// Enrolled already, or nothing waiting: answered without asking the server.
    private func pendingCheckShortcut(_ certLabel: String) -> ClientCertEnrollmentResult? {
        do {
            let store = try storage.openStrictStore()
            if try store.exists(certLabel) { return .enrolled(alreadyEnrolled: true) }
            if try store.loadPendingRequest(certLabel) == nil { return .failed(message: "No enrollment is waiting for approval") }
            return nil
        } catch {
            return credentialStoreUnreadable(certLabel, error)
        }
    }

    /// The enroll paths read the credential store strictly: a credential that
    /// cannot be read right now must not look like none — a new enrollment
    /// would replace it, and a refused one may delete the key it was issued
    /// over. Nothing is sent then.
    private func credentialStoreUnreadable(_ certLabel: String, _ error: any Error) -> ClientCertEnrollmentResult {
        Self.log.e("Client credential store cannot be read right now [\(certLabel)] — not enrolling", error)
        return .failed(
            message: "The stored client credentials cannot be read right now (\(Self.describe(error))); nothing was sent — try again later",
            cause: error
        )
    }

    /// A refusal the app can act on (with the server's reason), or a failure to get an answer.
    func enrollmentFailure(_ error: any Error) -> ClientCertEnrollmentResult {
        if case let PinVaultError.enrollmentPending(requestId, clientId, message, retryAfterSeconds, code) = error {
            Self.log.i("Enrollment waits for an administrator's approval — request \(requestId)")
            return .pending(requestId: requestId, clientId: clientId, message: message, retryAfterSeconds: retryAfterSeconds, verificationCode: code)
        }
        Self.log.e("Enrollment failed", error)
        if case let PinVaultError.enrollmentRefused(httpStatus, serverError, message) = error {
            return .refused(
                reason: EnrollmentRefusal.from(httpStatus: httpStatus, serverError: serverError),
                httpStatus: httpStatus, serverError: serverError, message: message
            )
        }
        return .failed(message: ClientCertRenewer.message(error), cause: error)
    }

    private func applyOptions(_ config: PinVaultConfig) {
        storage.options.apply(config, stores: storage.stores)
    }

    private static func isEnvironmentRefusal(_ error: any Error) -> Bool {
        if case PinVaultError.untrustedEnvironment = error { return true }
        return false
    }

    /// `SimpleName: message`, as the Kotlin texts print `e.javaClass.simpleName: e.message`.
    static func describe(_ error: any Error) -> String {
        if let error = error as? PinVaultError { return "\(error.exceptionName): \(error.message)" }
        if let error = error as? ServerGeneratedKeyRefusedError { return "ServerGeneratedKeyRefusedException: \(error.message)" }
        return "\(type(of: error)): \(ClientCertRenewer.message(error))"
    }
}
