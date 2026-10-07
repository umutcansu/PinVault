import Foundation
import Security

/// Routes vault file fetches to the right Config API and applies per-file
/// decryption on the way back (Kotlin `VaultFileRouter`):
///
///   1. Look up `file.configApiId` among the clients.
///   2. Resolve the device id and access token from the file's access policy.
///   3. `downloadVaultFileWithMeta` on that Config API's ``CertificateConfigApi``.
///   4. `encryption = END_TO_END`: open the envelope with the device's RSA key.
///   5. `encryption = USER_AUTH`: make sure the server has the device's
///      user-auth key, and store the envelope sealed as it came: it is opened
///      (and its signature checked) only in `unlockFile`.
///   6. Verify signatures (fail closed), refuse downgrades and absurd versions,
///      persist through the file's ``VaultStorageProvider`` and return a
///      ``VaultFileResult``.
///
/// The distribution report is the caller's ( ``VaultService`` ) concern.
final class VaultFileRouter: Sendable {

    /// One Config API as the router sees it (Kotlin `ConfigApiClient`'s `api`,
    /// `block` and `signatureTrust`).
    struct Client: Sendable {
        let api: any CertificateConfigApi
        let block: ConfigApiBlock
        /// The block's trust (nil: it runs unsigned).
        let signatureTrust: SignatureTrust?

        var id: String { block.id }

        init(api: any CertificateConfigApi, block: ConfigApiBlock, signatureTrust: SignatureTrust?) {
            self.api = api
            self.block = block
            self.signatureTrust = signatureTrust
        }
    }

    /// The `error` of a server's 412 for a `user_auth` file it has no key for.
    static let userAuthKeyRequired = "user_auth_key_required"

    /// Largest accepted step of a file version over the stored one; the bound pin versions have.
    static let maxVersionJump: Int64 = 1_000_000

    private let clients: [String: Client]
    /// The clients in configuration order (registration goes to every one).
    private let clientOrder: [String]
    private let storageFor: @Sendable (String) -> any VaultStorageProvider
    private let deviceKeyProvider: (any DeviceKeyProvider)?
    private let deviceIdProvider: @Sendable () -> String
    /// The device's user-auth key; nil when no file uses `userAuth`.
    private let userAuthKeys: (any UserAuthKeys)?
    /// Every vault file of the config, for the key-replacement proof.
    private let files: @Sendable () -> [VaultFileConfig]
    /// Config API id → hex id of the user-auth key last registered there.
    private let registrations: any UserAuthRegistrations
    /// Keeps, per stored file, its signatures and when the server last confirmed it. Nil = not recorded.
    private let vaultGuard: VaultFileGuard?
    /// App Attest for the screen-lock key registration: client data hash → token
    /// JSON, or nil (simulator, unsupported, failure). Nil = never attested.
    private let appAttestation: (@Sendable (Data) async -> String?)?
    /// Serialises "make sure there is a key" + "register it": start registers in
    /// the background while the app may already fetch.
    private let userAuthRegistration = AsyncGate()
    private let log = PinVaultLog.tag("VaultFileRouter")

    init(
        clients: [Client],
        storageFor: @escaping @Sendable (String) -> any VaultStorageProvider,
        deviceKeyProvider: (any DeviceKeyProvider)?,
        deviceIdProvider: @escaping @Sendable () -> String,
        userAuthKeys: (any UserAuthKeys)? = nil,
        files: @escaping @Sendable () -> [VaultFileConfig] = { [] },
        registrations: any UserAuthRegistrations = UserAuthRegistrationsInMemory(),
        guard vaultGuard: VaultFileGuard? = nil,
        appAttestation: (@Sendable (Data) async -> String?)? = nil
    ) {
        var byId: [String: Client] = [:]
        var order: [String] = []
        for client in clients where byId[client.id] == nil {
            byId[client.id] = client
            order.append(client.id)
        }
        self.clients = byId
        self.clientOrder = order
        self.storageFor = storageFor
        self.deviceKeyProvider = deviceKeyProvider
        self.deviceIdProvider = deviceIdProvider
        self.userAuthKeys = userAuthKeys
        self.files = files
        self.registrations = registrations
        self.vaultGuard = vaultGuard
        self.appAttestation = appAttestation
    }

    // MARK: Fetch

    /// Performs the fetch. Does NOT send the distribution report.
    func fetchFile(_ file: VaultFileConfig) async -> VaultFileResult {
        guard let client = clients[file.configApiId] else {
            return .failed(
                key: file.key, reason: "VaultFile '\(file.key)' bound to unknown configApi '\(file.configApiId)'",
                code: VaultFileResult.FailureCode.notConfigured
            )
        }
        do {
            let storage = storageFor(file.key)
            let deviceId = deviceIdProvider()

            // Before the stored version is read: preparing may give up a copy
            // that was sealed for a key the server no longer has.
            let sealedByServer = file.encryption == .userAuth
            if sealedByServer, let failure = try await prepareUserAuth(file, storage, deviceId) { return failure }

            let currentVersion = try storage.getVersion(key: file.key)
            let userAuthStorage = storage as? UserAuthVaultStorage
            // A user_auth copy waiting in the pending slot counts for what the
            // server is asked; the downgrade and jump checks keep using the
            // verified copy's version, so nothing unverified raises the bar.
            var pendingVersion = 0
            if sealedByServer, let userAuthStorage { pendingVersion = try userAuthStorage.pendingVersion(file.key) }
            let knownVersion = max(currentVersion, pendingVersion)
            // A signed file stored without its signatures is downloaded again,
            // and so is a locked copy whose approved unlock failed for a reason
            // that may be the copy itself.
            let refetch = userAuthStorage?.needsFetch(file.key) == true
            let askedVersion: Int
            if currentVersion > 0, vaultGuard?.needsSignature(file, storedVerifier(file)) == true {
                log.i("Vault file [\(file.key)] has no signature on record — downloading it again")
                askedVersion = 0
            } else if currentVersion > 0 && refetch {
                log.i("Vault file [\(file.key)] did not open after an approved unlock — downloading it again")
                askedVersion = 0
            } else {
                askedVersion = knownVersion
            }

            // A blank provider result means "the host app has no token yet", not
            // "the token is the empty string": no `X-Vault-Token: ` header then.
            let token: String?
            switch file.accessPolicy {
            case .token, .tokenMtls:
                token = file.accessTokenProvider?().nonBlank
            default:
                token = nil
            }
            // Whether a token is sent, never any part of it.
            log.d("Vault fetch [\(file.key)] via \(file.accessPolicy.rawValue.lowercased()) (token present: \(token != nil))")

            let download: @Sendable () async throws -> VaultFetchResponse = {
                try await client.api.downloadVaultFileWithMeta(
                    endpoint: file.endpoint,
                    currentVersion: askedVersion,
                    deviceId: deviceId.nonBlank,
                    accessToken: token
                )
            }
            let response: VaultFetchResponse
            do {
                response = try await download()
            } catch let error as VaultFetchHTTPFailure {
                // The server has no (or another) user-auth key for this device:
                // make sure there is a key, register it, try once more.
                guard sealedByServer, error.httpStatus == 412,
                      error.responseBody?.contains(Self.userAuthKeyRequired) == true else { throw error }
                log.w("Vault fetch [\(file.key)]: server has no user-auth key for this device — registering and retrying")
                try await ensureUserAuthKeyRegistered(file.configApiId, deviceId: deviceId, force: true)
                response = try await download()
            }

            if response.notModified {
                vaultGuard?.confirmed(file)
                return .alreadyCurrent(key: file.key, version: knownVersion)
            }

            // The version header is only as good as the response: it must not
            // be able to plant a version so high that the real file is answered
            // "older" from then on.
            if let problem = versionJumpProblem(file.key, served: response.version, stored: currentVersion) {
                return .failed(key: file.key, reason: problem, code: VaultFileResult.FailureCode.versionRejected)
            }

            let served = VaultFileEncryption.allCases.first { $0.rawValue.caseInsensitiveCompare(response.encryption) == .orderedSame }
            if sealedByServer || served == .userAuth {
                return try storeSealedByServer(file, client, storage, currentVersion, response, served)
            }

            // Fail closed, as for user_auth: a file the app declared end_to_end
            // must not be taken as plain because the response says so.
            if file.encryption == .endToEnd, let served, served != .endToEnd {
                return .failed(
                    key: file.key,
                    reason: "Vault file '\(file.key)': the server answered encryption=\(response.encryption) for an end_to_end file; refused",
                    code: VaultFileResult.FailureCode.encryptionMismatch
                )
            }

            // Integrity (default-on, fail-closed): the signature covers the
            // PLAINTEXT, so an end_to_end envelope is checked once it is open;
            // an answer without the signatures the block requires is refused unopened.
            let trust = trustFor(file, client).flatMap { $0.isEnabled ? $0 : nil }
            let scope = client.block.serverScope
            let entries = trust != nil ? signatureEntries(response, scope) : []
            if trust != nil && entries.isEmpty {
                return .failed(key: file.key, reason: noSignatureMessage(file.key, scope), code: VaultFileResult.FailureCode.signatureMissing)
            }

            let plain: Data
            switch served ?? file.encryption {
            case .endToEnd:
                guard let keys = deviceKeyProvider else {
                    return .failed(
                        key: file.key, reason: "encryption=end_to_end requires DeviceKeyProvider; none configured",
                        code: VaultFileResult.FailureCode.notConfigured
                    )
                }
                try keys.ensureKeyPair()
                do {
                    plain = try VaultFileDecryptor.decrypt(response.content, privateKey: keys.getPrivateKey())
                } catch {
                    // One result for every way the envelope can fail; the
                    // exception goes to the local log only (no padding oracle).
                    log.e("E2E decrypt failed: \(file.key)", error)
                    return .failed(
                        key: file.key,
                        reason: "Vault file '\(file.key)': the end_to_end envelope did not open for this device's key; not saved",
                        exception: error, code: VaultFileResult.FailureCode.decryptFailed
                    )
                }
            default:
                plain = response.content
            }

            // Verify the PLAINTEXT BEFORE persisting; what the stored copy is
            // checked against again whenever it is read.
            var accepted: StoredSignatures?
            if let trust {
                let verification = try trust.verifyVaultFile(
                    key: file.key, version: response.version, plaintext: plain, entries: entries, serverScope: scope
                )
                accepted = StoredSignatures(version: response.version, scheme: Self.schemeOf(scope), entries: entries)
                if !verification.ok {
                    return .failed(
                        key: file.key,
                        reason: "Vault file '\(file.key)' signature verification FAILED — possible tampering. Not saved.\(verification.detail)",
                        code: VaultFileResult.FailureCode.signatureInvalid
                    )
                }
                // Downgrade guard: a validly-signed but OLDER version must not
                // overwrite a newer stored copy.
                if response.version >= 1 && response.version < currentVersion {
                    return .failed(
                        key: file.key, reason: downgradeMessage(file.key, served: response.version, stored: currentVersion),
                        code: VaultFileResult.FailureCode.versionRejected
                    )
                }
                log.d("Vault file signature verified ✓ [\(file.key)] v\(response.version)")
            } else {
                log.w("Vault file '\(file.key)' fetched WITHOUT signature verification " +
                    "(no signaturePublicKey / allowUnsigned). Set signaturePublicKey for integrity.")
            }

            // Persist. The same bytes again (a backend without version support,
            // or a policy change that bumped the version) are "already current".
            let storedBytes = try storage.load(key: file.key)
            if let storedBytes, storedBytes == plain {
                if let accepted, response.version > 0, response.version != currentVersion {
                    // Same content under a new version: keep the label the signature names.
                    try storage.save(key: file.key, bytes: plain, version: response.version)
                    vaultGuard?.stored(file, version: response.version, signatures: accepted)
                    return .alreadyCurrent(key: file.key, version: response.version)
                }
                // Signatures go on record here too.
                if let accepted { vaultGuard?.stored(file, version: currentVersion, signatures: accepted) } else { vaultGuard?.confirmed(file) }
                return .alreadyCurrent(key: file.key, version: currentVersion)
            }
            let newVersion = response.version > 0 ? response.version : currentVersion + 1
            try storage.save(key: file.key, bytes: plain, version: newVersion)
            vaultGuard?.stored(file, version: newVersion, signatures: accepted)
            log.d("Vault file updated [\(file.configApiId)]: \(file.key) v\(currentVersion) → v\(newVersion) " +
                "(\(plain.count) bytes, encryption=\(response.encryption))")
            // A locked file's content is only handed out by unlockFile.
            return .updated(key: file.key, version: newVersion, bytes: file.userAuth == .none ? plain : Data())
        } catch {
            // Expected HTTP 4xx answers (no file, invalid token, not allowed)
            // are not bugs: warn without the error. Network and 5xx are errors.
            let message = VaultErrorText.message(error)
            if message.range(of: #"HTTP 4\d{2}"#, options: .regularExpression) != nil {
                log.w("Vault fetch rejected [\(file.configApiId)]: \(file.key) — \(String(message.prefix(120)))")
            } else {
                log.e("Vault fetch failed [\(file.configApiId)]: \(file.key)", error)
            }
            return .failed(key: file.key, reason: message.isEmpty ? "Unknown error" : message, exception: error, code: Self.codeOf(error))
        }
    }

    /// The fixed class of a failure that ended in an error, for the distribution report. Never the text.
    static func codeOf(_ error: any Error) -> String {
        if let error = error as? VaultFetchHTTPFailure { return VaultFileResult.FailureCode.http(error.httpStatus) }
        if case PinVaultError.screenLockRequired = error { return VaultFileResult.FailureCode.screenLock }
        if error is VaultKeyRefusalFailure { return VaultFileResult.FailureCode.userAuthKey }
        if error is VaultResponseTooLargeFailure { return VaultFileResult.FailureCode.responseTooLarge }
        if VaultErrorText.isNetwork(error) { return VaultFileResult.FailureCode.network }
        return VaultFileResult.FailureCode.other
    }

    /// Before a `user_auth` download: a passcode, a device id and a registered
    /// user-auth key. Returns the failure, or nil to go ahead.
    private func prepareUserAuth(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, _ deviceId: String) async throws -> VaultFileResult? {
        guard let storage = storage as? UserAuthVaultStorage, let keys = userAuthKeys else {
            return .failed(
                key: file.key, reason: "Vault file '\(file.key)': encryption(USER_AUTH) needs userAuth(REQUIRED or IF_SCREEN_LOCK)",
                code: VaultFileResult.FailureCode.notConfigured
            )
        }
        if !keys.isScreenLockSet() {
            let error: PinVaultError = file.userAuth == .required
                ? .screenLockRequired(key: file.key)
                : .screenLockRequired(
                    key: file.key,
                    message: "Vault file '\(file.key)' is sealed by the server for the screen lock (encryption = USER_AUTH) and the " +
                        "device has none, so it cannot be received; IF_SCREEN_LOCK cannot store this one unlocked"
                )
            return .failed(key: file.key, reason: error.message, exception: error, code: VaultFileResult.FailureCode.screenLock)
        }
        if deviceId.isBlank {
            return .failed(
                key: file.key, reason: "Vault file '\(file.key)': user_auth files need a device id (X-Device-Id); none is available",
                code: VaultFileResult.FailureCode.notConfigured
            )
        }
        do {
            try await ensureUserAuthKeyRegistered(file.configApiId, deviceId: deviceId)
        } catch {
            // A request that did not complete is a network failure; any answer is the server's refusal of the key.
            let transport = VaultErrorText.isNetwork(error) || error is VaultResponseTooLargeFailure
            return .failed(
                key: file.key,
                reason: "Vault file '\(file.key)': could not register the user-auth key with '\(file.configApiId)': \(VaultErrorText.message(error))",
                exception: error,
                code: transport ? Self.codeOf(error) : VaultFileResult.FailureCode.userAuthKey
            )
        }
        // A copy sealed for a key other than the one the server has now can
        // never open, and the server would answer "already current" to its
        // version: give it up so this fetch downloads the file again.
        let registered = registrations.get(file.configApiId)
        let stamp = try storage.sealedKeyId(file.key).map(Hex.encode)
        if let stamp, let registered, stamp != registered {
            log.w("Vault file [\(file.key)] was sealed for user-auth key \(stamp), the server now has \(registered) — downloading it again")
            try storage.clear(key: file.key)
        } else if let pendingStamp = try storage.pendingSealedKeyId(file.key).map(Hex.encode),
                  let registered, pendingStamp != registered {
            // The same for a copy waiting in the pending slot, on its own.
            log.w("Vault file [\(file.key)]: the pending copy was sealed for user-auth key \(pendingStamp), the server now has \(registered) — dropped")
            try storage.clearPending(file.key)
        }
        return nil
    }

    /// Stores a `user_auth` response as it came. Nothing is decrypted or
    /// verified here, but a missing signature and an older version are refused now.
    private func storeSealedByServer(
        _ file: VaultFileConfig,
        _ client: Client,
        _ storage: any VaultStorageProvider,
        _ currentVersion: Int,
        _ response: VaultFetchResponse,
        _ served: VaultFileEncryption?
    ) throws -> VaultFileResult {
        if file.encryption != .userAuth {
            return .failed(
                key: file.key,
                reason: "Vault file '\(file.key)': the server sent a user_auth file, but the app did not declare encryption(USER_AUTH)",
                code: VaultFileResult.FailureCode.encryptionMismatch
            )
        }
        if served != .userAuth {
            // Fail closed: a copy not sealed for the passcode would put the
            // content in the app's hands without the prompt.
            return .failed(
                key: file.key,
                reason: "Vault file '\(file.key)': the server answered encryption=\(response.encryption) for a user_auth file; refused",
                code: VaultFileResult.FailureCode.encryptionMismatch
            )
        }
        let trust = trustFor(file, client)
        // The signatures the copy is checked with at unlock: v2 when the block
        // names its server-side Config API, else v1.
        let scope = client.block.serverScope
        let enabled = trust?.isEnabled == true
        let entries = enabled ? signatureEntries(response, scope) : signatureEntries(response, nil)
        if enabled && entries.isEmpty {
            return .failed(key: file.key, reason: noSignatureMessage(file.key, scope), code: VaultFileResult.FailureCode.signatureMissing)
        }
        if response.version >= 1 && response.version < currentVersion {
            return .failed(
                key: file.key, reason: downgradeMessage(file.key, served: response.version, stored: currentVersion),
                code: VaultFileResult.FailureCode.versionRejected
            )
        }
        guard let userAuthStorage = storage as? UserAuthVaultStorage else {
            return .failed(
                key: file.key, reason: "Vault file '\(file.key)': encryption(USER_AUTH) needs userAuth(REQUIRED or IF_SCREEN_LOCK)",
                code: VaultFileResult.FailureCode.notConfigured
            )
        }
        let refetch = userAuthStorage.needsFetch(file.key)
        if response.version > 0, response.version == currentVersion, try storage.exists(key: file.key), !refetch {
            vaultGuard?.confirmed(file)
            return .alreadyCurrent(key: file.key, version: currentVersion)
        }
        let newVersion = response.version > 0 ? response.version : currentVersion + 1
        // Stamped with the key the server was given (and sealed for).
        let sealedFor = registrations.get(file.configApiId).flatMap(Hex.decode)
        let pending = try userAuthStorage.saveSealedByServer(
            file.key, envelope: response.content, version: newVersion, signatures: entries, sealedFor: sealedFor
        )
        if pending {
            vaultGuard?.pendingStored(file)
            log.d("Vault file stored sealed [\(file.configApiId)]: \(file.key) v\(newVersion) waits in the pending slot beside " +
                "v\(currentVersion) (user_auth, verified at unlockFile)")
            return .updated(key: file.key, version: newVersion, bytes: Data())
        }
        vaultGuard?.stored(file, version: newVersion, signatures: nil)
        log.d("Vault file stored sealed [\(file.configApiId)]: \(file.key) v\(currentVersion) → v\(newVersion) (user_auth, opens with unlockFile)")
        return .updated(key: file.key, version: newVersion, bytes: Data())
    }

    // MARK: User-auth key registration

    /// Makes sure Config API `configApiId` has this device's user-auth key: a
    /// key exists (made now if there was none) and was registered there.
    /// `force` registers again anyway (the server said it has none). Throws when that fails.
    func ensureUserAuthKeyRegistered(_ configApiId: String, deviceId: String, force: Bool = false) async throws {
        await userAuthRegistration.lock()
        defer { userAuthRegistration.unlock() }
        guard let keys = userAuthKeys else { throw PinVaultError.illegalState("No user-auth key: no vault file uses userAuth") }
        let generated = try keys.ensureKey()
        let publicKey = try keys.publicKey()
        let keyId = Hex.encode(try UserAuthKeyConstants.keyId(publicKey))
        if !force && !generated && registrations.get(configApiId) == keyId { return }
        guard let client = clients[configApiId] else { throw PinVaultError.illegalState("Unknown Config API '\(configApiId)'") }
        let pem = try SPKI.pem(for: publicKey)
        // Leaf first; always empty on iOS (no key attestation).
        let chain: [String]
        do {
            chain = try keys.attestationChain().map(Base64.encode)
        } catch {
            log.w("Could not read the user-auth key's attestation chain; registering without", error)
            chain = []
        }
        var attested = false
        if let api = client.api as? any VaultKeyProofRegistering {
            // App Attest stands in for the Android chain (PORTING.md §6): a fresh
            // attestation bound to this device id and this key.
            let token = await appAttestationToken(deviceId: deviceId, publicKey: publicKey)
            attested = token != nil
            try await api.registerUserAuthPublicKey(
                deviceId: deviceId, publicKeyPem: pem, attestationChain: chain, proof: keyProof(configApiId, files()),
                appAttestation: token
            )
        } else {
            try await client.api.registerUserAuthPublicKey(deviceId: deviceId, publicKeyPem: pem, attestationChain: chain)
        }
        registrations.put(configApiId, keyId)
        log.d("User-auth key \(keyId) registered with [\(configApiId)] (attestation chain: \(chain.count), App Attest: \(attested))")
    }

    /// The App Attest token for registering `publicKey` from `deviceId`, or nil.
    private func appAttestationToken(deviceId: String, publicKey: SecKey) async -> String? {
        guard let appAttestation else { return nil }
        let spki: Data
        do {
            spki = try SPKI.der(for: publicKey)
        } catch {
            log.w("Could not encode the user-auth key for App Attest; registering without", error)
            return nil
        }
        let token = await appAttestation(UserAuthKeyAppAttest.clientDataHash(deviceId: deviceId, spki: spki))
        if token == nil { log.w("No App Attest attestation for the user-auth key; registering without") }
        return token
    }

    /// Registers the user-auth key with every Config API that has a
    /// `user_auth` file (at start). Needs a passcode; never throws.
    func registerUserAuthKeyEverywhere(deviceId: String) async {
        guard let keys = userAuthKeys else { return }
        var ids: [String] = []
        for file in files() where file.encryption == .userAuth && !ids.contains(file.configApiId) { ids.append(file.configApiId) }
        if ids.isEmpty || deviceId.isBlank { return }
        if !keys.isScreenLockSet() {
            log.w("No screen lock — user_auth files cannot be received until one is set")
            return
        }
        for id in ids {
            do {
                try await ensureUserAuthKeyRegistered(id, deviceId: deviceId)
            } catch {
                log.w("User-auth key registration failed on [\(id)]", error)
            }
        }
    }

    /// After the key is deleted (a wipe): register again before the next `user_auth` fetch.
    func forgetUserAuthRegistrations() { registrations.clear() }

    /// After a copy of `configApiId` turned out to be sealed for another key:
    /// register again before its next `user_auth` fetch.
    func forgetUserAuthRegistration(_ configApiId: String) { registrations.remove(configApiId) }

    // MARK: Verification at read time

    /// What `unlockFile` checks a server-sealed copy with once it is open: the
    /// same trust the fetch path uses. For a Config API that runs unsigned it
    /// checks nothing and logs a warning. Nil only when the file's Config API is
    /// unknown — the caller then refuses to open the copy (fail closed).
    func unlockVerifier(_ file: VaultFileConfig) -> UnlockVerifier? {
        guard clients[file.configApiId] != nil else {
            log.e("Vault file '\(file.key)' is bound to unknown Config API '\(file.configApiId)'; it is not opened")
            return nil
        }
        guard let verifier = storedVerifier(file) else {
            let log = self.log
            let key = file.key
            return { _, _, _ in
                log.w("Vault file '\(key)' opened WITHOUT signature verification (allowUnsigned).")
                return nil
            }
        }
        return verifier.verify
    }

    /// How a stored copy of `file` is checked when it is read: with the trust
    /// of its Config API (or the file's own key), against v2 signatures when
    /// the block set `serverScope`, else v1. Nil when the block runs unsigned (or is unknown).
    func storedVerifier(_ file: VaultFileConfig) -> StoredVerifier? {
        guard let client = clients[file.configApiId], let trust = trustFor(file, client), trust.isEnabled else { return nil }
        let scope = client.block.serverScope
        let key = file.key
        return StoredVerifier(scheme: Self.schemeOf(scope)) { plaintext, version, entries in
            if entries.isEmpty { return "it carries no signature but a verifying key is configured" }
            let verification = try trust.verifyVaultFile(key: key, version: version, plaintext: plaintext, entries: entries, serverScope: scope)
            return verification.ok ? nil : "signature verification failed — possible tampering.\(verification.detail)"
        }
    }

    private func trustFor(_ file: VaultFileConfig, _ client: Client) -> SignatureTrust? {
        file.signaturePublicKey.map { SignatureTrust.single(configApiId: file.configApiId, key: $0) } ?? client.signatureTrust
    }

    /// The signatures of the scheme the block verifies: the v2 headers when it
    /// has a server scope, the v1 headers otherwise. Never one for the other.
    private func signatureEntries(_ response: VaultFetchResponse, _ serverScope: String?) -> [SignatureEntry] {
        let several = serverScope != nil ? response.signaturesV2 : response.signatures
        let single = serverScope != nil ? response.signatureV2 : response.signature
        if let several, !several.isEmpty { return several }
        if let single, !single.isBlank { return [SignatureEntry(signature: single)] }
        return []
    }

    private static func schemeOf(_ serverScope: String?) -> Int { serverScope != nil ? 2 : 1 }

    private func noSignatureMessage(_ key: String, _ serverScope: String?) -> String {
        if let serverScope {
            return "Vault file '\(key)' carries no X-Vault-Signature-V2, which this Config API block requires " +
                "(serverScope '\(serverScope)': the signature must name the Config API) — refusing (fail-closed)."
        }
        return "Vault file '\(key)' carries no X-Vault-Signature but a verifying key is configured — refusing (fail-closed)."
    }

    /// Why a served version is not believable, or nil: more than
    /// ``maxVersionJump`` above the stored one (or above zero for a first copy).
    private func versionJumpProblem(_ key: String, served: Int, stored: Int) -> String? {
        guard Int64(served) - Int64(max(stored, 0)) > Self.maxVersionJump else { return nil }
        return "Vault file '\(key)' refused: served v\(served) is more than \(Self.maxVersionJump) above stored v\(stored)."
    }

    private func downgradeMessage(_ key: String, served: Int, stored: Int) -> String {
        "Vault file '\(key)' downgrade rejected: served v\(served) < stored v\(stored)."
    }

    // MARK: Reports and E2E keys

    /// Asks the bound Config API to record the outcome. Never throws.
    func report(_ file: VaultFileConfig, _ report: VaultDownloadReport) async {
        guard let client = clients[file.configApiId] else { return }
        do {
            try await client.api.reportVaultDownload(report)
        } catch {
            log.e("Report send failed [\(file.configApiId)]: \(file.key)", error)
        }
    }

    /// Registers this device's RSA public key with EVERY Config API (E2E).
    /// A TLS listener keeps the first key it was given; replacing it needs the
    /// device's token for one of that API's end_to_end / user_auth files, so
    /// one goes along when `files` has it. Never throws.
    func registerDevicePublicKey(deviceId: String, publicKeyPem: String, files: [VaultFileConfig] = []) async {
        for id in clientOrder {
            guard let client = clients[id] else { continue }
            do {
                if let api = client.api as? any VaultKeyProofRegistering {
                    try await api.registerDevicePublicKey(deviceId: deviceId, publicKeyPem: publicKeyPem, proof: keyProof(id, files))
                } else {
                    try await client.api.registerDevicePublicKey(deviceId: deviceId, publicKeyPem: publicKeyPem)
                }
            } catch {
                log.w("Public-key registration failed on [\(id)]", error)
            }
        }
    }

    /// The device's token for an end_to_end or user_auth file of Config API
    /// `configApiId`, or nil when the app has none (yet). The server-side key is
    /// the last segment of the file's endpoint.
    func keyProof(_ configApiId: String, _ files: [VaultFileConfig]) -> VaultDeviceKeyProof? {
        for file in files where file.configApiId == configApiId
            && (file.encryption == .endToEnd || file.encryption == .userAuth)
            && (file.accessPolicy == .token || file.accessPolicy == .tokenMtls) {
            guard let token = file.accessTokenProvider?(), !token.isBlank else { continue }
            let path = String(file.endpoint.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            let trimmed = String(path.reversed().drop { $0 == "/" }.reversed())
            let key = trimmed.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? ""
            if key.isEmpty { continue }
            return VaultDeviceKeyProof(vaultKey: key, token: token)
        }
        return nil
    }
}

fileprivate extension String {
    /// Kotlin `takeIf { it.isNotBlank() }`.
    var nonBlank: String? { isBlank ? nil : self }
}
