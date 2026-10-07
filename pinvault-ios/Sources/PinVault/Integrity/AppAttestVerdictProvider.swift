import Foundation

/// Apple App Attest as the attestation report's second opinion
/// (`ATTESTATION.md` §12, `PORTING.md` §6): Apple's word that the report
/// comes from your unmodified app on a genuine Apple device, verified by the
/// PinVault server against Apple's App Attestation Root CA.
///
/// The first round of a Config API block generates an App Attest key and
/// sends its attestation; later rounds send assertions by that key. Both are
/// bound to the round with the client data hash
/// `SHA-256("pinvault-app-attest:v1:" + nonce + ":" + deviceId)`. When the
/// server answers `app_attest_unknown_key` (it forgot the device, or never
/// saw the attestation), the key is dropped and a new one attested on the
/// next round. Key ids are kept in the library's encrypted preferences.
///
/// PinVault uses this provider on its own when the app registers no
/// ``IntegrityVerdictProvider``. It answers nil — the report then carries no
/// verdict — where `DCAppAttestService.isSupported` is false (the simulator,
/// devices without a Secure Enclave) and, for the rest of the process, after
/// App Attest said the app cannot use it (missing App Attest capability).
///
/// ```swift
/// .integrityVerdictProvider(AppAttestVerdictProvider())
/// ```
public final class AppAttestVerdictProvider: IntegrityVerdictProvider, Sendable {

    /// The key state of one block, as stored.
    enum KeyState: String, Sendable {
        /// Generated; no attestation made yet (Apple's server was unavailable).
        case generated
        /// The attestation went out with a report; no verdict has confirmed it yet.
        case sent
        /// A verdict answered a round that carried the attestation: assertions from now on.
        case confirmed
    }

    /// The block name the plain ``verdict(nonce:)`` keeps its key under.
    static let defaultScope = "default"
    static let unknownKeyWarning = "app_attest_unknown_key"
    static let prefsFileName = "pinvault_app_attest"
    static let prefsNamespace = "keys"

    private let service: any AppAttestService
    private let store: @Sendable () -> (any PreferenceStore)?
    private let deviceId: @Sendable () -> String?
    /// Set when App Attest said this app or device cannot use it: nil for the rest of the process.
    private let disabled = Locked<Bool>(false)
    private let log = PinVaultLog.tag("AppAttestVerdictProvider")

    /// The provider over `DCAppAttestService.shared`.
    public convenience init() {
        let opened = Locked<(any PreferenceStore)??>(nil)
        let log = PinVaultLog.tag("AppAttestVerdictProvider")
        self.init(
            service: DeviceCheckAppAttestService(),
            store: {
                opened.withLock { cached in
                    if let cached { return cached }
                    let store: (any PreferenceStore)?
                    do {
                        store = try SecurePreferences.open(
                            fileName: AppAttestVerdictProvider.prefsFileName,
                            namespace: AppAttestVerdictProvider.prefsNamespace
                        )
                    } catch {
                        // Without the store a key is kept for this process only.
                        log.w("App Attest: the key store cannot be opened — keys are kept in memory", error)
                        store = InMemoryPreferences()
                    }
                    cached = .some(store)
                    return store
                }
            },
            deviceId: { DeviceIdentity.deviceId() }
        )
    }

    /// - Parameters:
    ///   - service: the App Attest calls (a fake in tests).
    ///   - store: where key ids are kept; nil = in memory.
    ///   - deviceId: the device id the plain ``verdict(nonce:)`` binds to.
    init(
        service: any AppAttestService,
        store: @escaping @Sendable () -> (any PreferenceStore)?,
        deviceId: @escaping @Sendable () -> String? = { DeviceIdentity.deviceId() }
    ) {
        self.service = service
        let memory = InMemoryPreferences()
        self.store = { store() ?? memory }
        self.deviceId = deviceId
    }

    /// The verdict for a round of the default block, bound to `nonce` and
    /// this device's id (`identifierForVendor`, as the library sends it).
    public func verdict(nonce: String) async throws -> IntegrityVerdict? {
        try await verdict(nonce: nonce, deviceId: AttestationManager.resolveDeviceId(deviceId()), scope: Self.defaultScope)
    }

    // MARK: Key state

    private func keyIdName(_ scope: String) -> String { "key_id.\(scope)" }
    private func stateName(_ scope: String) -> String { "key_state.\(scope)" }

    /// The block's key id and its state; nil without a key.
    func key(scope: String) -> (keyId: String, state: KeyState)? {
        guard let store = store() else { return nil }
        do {
            guard let keyId = try store.getString(keyIdName(scope), nil), !keyId.isEmpty else { return nil }
            let state = KeyState(rawValue: try store.getString(stateName(scope), nil) ?? "") ?? .generated
            return (keyId, state)
        } catch {
            log.w("App Attest: the key of [\(scope)] cannot be read — making a new one", error)
            return nil
        }
    }

    private func save(scope: String, keyId: String?, state: KeyState?) {
        guard let store = store() else { return }
        do {
            try store.edit()
                .putString(keyIdName(scope), keyId)
                .putString(stateName(scope), state?.rawValue)
                .commit()
        } catch {
            log.w("App Attest: the key of [\(scope)] cannot be stored", error)
        }
    }

    /// Forgets the block's key: the next round attests a new one.
    func dropKey(scope: String) {
        save(scope: scope, keyId: nil, state: nil)
    }
}

extension AppAttestVerdictProvider: AttestationRoundVerdictProvider {

    func verdict(nonce: String, deviceId: String, scope: String) async throws -> IntegrityVerdict? {
        guard !disabled.get(), service.isSupported else { return nil }
        let clientDataHash = AppAttestToken.roundClientDataHash(nonce: nonce, deviceId: deviceId)
        do {
            if let stored = key(scope: scope), stored.state == .confirmed {
                let keyId = stored.keyId
                do {
                    let assertion = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
                    return IntegrityVerdict(name: AppAttestToken.provider, token: AppAttestToken.assertion(keyId: keyId, object: assertion))
                } catch AppAttestServiceError.invalidKey {
                    // The key is gone (restored to another device, reset): attest a new one now.
                    log.w("App Attest: the key of [\(scope)] is no longer valid — attesting a new one")
                    dropKey(scope: scope)
                }
            }
            return try await attest(clientDataHash: clientDataHash, scope: scope)
        } catch AppAttestServiceError.featureUnsupported {
            disabled.set(true)
            log.w("App Attest is not available to this app (featureUnsupported) — attesting without it from now on")
            return nil
        }
    }

    /// A new key's attestation — or the stored key's, when it was generated
    /// but never attested (Apple's server was unavailable). A key whose
    /// attestation went out without a verdict confirming it is replaced: the
    /// server may never have seen it.
    private func attest(clientDataHash: Data, scope: String) async throws -> IntegrityVerdict? {
        let keyId: String
        if let stored = key(scope: scope), stored.state == .generated {
            keyId = stored.keyId
        } else {
            keyId = try await service.generateKey()
            save(scope: scope, keyId: keyId, state: .generated)
        }
        do {
            let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)
            save(scope: scope, keyId: keyId, state: .sent)
            return IntegrityVerdict(name: AppAttestToken.provider, token: AppAttestToken.attestation(keyId: keyId, object: attestation))
        } catch AppAttestServiceError.serverUnavailable {
            // Apple asks to retry later with the same key.
            log.w("App Attest: Apple's server is unavailable — the key of [\(scope)] is attested next round")
            return nil
        } catch {
            if (error as? AppAttestServiceError) != .featureUnsupported { dropKey(scope: scope) }
            throw error
        }
    }

    func roundAnswered(scope: String, warnings: [String], rejectionReasons: [String]) {
        if warnings.contains(Self.unknownKeyWarning) || rejectionReasons.contains(Self.unknownKeyWarning) {
            log.w("App Attest: the server does not know the key of [\(scope)] — attesting a new one next round")
            dropKey(scope: scope)
            return
        }
        if let stored = key(scope: scope), stored.state == .sent {
            save(scope: scope, keyId: stored.keyId, state: .confirmed)
        }
    }
}
