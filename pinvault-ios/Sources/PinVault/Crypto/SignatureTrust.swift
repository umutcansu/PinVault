import Foundation

/// Which keys a Config API block trusts to sign its configs and vault files,
/// how many of them have to sign, and how that list changes over the air.
///
/// Three layers, each optional and off unless the block configures it:
///
/// 1. **Several trusted keys** (`signaturePublicKeys`). One valid signature is
///    enough. Ship an offline backup key in the app and the backend can switch
///    to it — after the primary is lost or stolen — without an app update.
/// 2. **m-of-n** (`requiredSignatures`). A config needs valid signatures from
///    that many DISTINCT trusted keys.
/// 3. **Signing-key sets** (`recoveryPublicKeys`). Offline recovery keys sign
///    a versioned list of signing keys. A device applies a list newer than the
///    one it holds and from then on trusts exactly that list, which is how a
///    signing key is rotated or REVOKED without an app update. Recovery keys
///    never sign configs, a set may not name one as a signing key, and a
///    stolen signing key cannot produce a set.
///
/// Keys are compared in canonical form (parsed and re-encoded), never as the
/// text they were configured with: two spellings of one key must not count as
/// two signers. With none of the layers configured this behaves exactly like
/// the single `signaturePublicKey` check it replaces.
///
/// Every read of the trusted keys may throw
/// ``PinVaultError/storeUnreadable(message:cause:)``: the applied key set
/// cannot be read right now, which is "cannot tell", never "no set".
final class SignatureTrust: Sendable {
    static let keySetType = "pinvault-signing-keys"
    /// Signature entries looked at per document; the rest are ignored.
    private static let maxEntries = 16
    /// Keys a signing-key set may list.
    private static let maxSetKeys = 32

    /// Outcome of a signature check.
    struct Verification: Sendable, Equatable {
        let ok: Bool
        /// Key ids whose signatures verified.
        let signedBy: [String]
        let required: Int
        /// Empty when ``ok``; otherwise a sentence (with a leading space) explaining why.
        let detail: String
    }

    private struct KeySet: Sendable, Equatable {
        let version: Int
        let keys: [String]
        let requiredSignatures: Int
    }

    private struct State {
        /// Opened on first use; a failed open is not remembered.
        var store: SigningKeyStore?
        var storeOpened = false
        /// Verified copy of the stored key set; nil = the compiled-in keys apply.
        var activeSet: KeySet?
        var activeSetLoaded = false
        var lastSignedBy: [String] = []
    }

    let configApiId: String
    private let builtInKeys: [String]
    private let builtInThreshold: Int
    private let recoveryKeys: [String]
    private let recoveryThreshold: Int
    /// The block's `serverScope`. A signing-key set whose payload names a
    /// `configApiId` is applied only when it names this one; a set that names
    /// none is accepted (the field is optional; older sets do not carry it).
    private let serverScope: String?
    private let storeProvider: @Sendable () throws -> SigningKeyStore?
    /// From the keys as configured, not as parsed: a block whose keys are all
    /// malformed must fail closed (nothing verifies), not look unsigned.
    private let configured: Bool
    private let state = Locked(State())
    private let keyIds = Locked<[String: String]>([:])
    /// The newest key set this device applied and the anchors it was applied
    /// under, kept outside the container (``CertificateConfigStore/keySetFloor()``).
    private let floorProvider = Locked<(@Sendable () throws -> KeySetFloor?)?>(nil)
    private let log = PinVaultLog.tag("SignatureTrust")

    init(
        configApiId: String,
        builtInKeys: [String],
        builtInThreshold: Int,
        recoveryKeys: [String],
        recoveryThreshold: Int,
        serverScope: String? = nil,
        storeProvider: @escaping @Sendable () throws -> SigningKeyStore?
    ) {
        self.configApiId = configApiId
        self.serverScope = serverScope
        self.storeProvider = storeProvider
        self.configured = builtInKeys.contains { !$0.isBlank }
        let log = PinVaultLog.tag("SignatureTrust")
        let signing = Self.canonicalize(builtInKeys, role: "signing", configApiId: configApiId, log: log)
        self.builtInKeys = signing
        self.builtInThreshold = max(builtInThreshold, 1)
        self.recoveryKeys = Self.canonicalize(recoveryKeys, role: "recovery", configApiId: configApiId, log: log).filter { key in
            let distinct = !signing.contains(key)
            if !distinct {
                log.e("Config API '\(configApiId)': a recovery key is also a signing key — ignoring it as a recovery key")
            }
            return distinct
        }
        self.recoveryThreshold = max(recoveryThreshold, 1)
    }

    /// For tests and callers that already hold the store.
    convenience init(
        configApiId: String,
        builtInKeys: [String],
        builtInThreshold: Int,
        recoveryKeys: [String],
        recoveryThreshold: Int,
        store: SigningKeyStore?,
        serverScope: String? = nil
    ) {
        self.init(
            configApiId: configApiId, builtInKeys: builtInKeys, builtInThreshold: builtInThreshold,
            recoveryKeys: recoveryKeys, recoveryThreshold: recoveryThreshold, serverScope: serverScope,
            storeProvider: { store }
        )
    }

    /// The trust a block's configuration asks for, or nil when it runs unsigned.
    static func forBlock(_ block: ConfigApiBlock, storeProvider: @escaping @Sendable () throws -> SigningKeyStore?) -> SignatureTrust? {
        let keys = block.effectiveSignatureKeys()
        if keys.isEmpty { return nil }
        return SignatureTrust(
            configApiId: block.id,
            builtInKeys: keys,
            builtInThreshold: block.requiredSignatures,
            recoveryKeys: block.recoveryPublicKeys,
            recoveryThreshold: block.requiredRecoverySignatures,
            serverScope: block.serverScope,
            storeProvider: storeProvider
        )
    }

    static func forBlock(_ block: ConfigApiBlock, store: SigningKeyStore?) -> SignatureTrust? {
        forBlock(block) { store }
    }

    /// A single fixed key: one signature from it is required, no rotation.
    static func single(configApiId: String, key: String) -> SignatureTrust {
        SignatureTrust(configApiId: configApiId, builtInKeys: [key], builtInThreshold: 1, recoveryKeys: [], recoveryThreshold: 1) { nil }
    }

    /// SHA-256 (hex) over what this build trusts by itself: the compiled-in
    /// signing keys and how many must sign, the recovery keys and their
    /// threshold, in canonical form and order. It changes only with an app
    /// update that rotates them; see `SSLCertificateUpdater.syncTrustAnchors`.
    func anchorsFingerprint() -> String {
        var text = "pinvault-trust-anchors:v1\n"
        text += "signing:\(builtInThreshold)\n"
        for key in builtInKeys.sorted() { text += key + "\n" }
        text += "recovery:\(recoveryThreshold)\n"
        for key in recoveryKeys.sorted() { text += key + "\n" }
        return Hashing.sha256Hex(Data(text.utf8))
    }

    /// Where the key-set floor comes from (set once the block's store is open).
    func setFloorProvider(_ provider: @escaping @Sendable () throws -> KeySetFloor?) {
        floorProvider.set(provider)
    }

    /// True when the key set in force is older than one this device applied
    /// under the same compiled-in anchors: a key-set file put back from before
    /// a rotation, which would bring revoked keys back. Nothing verifies then.
    /// Under other anchors (an update that changed the keys) there is no floor.
    func keySetBelowFloor() throws -> Bool {
        // Without recovery keys no set is ever applied (version 0): no floor to read.
        if recoveryKeys.isEmpty { return false }
        guard let provider = floorProvider.get(), let floor = try provider() else { return false }
        if let anchors = floor.anchors, anchors != recoveryFingerprint() { return false }
        return try keySetVersion() < floor.version
    }

    /// Fingerprint of the recovery keys and their threshold: what decides
    /// whether a stored signing-key set still verifies (the floor's epoch).
    func recoveryFingerprint() -> String {
        var text = "pinvault-recovery-anchors:v1\nrecovery:\(recoveryThreshold)\n"
        for key in recoveryKeys.sorted() { text += key + "\n" }
        return Hashing.sha256Hex(Data(text.utf8))
    }

    /// False only when the block has no signing key configured at all (`allowUnsigned()`).
    var isEnabled: Bool { configured }

    func trustedKeys() throws -> [String] {
        try currentSet()?.keys ?? builtInKeys
    }

    func requiredSignatures() throws -> Int {
        try currentSet()?.requiredSignatures ?? builtInThreshold
    }

    func keySetVersion() throws -> Int {
        try currentSet()?.version ?? 0
    }

    func status() throws -> SigningStatus {
        SigningStatus(
            configApiId: configApiId,
            trustedKeyIds: try trustedKeys().map(keyId),
            requiredSignatures: try requiredSignatures(),
            keySetVersion: try keySetVersion(),
            recoveryKeyIds: recoveryKeys.map(keyId),
            lastConfigSignedBy: state.withLock { $0.lastSignedBy }
        )
    }

    /// Applies a signing-key set delivered with a config, if it is newer than
    /// the one this block holds.
    ///
    /// Throws ``PinVaultError/security(message:cause:)`` when the set is present
    /// but does not carry enough valid recovery signatures or is malformed: a
    /// backend that sends a set means it, and silently keeping the old keys
    /// would hide a forged or broken rotation. A set that is merely older or
    /// equal is ignored.
    ///
    /// - Returns: true when `incoming` was newer and is now the set in force.
    @discardableResult
    func applyKeySetUpdate(_ incoming: SignedKeySet?) throws -> Bool {
        guard let incoming else { return false }
        if recoveryKeys.isEmpty {
            log.w("Config API '\(configApiId)': the response carries a signing-key set but no recoveryPublicKeys " +
                "are configured — ignoring it and keeping the compiled-in keys")
            return false
        }
        let candidate = try check(incoming)
        return try state.withLock { state -> Bool in
            let current = try loadedSet(&state)
            let currentVersion = current?.version ?? 0
            if candidate.version > currentVersion {
                try openedStore(&state)?.save(configApiId, incoming)
                state.activeSet = candidate
                state.activeSetLoaded = true
                log.i("Config API '\(configApiId)': signing-key set v\(candidate.version) applied — " +
                    "\(candidate.keys.count) trusted key(s), \(candidate.requiredSignatures) signature(s) required")
                return true
            }
            if candidate.version == currentVersion, let current, Set(candidate.keys) != Set(current.keys) {
                log.w("Config API '\(configApiId)': a different signing-key set with the same version v\(currentVersion) was " +
                    "offered — keeping the one already applied")
            } else {
                log.d("Config API '\(configApiId)': signing-key set v\(candidate.version) is not newer than v\(currentVersion) — nothing to apply")
            }
            return false
        }
    }

    /// Checks `payload` against the signatures in `entries`. The result is ok
    /// when at least ``requiredSignatures()`` distinct trusted keys produced
    /// one of them; ``Verification/detail`` explains a failure in words fit
    /// for a log or an `UpdateResult.failed` reason.
    func verifyConfig(payload: String, entries: [SignatureEntry]) throws -> Verification {
        let result = try evaluate(payload, entries)
        if result.ok { state.withLock { $0.lastSignedBy = result.signedBy } }
        return result
    }

    /// ``verifyConfig(payload:entries:)`` for a config envelope read back from
    /// storage: the same check against the keys trusted now, without recording
    /// its signers as "the last accepted config".
    func verifyStoredConfig(payload: String, entries: [SignatureEntry]) throws -> Verification {
        try evaluate(payload, entries)
    }

    /// The same check for a vault file's canonical content string: v1 when
    /// `serverScope` is nil, v2 (which names that Config API) when the block
    /// set one. `entries` must be the signatures of that scheme.
    func verifyVaultFile(
        key: String,
        version: Int,
        plaintext: Data,
        entries: [SignatureEntry],
        serverScope: String? = nil
    ) throws -> Verification {
        let canonical = serverScope.map {
            ConfigSignatureVerifier.vaultCanonicalV2(configApiId: $0, key: key, version: version, plaintext: plaintext)
        } ?? ConfigSignatureVerifier.vaultCanonical(key: key, version: version, plaintext: plaintext)
        return try evaluate(canonical, entries)
    }

    private func evaluate(_ payload: String, _ entries: [SignatureEntry]) throws -> Verification {
        // Configs, stored configs and vault files alike: below the floor the
        // keys on disk may be ones a newer set revoked.
        if try keySetBelowFloor() {
            return Verification(ok: false, signedBy: [], required: try requiredSignatures(),
                                detail: " The signing-key set in force (v\(try keySetVersion())) is older than one this device applied.")
        }
        // One snapshot for the keys AND the count: a key-set update landing
        // between two separate reads could pair the old keys with a new count.
        let set = try currentSet()
        let keys = set?.keys ?? builtInKeys
        let required = set?.requiredSignatures ?? builtInThreshold
        let signers = validSigners(payload, entries, keys)
        if signers.count >= required {
            return Verification(ok: true, signedBy: signers.map(keyId), required: required, detail: "")
        }
        var detail = ""
        if required > 1 { detail += " \(signers.count) of \(required) required signatures valid." }
        // Name the reason an operator will want first: the signature is
        // genuine, but from a key the applied set no longer trusts.
        if let set, signers.isEmpty {
            let revoked = validSigners(payload, entries, builtInKeys.filter { !set.keys.contains($0) })
            if !revoked.isEmpty {
                detail += " Signed by a key revoked by signing-key set v\(set.version) " +
                    "(\(revoked.map(keyId).joined(separator: ", ")))."
            }
        }
        return Verification(ok: false, signedBy: signers.map(keyId), required: required, detail: detail)
    }

    /// Distinct keys from `keys` (canonical) that produced a valid signature in
    /// `entries`. An entry's `keyId` only decides which key is tried first — it
    /// is not signed, so a missing or wrong hint must not turn a good signature
    /// bad. At most ``maxEntries`` entries are looked at.
    private func validSigners(_ payload: String, _ entries: [SignatureEntry], _ keys: [String]) -> [String] {
        if keys.isEmpty { return [] }
        var verified: [String] = []
        for entry in entries.prefix(Self.maxEntries) {
            let signature = entry.signature
            if signature.isBlank { continue }
            let hinted = entry.keyId.map { id in keys.filter { keyId($0) == id } } ?? []
            for key in hinted + keys.filter({ !hinted.contains($0) }) {
                if verified.contains(key) { continue }
                if ConfigSignatureVerifier.verifyQuietly(payload: payload, signature: signature, publicKeyBase64: key) {
                    verified.append(key)
                    break
                }
            }
            if verified.count == keys.count { break }
        }
        return verified
    }

    /// The applied key set, read from the store on first use. A read that
    /// fails leaves it unloaded — never "loaded, none" — so the caller's check
    /// fails now and the read is tried again.
    private func currentSet() throws -> KeySet? {
        if recoveryKeys.isEmpty { return nil }
        return try state.withLock { try loadedSet(&$0) }
    }

    private func loadedSet(_ state: inout State) throws -> KeySet? {
        if recoveryKeys.isEmpty { return nil }
        if !state.activeSetLoaded {
            var loaded: KeySet?
            if let stored = try openedStore(&state)?.load(configApiId) {
                do {
                    loaded = try check(stored)
                } catch {
                    // Only possible when this build ships different recovery
                    // keys than the one that stored the set.
                    log.w("Config API '\(configApiId)': the stored signing-key set no longer verifies against " +
                        "this build's recovery keys — using the compiled-in keys (\((error as? PinVaultError)?.message ?? "\(error)"))")
                }
            }
            state.activeSet = loaded
            state.activeSetLoaded = true
        }
        return state.activeSet
    }

    /// A store that fails to open is NOT "no persisted set": the set may hold
    /// a revocation, and falling back to the compiled-in keys would trust the
    /// revoked key again. The failure is thrown to whoever asked (nothing
    /// verifies for that attempt) and opening is tried again on the next use.
    private func openedStore(_ state: inout State) throws -> SigningKeyStore? {
        if state.storeOpened { return state.store }
        do {
            state.store = try storeProvider()
            state.storeOpened = true
            return state.store
        } catch let error as PinVaultError {
            if case .storeUnreadable = error { throw error }
            throw storeOpenFailure(error, name: error.exceptionName)
        } catch {
            throw storeOpenFailure(error, name: String(describing: type(of: error)))
        }
    }

    private func storeOpenFailure(_ error: any Error, name: String) -> PinVaultError {
        log.e("Config API '\(configApiId)': signing-key store unavailable — nothing is verified until it opens", error)
        return .storeUnreadable(
            message: "Config API '\(configApiId)': the signing-key store cannot be opened right now (\(name))",
            cause: error
        )
    }

    private func check(_ keySet: SignedKeySet) throws -> KeySet {
        let entries = keySet.signatures
        // The wire model reads an absent payload as "".
        let payload = keySet.payload
        if payload.isEmpty { throw Self.rejected("Signing-key set rejected — it has no payload.") }
        let signers = validSigners(payload, entries, recoveryKeys)
        if signers.count < recoveryThreshold {
            throw Self.rejected(
                "Signing-key set rejected — \(signers.count) of \(recoveryThreshold) required recovery " +
                    "signature(s) valid. Keeping the current signing keys."
            )
        }
        guard let parsed = try? JSONDecoder().decode(SigningKeySetPayload.self, from: Data(payload.utf8)) else {
            throw Self.rejected("Signing-key set rejected — the payload is not a key set.")
        }
        if parsed.type != Self.keySetType {
            throw Self.rejected("Signing-key set rejected — type '\(parsed.type ?? "null")' is not '\(Self.keySetType)'.")
        }
        if parsed.version <= 0 {
            throw Self.rejected("Signing-key set rejected — version must be positive.")
        }
        // Inside the recovery-signed payload, so it cannot be swapped.
        if let scopedTo = parsed.configApiId, !scopedTo.isBlank, let serverScope, scopedTo != serverScope {
            throw Self.rejected(
                "Signing-key set rejected — it was made for Config API '\(scopedTo.kotlinTake(64))', this block is '\(serverScope)' (serverScope)."
            )
        }
        let raw = (parsed.keys ?? []).compactMap { $0 }.filter { !$0.isBlank }
        if raw.count > Self.maxSetKeys {
            throw Self.rejected("Signing-key set rejected — more than \(Self.maxSetKeys) keys.")
        }
        let keys = try raw.map { key -> String in
            guard let canonical = ConfigSignatureVerifier.canonicalKey(key) else {
                throw Self.rejected("Signing-key set rejected — not an EC public key: \(key.kotlinTake(16))…")
            }
            return canonical
        }.distinctPreservingOrder()
        if keys.isEmpty {
            throw Self.rejected("Signing-key set rejected — it lists no signing keys.")
        }
        if keys.contains(where: recoveryKeys.contains) {
            throw Self.rejected("Signing-key set rejected — a recovery key may not be a signing key.")
        }
        // A set can raise the number of signatures a config needs, never lower
        // it below what the app itself demands.
        let required = max(builtInThreshold, parsed.requiredSignatures ?? 1)
        if required > keys.count {
            throw Self.rejected(
                "Signing-key set rejected — it requires \(required) signatures but lists only \(keys.count) key(s)."
            )
        }
        return KeySet(version: parsed.version, keys: keys, requiredSignatures: required)
    }

    private static func rejected(_ message: String) -> PinVaultError {
        .security(message: message)
    }

    private func keyId(_ key: String) -> String {
        if let id = keyIds.withLock({ $0[key] }) { return id }
        let id = ConfigSignatureVerifier.keyIdOf(key) ?? "invalid-key"
        keyIds.withLock { $0[key] = id }
        return id
    }

    private static func canonicalize(_ keys: [String], role: String, configApiId: String, log: PinVaultLog.Tag) -> [String] {
        keys.compactMap { key -> String? in
            let canonical = ConfigSignatureVerifier.canonicalKey(key)
            if canonical == nil {
                log.e("Config API '\(configApiId)': ignoring a \(role) key that is not an EC public key (\(key.kotlinTake(16))…)")
            }
            return canonical
        }.distinctPreservingOrder()
    }
}

extension String {
    /// Kotlin `take(n)`: the first `n` UTF-16 code units (never splitting a scalar).
    func kotlinTake(_ count: Int) -> String {
        var units = 0
        var out = String.UnicodeScalarView()
        for scalar in unicodeScalars {
            units += scalar.utf16.count
            if units > count { break }
            out.append(scalar)
        }
        return String(out)
    }
}

/// The newest signing-key set a device applied, and the anchors it was applied under.
struct KeySetFloor: Sendable, Equatable {
    let version: Int
    let anchors: String?
}
