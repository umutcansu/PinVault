import Foundation

/// How a block checks a stored copy (Kotlin `StoredVerifier`): which signature
/// scheme it expects (1 or 2) and the check itself — nil when the copy passes,
/// otherwise why it does not.
struct StoredVerifier: Sendable {
    let scheme: Int
    let verify: UnlockVerifier
}

/// Stands between the app and a stored vault file (Kotlin `VaultFileGuard`).
/// What is checked every time a copy is read:
///
///  - **Signature.** A file of a signing Config API is stored with the
///    signatures it came with (``VaultFileMeta``) and verified again on every
///    `loadFile` / `unlockFile`, with the keys trusted now. A copy that fails is
///    deleted. A copy with no signature on record is not handed out and is
///    downloaded again by the next fetch. Files of unsigned blocks are not checked.
///  - **Offline lifetime** (`maxOfflineAge`). The time the server last
///    confirmed the copy is recorded; once that is longer ago than the file
///    allows — by the trusted clock — the copy is not handed out, and deleted
///    with `wipeWhenStale()`. A confirmation time ahead of the trusted clock
///    counts as "not confirmed": not handed out, never deleted on that ground alone.
///  - **Version floor.** The highest version of a file that was accepted with
///    a verified signature is remembered apart from the copy, per Config API
///    and key, and nothing that deletes the copy (``forget(_:)``, a failed
///    check, `wipeWhenStale`, a wipe) lowers it: the router refuses an older
///    version however the copy went away, and a stored copy below it is not
///    handed out when it is read (an older copy put back on its own with its
///    own signature record). Files of unsigned blocks have none.
///
/// A store that cannot be read right now is none of these: nothing is handed
/// out and nothing is deleted.
final class VaultFileGuard: Sendable {

    /// What a read came to: the content, or why there is none.
    enum Read: Sendable, Equatable {
        case content(Data)
        case refused(status: VaultFileStatus, reason: String)
        /// Nothing stored, or a sealed copy `loadFile` does not open.
        case absent
    }

    /// Suffix of the pending slot's record; the same one ``UserAuthVaultStorage`` uses for the copy.
    private static let pendingSuffix = UserAuthVaultStorage.pendingSuffix

    private let meta: any VaultFileMeta
    /// The trusted clock of a Config API, by id (epoch ms).
    private let now: @Sendable (_ configApiId: String) -> Int64
    /// `PinVaultConfig.vaultFileMaxOfflineAgeMs`; 0 = no limit.
    private let defaultMaxOfflineAgeMs: Int64
    /// Told when a stored copy was deleted here, and why.
    private let onRemoved: @Sendable (_ key: String, _ reason: String) -> Void
    private let log = PinVaultLog.tag("VaultFileGuard")

    init(
        meta: any VaultFileMeta,
        now: @escaping @Sendable (_ configApiId: String) -> Int64,
        defaultMaxOfflineAgeMs: Int64 = 0,
        onRemoved: @escaping @Sendable (_ key: String, _ reason: String) -> Void = { _, _ in }
    ) {
        self.meta = meta
        self.now = now
        self.defaultMaxOfflineAgeMs = defaultMaxOfflineAgeMs
        self.onRemoved = onRemoved
    }

    // MARK: What the router records

    /// A download was verified and stored as `version`. `signatures` nil: an
    /// unsigned block, or a copy that carries its own.
    func stored(_ file: VaultFileConfig, version: Int, signatures: StoredSignatures?) {
        quietly(file.key) {
            try meta.saveSignatures(file.key, signatures)
            try recordConfirmation(file)
            try meta.setProblem(file.key, nil)
        }
        // The version the signature names, not the one the store counts by
        // itself for a backend that sends none.
        if let signatures { verified(file, version: signatures.version) }
    }

    /// Version `version` of `file` passed its signature check (at the fetch,
    /// or at `unlockFile` for a server-sealed copy): the floor rises to it.
    func verified(_ file: VaultFileConfig, version: Int) {
        guard version > 0 else { return }
        quietly(file.key) { try meta.raiseVersionFloor(configApiId: file.configApiId, key: file.key, to: version) }
    }

    /// `unlockFile` opened a server-sealed copy and its signature passed: nil
    /// when it may be handed out, and the floor rises to `version`. First,
    /// though, the floor as it stood before this unlock: a copy below it is one
    /// a newer verified version superseded, put back on its own (its envelope
    /// still verifies — nothing in it names the floor). It is deleted the way
    /// a failed check deletes, and the floor is kept.
    func verifiedAtUnlock(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, version: Int) -> Read? {
        let floor: Int
        do {
            floor = try meta.versionFloor(configApiId: file.configApiId, key: file.key)
        } catch {
            return unavailable(file.key, error)
        }
        if let problem = Self.belowFloorProblem(version, floor) {
            return remove(file, storage, .integrityFailed,
                          "Vault file '\(file.key)' failed its check when unlocked: \(problem). The stored copy was deleted; fetch it again.")
        }
        verified(file, version: version)
        return nil
    }

    /// Why a copy signed as `version` may not be handed out under `floor`, or
    /// nil. A copy without a version (0: a backend that sends none) is not
    /// judged, as at download.
    private static func belowFloorProblem(_ version: Int, _ floor: Int) -> String? {
        guard version > 0, version < floor else { return nil }
        return "it is signed as v\(version), but this device has already verified v\(floor) of it (an older copy put back)"
    }

    /// The highest version of `file` this device accepted with a verified
    /// signature, whatever happened to the copy since; 0 = none.
    /// - Throws: when the record cannot be read right now (no floor is not assumed).
    func versionFloor(_ file: VaultFileConfig) throws -> Int {
        try meta.versionFloor(configApiId: file.configApiId, key: file.key)
    }

    /// Tests only: see ``VaultFileMeta/wipeVersionFloors()``.
    func wipeVersionFloors() {
        quietly("*") { try meta.wipeVersionFloors() }
    }

    /// The server confirmed the stored copy (304, or the same content again).
    func confirmed(_ file: VaultFileConfig) {
        quietly(file.key) { try recordConfirmation(file) }
    }

    /// A `user_auth` download went to the pending slot: nothing in it has been
    /// checked, so the copy on record keeps its signatures and its confirmation.
    /// Only the time the server served the new copy is written down, apart.
    func pendingStored(_ file: VaultFileConfig) {
        quietly(file.key) { try meta.setConfirmedAt(pendingRecord(file.key), now(file.configApiId)) }
    }

    /// `unlockFile` opened the pending copy and its signature passed: it is the
    /// stored copy now. Its confirmation is the time the server served it.
    func promoted(_ file: VaultFileConfig, version: Int) {
        quietly(file.key) {
            let served = try meta.confirmedAt(pendingRecord(file.key))
            try meta.clear(pendingRecord(file.key))
            try meta.saveSignatures(file.key, nil)
            try meta.setConfirmedAt(file.key, served > 0 ? served : now(file.configApiId))
            try meta.setProblem(file.key, nil)
            log.d("Vault file [\(file.key)] v\(version) verified at unlock; it is the stored copy now")
        }
    }

    private func pendingRecord(_ key: String) -> String { key + Self.pendingSuffix }

    /// The confirmation time is the trusted clock's reading, never more.
    private func recordConfirmation(_ file: VaultFileConfig) throws {
        try meta.setConfirmedAt(file.key, now(file.configApiId))
    }

    /// True when the stored copy of a signed file has no usable signature on
    /// record, so the fetch must download the file whatever version the device holds.
    func needsSignature(_ file: VaultFileConfig, _ verifier: StoredVerifier?) -> Bool {
        guard let verifier, !carriesOwnSignatures(file) else { return false }
        do {
            return try meta.signatures(file.key)?.scheme != verifier.scheme
        } catch {
            return false
        }
    }

    /// The app cleared the file, or it was wiped. Its version floor stays.
    func forget(_ key: String) {
        quietly(key) {
            try meta.clear(key)
            try meta.clear(pendingRecord(key))
            try meta.setProblem(key, nil)
        }
    }

    // MARK: What a read checks

    /// `loadFile`: the content when the copy may be handed out.
    func load(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, _ verifier: StoredVerifier?) -> Read {
        do {
            if try !storage.exists(key: file.key) { return .absent }
            if try isStale(file) { return try stale(file, storage) }
            if let bytes = try storage.load(key: file.key) {
                return check(file, storage, bytes, version: try storage.getVersion(key: file.key), verifier)
            }
            // The store itself found the copy bad (it did not decrypt for this
            // file and version) and dropped it.
            if try !storage.exists(key: file.key) {
                let reason = "Vault file '\(file.key)' did not open for this file and version. The stored copy was deleted; fetch it again."
                integrityFailed(file, reason: reason)
                return .refused(status: .integrityFailed, reason: reason)
            }
            return .absent
        } catch {
            return unavailable(file.key, error)
        }
    }

    /// `unlockFile`, before the prompt: nil to go ahead, otherwise why not.
    func beforeUnlock(_ file: VaultFileConfig, _ storage: any VaultStorageProvider) -> Read? {
        do {
            guard try storage.exists(key: file.key), try isStale(file) else { return nil }
            // A newer copy the server served within the lifetime is waiting to
            // be opened: the prompt goes ahead for it. What the unlock hands
            // out is checked again afterwards (``staleAfterUnlock``), so a
            // waiting copy that fails its check does not let the old one out.
            if try freshness(file, record: pendingRecord(file.key)) == .fresh { return nil }
            return try stale(file, storage)
        } catch {
            return unavailable(file.key, error)
        }
    }

    /// `unlockFile`, after a copy opened: nil when it may be handed out. A
    /// waiting copy that passed its check is the stored copy by now, confirmed
    /// as of the time the server served it; a copy still past its lifetime
    /// here is the old one, opened because the waiting copy was missing or failed.
    func staleAfterUnlock(_ file: VaultFileConfig, _ storage: any VaultStorageProvider) -> Read? {
        do {
            guard try isStale(file) else { return nil }
            return try stale(file, storage)
        } catch {
            return unavailable(file.key, error)
        }
    }

    /// Checks content that was just read (or unsealed) against the signatures
    /// stored with it. A copy that fails is deleted.
    func check(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, _ bytes: Data, version: Int, _ verifier: StoredVerifier?) -> Read {
        guard let verifier, !carriesOwnSignatures(file) else { return .content(bytes) }
        let signatures: StoredSignatures?
        do {
            signatures = try meta.signatures(file.key)
        } catch {
            return unavailable(file.key, error)
        }
        guard let signatures, signatures.scheme == verifier.scheme else {
            let reason = "Vault file '\(file.key)' has no signature on record for this Config API (it was stored by an " +
                "earlier version, or before serverScope was set); it is not handed out until it has been fetched again"
            log.w(reason)
            return .refused(status: .needsFetch, reason: reason)
        }
        // The version the signature names. (A backend that sends no version
        // header has its files signed and recorded as v0 while the store
        // counts them itself; only then may the two differ.)
        let signedVersion = signatures.version
        // The floor lives in an entry of its own: an older copy put back with
        // its own signature record (entries are bound to their names, not to
        // each other) still verifies, but sits below it.
        let floor: Int
        do {
            floor = try meta.versionFloor(configApiId: file.configApiId, key: file.key)
        } catch {
            return unavailable(file.key, error)
        }
        let problem: String?
        if signedVersion > 0 && signedVersion != version {
            problem = "it is stored as v\(version) but was signed as v\(signedVersion)"
        } else if signatures.entries.isEmpty {
            problem = "it carries no signature but a verifying key is configured"
        } else {
            do {
                problem = try verifier.verify(bytes, signedVersion, signatures.entries) ?? Self.belowFloorProblem(signedVersion, floor)
            } catch {
                return unavailable(file.key, error)
            }
        }
        guard let problem else { return .content(bytes) }
        return remove(file, storage, .integrityFailed,
                      "Vault file '\(file.key)' failed its check when read: \(problem). The stored copy was deleted; fetch it again.")
    }

    /// A copy that did not open for this file and version, or failed the check done at unlock: gone already.
    func integrityFailed(_ file: VaultFileConfig, reason: String) {
        quietly(file.key) {
            try meta.clear(file.key)
            try meta.clear(pendingRecord(file.key))
            try meta.setProblem(file.key, .integrityFailed)
        }
        onRemoved(file.key, reason)
    }

    func status(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, _ verifier: StoredVerifier?) -> VaultFileStatus {
        do {
            // Read first: an unreadable store must show as that, not as "nothing stored".
            let problem = try meta.problem(file.key)
            if try !storage.exists(key: file.key) { return problem ?? .notStored }
            if try isStale(file) { return .stale }
            if needsSignature(file, verifier) { return .needsFetch }
            if let locked = storage as? UserAuthVaultStorage, try locked.isLocked(file.key) { return .locked }
            return .available
        } catch {
            return .storageUnavailable
        }
    }

    /// Deletes every copy that is past its offline lifetime and asked for
    /// `wipeWhenStale()`. Run at start and on the periodic update.
    func sweep(_ files: [VaultFileConfig], storageFor: (String) -> any VaultStorageProvider) {
        for file in files where file.wipeWhenStale {
            do {
                let storage = storageFor(file.key)
                if try storage.exists(key: file.key), try isStale(file) { _ = try stale(file, storage) }
            } catch let error as PinVaultError {
                if case .storeUnreadable = error {
                    log.w("Vault file [\(file.key)]: storage unreadable right now — offline lifetime not checked")
                } else {
                    log.w("Vault file [\(file.key)]: could not check its offline lifetime", error)
                }
            } catch {
                log.w("Vault file [\(file.key)]: could not check its offline lifetime", error)
            }
        }
    }

    /// The file's offline lifetime in ms; 0 = no limit.
    func maxOfflineAgeMs(_ file: VaultFileConfig) -> Int64 { file.maxOfflineAgeMs ?? defaultMaxOfflineAgeMs }

    /// - Throws: when the confirmation time cannot be read right now.
    func isStale(_ file: VaultFileConfig) throws -> Bool { try freshness(file) != .fresh }

    private enum Freshness { case fresh, stale, unconfirmed }

    /// ``Freshness/stale`` is established from the record alone: past the
    /// lifetime, or never confirmed. ``Freshness/unconfirmed`` is a confirmation
    /// time that lies ahead of the trusted clock: not handed out until the
    /// server confirms it again, but never deleted on that ground alone.
    private func freshness(_ file: VaultFileConfig, record: String? = nil) throws -> Freshness {
        let max = maxOfflineAgeMs(file)
        if max <= 0 { return .fresh }
        let confirmedAt = try meta.confirmedAt(record ?? file.key)
        // Never on record: stored before a limit was set. Fail closed.
        if confirmedAt <= 0 { return .stale }
        let now = now(file.configApiId)
        // The trusted clock may restart up to one persist step behind the time
        // it last handed out (see TrustedClock): not "in the future".
        if confirmedAt > now + TrustedClock.persistStepMs { return .unconfirmed }
        return now - confirmedAt > max ? .stale : .fresh
    }

    private func stale(_ file: VaultFileConfig, _ storage: any VaultStorageProvider) throws -> Read {
        if try freshness(file) == .unconfirmed {
            let reason = "Vault file '\(file.key)': the time its server last confirmed it lies ahead of the trusted " +
                "clock, so its offline lifetime cannot be counted; it is not handed out until it is fetched again"
            log.w(reason)
            return .refused(status: .stale, reason: reason)
        }
        let reason = "Vault file '\(file.key)' has not been confirmed by its server within its offline lifetime " +
            "(maxOfflineAge); fetch it again"
        if !file.wipeWhenStale {
            log.w(reason)
            return .refused(status: .stale, reason: reason)
        }
        return remove(file, storage, .stale, "\(reason). The stored copy was deleted (wipeWhenStale).")
    }

    private func remove(_ file: VaultFileConfig, _ storage: any VaultStorageProvider, _ status: VaultFileStatus, _ reason: String) -> Read {
        log.e(reason)
        do {
            try storage.clear(key: file.key)
        } catch {
            log.w("Could not delete vault file [\(file.key)]", error)
        }
        quietly(file.key) {
            try meta.clear(file.key)
            try meta.clear(pendingRecord(file.key))
            try meta.setProblem(file.key, status)
        }
        onRemoved(file.key, reason)
        return .refused(status: status, reason: reason)
    }

    private func unavailable(_ key: String, _ error: any Error) -> Read {
        let message = VaultErrorText.message(error)
        log.w("Vault file [\(key)]: storage cannot be read right now — nothing handed out, nothing deleted (\(message))")
        return .refused(
            status: .storageUnavailable,
            reason: "Vault file '\(key)' cannot be checked right now: the encrypted storage is unreadable (\(message))"
        )
    }

    /// A server-sealed `user_auth` copy keeps its signatures inside the copy and is checked at unlock.
    private func carriesOwnSignatures(_ file: VaultFileConfig) -> Bool { file.encryption == .userAuth }

    /// Bookkeeping must never fail a fetch or a read.
    private func quietly(_ key: String, _ body: () throws -> Void) {
        do {
            try body()
        } catch {
            log.w("Vault file [\(key)]: could not update its record", error)
        }
    }
}
