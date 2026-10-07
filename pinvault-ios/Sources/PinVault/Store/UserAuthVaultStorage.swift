import CryptoKit
import Foundation
import Security

/// What the unlock prompt reported (Kotlin `AuthOutcome`).
enum AuthOutcome: Sendable {
    /// The prompt passed; the grant is what it authorised (nil for a time-bound key).
    case succeeded(UserAuthGrant?)
    case cancelled
    case noScreenLock
    case error(String)
}

/// Checks the signature of a `user_auth` file once it is open: nil when it
/// passes (or the file's Config API runs unsigned), otherwise why it failed.
/// Throws when the trusted keys cannot be read right now (the signing-key
/// store is unreadable): no verdict, so nothing is deleted.
typealias UnlockVerifier = @Sendable (_ plaintext: Data, _ version: Int, _ signatures: [SignatureEntry]) throws -> String?

/// Shows the prompt for the key's kind; gets what the prompt must authorise.
typealias UserAuthAuthenticate = @Sendable (_ kind: UserAuthKeyKind, _ grant: UserAuthGrant?) async -> AuthOutcome

/// A `userAuth` vault file, stored in `inner` (which adds its own encryption on
/// top) in one of these forms (Kotlin `UserAuthVaultStorage`, same layout):
///
/// - **Sealed here** — `PVUA` `0x04` `[key id, 8][wrapped key length, 2][wrapped key][IV, 12][ciphertext + tag]`:
///   the content under a fresh AES-256-GCM key, that key wrapped with the
///   device's user-auth RSA key (RSA-OAEP SHA-256, MGF1-SHA256 on iOS). The GCM
///   tag covers the file name and the version it is stored as. (`0x02` is the
///   same without the version: read, and written again as `0x04` when opened.)
/// - **Sealed by the server** (`encryption = USER_AUTH`) — `PVUA` `0x03`
///   `[key id, 8][signatures length, 2][signatures][envelope]`: the server's
///   envelope exactly as downloaded, with its signatures. The content is only
///   ever decrypted in ``unlock(_:authenticate:onSealedForAnotherKey:onPromoted:verify:)``,
///   after the prompt, and checked there. The key id is the key the library
///   had registered with the server when it saved the copy.
/// - **Open** — `PVUA` `0x00` `[content]`: an `ifScreenLock` copy saved while the
///   device had no passcode.
/// - Anything without the `PVUA` prefix is a copy stored before the app turned
///   the lock on; it is sealed on first read. Any other `PVUA` kind counts as retired.
///
/// With `serverSealedOnly` (an `encryption = USER_AUTH` file) ONLY the
/// server-sealed kind is accepted: anything else is deleted unread.
///
/// **The pending slot.** A download that arrives while a copy is stored goes to
/// `<key>.pending` in `inner` and is opened first at the next unlock: when it
/// passes its checks it replaces the stored copy; when it fails, it alone is
/// deleted and the stored copy is opened instead. ``exists(key:)``,
/// ``getVersion(key:)``, ``isLocked(_:)`` and ``load(key:)`` describe the copy
/// under the file's own name.
///
/// Only a missing key, a server copy sealed for another key (OAEP that does
/// not decode after a passed prompt) or a copy that is not of the expected kind
/// deletes a copy; only a missing key replaces the key. Any other Keychain error
/// is reported as `.failed` and leaves everything as it was (the copy is at most
/// marked ``needsFetch(_:)``); so does a cancelled prompt.
///
/// iOS differences: the prompt's grant is an evaluated `LAContext`, which can
/// open both slots (one prompt where Android's per-use cipher asks twice), and
/// Android's "unknown Keystore error twice in a row" counter has no iOS cause,
/// so only an OAEP decoding failure (`errSecParam`) gives a server copy up.
final class UserAuthVaultStorage: VaultStorageProvider {
    /// The pending slot's name in the inner store: `<key>.pending`.
    static let pendingSuffix = ".pending"

    private static let magic = Data("PVUA".utf8)
    private static let header = 5
    private static let kindOpen: UInt8 = 0x00
    // 0x01 was the key-per-file format of earlier Android development builds.
    private static let kindSealed: UInt8 = 0x02
    private static let kindServer: UInt8 = 0x03
    /// Sealed here, the tag covering file name AND version.
    private static let kindSealedV3: UInt8 = 0x04
    private static let gcmIVBytes = 12
    private static let gcmTagBytes = 16

    let inner: any VaultStorageProvider
    let keys: any UserAuthKeys
    let policy: UserAuth
    let serverSealedOnly: Bool
    /// Copies kept after an inconclusive failure that the next fetch downloads whole; see ``needsFetch(_:)``.
    private let refetch = Locked<Set<String>>([])
    private let log = PinVaultLog.tag("UserAuthVaultStorage")

    init(inner: any VaultStorageProvider, keys: any UserAuthKeys, policy: UserAuth, serverSealedOnly: Bool = false) {
        precondition(policy != .none, "UserAuthVaultStorage needs a locking policy")
        self.inner = inner
        self.keys = keys
        self.policy = policy
        self.serverSealedOnly = serverSealedOnly
    }

    // MARK: VaultStorageProvider

    func save(key: String, bytes: Data, version: Int) throws {
        if serverSealedOnly {
            throw PinVaultError.illegalState(
                "Vault file '\(key)' is sealed by the server (encryption = USER_AUTH); only saveSealedByServer stores it"
            )
        }
        try inner.save(key: key, bytes: seal(key, bytes, version), version: version)
        replaced(key)
    }

    func load(key: String) throws -> Data? {
        guard let blob = try inner.load(key: key) else { return nil }
        if serverSealedOnly {
            // Never content: a server-sealed copy opens only in unlock, and
            // anything else was not written here for this file.
            if Self.kindOf(blob) != .server { dropForeign(key, .main) } else {
                log.d("Vault file [\(key)] is locked; PinVault.unlockFile opens it")
            }
            return nil
        }
        switch Self.kindOf(blob) {
        case .open: return adopt(key, blob.dropFirst(Self.header))
        case .earlier: return adopt(key, blob)
        case .sealed, .server, .retired:
            log.d("Vault file [\(key)] is locked; PinVault.unlockFile opens it")
            return nil
        }
    }

    func getVersion(key: String) throws -> Int { try inner.getVersion(key: key) }

    func exists(key: String) throws -> Bool { try inner.exists(key: key) }

    /// Deletes the copy, and a pending one. The key is the device's and stays.
    func clear(key: String) throws {
        try inner.clear(key: key)
        try inner.clear(key: pendingKey(key))
        replaced(key)
    }

    // MARK: Server-sealed copies

    /// Stores a `user_auth` download as it came: `envelope` is sealed for the
    /// user-auth key the library registered with the server, whose id is
    /// `sealedFor` (the device's current key when nil), and is only opened by unlock.
    ///
    /// - Returns: true when the copy went to the pending slot (a copy is already
    ///   stored and keeps its place until the new one has passed its checks).
    @discardableResult
    func saveSealedByServer(
        _ key: String,
        envelope: Data,
        version: Int,
        signatures: [SignatureEntry],
        sealedFor: Data? = nil
    ) throws -> Bool {
        _ = try VaultFileDecryptor.parse(envelope)   // refuse a malformed envelope now, not at unlock
        let keyId = try sealedFor ?? UserAuthKeyConstants.keyId(keys.publicKey())
        guard keyId.count == UserAuthKeyConstants.keyIdBytes else {
            throw PinVaultError.illegalArgument("key id must be \(UserAuthKeyConstants.keyIdBytes) bytes")
        }
        let sigs = Self.encodeSignatures(signatures)
        guard sigs.count <= Int(UInt16.max) else { throw PinVaultError.illegalArgument("too many signatures") }
        var blob = Self.magic
        blob.append(Self.kindServer)
        blob.append(keyId)
        Self.appendUInt16(&blob, sigs.count)
        blob.append(sigs)
        blob.append(envelope)
        if try inner.exists(key: key) {
            // Nothing in the new copy has been checked: the one on record stays,
            // with its stamp, until the new one has opened. The whole file did
            // arrive, though, so a copy kept after an inconclusive failure needs
            // no download again.
            try inner.save(key: pendingKey(key), bytes: blob, version: version)
            refetch.withLock { _ = $0.remove(key) }
            log.d("Vault file [\(key)] v\(version) stored in the pending slot; it replaces the stored copy once an unlock has verified it")
            return true
        }
        try inner.save(key: key, bytes: blob, version: version)
        replaced(key)
        return false
    }

    /// The version waiting in the pending slot, or 0 when it is empty.
    func pendingVersion(_ key: String) throws -> Int {
        try inner.exists(key: pendingKey(key)) ? inner.getVersion(key: pendingKey(key)) : 0
    }

    /// Deletes the pending copy alone; the stored copy stays.
    func clearPending(_ key: String) throws {
        try inner.clear(key: pendingKey(key))
    }

    /// The id of the key the pending copy was sealed for, or nil when the slot is empty.
    func pendingSealedKeyId(_ key: String) throws -> Data? {
        try inner.load(key: pendingKey(key)).flatMap(Self.sealedKeyIdOf)
    }

    /// The id of the key the stored copy was sealed for (8 bytes), or nil when nothing sealed is stored.
    func sealedKeyId(_ key: String) throws -> Data? {
        try inner.load(key: key).flatMap(Self.sealedKeyIdOf)
    }

    /// True when the stored copy is sealed, i.e. only unlock opens it.
    func isLocked(_ key: String) throws -> Bool {
        guard let blob = try inner.load(key: key) else { return false }
        let kind = Self.kindOf(blob)
        return serverSealedOnly ? kind == .server : (kind == .sealed || kind == .server || kind == .retired)
    }

    /// True when an approved unlock of the stored copy failed in a way that
    /// says nothing certain about the copy: it is kept, and the next fetch asks
    /// for the whole file. Cleared by any save, clear or successful unlock. In
    /// memory: a new process simply tries the copy again.
    func needsFetch(_ key: String) -> Bool {
        refetch.withLock { $0.contains(key) }
    }

    private func pendingKey(_ key: String) -> String { key + Self.pendingSuffix }

    /// A new copy (or none) is stored: earlier failures say nothing about it.
    private func replaced(_ key: String) {
        refetch.withLock { _ = $0.remove(key) }
    }

    // MARK: Unlock

    /// Opens the stored copy. `authenticate` shows the prompt; it runs only for
    /// a sealed copy. `verify` checks a server-sealed copy's signature once it
    /// is open; a copy that fails is deleted. A `serverSealedOnly` file needs
    /// `verify` (fail closed without one).
    ///
    /// A key that passed the prompt but cannot unwrap a server-sealed copy
    /// (OAEP does not decode: sealed for another key) makes the copy useless:
    /// it is deleted, `onSealedForAnotherKey` runs (the router forgets the
    /// registration) and the result is `.invalidated`.
    ///
    /// A copy waiting in the pending slot is opened first; when it passes it
    /// becomes the stored copy and `onPromoted` runs with its version.
    func unlock(
        _ key: String,
        authenticate: UserAuthAuthenticate,
        onSealedForAnotherKey: @Sendable () -> Void = {},
        onPromoted: @Sendable (_ version: Int) -> Void = { _ in },
        verify: UnlockVerifier? = nil
    ) async -> VaultFileUnlockResult {
        var stored: Data?
        let pending: Data?
        do {
            stored = try inner.load(key: key)
            pending = try inner.load(key: pendingKey(key))
        } catch {
            return keystoreFailure(key, "Could not read the stored copy", error)
        }
        if stored == nil && pending == nil { return .notFound(key: key) }
        if serverSealedOnly {
            if let blob = stored, Self.kindOf(blob) != .server {
                dropForeign(key, .main)
                // A pending copy the server did seal may still open below.
                if pending == nil { return .invalidated(key: key) }
                stored = nil
            }
            if verify == nil {
                log.e("Vault file [\(key)]: no signature check available (its Config API is not configured) — not opened")
                return .failed(key: key, reason: "Vault file '\(key)' cannot be checked: its Config API is not configured, so it is not opened")
            }
        }

        // Every grant made here ends with this unlock.
        let grants = Locked<[UserAuthGrant]>([])
        defer { grants.get().forEach { $0.invalidate() } }

        // A prompt that passed for the pending copy and can still serve the
        // stored one. Nil = ask again.
        var passed: Passed?
        var pendingFailure: VaultFileUnlockResult?
        if let pending {
            let version = (try? inner.getVersion(key: pendingKey(key))) ?? 0
            let attempt = await openSlot(key, .pending, pending, version, authenticate, verify, onSealedForAnotherKey, nil, grants)
            if case .unlocked(_, let version, _) = attempt.result {
                promote(key, pending, version)
                onPromoted(version)
                return attempt.result
            }
            // Cancelled, a prompt error, a Keychain fault, a missing key:
            // nothing more is tried, nothing else is touched.
            if !attempt.condemned { return attempt.result }
            log.w("Vault file [\(key)]: the pending copy did not open and was deleted; opening the copy it was to replace")
            pendingFailure = attempt.result
            passed = attempt.passed
        }
        guard let blob = stored else { return pendingFailure ?? .notFound(key: key) }
        let version = (try? inner.getVersion(key: key)) ?? 0
        return await openSlot(key, .main, blob, version, authenticate, verify, onSealedForAnotherKey, passed, grants).result
    }

    /// The two places a copy can be: under the file's own name, and the pending slot.
    private enum Slot { case main, pending }

    /// A passed prompt another slot may reuse.
    private struct Passed { let grant: UserAuthGrant? }

    /// What opening one slot came to. `condemned`: the copy was found bad and
    /// deleted, so the other slot may be tried; `passed`: a passed prompt the
    /// next slot may reuse.
    private struct Attempt {
        let result: VaultFileUnlockResult
        var condemned = false
        var passed: Passed?
    }

    /// One slot, from the stored blob to the content: the checks before the prompt, the prompt, then ``open``.
    private func openSlot(
        _ key: String,
        _ slot: Slot,
        _ blob: Data,
        _ version: Int,
        _ authenticate: UserAuthAuthenticate,
        _ verify: UnlockVerifier?,
        _ onSealedForAnotherKey: @Sendable () -> Void,
        _ passed: Passed?,
        _ grants: Locked<[UserAuthGrant]>
    ) async -> Attempt {
        let kindOfBlob = Self.kindOf(blob)
        if slot == .pending && kindOfBlob != .server {
            // Only saveSealedByServer writes this slot: anything else was planted.
            dropForeign(key, slot)
            return Attempt(result: .invalidated(key: key), condemned: true, passed: passed)
        }
        let unsealed: Data?
        switch kindOfBlob {
        case .open: unsealed = Data(blob.dropFirst(Self.header))
        case .earlier: unsealed = blob
        case .sealed, .server: unsealed = nil
        case .retired: return Attempt(result: invalidated(key))
        }
        if let unsealed {
            guard let bytes = adopt(key, unsealed) else { return Attempt(result: invalidated(key)) }
            return Attempt(result: .unlocked(key: key, version: version, bytes: bytes))
        }

        let sealed: Sealed
        do {
            sealed = try Sealed.parse(blob)
        } catch {
            return Attempt(result: damaged(key, slot, "the stored copy is malformed", error), condemned: true, passed: passed)
        }

        // Which key the copy needs, and whether it is still there. Only a
        // missing key is a reason to give the copy up — and that gives up
        // every copy, not just this slot's.
        let kind: UserAuthKeyKind
        do {
            if try keys.state() != .usable { return Attempt(result: invalidated(key)) }
            if sealed.keyId != (try UserAuthKeyConstants.keyId(keys.publicKey())) {
                log.w("Vault file [\(key)] was sealed with a user-auth key that no longer exists")
                // A pending copy for another key says nothing about the stored one.
                return slot == .pending
                    ? Attempt(result: givenUp(key, slot), condemned: true, passed: passed)
                    : Attempt(result: invalidated(key))
            }
            kind = try keys.kind()
        } catch {
            return Attempt(result: keystoreFailure(key, "Could not read the unlock key", error))
        }

        let outcome: AuthOutcome
        if let passed {
            outcome = .succeeded(passed.grant)
        } else {
            let grant: UserAuthGrant?
            do {
                grant = try keys.grantForPrompt()
            } catch {
                return Attempt(result: keystoreFailure(key, "Could not prepare the unlock", error))
            }
            if let grant { grants.withLock { $0.append(grant) } }
            outcome = await authenticate(kind, grant)
        }

        switch outcome {
        case .succeeded(let grant):
            if let grant { grants.withLock { $0.append(grant) } }
            return open(key, slot, version, sealed, grant, verify, onSealedForAnotherKey)
        case .cancelled:
            return Attempt(result: .cancelled(key: key))
        case .noScreenLock:
            return Attempt(result: .failed(key: key, reason: "The device has no screen lock; set one to open this file"))
        case .error(let message):
            return Attempt(result: .failed(key: key, reason: message))
        }
    }

    /// After a passed prompt: the key step, then the software steps.
    private func open(
        _ key: String,
        _ slot: Slot,
        _ version: Int,
        _ sealed: Sealed,
        _ grant: UserAuthGrant?,
        _ verify: UnlockVerifier?,
        _ onSealedForAnotherKey: @Sendable () -> Void
    ) -> Attempt {
        // A single-use grant does one operation: once the unwrap has run, the
        // other slot needs a prompt of its own. An evaluated LAContext (and a
        // time-bound key) serves both.
        var used = false
        func unwrap(_ wrapped: Data) throws -> Data {
            used = true
            return try keys.unwrap(grant, wrapped)
        }
        func reusable() -> Passed? {
            guard let grant, grant.singleUse, used else { return Passed(grant: grant) }
            return nil
        }

        switch sealed {
        case .local(let local):
            // Never given up here (only a missing key is): the copy's key id
            // was checked against the current key before the prompt, and this
            // device sealed it itself, so a failure now is a Keychain fault or
            // a damaged copy — not "another key". The next fetch downloads the
            // file whole and replaces it.
            let fileKey: Data
            do {
                fileKey = try unwrap(local.wrappedKey)
            } catch {
                if !UserAuthKeyConstants.isRetired(error) && !WrongKeyForCopy.isAuthFailure(error) { markForFetch(key) }
                return Attempt(result: keystoreFailure(key, "Unlock was approved but the key did not open", error))
            }
            let content: Data
            do {
                content = try local.open(key, version, fileKey)
            } catch {
                return Attempt(
                    result: damaged(key, slot, "the stored copy did not decrypt for this file and version", error),
                    condemned: true, passed: reusable()
                )
            }
            if !local.boundToVersion {
                // Sealed by an earlier build, without the version: write it
                // again in the current form (sealing needs no prompt).
                do {
                    try inner.save(key: key, bytes: Sealed.createLocal(key, version, content, keys.publicKey()), version: version)
                } catch {
                    log.w("Vault file [\(key)]: could not re-seal the copy in the current form", error)
                }
            }
            replaced(key)
            return Attempt(result: .unlocked(key: key, version: version, bytes: content))

        case .server(let server):
            let parts: VaultFileDecryptor.Parts
            do {
                parts = try VaultFileDecryptor.parse(server.envelope)
            } catch {
                return Attempt(result: damaged(key, slot, "the stored envelope is malformed", error), condemned: true, passed: reusable())
            }
            let sessionKey: Data
            do {
                sessionKey = try unwrap(parts.wrappedKey)
            } catch {
                if WrongKeyForCopy.matches(error) {
                    return Attempt(
                        result: sealedForAnotherKey(key, slot, error, onSealedForAnotherKey),
                        condemned: true, passed: reusable()
                    )
                }
                // Kept: what failed is not known to be the copy. A fresh
                // download replaces a stored copy if it was (a pending one is
                // the fresh download already).
                if slot == .main && !UserAuthKeyConstants.isRetired(error) && !WrongKeyForCopy.isAuthFailure(error) {
                    markForFetch(key)
                }
                return Attempt(result: keystoreFailure(key, "Unlock was approved but the key did not open", error))
            }
            let content: Data
            do {
                content = try VaultFileDecryptor.openContent(parts, sessionKey: sessionKey)
            } catch {
                return Attempt(result: damaged(key, slot, "the server's envelope did not decrypt", error), condemned: true, passed: reusable())
            }
            let problem: String?
            do {
                problem = try verify?(content, version, server.signatures)
            } catch {
                // The keys to check it with cannot be read now: no verdict, nothing deleted.
                return Attempt(result: keystoreFailure(key, "Could not check the signature", error))
            }
            if let problem {
                return Attempt(result: damaged(key, slot, problem, nil), condemned: true, passed: reusable())
            }
            if slot == .main { replaced(key) }
            return Attempt(result: .unlocked(key: key, version: version, bytes: content))
        }
    }

    /// The pending copy passed: it is written under the file's own name (the
    /// inner store binds a blob to its name, so it cannot simply be renamed)
    /// and the slot is emptied. The copy it replaces is gone with that save.
    private func promote(_ key: String, _ blob: Data, _ version: Int) {
        do {
            try inner.save(key: key, bytes: blob, version: version)
            try inner.clear(key: pendingKey(key))
            replaced(key)
            log.d("Vault file [\(key)]: the pending copy (v\(version)) opened and replaced the stored one")
        } catch {
            log.w("Vault file [\(key)]: the pending copy opened but could not replace the stored one", error)
        }
    }

    private func markForFetch(_ key: String) {
        refetch.withLock { _ = $0.insert(key) }
    }

    /// Deletes one slot's copy. The stored copy's deletion takes its mark with it.
    private func condemn(_ key: String, _ slot: Slot) {
        do {
            if slot == .pending {
                try clearPending(key)
            } else {
                try inner.clear(key: key)
                replaced(key)
            }
        } catch {
            log.w("Vault file [\(key)]: could not delete the \(slotName(slot)) copy", error)
        }
    }

    private func seal(_ key: String, _ bytes: Data, _ version: Int) throws -> Data {
        if keys.isScreenLockSet() {
            try keys.ensureKey()
            return try Sealed.createLocal(key, version, bytes, keys.publicKey())
        }
        if policy == .required { throw PinVaultError.screenLockRequired(key: key) }
        log.w("Vault file [\(key)] stored without a lock: the device has no screen lock (IF_SCREEN_LOCK)")
        var blob = Self.magic
        blob.append(Self.kindOpen)
        blob.append(bytes)
        return blob
    }

    /// An unsealed copy's content, sealed in place when the device has a
    /// passcode. Nil when the policy does not allow it unsealed.
    private func adopt(_ key: String, _ bytes: Data) -> Data? {
        let content = Data(bytes)
        if !keys.isScreenLockSet() { return policy == .ifScreenLock ? content : nil }
        do {
            let version = try inner.getVersion(key: key)
            try inner.save(key: key, bytes: seal(key, content, version), version: version)
            log.d("Vault file [\(key)] sealed now that the device has a screen lock")
        } catch {
            log.w("Could not seal vault file [\(key)]", error)
        }
        return content
    }

    /// The key is gone: no copy of this file will open again, whichever slot it is in.
    private func invalidated(_ key: String) -> VaultFileUnlockResult {
        log.w("Vault file [\(key)]: the unlock key is gone (the screen lock was removed, or the fingerprints changed on a fingerprint-only key); stored copy deleted")
        do {
            try clear(key: key)
        } catch {
            log.w("Vault file [\(key)]: could not delete the stored copy", error)
        }
        return .invalidated(key: key)
    }

    /// A pending copy stamped with a key the device no longer has: it alone is given up.
    private func givenUp(_ key: String, _ slot: Slot) -> VaultFileUnlockResult {
        log.w("Vault file [\(key)]: the \(slotName(slot)) copy was sealed for a key that is gone; deleted")
        condemn(key, slot)
        return .invalidated(key: key)
    }

    /// A blob a `serverSealedOnly` file (or the pending slot) must not hold: deleted unread.
    private func dropForeign(_ key: String, _ slot: Slot) {
        log.e("Vault file [\(key)]: the \(slotName(slot)) copy is not one the server sealed; deleted unread — fetch it again")
        condemn(key, slot)
    }

    /// The prompt passed but the key could not unwrap the copy: it was sealed
    /// for another key. Nothing about it will ever open; give it up.
    private func sealedForAnotherKey(
        _ key: String, _ slot: Slot, _ error: any Error, _ onSealedForAnotherKey: @Sendable () -> Void
    ) -> VaultFileUnlockResult {
        log.w("Vault file [\(key)]: approved, but the \(slotName(slot)) copy is not sealed for this key — deleted; fetch it again", error)
        condemn(key, slot)
        onSealedForAnotherKey()
        return .invalidated(key: key)
    }

    private func slotName(_ slot: Slot) -> String { slot == .pending ? "pending" : "stored" }

    /// A Keychain error: a missing key → invalidated; anything else keeps the copy and the key.
    private func keystoreFailure(_ key: String, _ what: String, _ error: any Error) -> VaultFileUnlockResult {
        if UserAuthKeyConstants.isRetired(error) { return invalidated(key) }
        log.w("Vault file [\(key)]: \(what) — copy kept, try again", error)
        return .failed(key: key, reason: "\(what): \(VaultErrorText.message(error))", exception: error)
    }

    /// The copy itself is bad (damaged, wrong signature): delete that slot's copy; the next fetch replaces it.
    private func damaged(_ key: String, _ slot: Slot, _ problem: String, _ error: (any Error)?) -> VaultFileUnlockResult {
        log.e("Vault file [\(key)]: \(problem) — \(slotName(slot)) copy deleted", error)
        condemn(key, slot)
        return .failed(
            key: key,
            reason: "Vault file '\(key)' did not open: \(problem). The \(slotName(slot)) copy was deleted; fetch it again.",
            exception: error
        )
    }

    // MARK: Layout

    private enum Kind { case sealed, server, open, earlier, retired }

    private static func kindOf(_ blob: Data) -> Kind {
        guard blob.count >= header, blob.prefix(magic.count) == magic else { return .earlier }
        switch blob[blob.startIndex + magic.count] {
        case kindSealed, kindSealedV3: return .sealed
        case kindServer: return .server
        case kindOpen: return .open
        default: return .retired
        }
    }

    private static func sealedKeyIdOf(_ blob: Data) -> Data? {
        let kind = kindOf(blob)
        guard kind == .sealed || kind == .server, blob.count >= header + UserAuthKeyConstants.keyIdBytes else { return nil }
        let start = blob.startIndex + header
        return Data(blob[start..<(start + UserAuthKeyConstants.keyIdBytes)])
    }

    private static func appendUInt16(_ data: inout Data, _ value: Int) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// `keyId:signature` per line, as in the `X-Vault-Signatures` header; an
    /// entry without a key id is written with an empty one.
    private static func encodeSignatures(_ entries: [SignatureEntry]) -> Data {
        Data(entries.map(VaultFileSignatureLines.line).joined(separator: "\n").utf8)
    }

    fileprivate static func decodeSignatures(_ bytes: Data) -> [SignatureEntry] {
        String(decoding: bytes, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { !$0.isBlank }
            .map(VaultFileSignatureLines.entry)
    }

    private enum Sealed {
        case local(Local)
        case server(Server)

        var keyId: Data {
            switch self {
            case .local(let local): return local.keyId
            case .server(let server): return server.keyId
            }
        }

        struct Local {
            let keyId: Data
            let wrappedKey: Data
            let iv: Data
            /// Ciphertext followed by the 16-byte tag (the Java GCM output).
            let ciphertext: Data
            /// False for a `0x02` copy, whose tag covers the file name only.
            let boundToVersion: Bool

            func open(_ key: String, _ version: Int, _ fileKey: Data) throws -> Data {
                guard ciphertext.count >= UserAuthVaultStorage.gcmTagBytes else {
                    throw PinVaultError.crypto(message: "Input too short - need tag", cause: nil)
                }
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: iv),
                    ciphertext: ciphertext.prefix(ciphertext.count - UserAuthVaultStorage.gcmTagBytes),
                    tag: ciphertext.suffix(UserAuthVaultStorage.gcmTagBytes)
                )
                return try AES.GCM.open(
                    box, using: SymmetricKey(data: fileKey),
                    authenticating: boundToVersion ? aad(key, version) : legacyAad(key)
                )
            }
        }

        struct Server {
            let keyId: Data
            let signatures: [SignatureEntry]
            let envelope: Data
        }

        static func createLocal(_ key: String, _ version: Int, _ bytes: Data, _ publicKey: SecKey) throws -> Data {
            let fileKey = SymmetricKey(size: .bits256)
            let box = try AES.GCM.seal(bytes, using: fileKey, nonce: AES.GCM.Nonce(), authenticating: aad(key, version))
            let wrapped = try UserAuthKeyConstants.wrap(fileKey.withUnsafeBytes { Data($0) }, for: publicKey)
            var blob = UserAuthVaultStorage.magic
            blob.append(UserAuthVaultStorage.kindSealedV3)
            blob.append(try UserAuthKeyConstants.keyId(publicKey))
            UserAuthVaultStorage.appendUInt16(&blob, wrapped.count)
            blob.append(wrapped)
            blob.append(contentsOf: box.nonce)
            blob.append(box.ciphertext)
            blob.append(box.tag)
            return blob
        }

        /// File name and version: neither can be swapped under the tag.
        static func aad(_ key: String, _ version: Int) -> Data { Data("pinvault-user-auth:v3:\(key):\(version)".utf8) }

        static func legacyAad(_ key: String) -> Data { Data("pinvault-user-auth:v2:\(key)".utf8) }

        static func parse(_ blob: Data) throws -> Sealed {
            let bytes = [UInt8](blob)
            var offset = UserAuthVaultStorage.header
            let idBytes = UserAuthKeyConstants.keyIdBytes
            guard bytes.count >= offset + idBytes + 2 else { throw PinVaultError.illegalArgument("truncated") }
            let keyId = Data(bytes[offset..<(offset + idBytes)])
            offset += idBytes
            let length = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
            offset += 2
            let remaining = bytes.count - offset
            guard remaining >= length else { throw PinVaultError.illegalArgument("truncated") }
            let kind = bytes[UserAuthVaultStorage.magic.count]
            if kind == UserAuthVaultStorage.kindSealed || kind == UserAuthVaultStorage.kindSealedV3 {
                guard remaining > length + UserAuthVaultStorage.gcmIVBytes else { throw PinVaultError.illegalArgument("truncated") }
                let wrapped = Data(bytes[offset..<(offset + length)])
                offset += length
                let iv = Data(bytes[offset..<(offset + UserAuthVaultStorage.gcmIVBytes)])
                offset += UserAuthVaultStorage.gcmIVBytes
                return .local(Local(
                    keyId: keyId, wrappedKey: wrapped, iv: iv, ciphertext: Data(bytes[offset...]),
                    boundToVersion: kind == UserAuthVaultStorage.kindSealedV3
                ))
            }
            let sigs = Data(bytes[offset..<(offset + length)])
            offset += length
            return .server(Server(keyId: keyId, signatures: UserAuthVaultStorage.decodeSignatures(sigs), envelope: Data(bytes[offset...])))
        }
    }
}

/// Tells "this ciphertext was not made for this key" apart from "the Keychain
/// failed" after a passed prompt (Kotlin `WrongKeyForCopy`). The first makes a
/// server-sealed copy useless (it is deleted and fetched again); the second
/// says nothing about the copy, which must be kept.
///
/// Security reports an OAEP block that does not decode with the key as
/// `errSecParam` ("RSAdecrypt wrong input") from `SecKeyCreateDecryptedData`;
/// that is ``UserAuthKeyError/wrongKey(_:)``. Everything else — a refused or
/// missing authentication, a locked Keychain, any other status — keeps the copy.
enum WrongKeyForCopy {

    static func matches(_ error: any Error) -> Bool {
        if UserAuthKeyConstants.isRetired(error) || isAuthFailure(error) { return false }
        if case UserAuthKeyError.wrongKey = error { return true }
        return false
    }

    /// True when the failure is about user authentication (a locked key, a
    /// prompt that did not pass), never about the copy.
    static func isAuthFailure(_ error: any Error) -> Bool {
        if case UserAuthKeyError.notAuthenticated = error { return true }
        let nsError = error as NSError
        if nsError.domain == "com.apple.LocalAuthentication" { return true }
        if nsError.domain == NSOSStatusErrorDomain,
           UserAuthKeyError.authenticationStatuses.contains(OSStatus(truncatingIfNeeded: nsError.code)) {
            return true
        }
        return VaultErrorText.message(error).range(of: "authenticat", options: .caseInsensitive) != nil
    }
}
