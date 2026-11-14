import Foundation

/// The signatures a vault file was accepted with (Kotlin `StoredSignatures`):
/// `scheme` 1 signs `pinvault-vault-file:v1:<key>:<version>:<sha256>`, 2 the v2
/// string that also names the Config API. Kept so the stored copy can be checked
/// again every time it is read, not only when it was downloaded.
struct StoredSignatures: Sendable, Equatable {
    let version: Int
    let scheme: Int
    let entries: [SignatureEntry]
}

/// What the library remembers about each stored vault file besides its
/// content (Kotlin `VaultFileMeta`): the signatures it came with, when the
/// server last confirmed it, and why it was last refused.
///
/// Every read may throw ``PinVaultError/storeUnreadable(message:cause:)``:
/// "the Keychain cannot open this right now" must not read as "never
/// confirmed" (a stale file, possibly wiped) or "no signature" (an unverified file).
protocol VaultFileMeta: Sendable {
    func signatures(_ key: String) throws -> StoredSignatures?
    func saveSignatures(_ key: String, _ signatures: StoredSignatures?) throws

    /// When the server last confirmed the stored copy (trusted-clock ms); 0 = never on record.
    func confirmedAt(_ key: String) throws -> Int64
    func setConfirmedAt(_ key: String, _ time: Int64) throws

    /// Why the copy was last refused and removed, until a fetch stores a new one.
    func problem(_ key: String) throws -> VaultFileStatus?
    func setProblem(_ key: String, _ problem: VaultFileStatus?) throws

    /// Forgets everything about `key` except a recorded problem and its version floor.
    func clear(_ key: String) throws

    /// The highest version of file `key` of Config API `configApiId` this
    /// device ever accepted with a verified signature; 0 = none.
    ///
    /// It outlives the copy on purpose. The downgrade check used to compare
    /// with the stored copy's version only, so once the copy was gone —
    /// `clearFile`, a copy deleted by its checks, `wipeWhenStale`, a wipe on
    /// revocation or unenroll — any older version the server's key ever signed
    /// was accepted again. Nothing ``clear(_:)`` does touches it.
    func versionFloor(configApiId: String, key: String) throws -> Int
    /// Raises the floor to `version`; a lower value leaves it where it is.
    func raiseVersionFloor(configApiId: String, key: String, to version: Int) throws
    /// Forgets every floor. Tests only (`PinVault.resetAndWipeStoredState()`):
    /// nothing the app or a server can reach lowers a floor.
    func wipeVersionFloors() throws
}

/// The name a version floor is kept under: the Config API id and the file key,
/// the first with its length so that no two pairs share a name.
enum VaultFileFloorName {
    static func of(configApiId: String, key: String) -> String {
        "\(configApiId.utf8.count):\(configApiId):\(key)"
    }
}

/// This process only (tests; Kotlin `VaultFileMeta.InMemory`).
final class VaultFileMetaInMemory: VaultFileMeta {
    private struct State {
        var signatures: [String: StoredSignatures] = [:]
        var confirmed: [String: Int64] = [:]
        var problems: [String: VaultFileStatus] = [:]
        var floors: [String: Int] = [:]
    }

    private let state = Locked(State())

    init() {}

    func signatures(_ key: String) -> StoredSignatures? { state.withLock { $0.signatures[key] } }
    func saveSignatures(_ key: String, _ signatures: StoredSignatures?) { state.withLock { $0.signatures[key] = signatures } }
    func confirmedAt(_ key: String) -> Int64 { state.withLock { $0.confirmed[key] ?? 0 } }
    func setConfirmedAt(_ key: String, _ time: Int64) { state.withLock { $0.confirmed[key] = time } }
    func problem(_ key: String) -> VaultFileStatus? { state.withLock { $0.problems[key] } }
    func setProblem(_ key: String, _ problem: VaultFileStatus?) { state.withLock { $0.problems[key] = problem } }

    func clear(_ key: String) {
        state.withLock {
            $0.signatures[key] = nil
            $0.confirmed[key] = nil
        }
    }

    func versionFloor(configApiId: String, key: String) -> Int {
        state.withLock { $0.floors[VaultFileFloorName.of(configApiId: configApiId, key: key)] ?? 0 }
    }

    func raiseVersionFloor(configApiId: String, key: String, to version: Int) {
        let name = VaultFileFloorName.of(configApiId: configApiId, key: key)
        state.withLock { $0.floors[name] = max($0.floors[name] ?? 0, version) }
    }

    func wipeVersionFloors() { state.withLock { $0.floors = [:] } }
}

/// In a strict ``SecurePreferences`` namespace of the vault-file store's
/// encrypted file (Kotlin `VaultFileMeta.Persistent`).
final class VaultFileMetaPersistent: VaultFileMeta {
    static let namespace = "pinvault_vault_file_meta"
    private static let signaturesPrefix = "sig_"
    private static let confirmedPrefix = "seen_"
    private static let problemPrefix = "problem_"
    /// Version floors, and the list of their names (so the test-only wipe finds them).
    private static let floorPrefix = "floor_"
    private static let floorNamesKey = "floors"
    /// A floor is read, compared and written in one step.
    private let floorLock = NSLock()

    private let prefs: any PreferenceStore

    init(prefs: any PreferenceStore) {
        self.prefs = prefs
    }

    /// Inside `pinvault_secure_vault_files`, which is excluded from backup.
    /// Strict: a Keychain failure is reported, never read as "nothing on record".
    static func open(environment: SecureStoreEnvironment = .shared) throws -> VaultFileMetaPersistent {
        VaultFileMetaPersistent(prefs: try SecurePreferences.openStrict(
            fileName: VaultFileStore.fileName, namespace: namespace, environment: environment
        ))
    }

    func signatures(_ key: String) throws -> StoredSignatures? {
        guard let text = try prefs.getString(Self.signaturesPrefix + key, nil) else { return nil }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.count >= 2, let scheme = Int(lines[0]), let version = Int(lines[1]) else { return nil }
        let entries = lines.dropFirst(2).filter { !$0.isBlank }.map(VaultFileSignatureLines.entry)
        return StoredSignatures(version: version, scheme: scheme, entries: entries)
    }

    // `keyId:signature` per line, as in the X-Vault-Signatures header: Base64
    // has no `:` and no newline.
    func saveSignatures(_ key: String, _ signatures: StoredSignatures?) throws {
        let editor = prefs.edit()
        if let signatures {
            let lines = ["\(signatures.scheme)", "\(signatures.version)"] + signatures.entries.map(VaultFileSignatureLines.line)
            editor.putString(Self.signaturesPrefix + key, lines.joined(separator: "\n"))
        } else {
            editor.remove(Self.signaturesPrefix + key)
        }
        try editor.apply()
    }

    func confirmedAt(_ key: String) throws -> Int64 {
        try prefs.getLong(Self.confirmedPrefix + key, 0)
    }

    func setConfirmedAt(_ key: String, _ time: Int64) throws {
        try prefs.edit().putLong(Self.confirmedPrefix + key, time).apply()
    }

    func problem(_ key: String) throws -> VaultFileStatus? {
        try prefs.getString(Self.problemPrefix + key, nil).flatMap { VaultFileStatus(rawValue: $0) }
    }

    func setProblem(_ key: String, _ problem: VaultFileStatus?) throws {
        let editor = prefs.edit()
        if let problem { editor.putString(Self.problemPrefix + key, problem.rawValue) } else { editor.remove(Self.problemPrefix + key) }
        try editor.apply()
    }

    // The floor stays: see `versionFloor(configApiId:key:)`.
    func clear(_ key: String) throws {
        try prefs.edit().remove(Self.signaturesPrefix + key).remove(Self.confirmedPrefix + key).apply()
    }

    // In this store and not beside the pin watermarks' Keychain copy: a server
    // numbers a file from 1 again when it is deleted and uploaded anew, and a
    // floor in the Keychain would outlive even a reinstall, leaving a device
    // that can never take that file again. (Against a container put back the
    // Keychain copy would not help by itself either: the older container brings
    // the older signed copy along, and that one still passes its check.)
    func versionFloor(configApiId: String, key: String) throws -> Int {
        max(0, Int(clamping: try prefs.getLong(Self.floorPrefix + VaultFileFloorName.of(configApiId: configApiId, key: key), 0)))
    }

    func raiseVersionFloor(configApiId: String, key: String, to version: Int) throws {
        floorLock.lock()
        defer { floorLock.unlock() }
        let name = VaultFileFloorName.of(configApiId: configApiId, key: key)
        guard version > (try versionFloor(configApiId: configApiId, key: key)) else { return }
        var names = try floorNames()
        if !names.contains(name) { names.append(name) }
        try prefs.edit()
            .putLong(Self.floorPrefix + name, Int64(version))
            .putString(Self.floorNamesKey, JSONText.array(names.map(JSONText.string)))
            .apply()
    }

    func wipeVersionFloors() throws {
        floorLock.lock()
        defer { floorLock.unlock() }
        let editor = prefs.edit()
        for name in try floorNames() { editor.remove(Self.floorPrefix + name) }
        try editor.remove(Self.floorNamesKey).apply()
    }

    private func floorNames() throws -> [String] {
        guard let json = try prefs.getString(Self.floorNamesKey, nil) else { return [] }
        return (JSONText.parse(json) as? [Any])?.compactMap { $0 as? String } ?? []
    }
}

/// The `keyId:signature` line form of a signature entry (as in the
/// `X-Vault-Signatures` header); an entry without a key id has an empty one.
enum VaultFileSignatureLines {
    static func line(_ entry: SignatureEntry) -> String {
        "\(entry.keyId ?? ""):\(entry.signature)"
    }

    static func entry(_ line: String) -> SignatureEntry {
        guard let colon = line.firstIndex(of: ":") else { return SignatureEntry(keyId: nil, signature: line) }
        let keyId = String(line[line.startIndex..<colon])
        return SignatureEntry(keyId: keyId.isEmpty ? nil : keyId, signature: String(line[line.index(after: colon)...]))
    }
}
