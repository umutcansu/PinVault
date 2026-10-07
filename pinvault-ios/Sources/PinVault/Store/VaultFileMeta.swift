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

    /// Forgets everything about `key` except a recorded problem.
    func clear(_ key: String) throws
}

/// This process only (tests; Kotlin `VaultFileMeta.InMemory`).
final class VaultFileMetaInMemory: VaultFileMeta {
    private struct State {
        var signatures: [String: StoredSignatures] = [:]
        var confirmed: [String: Int64] = [:]
        var problems: [String: VaultFileStatus] = [:]
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
}

/// In a strict ``SecurePreferences`` namespace of the vault-file store's
/// encrypted file (Kotlin `VaultFileMeta.Persistent`).
final class VaultFileMetaPersistent: VaultFileMeta {
    static let namespace = "pinvault_vault_file_meta"
    private static let signaturesPrefix = "sig_"
    private static let confirmedPrefix = "seen_"
    private static let problemPrefix = "problem_"

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

    func clear(_ key: String) throws {
        try prefs.edit().remove(Self.signaturesPrefix + key).remove(Self.confirmedPrefix + key).apply()
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
