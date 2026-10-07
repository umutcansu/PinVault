import Foundation

/// Default encrypted storage for vault files (Kotlin `VaultFileStore`):
/// ``SecurePreferences`` (keys in the Keychain), file
/// `pinvault_secure_vault_files`, namespace `pinvault_vault_files`.
///
/// Best for small/medium files (<1MB). For larger files use
/// ``EncryptedFileStorageProvider``.
///
/// A file is ONE sealed entry, `2:<version>:<Base64 content>`: SecurePreferences
/// binds an entry to its name, so content and version cannot be taken from two
/// different moments, and neither can be moved under another file's name.
/// (Android's earlier two-entry form never existed on iOS: nothing to migrate.)
final class VaultFileStore: VaultStorageProvider {
    /// The store file, shared with the vault-file metadata and the user-auth registrations.
    static let fileName = "pinvault_secure_vault_files"
    /// The namespace inside it.
    static let namespace = "pinvault_vault_files"
    private static let dataPrefix = "vault_data_"
    /// Base64 has no `:`, so a malformed entry never parses as this.
    private static let recordPrefix = "2:"

    private let prefs: any PreferenceStore
    private let log = PinVaultLog.tag("VaultFileStore")

    init(prefs: any PreferenceStore) {
        self.prefs = prefs
    }

    /// The app's store. Throws ``PinVaultError/storeUnreadable(message:cause:)``
    /// when the Keychain cannot be used right now.
    static func open(environment: SecureStoreEnvironment = .shared) throws -> VaultFileStore {
        VaultFileStore(prefs: try SecurePreferences.open(fileName: fileName, namespace: namespace, environment: environment))
    }

    func save(key: String, bytes: Data, version: Int) throws {
        try prefs.edit()
            .putString(dataKey(key), "\(Self.recordPrefix)\(version):" + Base64.encode(bytes))
            .apply()
        log.d("Vault file saved [\(key)] — version: \(version), \(bytes.count) bytes")
    }

    func load(key: String) throws -> Data? {
        guard let stored = try prefs.getString(dataKey(key), nil) else { return nil }
        guard let record = Self.parse(stored), let bytes = Base64.decode(record.content) else {
            log.e("Failed to decode vault file [\(key)]")
            return nil
        }
        log.d("Vault file loaded [\(key)] — \(bytes.count) bytes")
        return bytes
    }

    func getVersion(key: String) throws -> Int {
        guard let stored = try prefs.getString(dataKey(key), nil) else { return 0 }
        return Self.parse(stored)?.version ?? 0
    }

    func exists(key: String) throws -> Bool {
        try prefs.contains(dataKey(key))
    }

    func clear(key: String) throws {
        try prefs.edit().remove(dataKey(key)).apply()
        log.d("Vault file cleared [\(key)]")
    }

    private func dataKey(_ key: String) -> String { Self.dataPrefix + key }

    /// (version, Base64 content) of an entry; nil when it is not of the current form.
    private static func parse(_ stored: String) -> (version: Int, content: String)? {
        guard stored.hasPrefix(recordPrefix) else { return nil }
        let rest = stored.dropFirst(recordPrefix.count)
        guard let colon = rest.firstIndex(of: ":"), let version = Int(rest[rest.startIndex..<colon]) else { return nil }
        return (version, String(rest[rest.index(after: colon)...]))
    }
}
