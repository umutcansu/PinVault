import Foundation

/// Encrypted persistence for the latest applied signing-key set of each
/// Config API block.
///
/// Deliberately a separate file from ``CertificateConfigStore``: that store's
/// active config is dropped by `PinVault.reset()`, by corrupt-store recovery
/// and by a health-gate rollback with nothing to roll back to. A key set
/// carries revocations, and forgetting one would put a revoked signing key
/// back into trust — so it survives all of those. It is excluded from backup
/// for the same reason (a restored older set would un-revoke keys).
///
/// One file for every block (`pinvault_secure_signing_keys.plist`). The signed
/// set is stored as received — payload plus signatures — and is re-verified
/// against the app's recovery keys every time it is read, so a set is only
/// ever trusted while the current build still vouches for it.
final class SigningKeyStore: Sendable {
    static let fileName = "pinvault_secure_signing_keys"
    /// Namespace (and the file PinVault 2.0.x used on Android).
    static let prefsName = "pinvault_signing_keys"

    private let prefs: any PreferenceStore
    private let log = PinVaultLog.tag("SigningKeyStore")

    /// A store over `prefs` (Kotlin `createForTest`).
    init(prefs: any PreferenceStore) {
        self.prefs = prefs
    }

    /// The app's store. Strict: a failure must not read as "no key set
    /// applied" — that would put a revoked signing key back into trust.
    static func open(environment: SecureStoreEnvironment = .shared) throws -> SigningKeyStore {
        SigningKeyStore(prefs: try SecurePreferences.openStrict(fileName: fileName, namespace: prefsName, environment: environment))
    }

    /// The stored set, or nil when none is stored. Throws
    /// ``PinVaultError/storeUnreadable(message:cause:)`` when the entry cannot
    /// be opened right now — which says nothing about whether a set is stored.
    func load(_ configApiId: String) throws -> SignedKeySet? {
        guard let json = try prefs.getString(key(configApiId), nil) else { return nil }
        do {
            return try JSONDecoder().decode(SignedKeySet.self, from: Data(json.utf8))
        } catch {
            log.w("Stored signing-key set for '\(configApiId)' is unreadable — ignoring it", error)
            return nil
        }
    }

    func save(_ configApiId: String, _ keySet: SignedKeySet) throws {
        let json = String(decoding: try JSONEncoder().encode(keySet), as: UTF8.self)
        // commit(), not apply(): a revocation must be on disk before the
        // device acts on it — a crash right after must not un-revoke a key.
        if try !prefs.edit().putString(key(configApiId), json).commit() {
            log.e("Signing-key set for '\(configApiId)' could not be written to disk")
        }
    }

    func clear(_ configApiId: String) throws {
        try prefs.edit().remove(key(configApiId)).apply()
    }

    private func key(_ id: String) -> String { "keyset_\(id)" }
}
