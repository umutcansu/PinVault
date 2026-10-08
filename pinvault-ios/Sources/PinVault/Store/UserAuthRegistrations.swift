import Foundation

/// Which user-auth key (its hex key id) the library last registered
/// successfully with each Config API (Kotlin `UserAuthRegistrations`). A
/// `user_auth` copy is stamped with that id, not with whatever key the device
/// holds when the copy is saved: the server sealed it for the key it was given.
/// Kept across restarts so a copy sealed for a key the device has since
/// replaced is recognised and given up instead of being answered "already
/// current" for ever.
protocol UserAuthRegistrations: Sendable {
    func get(_ configApiId: String) -> String?
    func put(_ configApiId: String, _ keyIdHex: String)
    func remove(_ configApiId: String)
    func clear()
}

/// This process only (tests, and callers without a store).
final class UserAuthRegistrationsInMemory: UserAuthRegistrations {
    private let ids = Locked<[String: String]>([:])

    init() {}

    func get(_ configApiId: String) -> String? { ids.withLock { $0[configApiId] } }
    func put(_ configApiId: String, _ keyIdHex: String) { ids.withLock { $0[configApiId] = keyIdHex } }
    func remove(_ configApiId: String) { ids.withLock { _ = $0.removeValue(forKey: configApiId) } }
    func clear() { ids.withLock { $0.removeAll() } }
}

/// In a ``SecurePreferences`` namespace of `pinvault_secure_vault_files`, which
/// is excluded from backup: a restored registration would name a key the new
/// device does not have. A store that cannot be read reads as "not registered"
/// (the key is registered again, which is harmless); a failed write is logged.
final class UserAuthRegistrationsPersistent: UserAuthRegistrations {
    static let namespace = "pinvault_user_auth_registrations"

    private let prefs: any PreferenceStore
    private let log = PinVaultLog.tag("UserAuthRegistrations")

    init(prefs: any PreferenceStore) {
        self.prefs = prefs
    }

    static func open(environment: SecureStoreEnvironment = .shared) throws -> UserAuthRegistrationsPersistent {
        UserAuthRegistrationsPersistent(prefs: try SecurePreferences.open(
            fileName: VaultFileStore.fileName, namespace: namespace, environment: environment
        ))
    }

    func get(_ configApiId: String) -> String? {
        (try? prefs.getString(configApiId, nil)) ?? nil
    }

    func put(_ configApiId: String, _ keyIdHex: String) {
        write { $0.putString(configApiId, keyIdHex) }
    }

    func remove(_ configApiId: String) {
        write { $0.remove(configApiId) }
    }

    func clear() {
        write { $0.clear() }
    }

    private func write(_ change: (PreferenceEditor) -> PreferenceEditor) {
        do {
            try change(prefs.edit()).apply()
        } catch {
            log.w("Could not record the user-auth key registration", error)
        }
    }
}
