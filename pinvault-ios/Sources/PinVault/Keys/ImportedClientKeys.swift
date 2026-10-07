import Foundation
import Security

/// Private keys that reached the device inside a PKCS12 bundle — a host's
/// client certificate, a server-made enrollment (`allowServerGeneratedKey()`),
/// a keystore bundled with the app — kept in the Keychain (this device only,
/// not extractable) instead of as P12 bytes in app storage (Kotlin
/// `ImportedClientKeys`).
///
/// A P12 in storage is the key itself: whoever reads the app's data and can
/// use the app's storage key walks away with it, and its password is a
/// constant compiled into the app. An imported key can still be USED by code
/// running as the app, but it is not in the app's files.
///
/// The import cannot undo where the key has already been (the server, the
/// wire, the app bundle): it only stops the device's files from being one
/// more place to steal it from.
///
/// The key is stored under application tag `alias`, its certificate under
/// label `alias`; the Keychain pairs the two into the `SecIdentity` a
/// handshake presents (``KeychainIdentities``).
protocol ImportedClientKeys: Sendable {

    /// Stores the private key of `identity` (and the leaf of `chain`) under
    /// `alias`, replacing what was there. Throws when the platform refuses
    /// the key (the caller then keeps the P12 form for it).
    func importIdentity(alias: String, identity: SecIdentity, chain: [SecCertificate]) throws

    /// The identity under `alias` for `leaf` — its key opaque, usable only
    /// through signatures and TLS — or nil when no key is stored under
    /// `alias`. Throws when the Keychain cannot say right now: "unreadable"
    /// must not read as "gone", or a hiccup would make the caller drop a good certificate.
    func identity(alias: String, leaf: SecCertificate) throws -> SecIdentity?

    func delete(alias: String)
}

/// Names and the stores of imported keys (Kotlin `ImportedClientKeys.Companion`).
enum ImportedKeys {
    private static let aliasPrefix = "pinvault_client_imported_"

    /// Keychain alias of the key imported for the credential stored under `label`.
    static func aliasFor(_ label: String) -> String { aliasPrefix + label }

    /// The Keychain. Preferred on a device.
    static func keychain() -> any ImportedClientKeys { KeychainImportedClientKeys() }
}

/// ``ImportedClientKeys`` in the Keychain.
final class KeychainImportedClientKeys: ImportedClientKeys, Sendable {

    private let options: KeystoreOptions
    private static let log = PinVaultLog.tag("ImportedClientKeys")

    init(options: KeystoreOptions = .shared) {
        self.options = options
    }

    func importIdentity(alias: String, identity: SecIdentity, chain: [SecCertificate]) throws {
        guard let leaf = chain.first else { throw PinVaultError.illegalArgument("certificate chain must not be empty") }
        var copied: SecKey?
        let status = SecIdentityCopyPrivateKey(identity, &copied)
        guard status == errSecSuccess, let key = copied else {
            throw KeychainIdentities.failure("The PKCS12 identity has no private key", status)
        }
        try options.generating("Imported client key", cleanUp: { delete(alias: alias) }) { unlockedDeviceRequired in
            delete(alias: alias)
            var add = KeychainIdentities.base(kSecClassKey)
            add[kSecValueRef] = key
            add[kSecAttrApplicationTag] = KeychainIdentities.tag(alias)
            add[kSecAttrLabel] = alias
            add[kSecAttrAccessible] = KeychainIdentities.accessibility(unlockedDeviceRequired: unlockedDeviceRequired)
            add[kSecAttrIsExtractable] = false
            let added = SecItemAdd(add as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw KeychainIdentities.failure("The Keychain refused the imported client key", added)
            }
            try KeychainIdentities.storeCertificate(leaf, alias: alias)
        }
        // An entry that cannot be read back is of no use: say so now, while
        // the caller still holds the P12.
        guard let imported = try self.identity(alias: alias, leaf: leaf) else {
            throw PinVaultError.illegalState("imported key cannot be read back")
        }
        // A Keychain key is a software key: with requireHardwareBackedKeys() it is refused.
        try options.checkLevel("Imported client key", KeyInspector.securityLevel(imported), cleanUp: { delete(alias: alias) })
    }

    func identity(alias: String, leaf: SecCertificate) throws -> SecIdentity? {
        guard try KeychainIdentities.privateKey(alias: alias) != nil else { return nil }
        return try KeychainIdentities.identity(alias: alias, leaf: leaf)
    }

    func delete(alias: String) {
        do {
            try KeychainIdentities.deleteKeys(alias: alias)
        } catch {
            Self.log.w("Could not delete an imported client key", error)
        }
        KeychainIdentities.removeCertificates(alias: alias)
    }
}

/// Stand-in for tests: identities held per alias for the process lifetime
/// (Kotlin `SoftwareImportedClientKeys`).
final class InMemoryImportedClientKeys: ImportedClientKeys, @unchecked Sendable {

    private struct State {
        var identities: [String: SecIdentity] = [:]
        var refused: Set<String> = []
        var unreadable = false
    }

    private let state = Locked(State())

    init() {}

    /// Aliases whose import fails, like a platform that refuses the key.
    func refuse(_ alias: String) { state.withLock { _ = $0.refused.insert(alias) } }

    /// While true every read fails, like a Keychain that is busy or locked.
    var unreadable: Bool {
        get { state.withLock { $0.unreadable } }
        set { state.withLock { $0.unreadable = newValue } }
    }

    func importIdentity(alias: String, identity: SecIdentity, chain: [SecCertificate]) throws {
        guard !chain.isEmpty else { throw PinVaultError.illegalArgument("certificate chain must not be empty") }
        try state.withLock { state in
            if state.refused.contains(alias) { throw PinVaultError.crypto(message: "import refused (test)") }
            state.identities[alias] = identity
        }
    }

    func identity(alias: String, leaf: SecCertificate) throws -> SecIdentity? {
        try state.withLock { state in
            if state.unreadable { throw PinVaultError.crypto(message: "Keychain operation failed (test)") }
            return state.identities[alias]
        }
    }

    func delete(alias: String) {
        state.withLock { _ = $0.identities.removeValue(forKey: alias) }
    }

    /// The private key stored under `alias` (tests).
    func privateKey(alias: String) -> SecKey? {
        guard let identity = state.withLock({ $0.identities[alias] }) else { return nil }
        var key: SecKey?
        SecIdentityCopyPrivateKey(identity, &key)
        return key
    }
}
