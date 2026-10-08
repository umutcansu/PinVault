import Foundation
import Security

extension DeviceKeys {

    /// The Keychain implementation (Kotlin `DeviceKeyProvider.androidKeystore`):
    /// a permanent RSA-2048 private key with application tag `alias`,
    /// `AfterFirstUnlockThisDeviceOnly` (`WhenUnlockedThisDeviceOnly` with
    /// `requireUnlockedDevice`), never in a backup. The Secure Enclave holds no
    /// RSA keys, so the key is a Keychain software key: with
    /// `requireHardwareBacked` it is refused
    /// (``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``).
    public static func keychain(
        alias: String = defaultAlias,
        requireUnlockedDevice: Bool = false,
        requireHardwareBacked: Bool = false
    ) -> any DeviceKeyProvider {
        KeychainDeviceKeyProvider(
            alias: alias, requireUnlockedDevice: requireUnlockedDevice, requireHardwareBacked: requireHardwareBacked
        )
    }

    /// A key held in memory for the process lifetime (Kotlin
    /// `DeviceKeyProvider.software`): tests and environments without a Keychain.
    public static func software(alias: String = defaultAlias) -> any DeviceKeyProvider {
        SoftwareDeviceKeyProvider(alias: alias)
    }
}

/// The Keychain-backed device RSA key (Kotlin `AndroidKeystoreDeviceKeyProvider`).
final class KeychainDeviceKeyProvider: DeviceKeyProvider {
    let alias: String
    private let requireUnlockedDevice: Bool
    private let requireHardwareBacked: Bool
    /// Serialises "is there a key" + "make one": two callers must not both generate.
    private let lock = Locked(())
    private let log = PinVaultLog.tag("DeviceKeyProvider")

    init(alias: String, requireUnlockedDevice: Bool = false, requireHardwareBacked: Bool = false) {
        self.alias = alias
        self.requireUnlockedDevice = requireUnlockedDevice
        self.requireHardwareBacked = requireHardwareBacked
    }

    func ensureKeyPair() throws {
        try lock.withLock { _ in
            if try DeviceKeyKeychain.privateKey(tag: alias) != nil {
                log.d("Device RSA key exists: \(alias)")
                return
            }
            log.i("Generating device RSA key in the Keychain: \(alias)")
            try DeviceKeyKeychain.generateRSA(
                tag: alias,
                accessible: requireUnlockedDevice
                    ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                accessControl: nil
            )
            // The Secure Enclave holds no RSA key: this one is always in software.
            try DeviceKeyLevelCheck.check(
                "Device RSA key", level: .software, required: requireHardwareBacked,
                cleanUp: { try? self.clear() }
            )
        }
    }

    func getPublicKeyPem() throws -> String {
        try SPKI.pem(for: getPrivateKey())
    }

    func getPrivateKey() throws -> SecKey {
        guard let key = try DeviceKeyKeychain.privateKey(tag: alias) else {
            throw PinVaultError.illegalState("Device RSA key not found — call ensureKeyPair() first")
        }
        return key
    }

    func clear() throws {
        try DeviceKeyKeychain.delete(tag: alias)
    }
}

/// The in-memory device RSA key (Kotlin `SoftwareDeviceKeyProvider`): same
/// crypto as the Keychain one, gone when the process ends.
final class SoftwareDeviceKeyProvider: DeviceKeyProvider {
    let alias: String
    private let keyPair = Locked<SecKey?>(nil)
    private let log = PinVaultLog.tag("DeviceKeyProvider")

    init(alias: String) {
        self.alias = alias
    }

    /// A provider over an existing private key (tests: a committed fixture key).
    init(alias: String, privateKey: SecKey) {
        self.alias = alias
        keyPair.set(privateKey)
    }

    func ensureKeyPair() throws {
        try keyPair.withLock { key in
            if key != nil { return }
            key = try DeviceKeyKeychain.ephemeralRSA()
            log.d("Generated software RSA key: \(alias)")
        }
    }

    func getPublicKeyPem() throws -> String {
        try SPKI.pem(for: getPrivateKey())
    }

    func getPrivateKey() throws -> SecKey {
        guard let key = keyPair.get() else { throw PinVaultError.illegalState("ensureKeyPair() first") }
        return key
    }

    func clear() throws {
        keyPair.set(nil)
    }
}

/// `KeystoreOptions.checkLevel` for the RSA keys of the vault (the device key
/// and the user-auth key): logs where the key lives and, with
/// `requireHardwareBackedKeys()`, refuses a key outside secure hardware.
enum DeviceKeyLevelCheck {
    private static let log = PinVaultLog.tag("KeystoreOptions")

    @discardableResult
    static func check(_ what: String, level: KeySecurityLevel, required: Bool, cleanUp: () -> Void = {}) throws -> KeySecurityLevel {
        if level.hardwareBacked {
            log.i("\(what): security level \(level.wireName)")
            return level
        }
        if required {
            log.e("\(what): the Keychain made the key at level \(level.wireName) and requireHardwareBackedKeys() is on — deleting it")
            cleanUp()
            throw PinVaultError.hardwareBackedKeyRequired(keyKind: what, level: level)
        }
        log.w("\(what): the Keychain made the key at level \(level.wireName) — not in secure hardware")
        return level
    }
}

/// The Keychain operations behind the vault's RSA keys (device key, user-auth key).
enum DeviceKeyKeychain {

    /// A key class private item with application tag `tag`.
    static func query(tag: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: Data(tag.utf8),
            kSecUseDataProtectionKeychain: true,
        ]
    }

    /// The private key under `tag`, or nil when there is none. `context`, when
    /// given, is the LocalAuthentication context its later use is authorised
    /// by (`kSecUseAuthenticationContext`). Throws ``DeviceKeyKeychainError``
    /// for any other Keychain answer.
    static func privateKey(tag: String, context: AnyObject? = nil) throws -> SecKey? {
        var query = query(tag: tag)
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        if let context { query[kSecUseAuthenticationContext] = context }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
                throw DeviceKeyKeychainError(status: errSecInternalComponent, operation: "read key \(tag)")
            }
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw DeviceKeyKeychainError(status: status, operation: "read key \(tag)")
        }
    }

    /// Generates a permanent RSA-2048 private key under `tag` (a key already
    /// there is not touched: callers delete first).
    static func generateRSA(tag: String, accessible: CFString, accessControl: SecAccessControl?) throws {
        var privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: Data(tag.utf8),
            kSecAttrLabel: tag,
        ]
        if let accessControl {
            privateAttributes[kSecAttrAccessControl] = accessControl
        } else {
            privateAttributes[kSecAttrAccessible] = accessible
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: privateAttributes,
        ]
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            let cause = error?.takeRetainedValue()
            let status = (cause as Error?).map { OSStatus(($0 as NSError).code) } ?? errSecInternalComponent
            throw DeviceKeyKeychainError(status: status, operation: "generate key \(tag)", cause: cause)
        }
    }

    /// An RSA-2048 key that lives in memory only.
    static func ephemeralRSA() throws -> SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw PinVaultError.crypto(message: "RSA key generation failed", cause: error?.takeRetainedValue())
        }
        return key
    }

    /// Deletes the key under `tag`; nothing there is not an error.
    static func delete(tag: String) throws {
        let status = SecItemDelete(query(tag: tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DeviceKeyKeychainError(status: status, operation: "delete key \(tag)")
        }
    }
}

/// A Keychain call that failed (Kotlin `KeyStoreException`).
struct DeviceKeyKeychainError: Error, CustomStringConvertible, LocalizedError {
    let status: OSStatus
    let operation: String
    var cause: (any Error)?

    init(status: OSStatus, operation: String, cause: (any Error)? = nil) {
        self.status = status
        self.operation = operation
        self.cause = cause
    }

    var description: String {
        let text = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return "KeyStoreException: Keychain could not \(operation) (OSStatus \(status): \(text))"
    }

    var errorDescription: String? { description }
}
