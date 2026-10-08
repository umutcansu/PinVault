import CryptoKit
import Foundation
import Security

/// The two operations ``SecurePreferences`` needs: authenticated encryption of
/// values and a keyed hash for preference names.
///
/// Errors: ``PrefsCipherError/badTag(_:)`` from ``open(_:aad:)`` means the
/// value was not sealed by this key with this AAD (Kotlin `AEADBadTagException`:
/// the entry is dropped). Any other error means the keys cannot be used right
/// now (Kotlin `GeneralSecurityException` / `ProviderException`: the entry is kept).
protocol PrefsCipher: Sendable {
    /// AES-256-GCM over `plaintext` with `aad`; returns `iv || ciphertext+tag`.
    func seal(_ plaintext: Data, aad: Data) throws -> Data

    /// Inverse of ``seal(_:aad:)``.
    func open(_ sealed: Data, aad: Data) throws -> Data

    /// HMAC-SHA256 of `input`.
    func mac(_ input: Data) throws -> Data
}

enum PrefsCipherError: Error, CustomStringConvertible {
    /// The sealed value does not open with this key and AAD (`AEADBadTagException`).
    case badTag(String)
    /// The keys cannot be read right now (Keychain locked or failing).
    case keyUnavailable(String)

    var description: String {
        switch self {
        case .badTag(let reason): return "AEADBadTagException: \(reason)"
        case .keyUnavailable(let reason): return "KeyStoreException: \(reason)"
        }
    }
}

/// The two 32-byte keys of the encrypted stores.
struct PrefsKeys: Sendable {
    let aes: SymmetricKey
    let mac: SymmetricKey
}

/// Where the store keys come from: the Keychain on a device, memory in tests.
protocol PrefsKeySource: Sendable {
    /// Both keys, created on first use. Throws when they cannot be read right now.
    func keys() throws -> PrefsKeys
}

/// ``PrefsCipher`` over CryptoKit with the keys of a ``PrefsKeySource``
/// (Kotlin `KeystorePrefsCipher`). One pair of keys per app, shared by every store.
struct KeyedPrefsCipher: PrefsCipher {
    static let ivLength = 12
    static let tagLength = 16

    let source: any PrefsKeySource

    func seal(_ plaintext: Data, aad: Data) throws -> Data {
        let key = try source.keys().aes
        let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        var out = Data(box.nonce)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    func open(_ sealed: Data, aad: Data) throws -> Data {
        guard sealed.count >= Self.ivLength + Self.tagLength else { throw PrefsCipherError.badTag("sealed value too short") }
        let key = try source.keys().aes
        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw PrefsCipherError.badTag("\(error)")
        }
    }

    func mac(_ input: Data) throws -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: input, using: try source.keys().mac))
    }
}

/// The store keys as Keychain generic passwords `pinvault_prefs_aes` /
/// `pinvault_prefs_mac` (service `io.github.umutcansu.pinvault`), 32 random
/// bytes each, wrapped by a Secure Enclave key where there is one
/// (``SecureEnclaveKeyWrap``), `AfterFirstUnlockThisDeviceOnly` — `WhenUnlockedThisDeviceOnly`
/// for keys made while `requireUnlockedDevice` is on (existing keys stay as
/// they are, as on Android).
///
/// The keys are kept in memory after the first read, except with
/// `requireUnlockedDevice`: then every use reads the Keychain, so a locked
/// device cannot open the stores (the Android Keystore refuses there too).
///
/// On macOS this needs an app with Keychain entitlements (data-protection
/// keychain); `swift test` injects ``InMemoryPrefsKeySource`` instead.
final class KeychainPrefsKeySource: PrefsKeySource, @unchecked Sendable {
    static let service = "io.github.umutcansu.pinvault"
    static let aesAlias = "pinvault_prefs_aes"
    static let macAlias = "pinvault_prefs_mac"
    static let keyLength = 32

    private let requireUnlockedDevice: @Sendable () -> Bool
    private let cached = Locked<PrefsKeys?>(nil)
    private let log = PinVaultLog.tag("KeystorePrefsCipher")

    init(requireUnlockedDevice: @escaping @Sendable () -> Bool) {
        self.requireUnlockedDevice = requireUnlockedDevice
    }

    func keys() throws -> PrefsKeys {
        if let keys = cached.get() { return keys }
        let unlockedOnly = requireUnlockedDevice()
        let keys = PrefsKeys(
            aes: SymmetricKey(data: try loadOrCreate(Self.aesAlias, what: "Store encryption key", unlockedOnly: unlockedOnly)),
            mac: SymmetricKey(data: try loadOrCreate(Self.macAlias, what: "Store name key", unlockedOnly: unlockedOnly))
        )
        if !unlockedOnly { cached.set(keys) }
        return keys
    }

    private func baseQuery(_ alias: String) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: alias,
        ]
        query[kSecUseDataProtectionKeychain] = true
        return query
    }

    private func loadOrCreate(_ alias: String, what: String, unlockedOnly: Bool) throws -> Data {
        for _ in 0..<2 {
            var query = baseQuery(alias)
            query[kSecReturnData] = true
            query[kSecMatchLimit] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            switch status {
            case errSecSuccess:
                if let data = item as? Data {
                    switch try StoredKeyBytes.read(data, length: Self.keyLength, what: what) {
                    case .raw(let key):
                        StoredKeyBytes.wrapInPlace(baseQuery(alias), raw: key, what: what, log: log)
                        return key
                    case .unwrapped(let key):
                        return key
                    case .unusable:
                        break
                    }
                }
                // Not a key this library wrote, or wrapped by a Secure Enclave key that is
                // gone: unusable for good, so it is replaced (entries sealed with it no
                // longer open and are dropped).
                log.e("\(what): the Keychain item \(alias) is not a usable key — replacing it")
                SecItemDelete(baseQuery(alias) as CFDictionary)
            case errSecItemNotFound:
                var key = Data(count: Self.keyLength)
                let generated = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Self.keyLength, $0.baseAddress!) }
                guard generated == errSecSuccess else {
                    throw PrefsCipherError.keyUnavailable("\(what): no random bytes (OSStatus \(generated))")
                }
                var add = baseQuery(alias)
                add[kSecValueData] = SecureEnclaveKeyWrap.wrap(key) ?? key
                add[kSecAttrAccessible] = unlockedOnly
                    ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                let added = SecItemAdd(add as CFDictionary, nil)
                if added == errSecSuccess {
                    log.i("\(what): created in the Keychain (\(unlockedOnly ? "WhenUnlockedThisDeviceOnly" : "AfterFirstUnlockThisDeviceOnly"))")
                    return key
                }
                // Another thread made it first: read that one.
                if added == errSecDuplicateItem { continue }
                throw PrefsCipherError.keyUnavailable("\(what): Keychain item \(alias) cannot be created (OSStatus \(added))")
            default:
                throw PrefsCipherError.keyUnavailable("\(what): Keychain item \(alias) cannot be read (OSStatus \(status))")
            }
        }
        throw PrefsCipherError.keyUnavailable("\(what): Keychain item \(alias) cannot be read")
    }
}

/// What a stored key item holds: the key in the clear (written before 2.4.0
/// or without a Secure Enclave), the key unwrapped, or nothing usable.
enum StoredKeyBytes {
    case raw(Data)
    case unwrapped(Data)
    case unusable

    /// Reads `data`; throws ``PrefsCipherError/keyUnavailable(_:)`` when the
    /// wrapping key exists but cannot be used now (the item is kept).
    static func read(_ data: Data, length: Int, what: String) throws -> StoredKeyBytes {
        if data.count == length && !SecureEnclaveKeyWrap.isWrapped(data) { return .raw(data) }
        guard SecureEnclaveKeyWrap.isWrapped(data) else { return .unusable }
        do {
            let key = try SecureEnclaveKeyWrap.unwrap(data)
            return key.count == length ? .unwrapped(key) : .unusable
        } catch SecureEnclaveKeyWrap.UnwrapError.unavailable(let reason) {
            throw PrefsCipherError.keyUnavailable("\(what): the Secure Enclave cannot open it now (\(reason))")
        } catch {
            return .unusable
        }
    }

    /// Replaces a clear key item with its wrapped form, when this device can wrap.
    static func wrapInPlace(_ query: [CFString: Any], raw: Data, what: String, log: PinVaultLog.Tag) {
        guard let wrapped = SecureEnclaveKeyWrap.wrap(raw) else { return }
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData: wrapped] as CFDictionary)
        if status == errSecSuccess {
            log.i("\(what): wrapped by the Secure Enclave")
        } else {
            log.w("\(what): cannot be wrapped in place (OSStatus \(status)); kept as it was")
        }
    }
}

/// Random keys held in memory (Kotlin test helper `SoftwarePrefsCipher`): for
/// tests and tools that must not touch the Keychain.
struct InMemoryPrefsKeySource: PrefsKeySource {
    private let stored = PrefsKeys(aes: SymmetricKey(size: .bits256), mac: SymmetricKey(size: .bits256))

    init() {}

    func keys() throws -> PrefsKeys { stored }
}
