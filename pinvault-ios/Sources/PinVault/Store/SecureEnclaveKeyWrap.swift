import Foundation
import Security

/// Wraps the stores' symmetric keys under a Secure Enclave key, so a Keychain
/// dump yields only ciphertext.
///
/// The store keys (``KeychainPrefsKeySource``, ``VaultFileKeychainKeys``) are
/// AES/HMAC keys CryptoKit needs as bytes, which the Secure Enclave cannot
/// hold. On Android they are non-exportable Keystore keys; here, without this
/// wrap, they are generic-password bytes that a jailbroken device's Keychain
/// dump reads in the clear. Wrapped, they are opened on each read by one
/// P-256 Secure Enclave key (`.privateKeyUsage`, this device only,
/// `AfterFirstUnlockThisDeviceOnly`; the stored item keeps its own, possibly
/// stricter, accessibility): usable in the app on this device, never copied
/// off it.
///
/// Stored form: `PVW1` ‖ ECIES (X9.63 SHA-256, AES-GCM, variable IV) of the
/// 32 key bytes. A 32-byte item is a key written before 2.4.0 (or where the
/// Secure Enclave is missing: the simulator, macOS test runs); it keeps
/// working and is wrapped the first time it is read on a device that can.
/// Going back to an older library makes the wrapped items unreadable, and the
/// stores start empty, as after any key loss.
enum SecureEnclaveKeyWrap {
    static let magic = Data("PVW1".utf8)
    static let keyTag = Data("io.github.umutcansu.pinvault.store-key-wrap".utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private static let log = PinVaultLog.tag("SecureEnclaveKeyWrap")
    private static let lock = NSLock()
    /// Set once making the key failed: no Secure Enclave here, so later calls do not retry.
    nonisolated(unsafe) private static var unavailable = false

    /// Failures of a decryption that a later try may not have: the device is
    /// locked, or the Secure Enclave is busy or not reachable now.
    static let transientStatuses: Set<OSStatus> = [errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed, errSecUserCanceled]

    /// Whether `stored` is in the wrapped form.
    static func isWrapped(_ stored: Data) -> Bool { stored.starts(with: magic) }

    /// `raw` in the wrapped form, or nil where no Secure Enclave key can be
    /// made (the caller then stores `raw` as before).
    static func wrap(_ raw: Data) -> Data? {
        guard let privateKey = wrappingKey(create: true), let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        var error: Unmanaged<CFError>?
        guard let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, raw as CFData, &error) as Data? else {
            log.w("Store key cannot be wrapped: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")")
            return nil
        }
        return magic + sealed
    }

    enum UnwrapError: Error {
        /// The wrapping key is gone: the item can never open again.
        case keyMissing
        /// The wrapping key exists but cannot be used now (locked device, busy Secure Enclave).
        case unavailable(String)
        /// Not a value this library wrapped.
        case malformed
    }

    /// The key bytes inside `stored`.
    static func unwrap(_ stored: Data) throws -> Data {
        guard isWrapped(stored), stored.count > magic.count else { throw UnwrapError.malformed }
        guard let privateKey = wrappingKey(create: false) else { throw UnwrapError.keyMissing }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCreateDecryptedData(privateKey, algorithm, stored.dropFirst(magic.count) as CFData, &error) as Data? else {
            let failure = error?.takeRetainedValue()
            let reason = failure?.localizedDescription ?? "decryption failed"
            // Only a key that cannot be used right now keeps the item; a value it
            // cannot open (errSecParam, a bad tag) never will.
            if let failure, Self.transientStatuses.contains(OSStatus(CFErrorGetCode(failure))) {
                throw UnwrapError.unavailable(reason)
            }
            log.e("A wrapped store key does not open: \(reason)")
            throw UnwrapError.malformed
        }
        return raw
    }

    private static func query() -> [CFString: Any] {
        [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    private static func wrappingKey(create: Bool) -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        var lookup = query()
        lookup[kSecReturnRef] = true
        lookup[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        if SecItemCopyMatching(lookup as CFDictionary, &item) == errSecSuccess, let found = item {
            return (found as! SecKey)
        }
        guard create, !unavailable else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error
        ) else {
            unavailable = true
            return nil
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: keyTag,
                kSecAttrAccessControl: access,
            ] as [CFString: Any],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            // Expected on the simulator and in unsigned test runs.
            log.d("No Secure Enclave key for wrapping store keys: \(error?.takeRetainedValue().localizedDescription ?? "unknown error")")
            unavailable = true
            return nil
        }
        return key
    }
}
