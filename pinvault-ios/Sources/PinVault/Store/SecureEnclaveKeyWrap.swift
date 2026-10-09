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

    /// `raw` in the wrapped form, or nil where no Secure Enclave key can be
    /// made or read right now (the caller then stores `raw` as before).
    static func wrap(_ raw: Data) -> Data? {
        guard let privateKey = wrappingKeyForWrap(), let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
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
        /// The wrapping key cannot be read or used now (locked device, a Keychain error, busy Secure Enclave).
        case unavailable(String)
        /// Not a value this library wrapped.
        case malformed
    }

    /// Failures of a decryption that a later try may not have: the device is
    /// locked, or the Secure Enclave is busy or not reachable now.
    static let transientStatuses: Set<OSStatus> = [errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed, errSecUserCanceled]

    /// Whether `stored` is in the wrapped form.
    static func isWrapped(_ stored: Data) -> Bool { stored.starts(with: magic) }

    /// The key bytes inside `stored`. Only a Keychain that answers "no such
    /// key" makes the item unusable for good; any other error keeps it.
    static func unwrap(_ stored: Data) throws -> Data {
        guard isWrapped(stored), stored.count > magic.count else { throw UnwrapError.malformed }
        let keys: [SecKey]
        switch lookup() {
        case .found(let found): keys = found
        case .notFound: throw UnwrapError.keyMissing
        case .failed(let status): throw UnwrapError.unavailable("the wrapping key cannot be read (OSStatus \(status))")
        }
        // More than one key under the tag (an app and its extension made one
        // each): the value opens with the one that wrapped it.
        var transient: String?
        var last = "decryption failed"
        var allPermanent = true
        for key in keys {
            var error: Unmanaged<CFError>?
            if let raw = SecKeyCreateDecryptedData(key, algorithm, stored.dropFirst(magic.count) as CFData, &error) as Data? {
                return raw
            }
            let failure = error?.takeRetainedValue()
            last = failure?.localizedDescription ?? last
            if let failure, isTransient(failure) { transient = last }
            if !(failure.map(isPermanent) ?? false) { allPermanent = false }
        }
        if let transient { throw UnwrapError.unavailable(transient) }
        // Replaced only on positive evidence that the value can never open
        // (a malformed ciphertext, a tag that does not verify); any other
        // failure — a CryptoTokenKit error of a busy Secure Enclave among
        // them — keeps the item and reports the store unreadable for now.
        guard allPermanent else { throw UnwrapError.unavailable(last) }
        log.e("A wrapped store key does not open: \(last)")
        throw UnwrapError.malformed
    }

    /// Decryption failures that mean the value can never open with this key.
    static let permanentStatuses: Set<OSStatus> = [errSecParam, errSecDecode]

    static func isPermanent(_ error: CFError) -> Bool {
        (CFErrorGetDomain(error) as String) == (kCFErrorDomainOSStatus as String)
            && permanentStatuses.contains(OSStatus(CFErrorGetCode(error)))
    }

    /// An OSStatus-domain error whose code a later try may not have.
    static func isTransient(_ error: CFError) -> Bool {
        (CFErrorGetDomain(error) as String) == (kCFErrorDomainOSStatus as String)
            && transientStatuses.contains(OSStatus(CFErrorGetCode(error)))
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

    enum Lookup {
        case found([SecKey])
        case notFound
        case failed(OSStatus)
    }

    /// Every wrapping key under the tag.
    static func lookup() -> Lookup {
        var query = query()
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitAll
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        switch status {
        case errSecSuccess:
            let keys = (items as? [SecKey]) ?? (items.map { [$0 as! SecKey] } ?? [])
            return keys.isEmpty ? .notFound : .found(keys)
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed(status)
        }
    }

    /// The key to wrap with: the existing one, or a new one when there is none
    /// (never when the Keychain could not be read: that could make a second key).
    private static func wrappingKeyForWrap() -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        switch lookup() {
        case .found(let keys): return keys.first
        case .failed: return nil
        case .notFound: break
        }
        guard !unavailable else { return nil }
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
            let cfError = error?.takeRetainedValue()
            let status = cfError.map { OSStatus(($0 as Error as NSError).code) }
            // A transient failure (locked device, Secure Enclave busy / try again)
            // must not latch `unavailable` for the whole process: that would write
            // store keys raw until the next launch. Only a genuine "no Secure
            // Enclave here" (simulator, unsigned test run) latches, so a device
            // that was merely locked wraps again on a later read. (IOS-2)
            if let status, transientStatuses.contains(status) {
                log.d("Secure Enclave key not available right now, will retry: \(cfError?.localizedDescription ?? "unknown error")")
            } else {
                log.d("No Secure Enclave key for wrapping store keys: \(cfError?.localizedDescription ?? "unknown error")")
                unavailable = true
            }
            return nil
        }
        return key
    }
}
