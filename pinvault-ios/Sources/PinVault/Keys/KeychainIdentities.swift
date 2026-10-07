import Foundation
import Security

/// The Keychain side of a client identity whose private key stays in the
/// Secure Enclave or the Keychain.
///
/// iOS has no public call that pairs a `SecKey` with a `SecCertificate` into
/// the `SecIdentity` a TLS handshake needs; the Keychain does that itself:
/// once the certificate is stored next to its key, a `kSecClassIdentity`
/// search returns the pair. So the leaf of an issued chain is stored in the
/// Keychain (label = the key's alias, data-protection Keychain, this device
/// only) — the chain itself stays in ``ClientCertSecureStore`` — and the
/// identity is looked up by the leaf's bytes.
///
/// Every call needs a Keychain: an app on a device or a signed simulator
/// build. Under `swift test` (and in a package test bundle on the simulator,
/// which runs in the unsigned `xctest` process) the Keychain answers
/// errSecMissingEntitlement (-34018).
enum KeychainIdentities {

    private static let log = PinVaultLog.tag("KeychainIdentities")

    /// Errors of the Keychain calls, with the OSStatus.
    static func failure(_ what: String, _ status: OSStatus) -> PinVaultError {
        let text = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return .crypto(message: "\(what) (\(status): \(text))")
    }

    // MARK: Certificates

    /// Stores `leaf` under `alias`, replacing the certificates stored under it
    /// before. A certificate the Keychain already holds (under any label) is
    /// left where it is: the identity search finds it all the same.
    static func storeCertificate(_ leaf: SecCertificate, alias: String) throws {
        removeCertificates(alias: alias, keeping: leaf)
        var add = base(kSecClassCertificate)
        add[kSecValueRef] = leaf
        add[kSecAttrLabel] = alias
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw failure("The client certificate cannot be stored in the Keychain", status)
        }
    }

    /// Deletes the certificates stored under `alias` (but `keeping`, when given).
    static func removeCertificates(alias: String, keeping: SecCertificate? = nil) {
        var query = base(kSecClassCertificate)
        query[kSecAttrLabel] = alias
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnRef] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let certificates = result as? [SecCertificate] else {
            if status != errSecItemNotFound && status != errSecSuccess {
                log.w("Client certificates under a key alias cannot be listed (OSStatus \(status))")
            }
            return
        }
        let kept = keeping.map { SecCertificateCopyData($0) as Data }
        for certificate in certificates where (SecCertificateCopyData(certificate) as Data) != kept {
            var delete = base(kSecClassCertificate)
            delete[kSecValueRef] = certificate
            let deleted = SecItemDelete(delete as CFDictionary)
            if deleted != errSecSuccess && deleted != errSecItemNotFound {
                log.w("A client certificate could not be deleted from the Keychain (OSStatus \(deleted))")
            }
        }
    }

    // MARK: Identities

    /// The identity that pairs `leaf` with its private key in the Keychain, or
    /// nil when the Keychain has no such pair (the key is gone, or the
    /// certificate is not stored). Throws when the Keychain cannot be searched now.
    static func identity(for leaf: SecCertificate) throws -> SecIdentity? {
        var query = base(kSecClassIdentity)
        query[kSecMatchLimit] = kSecMatchLimitAll
        query[kSecReturnRef] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw failure("The Keychain cannot be searched for client identities", status) }
        let wanted = SecCertificateCopyData(leaf) as Data
        let identities: [SecIdentity]
        if let list = result as? [SecIdentity] {
            identities = list
        } else if let single = result, CFGetTypeID(single) == SecIdentityGetTypeID() {
            // A CF type: the cast always succeeds once the type ID matches.
            identities = [single as! SecIdentity]
        } else {
            identities = []
        }
        for identity in identities {
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { continue }
            if (SecCertificateCopyData(certificate) as Data) == wanted { return identity }
        }
        return nil
    }

    /// The identity for `leaf` under `alias`: looked up, and when the Keychain
    /// has the key but not the certificate (first use after enrollment or
    /// renewal, or a Keychain that lost it), the leaf is stored and looked up
    /// again. Nil when no key in the Keychain pairs with it.
    static func identity(alias: String, leaf: SecCertificate) throws -> SecIdentity? {
        if let found = try identity(for: leaf) { return found }
        try storeCertificate(leaf, alias: alias)
        return try identity(for: leaf)
    }

    // MARK: Keys

    /// The private key stored under application tag `alias`; nil when there is none.
    static func privateKey(alias: String) throws -> SecKey? {
        var query = keyQuery(alias)
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw failure("The Keychain cannot read the key \(alias)", status)
        }
        // A CF type: the cast always succeeds once the type ID matches.
        return (result as! SecKey)
    }

    /// Whether a private key is stored under `alias`; nil when the Keychain cannot say now.
    static func hasPrivateKey(alias: String) -> Bool? {
        let status = SecItemCopyMatching(keyQuery(alias) as CFDictionary, nil)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        default:
            log.w("The Keychain cannot say whether the key \(alias) exists (OSStatus \(status))")
            return nil
        }
    }

    /// Deletes every key stored under `alias` (both halves of a pair).
    static func deleteKeys(alias: String) throws {
        var query = base(kSecClassKey)
        query[kSecAttrApplicationTag] = tag(alias)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw failure("The Keychain cannot delete the key \(alias)", status)
        }
    }

    static func tag(_ alias: String) -> Data { Data(alias.utf8) }

    static func keyQuery(_ alias: String) -> [CFString: Any] {
        var query = base(kSecClassKey)
        query[kSecAttrApplicationTag] = tag(alias)
        query[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        return query
    }

    /// A query of `itemClass` in the data-protection Keychain.
    static func base(_ itemClass: CFString) -> [CFString: Any] {
        [kSecClass: itemClass, kSecUseDataProtectionKeychain: true]
    }

    /// `WhenUnlockedThisDeviceOnly` with `requireUnlockedDevice`, else `AfterFirstUnlockThisDeviceOnly`.
    static func accessibility(unlockedDeviceRequired: Bool) -> CFString {
        unlockedDeviceRequired ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }
}
