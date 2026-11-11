import Foundation
import LocalAuthentication
import Security

/// The Keychain user-auth key (Kotlin `KeystoreUserAuthKeys`): a permanent
/// RSA-2048 private key, application tag ``UserAuthKeyConstants/alias``, whose
/// access control is `SecAccessControl(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags)`
/// with `flags` chosen by the config's ``UserAuthStrength``:
///
/// - ``UserAuthStrength/deviceOwner`` (default): `.userPresence`. Every use
///   needs the device owner (Face ID / Touch ID or the passcode); the library
///   evaluates `.deviceOwnerAuthentication` on an `LAContext` first and uses
///   the key with `kSecUseAuthenticationContext: thatContext`, so a device
///   shows one prompt. `.userPresence` is not bound to the enrolled
///   biometrics, so enrolling a new face or finger does not retire it;
///   removing the passcode deletes the item (`WhenPasscodeSet…`), which the
///   library sees as a missing key (``UserAuthKeyState/missing``) — the
///   counterpart of Android retiring it.
/// - ``UserAuthStrength/biometricCurrentSet``: `.biometryCurrentSet`. Only the
///   biometrics enrolled when the key was made open it (the prompt evaluates
///   `.deviceOwnerAuthenticationWithBiometrics`; no passcode fallback). When
///   the enrolment changes the Keychain refuses the key even after a passed
///   prompt: that refusal (`errSecAuthFailed` on a use the evaluated context
///   authorised, or an item the Keychain no longer finds) is read as the key
///   being retired, the item is deleted and every copy sealed with it is given
///   up (``VaultFileUnlockResult/invalidated(key:)``); the next fetch makes a
///   new key. Removing the last face or finger is reported by the prompt
///   itself (`LAError.biometryNotEnrolled`, see ``UserAuthPrompt``).
///
/// **The public record.** The private key is never read before the user has
/// passed the prompt. For a key outside the Secure Enclave the Keychain has to
/// decrypt the item to hand out a `SecKey`, so a device may evaluate the
/// access control already at `SecItemCopyMatching` and refuse a silent lookup
/// (`errSecInteractionNotAllowed`); the simulator does not enforce it at all.
/// Everything needed before the prompt — the public half (SPKI) the server and
/// local seals wrap for, the key's kind — is therefore kept in a second item,
/// a generic password (service ``publicRecordService``, account = the tag)
/// WITHOUT user-presence access control, same accessibility
/// (`WhenPasscodeSetThisDeviceOnly`, never synchronised), written when the
/// key is generated. ``state()``, ``publicKey()``, ``kind()`` and
/// ``grantForPrompt()`` read that; only ``unwrap(_:_:)`` reads the private key,
/// with the context the user just authenticated.
///
/// The record cannot swap the key: after the private key is read in the
/// unwrap, its public half must equal the record's SPKI, otherwise both items
/// are deleted and the key counts as retired (``UserAuthKeyError/retired(_:)``).
/// Deleting or retiring the key deletes the record.
///
/// A key made by an earlier build has no record: until the private key is
/// first legitimately read (a silent lookup the Keychain allows, or the unwrap
/// after a passed prompt), which writes it, the lookups fall back to reading
/// the private key as before.
///
/// A key use never prompts by itself (`interactionNotAllowed`): without a
/// passed evaluation it fails, and the copy is kept. ThisDeviceOnly: never in
/// a backup, never on another device.
///
/// The Secure Enclave holds no RSA keys, so with `requireHardwareBacked` the
/// key is refused (``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``).
final class KeychainUserAuthKeys: UserAuthKeys {
    /// The Keychain service of the public record.
    static let publicRecordService = "io.github.umutcansu.pinvault.userauth.public"

    private let alias: String
    private let evaluator: any UserAuthEvaluator
    private let requireHardwareBacked: Bool
    private let keychain: any UserAuthKeychain
    let strength: UserAuthStrength
    /// Serialises ensureKey: a local seal and a registration may both find no
    /// key; only one may make it, or the other deletes the new key.
    private let lock = Locked(())
    private let log = PinVaultLog.tag("UserAuthKeys")

    init(
        alias: String = UserAuthKeyConstants.alias,
        evaluator: (any UserAuthEvaluator)? = nil,
        requireHardwareBacked: Bool = false,
        strength: UserAuthStrength = .deviceOwner,
        keychain: any UserAuthKeychain = SystemUserAuthKeychain()
    ) {
        self.alias = alias
        self.evaluator = evaluator ?? SystemUserAuthEvaluator(strength: strength)
        self.requireHardwareBacked = requireHardwareBacked
        self.strength = strength
        self.keychain = keychain
    }

    /// The access-control flags of the key for `strength`.
    static func accessControlFlags(for strength: UserAuthStrength) -> SecAccessControlCreateFlags {
        switch strength {
        case .deviceOwner: return .userPresence
        case .biometricCurrentSet: return .biometryCurrentSet
        }
    }

    /// Whether the key's policy can be evaluated: a passcode, or (biometrics
    /// only) enrolled and usable biometrics.
    func isScreenLockSet() -> Bool {
        evaluator.canEvaluate()
    }

    func state() throws -> UserAuthKeyState {
        let key: SecKey?
        do {
            // A context that may not show UI: reading the reference never asks.
            key = try keychain.privateKey(tag: alias, context: UserAuthContexts.silent())
        } catch let error as DeviceKeyKeychainError {
            // Locked, not gone: alive (Kotlin: a time-bound key outside its window).
            if UserAuthKeyError.authenticationStatuses.contains(error.status) { return .usable }
            throw UserAuthKeyError.keychainFailure(error)
        }
        guard let key else { return .missing }
        // The Keychain handed the key out without a prompt (the simulator, or a
        // device that evaluates the access control only at use): bind the record now.
        do {
            try bindRecord(to: key)
        } catch UserAuthKeyError.retired {
            return .missing
        }
        return .usable
    }

    @discardableResult
    func ensureKey() throws -> Bool {
        try lock.withLock { _ in
            if try state() == .usable { return false }
            delete()
            try generate()
            log.i("User-auth key created (\(kindForStrength.rawValue))")
            return true
        }
    }

    func publicKey() throws -> SecKey {
        if let record = try readRecord() { return try SPKI.secKey(fromSPKI: record.spki) }
        // A key made by an earlier build: only the private key knows its public half.
        let key = try privateKey(context: UserAuthContexts.silent())
        try bindRecord(to: key)
        return try SPKI.publicKeyOf(key)
    }

    func publicKey(authorisedBy grant: UserAuthGrant?) throws -> SecKey {
        if let record = try readRecord() { return try SPKI.secKey(fromSPKI: record.spki) }
        guard let context = grant?.context as? LAContext else { return try publicKey() }
        // An earlier build's key after a passed prompt: read it with that context and keep its record.
        context.interactionNotAllowed = true
        let key = try privateKey(context: context)
        try bindRecord(to: key)
        return try SPKI.publicKeyOf(key)
    }

    /// ``UserAuthKeyKind/perUse`` for the default key, ``UserAuthKeyKind/perUseBiometric``
    /// for a biometrics-only one (Android's "every use asks, fingerprint only").
    /// What the record says the key was made as; without a record, the
    /// configured strength.
    func kind() throws -> UserAuthKeyKind {
        if let record = try? readRecord() { return record.kind }
        guard try state() == .usable else { throw UserAuthKeyError.retired("no user-auth key") }
        return kindForStrength
    }

    private var kindForStrength: UserAuthKeyKind {
        strength == .biometricCurrentSet ? .perUseBiometric : .perUse
    }

    func grantForPrompt() throws -> UserAuthGrant? {
        // Only whether the key is there: never its private half.
        guard try state() == .usable else { throw UserAuthKeyError.retired("no user-auth key") }
        return UserAuthGrant(context: LAContext())
    }

    func unwrap(_ grant: UserAuthGrant?, _ wrapped: Data) throws -> Data {
        // Never a prompt from the key use itself: an evaluated context authorises
        // it, an unevaluated one (or none) makes it fail.
        let context = (grant?.context as? LAContext) ?? LAContext()
        context.interactionNotAllowed = true
        let key = try privateKey(context: context)
        // The record wrapped for this key, or it is not this key's record.
        try bindRecord(to: key)
        do {
            return try UserAuthKeyConstants.unwrap(wrapped, with: key)
        } catch UserAuthKeyError.notAuthenticated(let status, let message)
            where strength == .biometricCurrentSet && status == errSecAuthFailed && grant?.context != nil {
            // The storage calls this only after the prompt passed on this very
            // context, and the Keychain still refuses the key: its
            // `.biometryCurrentSet` no longer matches the enrolled biometrics.
            // Retired — delete it so the next fetch makes a new one.
            log.w("User-auth key refused after a passed biometric prompt: the enrolled biometrics changed; retiring it (\(message))")
            delete()
            throw UserAuthKeyError.retired("the enrolled biometrics changed; the key was bound to the previous set")
        }
    }

    func attestationChain() throws -> [Data] { [] }

    /// Deletes the key and its public record.
    func delete() {
        do {
            try keychain.deletePrivateKey(tag: alias)
        } catch {
            log.w("Could not delete the user-auth key", error)
        }
        deleteRecord()
    }

    // MARK: Internals

    private func privateKey(context: LAContext) throws -> SecKey {
        let key: SecKey?
        do {
            key = try keychain.privateKey(tag: alias, context: context)
        } catch let error as DeviceKeyKeychainError {
            throw UserAuthKeyError.keychainFailure(error)
        }
        guard let key else {
            deleteRecord()
            throw UserAuthKeyError.retired("no user-auth key")
        }
        return key
    }

    private func generate() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, Self.accessControlFlags(for: strength), &error
        ) else {
            throw PinVaultError.crypto(message: "User-auth key: access control refused", cause: error?.takeRetainedValue())
        }
        let key = try keychain.generatePrivateKey(tag: alias, accessControl: access)
        do {
            // The public half straight from the new key: no Keychain read, no prompt.
            try writeRecord(UserAuthPublicRecord(tag: alias, kind: kindForStrength, spki: SPKI.der(for: key)))
        } catch {
            // A key without its record would be the earlier builds' kind again: none at all instead.
            delete()
            throw error
        }
        // requireHardwareBackedKeys(): a software key is deleted and refused.
        try DeviceKeyLevelCheck.check("User-auth key", level: .software, required: requireHardwareBacked, cleanUp: delete)
    }

    /// The public record, or nil when there is none (a key from an earlier
    /// build) or it is not a readable record of this tag (deleted). Throws
    /// when the Keychain cannot say.
    private func readRecord() throws -> UserAuthPublicRecord? {
        let data: Data?
        do {
            data = try keychain.publicRecord(tag: alias)
        } catch let error as DeviceKeyKeychainError {
            throw UserAuthKeyError.keychainFailure(error)
        }
        guard let data else { return nil }
        guard let record = UserAuthPublicRecord.decode(data), record.tag == alias else {
            log.w("The user-auth key's public record is unreadable; deleted (the private key writes it again)")
            deleteRecord()
            return nil
        }
        return record
    }

    /// `key` is the private key the Keychain just handed out: a record must be
    /// its public half (else both go: retired); a missing one is written now.
    private func bindRecord(to key: SecKey) throws {
        let spki = try SPKI.der(for: key)
        let record: UserAuthPublicRecord?
        do {
            record = try readRecord()
        } catch {
            // Cannot say now (should not happen with the key in hand): no binding, no rewrite.
            log.w("The user-auth key's public record cannot be read", error)
            return
        }
        if let record {
            if record.spki == spki { return }
            log.e("The user-auth key's public record does not belong to the private key; retiring both")
            delete()
            throw UserAuthKeyError.retired("the stored public key does not belong to the user-auth key")
        }
        do {
            try writeRecord(UserAuthPublicRecord(tag: alias, kind: kindForStrength, spki: spki))
            log.i("User-auth key: public record written for a key made by an earlier build")
        } catch {
            log.w("Could not write the user-auth key's public record; trying again at the next use", error)
        }
    }

    private func writeRecord(_ record: UserAuthPublicRecord) throws {
        do {
            try keychain.savePublicRecord(record.encode(), tag: alias)
        } catch let error as DeviceKeyKeychainError {
            throw UserAuthKeyError.keychainFailure(error)
        }
    }

    private func deleteRecord() {
        do {
            try keychain.deletePublicRecord(tag: alias)
        } catch {
            log.w("Could not delete the user-auth key's public record", error)
        }
    }
}

/// What is known about the user-auth key without its private half: the SPKI,
/// its key id (the first 8 bytes of SHA-256(SPKI), checked on read) and the
/// kind it was made as. JSON `{"v":1,"tag":…,"kind":…,"spki":<base64>,"keyId":<hex>}`.
struct UserAuthPublicRecord: Equatable {
    let tag: String
    let kind: UserAuthKeyKind
    let spki: Data

    var keyId: Data { Hashing.sha256(spki).prefix(UserAuthKeyConstants.keyIdBytes) }

    func encode() -> Data {
        let object: [String: Any] = [
            "v": 1, "tag": tag, "kind": kind.rawValue, "spki": Base64.encode(spki), "keyId": Hex.encode(keyId),
        ]
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    /// Nil unless every field is there and the key id matches the SPKI.
    static func decode(_ data: Data) -> UserAuthPublicRecord? {
        guard let json = LenientJSON.object(data),
              (json["v"] as? NSNumber)?.intValue == 1,
              let tag = json["tag"] as? String,
              let kind = (json["kind"] as? String).flatMap(UserAuthKeyKind.init(rawValue:)),
              let spki = (json["spki"] as? String).flatMap(Base64.decode), !spki.isEmpty,
              let keyId = (json["keyId"] as? String).flatMap(Hex.decode)
        else { return nil }
        let record = UserAuthPublicRecord(tag: tag, kind: kind, spki: spki)
        guard record.keyId == keyId, (try? SPKI.secKey(fromSPKI: spki)) != nil else { return nil }
        return record
    }
}

/// The Keychain calls behind ``KeychainUserAuthKeys`` (a seam: tests play a
/// device that refuses a silent lookup of the private key). Every call throws
/// ``DeviceKeyKeychainError`` for a Keychain answer other than found / not found.
protocol UserAuthKeychain: Sendable {
    /// The private key under `tag`, read with `context`; nil when there is none.
    func privateKey(tag: String, context: LAContext) throws -> SecKey?
    /// Makes the permanent private key under `tag` with `accessControl`; returns it.
    func generatePrivateKey(tag: String, accessControl: SecAccessControl) throws -> SecKey
    func deletePrivateKey(tag: String) throws
    /// The public record under `tag`, or nil.
    func publicRecord(tag: String) throws -> Data?
    func savePublicRecord(_ data: Data, tag: String) throws
    func deletePublicRecord(tag: String) throws
}

/// The system Keychain: the key through ``DeviceKeyKeychain``, the record as a
/// generic password (no access control, `WhenPasscodeSetThisDeviceOnly`, not synchronised).
struct SystemUserAuthKeychain: UserAuthKeychain {

    func privateKey(tag: String, context: LAContext) throws -> SecKey? {
        try DeviceKeyKeychain.privateKey(tag: tag, context: context)
    }

    func generatePrivateKey(tag: String, accessControl: SecAccessControl) throws -> SecKey {
        try DeviceKeyKeychain.generateRSA(tag: tag, accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, accessControl: accessControl)
    }

    func deletePrivateKey(tag: String) throws {
        try DeviceKeyKeychain.delete(tag: tag)
    }

    static func recordQuery(tag: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: KeychainUserAuthKeys.publicRecordService,
            kSecAttrAccount: tag,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    func publicRecord(tag: String) throws -> Data? {
        var query = Self.recordQuery(tag: tag)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw DeviceKeyKeychainError(status: errSecInternalComponent, operation: "read public record \(tag)")
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw DeviceKeyKeychainError(status: status, operation: "read public record \(tag)")
        }
    }

    func savePublicRecord(_ data: Data, tag: String) throws {
        try deletePublicRecord(tag: tag)
        var add = Self.recordQuery(tag: tag)
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceKeyKeychainError(status: status, operation: "write public record \(tag)")
        }
    }

    func deletePublicRecord(tag: String) throws {
        let status = SecItemDelete(Self.recordQuery(tag: tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DeviceKeyKeychainError(status: status, operation: "delete public record \(tag)")
        }
    }
}

/// The `LAContext` plumbing of the user-auth key.
enum UserAuthContexts {

    /// A context that never shows UI: reading a key reference with it never asks.
    static func silent() -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        return context
    }

    static func invalidate(_ context: AnyObject?) {
        (context as? LAContext)?.invalidate()
    }
}
