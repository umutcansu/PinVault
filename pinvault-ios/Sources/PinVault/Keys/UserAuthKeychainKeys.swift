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
/// A key use never prompts by itself (`interactionNotAllowed`): without a
/// passed evaluation it fails, and the copy is kept. ThisDeviceOnly: never in
/// a backup, never on another device.
///
/// The Secure Enclave holds no RSA keys, so with `requireHardwareBacked` the
/// key is refused (``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``).
final class KeychainUserAuthKeys: UserAuthKeys {
    private let alias: String
    private let evaluator: any UserAuthEvaluator
    private let requireHardwareBacked: Bool
    let strength: UserAuthStrength
    /// Serialises ensureKey: a local seal and a registration may both find no
    /// key; only one may make it, or the other deletes the new key.
    private let lock = Locked(())
    private let log = PinVaultLog.tag("UserAuthKeys")

    init(
        alias: String = UserAuthKeyConstants.alias,
        evaluator: (any UserAuthEvaluator)? = nil,
        requireHardwareBacked: Bool = false,
        strength: UserAuthStrength = .deviceOwner
    ) {
        self.alias = alias
        self.evaluator = evaluator ?? SystemUserAuthEvaluator(strength: strength)
        self.requireHardwareBacked = requireHardwareBacked
        self.strength = strength
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
        do {
            // A context that may not show UI: reading the reference never asks.
            return try DeviceKeyKeychain.privateKey(tag: alias, context: UserAuthContexts.silent()) == nil ? .missing : .usable
        } catch let error as DeviceKeyKeychainError {
            // Locked, not gone: alive (Kotlin: a time-bound key outside its window).
            if UserAuthKeyError.authenticationStatuses.contains(error.status) { return .usable }
            throw UserAuthKeyError.keychainFailure(error)
        }
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
        try SPKI.publicKeyOf(privateKey(context: UserAuthContexts.silent()))
    }

    /// ``UserAuthKeyKind/perUse`` for the default key, ``UserAuthKeyKind/perUseBiometric``
    /// for a biometrics-only one (Android's "every use asks, fingerprint only").
    func kind() throws -> UserAuthKeyKind {
        _ = try privateKey(context: UserAuthContexts.silent())
        return kindForStrength
    }

    private var kindForStrength: UserAuthKeyKind {
        strength == .biometricCurrentSet ? .perUseBiometric : .perUse
    }

    func grantForPrompt() throws -> UserAuthGrant? {
        _ = try privateKey(context: UserAuthContexts.silent())
        return UserAuthGrant(context: LAContext())
    }

    func unwrap(_ grant: UserAuthGrant?, _ wrapped: Data) throws -> Data {
        // Never a prompt from the key use itself: an evaluated context authorises
        // it, an unevaluated one (or none) makes it fail.
        let context = (grant?.context as? LAContext) ?? LAContext()
        context.interactionNotAllowed = true
        let key = try privateKey(context: context)
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

    func delete() {
        do {
            try DeviceKeyKeychain.delete(tag: alias)
        } catch {
            log.w("Could not delete the user-auth key", error)
        }
    }

    // MARK: Internals

    private func privateKey(context: LAContext) throws -> SecKey {
        let key: SecKey?
        do {
            key = try DeviceKeyKeychain.privateKey(tag: alias, context: context)
        } catch let error as DeviceKeyKeychainError {
            throw UserAuthKeyError.keychainFailure(error)
        }
        guard let key else { throw UserAuthKeyError.retired("no user-auth key") }
        return key
    }

    private func generate() throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, Self.accessControlFlags(for: strength), &error
        ) else {
            throw PinVaultError.crypto(message: "User-auth key: access control refused", cause: error?.takeRetainedValue())
        }
        try DeviceKeyKeychain.generateRSA(tag: alias, accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, accessControl: access)
        // requireHardwareBackedKeys(): a software key is deleted and refused.
        try DeviceKeyLevelCheck.check("User-auth key", level: .software, required: requireHardwareBacked, cleanUp: delete)
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
