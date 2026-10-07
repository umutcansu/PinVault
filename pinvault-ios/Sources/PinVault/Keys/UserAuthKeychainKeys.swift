import Foundation
import LocalAuthentication
import Security

/// The Keychain user-auth key (Kotlin `KeystoreUserAuthKeys`): a permanent
/// RSA-2048 private key, application tag ``UserAuthKeyConstants/alias``, whose
/// access control is `SecAccessControl(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
/// .userPresence)`:
///
/// - every use needs the device owner (Face ID / Touch ID or the passcode);
///   the library evaluates `.deviceOwnerAuthentication` on an `LAContext` first
///   and uses the key with `kSecUseAuthenticationContext: thatContext`, so a
///   device shows one prompt. A key use never prompts by itself
///   (`interactionNotAllowed`): without a passed evaluation it fails, and the
///   copy is kept.
/// - `.userPresence` is not bound to the enrolled biometrics, so enrolling a
///   new face or finger does not retire it; removing the passcode deletes the
///   item (`WhenPasscodeSet…`), which the library sees as a missing key
///   (``UserAuthKeyState/missing``) — the counterpart of Android retiring it.
/// - ThisDeviceOnly: never in a backup, never on another device.
///
/// The Secure Enclave holds no RSA keys, so with `requireHardwareBacked` the
/// key is refused (``PinVaultError/hardwareBackedKeyRequired(keyKind:level:cause:)``).
final class KeychainUserAuthKeys: UserAuthKeys {
    private let alias: String
    private let evaluator: any UserAuthEvaluator
    private let requireHardwareBacked: Bool
    /// Serialises ensureKey: a local seal and a registration may both find no
    /// key; only one may make it, or the other deletes the new key.
    private let lock = Locked(())
    private let log = PinVaultLog.tag("UserAuthKeys")

    init(
        alias: String = UserAuthKeyConstants.alias,
        evaluator: any UserAuthEvaluator = SystemUserAuthEvaluator(),
        requireHardwareBacked: Bool = false
    ) {
        self.alias = alias
        self.evaluator = evaluator
        self.requireHardwareBacked = requireHardwareBacked
    }

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
            log.i("User-auth key created (\(UserAuthKeyKind.perUse.rawValue))")
            return true
        }
    }

    func publicKey() throws -> SecKey {
        try SPKI.publicKeyOf(privateKey(context: UserAuthContexts.silent()))
    }

    func kind() throws -> UserAuthKeyKind {
        _ = try privateKey(context: UserAuthContexts.silent())
        return .perUse
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
        return try UserAuthKeyConstants.unwrap(wrapped, with: key)
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
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error
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
