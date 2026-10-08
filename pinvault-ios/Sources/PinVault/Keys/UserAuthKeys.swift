import Foundation
import Security

/// How the user-auth key is opened (Kotlin `UserAuthKeyKind`). The iOS key is
/// ``perUse`` (``UserAuthStrength/deviceOwner``: every unlock evaluates the
/// device owner policy — Face ID, Touch ID or the passcode) or
/// ``perUseBiometric`` (``UserAuthStrength/biometricCurrentSet``: biometrics
/// only, bound to the enrolled set), and the key is used with the evaluated
/// context. ``timeBound`` exists on Android 7–10 and is kept so the shared
/// storage logic (and its tests) read the same.
enum UserAuthKeyKind: String, Sendable, Equatable {
    /// Every use asks: the biometrics or the passcode.
    case perUse = "PER_USE"
    /// Every use asks, biometrics only; the key dies with the enrolled set
    /// (Android 7–10 with a strong fingerprint; iOS `.biometryCurrentSet`).
    case perUseBiometric = "PER_USE_BIOMETRIC"
    /// Android 7–10 otherwise: opens for a few seconds after the screen lock.
    case timeBound = "TIME_BOUND"
}

/// Whether the user-auth key exists and works (Kotlin `UserAuthKeys.State`).
enum UserAuthKeyState: String, Sendable, Equatable {
    case usable = "USABLE"
    case missing = "MISSING"
    case invalidated = "INVALIDATED"
}

/// What a passed prompt authorises: the counterpart of the Android prompt's
/// `Cipher`. On iOS it carries the `LAContext` the device owner policy was
/// evaluated on; the key is then used with `kSecUseAuthenticationContext:
/// context`, so the user sees one prompt (and on the simulator, where the key's
/// access control is not enforced, the evaluation is what asks at all).
///
/// ``singleUse``: the grant authorises one key operation (an Android per-use
/// cipher). An evaluated `LAContext` authorises every use until it is
/// invalidated, so the library's grants are not single-use; the storage
/// invalidates them when the unlock is done.
final class UserAuthGrant: @unchecked Sendable {
    /// The `LAContext` (typed `AnyObject` so the type is usable where
    /// LocalAuthentication is not imported); nil for software test keys.
    let context: AnyObject?
    let singleUse: Bool

    init(context: AnyObject?, singleUse: Bool = false) {
        self.context = context
        self.singleUse = singleUse
    }

    /// Ends what the grant authorises (`LAContext.invalidate()`).
    func invalidate() {
        UserAuthContexts.invalidate(context)
    }
}

/// The key behind `userAuth` vault files (Kotlin `UserAuthKeys`): ONE RSA key
/// pair for the device whose private half the Keychain uses only after the
/// device owner was authenticated. Files sealed on the device and files the
/// server seals for it (`encryption = USER_AUTH`) both use it. Wrapping uses the
/// public half and needs no prompt.
///
/// Errors: ``UserAuthKeyError/retired(_:)`` means the key is gone (the passcode
/// was removed, which deletes the Keychain item). Any other error is a Keychain
/// hiccup: callers keep the key and every copy sealed with it and try again later.
protocol UserAuthKeys: Sendable {
    /// Whether the device has a passcode (`canEvaluatePolicy(.deviceOwnerAuthentication)`).
    func isScreenLockSet() -> Bool

    /// Whether the key exists and works. Throws on an error that says neither.
    func state() throws -> UserAuthKeyState

    /// Makes a key when there is none or it is gone; true when it did. Never
    /// replaces a key that may still work. Needs a passcode.
    @discardableResult func ensureKey() throws -> Bool

    /// The public half of the existing key.
    func publicKey() throws -> SecKey

    func kind() throws -> UserAuthKeyKind

    /// What the prompt must authorise for a per-use key (Kotlin
    /// `cipherForPrompt`), or nil for a time-bound key. Throws
    /// ``UserAuthKeyError/retired(_:)`` for a missing key.
    func grantForPrompt() throws -> UserAuthGrant?

    /// Unwraps `wrapped` (RSA-OAEP SHA-256, MGF1-SHA256) after a passed prompt.
    func unwrap(_ grant: UserAuthGrant?, _ wrapped: Data) throws -> Data

    /// The key's attestation chain (DER, leaf first). iOS keys carry none: always empty.
    func attestationChain() throws -> [Data]

    func delete()
}

/// Constants and helpers of the user-auth key (Kotlin `UserAuthKeys.Companion`).
enum UserAuthKeyConstants {
    /// Keychain application tag: one key for the whole device.
    static let alias = "pinvault_userauth_device"

    /// The RSA padding: SHA-256 with MGF1-SHA256 (what the server wraps with for
    /// a key registered as `RSA-OAEP-SHA256-MGF1-SHA256`).
    static let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256

    static let keyIdBytes = 8

    /// First 8 bytes of SHA-256 over the public key's SPKI: names the key a copy was sealed with.
    static func keyId(_ publicKey: SecKey) throws -> Data {
        Hashing.sha256(try SPKI.der(for: publicKey)).prefix(keyIdBytes)
    }

    /// SHA-256 of `pinvault-user-auth-key:v1:<deviceId>` (the Android
    /// attestation challenge; kept for parity, iOS keys carry no attestation).
    static func attestationChallenge(deviceId: String) -> Data {
        Hashing.sha256("pinvault-user-auth-key:v1:\(deviceId)")
    }

    /// True when `error` says the key is gone (Kotlin `isRetired`).
    static func isRetired(_ error: any Error) -> Bool {
        if case UserAuthKeyError.retired = error { return true }
        return false
    }

    /// RSA-OAEP wrap of `plaintext` for `publicKey`.
    static func wrap(_ plaintext: Data, for publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext as CFData, &error) as Data? else {
            throw PinVaultError.crypto(message: "RSA-OAEP wrap failed", cause: error?.takeRetainedValue())
        }
        return wrapped
    }

    /// RSA-OAEP unwrap with `privateKey`; failures become ``UserAuthKeyError``.
    static func unwrap(_ wrapped: Data, with privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(privateKey, algorithm, wrapped as CFData, &error) as Data? else {
            throw UserAuthKeyError.unwrapFailure(error?.takeRetainedValue())
        }
        return plain
    }
}

/// How a user-auth key operation failed. The cases are what the storage
/// decides on (Kotlin: `KeyPermanentlyInvalidatedException`, the
/// `WrongKeyForCopy` checks, `UserNotAuthenticatedException`, the rest).
enum UserAuthKeyError: Error, CustomStringConvertible, LocalizedError {
    /// The key is gone: no copy sealed with it opens again.
    case retired(String)
    /// The operation was not authorised (no passed prompt, user cancelled in a
    /// Keychain sheet, interaction not allowed). Says nothing about the copy.
    case notAuthenticated(status: OSStatus, message: String)
    /// RSA-OAEP did not decode with this key: the ciphertext was made for another key.
    case wrongKey(String)
    /// Any other Keychain / Security failure: says nothing about the copy.
    case keychain(status: OSStatus, message: String)

    /// `errSecParam` from `SecKeyCreateDecryptedData`: "RSAdecrypt wrong input",
    /// what Security answers when OAEP does not decode with this key.
    static let wrongKeyStatus: OSStatus = errSecParam

    /// The Security statuses that mean "not authorised", never "wrong key".
    static let authenticationStatuses: Set<OSStatus> = [
        errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed, errSecInteractionRequired,
    ]

    /// Classifies a `SecKeyCreateDecryptedData` failure.
    static func unwrapFailure(_ error: CFError?) -> UserAuthKeyError {
        guard let error else { return .keychain(status: errSecInternalComponent, message: "the key did not unwrap") }
        let nsError = error as Error as NSError
        let message = nsError.localizedDescription
        if nsError.domain == "com.apple.LocalAuthentication" {
            return .notAuthenticated(status: OSStatus(nsError.code), message: message)
        }
        guard nsError.domain == NSOSStatusErrorDomain else {
            return .keychain(status: OSStatus(truncatingIfNeeded: nsError.code), message: "\(nsError.domain) \(nsError.code): \(message)")
        }
        let status = OSStatus(truncatingIfNeeded: nsError.code)
        if authenticationStatuses.contains(status) { return .notAuthenticated(status: status, message: message) }
        if status == wrongKeyStatus { return .wrongKey(message) }
        if status == errSecItemNotFound || status == errSecInvalidKeyRef { return .retired(message) }
        return .keychain(status: status, message: message)
    }

    /// Classifies a Keychain read of the key.
    static func keychainFailure(_ error: DeviceKeyKeychainError) -> UserAuthKeyError {
        if authenticationStatuses.contains(error.status) {
            return .notAuthenticated(status: error.status, message: error.description)
        }
        return .keychain(status: error.status, message: error.description)
    }

    var description: String {
        switch self {
        case .retired(let message): return "KeyPermanentlyInvalidatedException: \(message)"
        case .notAuthenticated(let status, let message): return "UserNotAuthenticatedException: \(message) (OSStatus \(status))"
        case .wrongKey(let message): return "BadPaddingException: \(message)"
        case .keychain(let status, let message): return "KeyStoreException: \(message) (OSStatus \(status))"
        }
    }

    /// The Kotlin `e.message`.
    var message: String {
        switch self {
        case .retired(let message), .wrongKey(let message): return message
        case .notAuthenticated(_, let message), .keychain(_, let message): return message
        }
    }

    var errorDescription: String? { message }
}
