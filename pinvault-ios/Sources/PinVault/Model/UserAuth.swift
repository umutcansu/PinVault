import Foundation

/// Whether opening a vault file needs the person holding the phone.
///
/// A locked file is sealed to a device key that is used only after the user
/// passes the device passcode or biometrics (iOS: a Keychain RSA key with
/// `.userPresence`, LocalAuthentication `.deviceOwnerAuthentication`).
/// Fetching and storing need no prompt; reading goes through
/// `PinVault.unlockFile(key:prompt:)`. With ``VaultFileEncryption/userAuth``
/// the server seals the file for that key, so the content never reaches the
/// app before the prompt; otherwise the library seals it after download
/// (protection at rest only).
public enum UserAuth: String, Sendable, Equatable, Hashable, CaseIterable {
    /// No prompt: the file opens with `PinVault.loadFile` (default).
    case none = "NONE"
    /// Locked. Without a passcode the file is not stored: the fetch fails with
    /// ``PinVaultError/screenLockRequired(key:message:)``.
    case required = "REQUIRED"
    /// Locked when the device has a passcode; stored as with ``none`` when it
    /// has none, and sealed on the next open or fetch once a lock exists.
    case ifScreenLock = "IF_SCREEN_LOCK"
}

/// Texts of the unlock prompt. iOS shows `description` (else `subtitle`, else
/// `title`) as the LocalAuthentication reason; `negativeButtonText` is the
/// cancel title where the system allows one.
public struct VaultFileUnlockPrompt: Sendable, Equatable, Hashable {
    public var title: String
    public var subtitle: String?
    public var description: String?
    public var negativeButtonText: String

    public init(title: String, subtitle: String? = nil, description: String? = nil, negativeButtonText: String = "Cancel") {
        self.title = title
        self.subtitle = subtitle
        self.description = description
        self.negativeButtonText = negativeButtonText
    }

    /// The text LocalAuthentication shows (`localizedReason`).
    public var localizedReason: String {
        description ?? subtitle ?? title
    }
}

/// Result of `PinVault.unlockFile(key:prompt:)`.
public enum VaultFileUnlockResult: Sendable {
    case unlocked(key: String, version: Int, bytes: Data)
    /// Nothing stored yet: call `fetchFile` first.
    case notFound(key: String)
    /// The user closed the prompt.
    case cancelled(key: String)
    /// The key no longer works (the passcode was removed, or the copy was
    /// sealed for a key that is gone). The stored copy is deleted; `fetchFile`
    /// downloads it again with a new key.
    case invalidated(key: String)
    /// Older than the file's `maxOfflineAge`; no prompt was shown.
    case stale(key: String)
    /// Too many wrong attempts, a key store error, a copy that failed its
    /// signature check, …; `reason` says which.
    case failed(key: String, reason: String, exception: (any Error)? = nil)

    /// The file key, whatever the case.
    public var key: String {
        switch self {
        case .unlocked(let key, _, _), .notFound(let key), .cancelled(let key), .invalidated(let key),
             .stale(let key), .failed(let key, _, _):
            return key
        }
    }
}

extension VaultFileUnlockResult: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.unlocked(k1, v1, b1), .unlocked(k2, v2, b2)): return k1 == k2 && v1 == v2 && b1 == b2
        case let (.notFound(a), .notFound(b)), let (.cancelled(a), .cancelled(b)),
             let (.invalidated(a), .invalidated(b)), let (.stale(a), .stale(b)):
            return a == b
        case let (.failed(k1, r1, e1), .failed(k2, r2, e2)): return k1 == k2 && r1 == r2 && errorsEqual(e1, e2)
        default: return false
        }
    }
}
