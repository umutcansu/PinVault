import Foundation

/// The operations an ``EnvironmentGuard`` is asked about.
public enum GuardedOperation: String, Sendable, Equatable, Hashable, CaseIterable {
    /// `PinVault.start` (both overloads; Kotlin `INIT`). Refused: ``InitResult/failed(reason:exception:)``.
    case start = "INIT"
    /// `enroll`, `enrollForResult`, `autoEnroll`, `autoEnrollForResult`,
    /// `checkPendingEnrollment` (with or without a config) and the pick-up of a
    /// pending enrollment at start and on periodic updates. Refused:
    /// ``ClientCertEnrollmentResult/failed(message:cause:)``; nothing is sent.
    case enroll = "ENROLL"
    /// `fetchFile`, `syncAllFiles` and the periodic sync. Refused:
    /// ``VaultFileResult/failed(key:reason:exception:code:)``; nothing is downloaded.
    case fetchFile = "FETCH_FILE"
    /// `unlockFile`. Refused: ``VaultFileUnlockResult/failed(key:reason:exception:)``;
    /// no prompt is shown.
    case unlockFile = "UNLOCK_FILE"
    /// `loadFile` (and `loadFileAsString`): reading a stored copy, which needs
    /// no network. Refused: nil, the copy is not decrypted and stays stored.
    /// Added in 2.4.0: an exhaustive `switch` over this enum needs a case for it.
    case loadFile = "LOAD_FILE"
}

/// The app's own answer to "may PinVault do this here, now?".
///
/// PinVault detects nothing about the device itself (no jailbreak, hooking,
/// debugger checks for this purpose): wire the verdict of a tool made for it
/// here. PinVault asks just before each ``GuardedOperation`` and refuses it on
/// `false`. A guard that throws refuses (fail closed). Keep it quick: it runs
/// on the calling task. A check inside the app can be switched off by whoever
/// controls the device — let the server decide what matters
/// (``IntegrityTokenProvider``).
public protocol EnvironmentGuard: Sendable {
    /// True when `operation` may run on this device now.
    func allows(_ operation: GuardedOperation) throws -> Bool
}

/// An ``EnvironmentGuard`` made from a closure
/// (`PinVaultConfig.Builder.environmentGuard { op in … }`).
public struct ClosureEnvironmentGuard: EnvironmentGuard {
    private let body: @Sendable (GuardedOperation) throws -> Bool

    public init(_ body: @escaping @Sendable (GuardedOperation) throws -> Bool) {
        self.body = body
    }

    public func allows(_ operation: GuardedOperation) throws -> Bool {
        try body(operation)
    }
}
