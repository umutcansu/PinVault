import Foundation
import LocalAuthentication

/// Runs the LocalAuthentication policy of the user-auth key. Injectable, so
/// tests drive "approved", "rejected" and "cancelled" without a system sheet.
protocol UserAuthEvaluator: Sendable {
    /// `canEvaluatePolicy` for the key's policy: the device has a passcode
    /// (``UserAuthStrength/deviceOwner``), or biometrics are enrolled and
    /// usable (``UserAuthStrength/biometricCurrentSet``).
    func canEvaluate() -> Bool

    /// Shows the prompt on `grant`'s context; returns when the user passed it,
    /// throws (an `LAError` for the system one) otherwise.
    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws
}

/// The system's evaluator: `LAContext.evaluatePolicy(policy, localizedReason:)`
/// with the policy matching the key's ``UserAuthStrength``.
struct SystemUserAuthEvaluator: UserAuthEvaluator {
    let strength: UserAuthStrength

    init(strength: UserAuthStrength = .deviceOwner) {
        self.strength = strength
    }

    /// `.deviceOwnerAuthentication` (biometrics or passcode) for the default key,
    /// `.deviceOwnerAuthenticationWithBiometrics` for a biometrics-only key.
    var policy: LAPolicy {
        Self.policy(for: strength)
    }

    static func policy(for strength: UserAuthStrength) -> LAPolicy {
        switch strength {
        case .deviceOwner: return .deviceOwnerAuthentication
        case .biometricCurrentSet: return .deviceOwnerAuthenticationWithBiometrics
        }
    }

    func canEvaluate() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(policy, error: &error)
    }

    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws {
        let context = (grant.context as? LAContext) ?? LAContext()
        context.localizedCancelTitle = prompt.negativeButtonText
        context.interactionNotAllowed = false
        let reason = prompt.localizedReason
        let passed = try await context.evaluatePolicy(policy, localizedReason: reason)
        if !passed { throw LAError(.authenticationFailed) }
    }
}

/// The system unlock prompt, matched to the kind of the user-auth key
/// (Kotlin `UserAuthPrompt`). On iOS every key is per use: the prompt
/// evaluates the key's policy on the grant's context, which the key is then
/// used with. ``UserAuthKeyKind/perUseBiometric`` is the biometrics-only key
/// (``UserAuthStrength/biometricCurrentSet``).
enum UserAuthPrompt {

    /// Shows the prompt for `kind`; `grant` is what it must authorise (nil for
    /// a time-bound key, which a fresh context then opens).
    static func authenticate(
        prompt: VaultFileUnlockPrompt,
        kind: UserAuthKeyKind,
        grant: UserAuthGrant?,
        evaluator: any UserAuthEvaluator
    ) async -> AuthOutcome {
        let target = grant ?? UserAuthGrant(context: LAContext())
        do {
            try await evaluator.evaluate(target, prompt: prompt)
            return .succeeded(grant)
        } catch {
            return outcomeOf(error, biometricOnly: kind == .perUseBiometric)
        }
    }

    /// LocalAuthentication's answer as an outcome (Kotlin `outcomeOf(errorCode, errString)`):
    /// the user, the app or the system closing the prompt is ``AuthOutcome/cancelled``
    /// (so is "Enter Passcode" on a biometrics-only prompt: there is no passcode
    /// way into that key), no passcode ``AuthOutcome/noScreenLock``, anything
    /// else an error with its code.
    ///
    /// For a biometrics-only key (`biometricOnly`), "no biometrics enrolled"
    /// is ``AuthOutcome/keyInvalidated(_:)``: a `.biometryCurrentSet` key dies
    /// with the last enrolled face or finger, so nothing sealed with it opens
    /// again. A lockout (too many failed attempts) stays an error: the key is
    /// fine, the user unlocks the device with the passcode and tries again.
    static func outcomeOf(_ error: any Error, biometricOnly: Bool = false) -> AuthOutcome {
        let nsError = error as NSError
        guard nsError.domain == LAError.errorDomain else {
            return .error("Unlock prompt error: \(error.localizedDescription)")
        }
        switch LAError.Code(rawValue: nsError.code) {
        case .userCancel?, .appCancel?, .systemCancel?, .userFallback?:
            return .cancelled
        case .passcodeNotSet?:
            return .noScreenLock
        case .biometryNotEnrolled? where biometricOnly:
            return .keyInvalidated("no biometrics are enrolled any more; the key was bound to the enrolled set")
        default:
            return .error("Unlock prompt error \(nsError.code): \(nsError.localizedDescription)")
        }
    }
}
