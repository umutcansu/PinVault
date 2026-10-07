import Foundation
import LocalAuthentication

/// Runs the LocalAuthentication device owner policy. Injectable, so tests drive
/// "approved", "rejected" and "cancelled" without a system sheet.
protocol UserAuthEvaluator: Sendable {
    /// `canEvaluatePolicy(.deviceOwnerAuthentication)`: the device has a passcode.
    func canEvaluate() -> Bool

    /// Shows the prompt on `grant`'s context; returns when the user passed it,
    /// throws (an `LAError` for the system one) otherwise.
    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws
}

/// The system's evaluator: `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)`.
struct SystemUserAuthEvaluator: UserAuthEvaluator {

    func canEvaluate() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws {
        let context = (grant.context as? LAContext) ?? LAContext()
        context.localizedCancelTitle = prompt.negativeButtonText
        context.interactionNotAllowed = false
        let reason = prompt.localizedReason
        let passed = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        if !passed { throw LAError(.authenticationFailed) }
    }
}

/// The system unlock prompt, matched to the kind of the user-auth key
/// (Kotlin `UserAuthPrompt`). On iOS every key is per use: the prompt
/// evaluates the device owner policy on the grant's context, which the key
/// is then used with.
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
            return outcomeOf(error)
        }
    }

    /// LocalAuthentication's answer as an outcome (Kotlin `outcomeOf(errorCode, errString)`):
    /// the user, the app or the system closing the prompt is ``AuthOutcome/cancelled``,
    /// no passcode ``AuthOutcome/noScreenLock``, anything else an error with its code.
    static func outcomeOf(_ error: any Error) -> AuthOutcome {
        let nsError = error as NSError
        guard nsError.domain == LAError.errorDomain else {
            return .error("Unlock prompt error: \(error.localizedDescription)")
        }
        switch LAError.Code(rawValue: nsError.code) {
        case .userCancel?, .appCancel?, .systemCancel?, .userFallback?:
            return .cancelled
        case .passcodeNotSet?:
            return .noScreenLock
        default:
            return .error("Unlock prompt error \(nsError.code): \(nsError.localizedDescription)")
        }
    }
}
