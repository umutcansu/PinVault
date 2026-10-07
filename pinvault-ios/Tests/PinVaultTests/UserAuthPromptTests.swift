import Foundation
import LocalAuthentication
import XCTest
@testable import PinVault

/// An evaluator that answers like LocalAuthentication would, without a sheet:
/// approve, reject with an `LAError`, or cancel. Records what it was asked.
final class ScriptedEvaluator: UserAuthEvaluator, @unchecked Sendable {
    enum Answer { case approve, fail(LAError.Code) }

    private let state = Locked<(answers: [Answer], prompts: [VaultFileUnlockPrompt], grants: [UserAuthGrant])>(([], [], []))
    let screenLock: Bool

    init(_ answers: [Answer], screenLock: Bool = true) {
        self.screenLock = screenLock
        state.withLock { $0.answers = answers }
    }

    var prompts: [VaultFileUnlockPrompt] { state.get().prompts }
    var grants: [UserAuthGrant] { state.get().grants }

    func canEvaluate() -> Bool { screenLock }

    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws {
        let answer = state.withLock { state -> Answer in
            state.prompts.append(prompt)
            state.grants.append(grant)
            return state.answers.isEmpty ? .approve : state.answers.removeFirst()
        }
        if case .fail(let code) = answer { throw LAError(code) }
    }
}

/// The LocalAuthentication side of `unlockFile` (Kotlin `UserAuthPrompt` and
/// the prompt half of `UserAuthKeystoreTest`), driven through an injectable
/// evaluator: approve, reject, cancel. The real sheet is checked by hand on the
/// simulator (`UserAuthKeychainKeysTests.testManualFaceID…`).
final class UserAuthPromptTests: XCTestCase {

    private let prompt = VaultFileUnlockPrompt(title: "Open statement", subtitle: "Bank", description: "Your monthly statement", negativeButtonText: "Not now")

    func testLocalAuthenticationErrorsMapToOutcomes() {
        for code: LAError.Code in [.userCancel, .appCancel, .systemCancel, .userFallback] {
            guard case .cancelled = UserAuthPrompt.outcomeOf(LAError(code)) else { return XCTFail("\(code)") }
        }
        guard case .noScreenLock = UserAuthPrompt.outcomeOf(LAError(.passcodeNotSet)) else { return XCTFail() }
        guard case .error(let message) = UserAuthPrompt.outcomeOf(LAError(.biometryLockout)) else { return XCTFail() }
        XCTAssertTrue(message.hasPrefix("Unlock prompt error -8: "), message)
        guard case .error(let failed) = UserAuthPrompt.outcomeOf(LAError(.authenticationFailed)) else { return XCTFail() }
        XCTAssertTrue(failed.hasPrefix("Unlock prompt error -1: "), failed)
        guard case .error(let other) = UserAuthPrompt.outcomeOf(URLError(.badURL)) else { return XCTFail() }
        XCTAssertTrue(other.hasPrefix("Unlock prompt error: "), other)
    }

    func testThePromptEvaluatesOnTheGrantsContextAndPassesItOn() async {
        let evaluator = ScriptedEvaluator([.approve])
        let grant = UserAuthGrant(context: LAContext())
        guard case .succeeded(let passed) = await UserAuthPrompt.authenticate(prompt: prompt, kind: .perUse, grant: grant, evaluator: evaluator) else {
            return XCTFail()
        }
        XCTAssertTrue(passed === grant)
        XCTAssertTrue(evaluator.grants.first === grant, "the key is used with the context the user passed")
        XCTAssertEqual(evaluator.prompts.first?.localizedReason, "Your monthly statement")
    }

    func testATimeBoundKindGetsAFreshContextAndNoGrant() async {
        let evaluator = ScriptedEvaluator([.approve])
        guard case .succeeded(nil) = await UserAuthPrompt.authenticate(prompt: prompt, kind: .timeBound, grant: nil, evaluator: evaluator) else {
            return XCTFail()
        }
        XCTAssertNotNil(evaluator.grants.first?.context)
    }

    func testTheLocalizedReasonFallsBackToSubtitleThenTitle() {
        XCTAssertEqual(VaultFileUnlockPrompt(title: "T", subtitle: "S").localizedReason, "S")
        XCTAssertEqual(VaultFileUnlockPrompt(title: "T").localizedReason, "T")
    }

    // MARK: The whole unlock with the scripted prompt

    private let inner = MemVaultStore()
    private let keys = SoftwareUserAuthKeys()
    private let content = Data(utf8: "account-statement")

    private func unlock(_ storage: UserAuthVaultStorage, _ evaluator: ScriptedEvaluator,
                        verify: UnlockVerifier? = nil) async -> VaultFileUnlockResult {
        let prompt = self.prompt
        return await storage.unlock("st", authenticate: { kind, grant in
            await UserAuthPrompt.authenticate(prompt: prompt, kind: kind, grant: grant, evaluator: evaluator)
        }, verify: verify)
    }

    func testApprovedTheFileOpens() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 7)
        let result = await unlock(storage, ScriptedEvaluator([.approve]))
        XCTAssertEqual(result, .unlocked(key: "st", version: 7, bytes: content))
    }

    func testRejectedTheFileStaysAndThePromptErrorIsReported() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 7)
        let failed = unlockFailure(await unlock(storage, ScriptedEvaluator([.fail(.authenticationFailed)])))
        XCTAssertTrue(failed.reason.hasPrefix("Unlock prompt error -1"), failed.reason)
        XCTAssertTrue(try storage.exists(key: "st"))
        XCTAssertEqual(keys.unwraps, 0, "the key is not touched")
    }

    func testCancelledTheServerSealedFileStaysSealed() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        try keys.ensureKey()
        try storage.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 4, signatures: [])
        let verified = Locked(false)
        let result = await unlock(storage, ScriptedEvaluator([.fail(.userCancel)]), verify: { _, _, _ in verified.set(true); return nil })
        XCTAssertEqual(result, .cancelled(key: "st"))
        XCTAssertFalse(verified.get(), "nothing is decrypted before the prompt passes")
        XCTAssertTrue(try storage.exists(key: "st"))
    }

    func testNoPasscodeIsReportedAsSuch() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 1)
        let failed = unlockFailure(await unlock(storage, ScriptedEvaluator([.fail(.passcodeNotSet)])))
        XCTAssertEqual(failed.reason, "The device has no screen lock; set one to open this file")
    }

    func testEveryLAContextAGrantCarriedIsInvalidatedWhenTheUnlockEnds() async throws {
        /// Software keys whose grants carry a real LAContext, like the Keychain key's.
        final class ContextKeys: UserAuthKeys, @unchecked Sendable {
            let base = SoftwareUserAuthKeys()
            let contexts = Locked<[LAContext]>([])
            func isScreenLockSet() -> Bool { true }
            func state() throws -> UserAuthKeyState { try base.state() }
            func ensureKey() throws -> Bool { try base.ensureKey() }
            func publicKey() throws -> SecKey { try base.publicKey() }
            func kind() throws -> UserAuthKeyKind { .perUse }
            func grantForPrompt() throws -> UserAuthGrant? {
                let context = LAContext()
                contexts.withLock { $0.append(context) }
                return UserAuthGrant(context: context)
            }
            func unwrap(_ grant: UserAuthGrant?, _ wrapped: Data) throws -> Data { try base.unwrap(grant, wrapped) }
            func attestationChain() throws -> [Data] { [] }
            func delete() { base.delete() }
        }
        let contextKeys = ContextKeys()
        let storage = UserAuthVaultStorage(inner: inner, keys: contextKeys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 1)
        let result = await storage.unlock("st", authenticate: { _, grant in .succeeded(grant) })
        XCTAssertEqual(result, .unlocked(key: "st", version: 1, bytes: content))

        let context = try XCTUnwrap(contextKeys.contexts.get().first)
        var error: NSError?
        XCTAssertFalse(context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error))
        XCTAssertEqual(error?.code, LAError.Code.invalidContext.rawValue, "the evaluated context no longer authorises anything")
    }
}
