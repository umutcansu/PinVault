import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import PinVault

/// Port of the instrumented UserAuthKeystoreTest: ``UserAuthVaultStorage`` on
/// the real Keychain key (``KeychainUserAuthKeys``). Runs hosted by an app on
/// the simulator (`Tests/VaultKeychainHost`); the SwiftPM runner has no
/// Keychain entitlement (macOS and simulator alike) and skips.
///
/// The simulator does not enforce the key's `.userPresence` access control,
/// so the prompt is a scripted evaluator here; the real Face ID sheet is the
/// manual test at the end (see its comment for the `notifyutil` steps).
final class UserAuthKeychainKeysTests: XCTestCase {

    private let alias = "pinvault_userauth_test"
    private let inner = MemVaultStore()
    private let content = Data(utf8: "account-statement")
    private var keys: KeychainUserAuthKeys!

    override func setUpWithError() throws {
        keys = KeychainUserAuthKeys(alias: alias, evaluator: ScriptedEvaluator([]))
        keys.delete()   // every test starts with a fresh device key
        do {
            try keys.ensureKey()
        } catch UserAuthKeyError.keychain(let status, _) where status == errSecMissingEntitlement {
            throw XCTSkip("no Keychain entitlement in this test process (SwiftPM runner); runs hosted: Tests/VaultKeychainHost")
        } catch let error as DeviceKeyKeychainError where error.status == errSecMissingEntitlement {
            throw XCTSkip("no Keychain entitlement in this test process (SwiftPM runner); runs hosted: Tests/VaultKeychainHost")
        }
        keys.delete()
        let keys = self.keys!
        addTeardownBlock { keys.delete() }
    }

    private func unlock(_ storage: UserAuthVaultStorage, _ evaluator: ScriptedEvaluator,
                        onSealedForAnotherKey: @escaping @Sendable () -> Void = {},
                        verify: UnlockVerifier? = nil) async -> VaultFileUnlockResult {
        await storage.unlock("st", authenticate: { kind, grant in
            await UserAuthPrompt.authenticate(prompt: VaultFileUnlockPrompt(title: "Open statement"), kind: kind, grant: grant, evaluator: evaluator)
        }, onSealedForAnotherKey: onSealedForAnotherKey, verify: verify)
    }

    func testTheKeyIsPerUse() throws {
        try keys.ensureKey()
        XCTAssertEqual(try keys.kind(), .perUse)
        XCTAssertTrue(try keys.grantForPrompt()?.context is LAContext, "the prompt authorises an LAContext")
        XCTAssertEqual(try keys.attestationChain(), [])
    }

    func testEnsureKeyKeepsAUsableKey() throws {
        XCTAssertTrue(try keys.ensureKey(), "the first call makes the key")
        let first = try SPKI.der(for: keys.publicKey())
        XCTAssertFalse(try keys.ensureKey(), "a usable key is never replaced")
        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), first)
        XCTAssertEqual(try keys.state(), .usable)
        // Another instance over the same tag sees the same key: it lives in the Keychain.
        XCTAssertEqual(try SPKI.der(for: KeychainUserAuthKeys(alias: alias).publicKey()), first)
    }

    func testTheKeyIsUserPresenceWhenPasscodeSetThisDeviceOnly() throws {
        try keys.ensureKey()
        var query = DeviceKeyKeychain.query(tag: alias)
        query[kSecReturnAttributes] = true
        query[kSecUseAuthenticationContext] = UserAuthContexts.silent()
        var item: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &item), errSecSuccess)
        let attributes = try XCTUnwrap(item as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
        XCTAssertNotNil(attributes[kSecAttrAccessControl as String], "the key carries its access control")
        XCTAssertNotEqual(attributes[kSecAttrSynchronizable as String] as? Bool, true)
    }

    func testAMissingKeyIsRetiredNotAHiccup() throws {
        XCTAssertEqual(try keys.state(), .missing)
        XCTAssertThrowsError(try keys.grantForPrompt()) { XCTAssertTrue(UserAuthKeyConstants.isRetired($0)) }
        XCTAssertThrowsError(try keys.publicKey()) { XCTAssertTrue(UserAuthKeyConstants.isRetired($0)) }
        XCTAssertThrowsError(try keys.unwrap(nil, Data(count: 256))) { XCTAssertTrue(UserAuthKeyConstants.isRetired($0)) }
    }

    func testTheScreenLockOpensALocallySealedFile() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 7)
        XCTAssertTrue(try storage.isLocked("st"))
        XCTAssertNil(try storage.load(key: "st"))

        let result = await unlock(storage, ScriptedEvaluator([.approve]))
        XCTAssertEqual(result, .unlocked(key: "st", version: 7, bytes: content))
    }

    func testAServerSealedFileOpensOnlyAfterThePrompt() async throws {
        try keys.ensureKey()
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        try storage.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 4,
                                       signatures: [SignatureEntry(keyId: "k1", signature: "sig")])
        XCTAssertNil(try storage.load(key: "st"))

        let cancelled = await unlock(storage, ScriptedEvaluator([.fail(.userCancel)]), verify: { _, _, _ in nil })
        XCTAssertEqual(cancelled, .cancelled(key: "st"))
        let checked = Locked<(String, Int)?>(nil)
        let result = await unlock(storage, ScriptedEvaluator([.approve]), verify: { plain, version, _ in
            checked.set((String(decoding: plain, as: UTF8.self), version))
            return nil
        })
        XCTAssertEqual(result, .unlocked(key: "st", version: 4, bytes: content))
        XCTAssertEqual(checked.get()?.0, "account-statement")
        XCTAssertEqual(checked.get()?.1, 4)
    }

    func testACopySealedForAnotherKeyIsGivenUpAfterThePrompt() async throws {
        try keys.ensureKey()
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        // Stamped with this key, but wrapped for another one: after the prompt the
        // Keychain key's OAEP decode fails with errSecParam.
        let other = try rsaPrivateKey()
        try storage.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, publicOf(other)), version: 4, signatures: [])
        let forgotten = Locked(false)

        let result = await unlock(storage, ScriptedEvaluator([.approve]), onSealedForAnotherKey: { forgotten.set(true) }, verify: { _, _, _ in nil })
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try storage.exists(key: "st"), "the copy is deleted")
        XCTAssertTrue(forgotten.get(), "the registration is forgotten")
        XCTAssertEqual(try keys.state(), .usable, "the key stays")
    }

    func testACopySealedWithADeletedKeyIsGivenUp() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 1)
        keys.delete()   // what removing the passcode does to a WhenPasscodeSet item

        let result = await unlock(storage, ScriptedEvaluator([.approve]))
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    #if !targetEnvironment(simulator)
    /// On a device the Keychain enforces `.userPresence`: a forged "prompt
    /// passed" (an unevaluated context) fools our code, not the Keychain.
    func testTheKeychainRefusesTheKeyWithoutThePrompt() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 1)
        let result = await storage.unlock("st", authenticate: { _, grant in .succeeded(grant) })
        unlockFailure(result)
        XCTAssertTrue(try storage.exists(key: "st"), "a refused key is not a missing one: the copy stays")
        XCTAssertEqual(try keys.state(), .usable)
    }
    #endif

    /// The real Face ID sheet on the simulator, checked by hand (skipped unless
    /// `PINVAULT_MANUAL_FACEID` is set):
    ///
    ///     xcrun simctl spawn <udid> notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
    ///     xcrun simctl spawn <udid> notifyutil -p com.apple.BiometricKit.enrollmentChanged
    ///     TEST_RUNNER_PINVAULT_MANUAL_FACEID=match xcodebuild test-without-building … -only-testing:VaultKeychainHostTests/UserAuthKeychainKeysTests/testManualFaceIDThroughTheSystemSheet
    ///     # when the sheet is up (the test logs "Face ID sheet is up"):
    ///     xcrun simctl spawn <udid> notifyutil -p com.apple.BiometricKit_Sim.pearl.match     # or .nomatch
    ///
    /// `match` must open the file. `nomatch` leaves the sheet up (a failed face
    /// falls back to the passcode); after 20 s the test cancels the context, which
    /// must report `.cancelled` and keep the copy.
    func testManualFaceIDThroughTheSystemSheet() async throws {
        guard let mode = ProcessInfo.processInfo.environment["PINVAULT_MANUAL_FACEID"] else {
            throw XCTSkip("manual check: set PINVAULT_MANUAL_FACEID=match|nomatch (see the comment)")
        }
        let systemKeys = KeychainUserAuthKeys(alias: alias)
        XCTAssertTrue(systemKeys.isScreenLockSet(), "the simulator always reports a passcode")
        let storage = UserAuthVaultStorage(inner: inner, keys: systemKeys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 3)
        let canceller = Locked<Task<Void, Never>?>(nil)

        let result = await storage.unlock("st", authenticate: { kind, grant in
            NSLog("PinVault manual check: Face ID sheet is up (mode %@)", mode)
            if mode != "match", let context = grant?.context as? LAContext {
                let box = UncheckedSendable(context)
                canceller.set(Task {
                    try? await Task.sleep(nanoseconds: 20_000_000_000)
                    box.value.invalidate()
                })
            }
            return await UserAuthPrompt.authenticate(prompt: VaultFileUnlockPrompt(title: "PinVault L4", description: "Open the statement"),
                                                     kind: kind, grant: grant, evaluator: SystemUserAuthEvaluator())
        })
        canceller.get()?.cancel()
        NSLog("PinVault manual check result: %@", "\(result)")
        if mode == "match" {
            XCTAssertEqual(result, .unlocked(key: "st", version: 3, bytes: content))
        } else {
            XCTAssertEqual(result, .cancelled(key: "st"))
            XCTAssertTrue(try storage.exists(key: "st"))
        }
    }
}
