import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import PinVault

/// A Keychain for ``KeychainUserAuthKeys`` that can play a device evaluating
/// the key's access control already at the lookup (`enforceAtLookup`): the
/// private key is handed out only with a context an approved prompt evaluated,
/// any other lookup fails with `errSecInteractionNotAllowed`. The simulator
/// enforces nothing (`enforceAtLookup = false`).
final class FakeUserAuthKeychain: UserAuthKeychain, @unchecked Sendable {
    private struct State {
        var keys: [String: SecKey] = [:]
        var records: [String: Data] = [:]
        var authorised: [AnyObject] = []
        var enforceAtLookup: Bool
        var refusedLookups = 0
        var authorisedLookups = 0
    }

    private let store: Locked<State>

    init(enforceAtLookup: Bool) {
        store = Locked(State(enforceAtLookup: enforceAtLookup))
    }

    var enforceAtLookup: Bool { get { store.get().enforceAtLookup } set { store.withLock { $0.enforceAtLookup = newValue } } }
    var refusedLookups: Int { store.get().refusedLookups }
    var authorisedLookups: Int { store.get().authorisedLookups }
    func key(_ tag: String) -> SecKey? { store.get().keys[tag] }
    func setKey(_ key: SecKey?, _ tag: String) { store.withLock { $0.keys[tag] = key } }
    func record(_ tag: String) -> Data? { store.get().records[tag] }
    func setRecord(_ data: Data?, _ tag: String) { store.withLock { $0.records[tag] = data } }

    /// What a passed evaluation does to `context` on a device.
    func authorise(_ context: AnyObject?) {
        guard let context else { return }
        store.withLock { $0.authorised.append(context) }
    }

    func privateKey(tag: String, context: LAContext) throws -> SecKey? {
        try store.withLock { state -> SecKey? in
            guard let key = state.keys[tag] else { return nil }
            guard state.enforceAtLookup else { return key }
            guard state.authorised.contains(where: { $0 === context }) else {
                state.refusedLookups += 1
                throw DeviceKeyKeychainError(status: errSecInteractionNotAllowed, operation: "read key \(tag)")
            }
            state.authorisedLookups += 1
            return key
        }
    }

    func generatePrivateKey(tag: String, accessControl: SecAccessControl) throws -> SecKey {
        let key = try rsaPrivateKey()
        setKey(key, tag)
        return key
    }

    func deletePrivateKey(tag: String) throws { setKey(nil, tag) }

    func publicRecord(tag: String) throws -> Data? { record(tag) }

    func savePublicRecord(_ data: Data, tag: String) throws { setRecord(data, tag) }

    func deletePublicRecord(tag: String) throws { setRecord(nil, tag) }
}

/// A scripted prompt whose approval authorises the grant's context in `keychain`.
final class AuthorisingEvaluator: UserAuthEvaluator, @unchecked Sendable {
    let scripted: ScriptedEvaluator
    let keychain: FakeUserAuthKeychain

    init(_ answers: [ScriptedEvaluator.Answer], keychain: FakeUserAuthKeychain) {
        scripted = ScriptedEvaluator(answers)
        self.keychain = keychain
    }

    var prompts: Int { scripted.prompts.count }

    func canEvaluate() -> Bool { true }

    func evaluate(_ grant: UserAuthGrant, prompt: VaultFileUnlockPrompt) async throws {
        try await scripted.evaluate(grant, prompt: prompt)
        keychain.authorise(grant.context)
    }
}

/// Review 2026-11-11: the user-auth unlock reaches the prompt even where the Keychain
/// refuses a silent lookup of the private key (the expected behaviour of a
/// non-Secure-Enclave `.userPresence` key on a device). The public half and
/// the kind live in a record without access control; only the unwrap after
/// the prompt reads the private key, and the record must belong to it.
final class UserAuthPublicRecordTests: XCTestCase {

    private let alias = "pinvault_userauth_record_test"
    private let inner = MemVaultStore()
    private let content = Data(utf8: "account-statement")

    private func keys(_ keychain: FakeUserAuthKeychain) -> KeychainUserAuthKeys {
        KeychainUserAuthKeys(alias: alias, evaluator: ScriptedEvaluator([]), keychain: keychain)
    }

    private func unlock(_ storage: UserAuthVaultStorage, _ evaluator: AuthorisingEvaluator,
                        verify: UnlockVerifier? = nil) async -> VaultFileUnlockResult {
        await storage.unlock("st", authenticate: { kind, grant in
            await UserAuthPrompt.authenticate(prompt: VaultFileUnlockPrompt(title: "Open statement"), kind: kind, grant: grant, evaluator: evaluator)
        }, verify: verify)
    }

    private func recordOf(_ keychain: FakeUserAuthKeychain) throws -> UserAuthPublicRecord {
        try XCTUnwrap(keychain.record(alias).flatMap(UserAuthPublicRecord.decode))
    }

    // MARK: A device that refuses the silent lookup

    func testThePromptIsReachedAndTheFileOpensWhenTheKeychainRefusesASilentLookup() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: true)
        let keys = keys(keychain)
        XCTAssertTrue(try keys.ensureKey())
        // Everything before the prompt answers without the private key.
        XCTAssertEqual(try keys.state(), .usable)
        XCTAssertEqual(try keys.kind(), .perUse)
        XCTAssertTrue(try keys.grantForPrompt()?.context is LAContext)
        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), try SPKI.der(for: XCTUnwrap(keychain.key(alias))))

        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 7)
        XCTAssertTrue(try storage.isLocked("st"))
        XCTAssertEqual(keychain.authorisedLookups, 0, "sealing never read the private key")

        let evaluator = AuthorisingEvaluator([.approve], keychain: keychain)
        let result = await unlock(storage, evaluator)
        XCTAssertEqual(result, .unlocked(key: "st", version: 7, bytes: content))
        XCTAssertEqual(evaluator.prompts, 1, "the prompt was shown")
        XCTAssertEqual(keychain.authorisedLookups, 1, "the private key was read once, with the evaluated context")
    }

    func testWithoutAPassedPromptTheKeychainRefusesTheKeyAndTheCopyStays() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: true)
        let keys = keys(keychain)
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 1)

        // A forged "prompt passed": the context was never evaluated.
        let result = await storage.unlock("st", authenticate: { _, grant in .succeeded(grant) })
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertTrue(try storage.exists(key: "st"), "a refused key is not a missing one")
        XCTAssertNotNil(keychain.key(alias))
        XCTAssertNotNil(keychain.record(alias))
    }

    func testRegistrationAndAServerSealedCopyNeedNoPrivateKeyAndTheCopyOpensAfterThePrompt() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: true)
        let keys = keys(keychain)
        let signer = TestSigner()
        let api = VaultApiStub()
        let file = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", configApiId: "default", encryption: .userAuth, userAuth: .required)
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        let router = VaultFileRouter(
            clients: [vaultClient(api, vaultBlock(signer: signer))], storageFor: { _ in storage }, deviceKeyProvider: nil,
            deviceIdProvider: { "device-1" }, userAuthKeys: keys, files: { [file] }, registrations: UserAuthRegistrationsInMemory()
        )
        let content = self.content
        api.onRegisterUserAuth { _ in }
        api.onDownload { _ in
            VaultFetchResponse(
                content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()),
                version: 3, encryption: "user_auth", signature: signer.vaultV1("st", 3, content)
            )
        }

        let fetched = await router.fetchFile(file)
        XCTAssertEqual(fetched, .updated(key: "st", version: 3, bytes: Data()))
        XCTAssertEqual(api.userAuthRegistrations.count, 1, "the key was registered")
        XCTAssertEqual(api.userAuthRegistrations.first?.publicKeyPem, try SPKI.pem(for: XCTUnwrap(keychain.key(alias))))
        XCTAssertEqual(try storage.sealedKeyId("st"), try recordOf(keychain).keyId, "stamped with the record's key")
        XCTAssertEqual(keychain.authorisedLookups, 0, "registration and saveSealedByServer never read the private key")

        // saveSealedByServer on its own, too.
        let other = MemVaultStore()
        try UserAuthVaultStorage(inner: other, keys: keys, policy: .required, serverSealedOnly: true)
            .saveSealedByServer("x", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 1, signatures: [])
        XCTAssertTrue(try other.exists(key: "x"))

        let evaluator = AuthorisingEvaluator([.approve], keychain: keychain)
        let unlocked = await unlock(storage, evaluator, verify: router.unlockVerifier(file))
        XCTAssertEqual(unlocked, .unlocked(key: "st", version: 3, bytes: content))
        XCTAssertEqual(evaluator.prompts, 1)
    }

    // MARK: The record cannot swap the key

    func testARecordForAnotherKeyIsRefusedAfterThePromptAndBothItemsGo() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: true)
        let keys = keys(keychain)
        try keys.ensureKey()
        // Someone with Keychain write access puts their own public key in the record.
        let forged = try rsaPrivateKey()
        keychain.setRecord(try UserAuthPublicRecord(tag: alias, kind: .perUse, spki: SPKI.der(for: forged)).encode(), alias)
        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), try SPKI.der(for: forged), "before the prompt nothing can tell")

        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 2)   // wrapped for the forged key

        let evaluator = AuthorisingEvaluator([.approve], keychain: keychain)
        let result = await unlock(storage, evaluator)
        XCTAssertEqual(result, .invalidated(key: "st"), "a record that is not the key's own counts as a retired key")
        XCTAssertFalse(try storage.exists(key: "st"))
        XCTAssertNil(keychain.key(alias), "the key is retired")
        XCTAssertNil(keychain.record(alias), "and its record with it")
        XCTAssertEqual(try keys.state(), .missing)

        // The next seal makes a new key with its own record.
        try storage.save(key: "st", bytes: content, version: 3)
        XCTAssertEqual(try recordOf(keychain).spki, try SPKI.der(for: XCTUnwrap(keychain.key(alias))))
    }

    func testWhereTheLookupIsSilentAForeignRecordRetiresTheKeyAtOnce() throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: false)
        let keys = keys(keychain)
        try keys.ensureKey()
        keychain.setRecord(try UserAuthPublicRecord(tag: alias, kind: .perUse, spki: SPKI.der(for: rsaPrivateKey())).encode(), alias)

        XCTAssertEqual(try keys.state(), .missing)
        XCTAssertNil(keychain.key(alias))
        XCTAssertNil(keychain.record(alias))
    }

    func testAnUnreadableRecordIsDroppedAndWrittenAgainFromTheKey() throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: false)
        let keys = keys(keychain)
        try keys.ensureKey()
        let spki = try SPKI.der(for: XCTUnwrap(keychain.key(alias)))
        var tampered = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(keychain.record(alias))) as? [String: Any])
        tampered["keyId"] = "0011223344556677"   // not the SPKI's id
        keychain.setRecord(try JSONSerialization.data(withJSONObject: tampered), alias)

        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), spki)
        XCTAssertEqual(try recordOf(keychain).spki, spki)
    }

    func testDeletingTheKeyDeletesItsRecordAndARecordWithoutAKeyIsReplaced() throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: true)
        let keys = keys(keychain)
        try keys.ensureKey()
        XCTAssertNotNil(keychain.record(alias))
        keys.delete()
        XCTAssertNil(keychain.key(alias))
        XCTAssertNil(keychain.record(alias))

        try keys.ensureKey()
        let before = try recordOf(keychain)
        keychain.setKey(nil, alias)   // the passcode was removed: the key is gone
        XCTAssertEqual(try keys.state(), .missing)
        XCTAssertThrowsError(try keys.grantForPrompt()) { XCTAssertTrue(UserAuthKeyConstants.isRetired($0)) }
        XCTAssertTrue(try keys.ensureKey(), "a record alone is no key")
        XCTAssertNotEqual(try recordOf(keychain).spki, before.spki)
    }

    func testTheRecordIsThisDeviceOnlyWithoutAccessControlOrSync() {
        let query = SystemUserAuthKeychain.recordQuery(tag: alias)
        XCTAssertEqual(query[kSecClass] as? String, kSecClassGenericPassword as String)
        XCTAssertEqual(query[kSecAttrService] as? String, KeychainUserAuthKeys.publicRecordService)
        XCTAssertEqual(query[kSecAttrSynchronizable] as? Bool, false)
        XCTAssertNil(query[kSecAttrAccessControl])
    }

    // MARK: Keys made by an earlier build (no record)

    func testAKeyFromAnEarlierBuildWorksAndGetsItsRecordWhereTheLookupIsSilent() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: false)
        let legacy = try rsaPrivateKey()
        keychain.setKey(legacy, alias)
        let keys = keys(keychain)

        XCTAssertFalse(try keys.ensureKey(), "the existing key is kept")
        XCTAssertEqual(try keys.kind(), .perUse)
        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), try SPKI.der(for: legacy))
        XCTAssertEqual(try recordOf(keychain).spki, try SPKI.der(for: legacy), "the record was derived from the key")

        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 4)
        let result = await unlock(storage, AuthorisingEvaluator([.approve], keychain: keychain))
        XCTAssertEqual(result, .unlocked(key: "st", version: 4, bytes: content))
    }

    func testAnEarlierBuildsCopyOpensAfterThePromptWhenTheKeychainRefusesASilentLookup() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: false)
        let legacy = try rsaPrivateKey()
        keychain.setKey(legacy, alias)
        let keys = keys(keychain)
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 5)
        // As an earlier build left it: the key, the copy, no record; and a device that enforces at lookup.
        keychain.setRecord(nil, alias)
        keychain.enforceAtLookup = true
        XCTAssertThrowsError(try keys.publicKey()) { XCTAssertTrue(WrongKeyForCopy.isAuthFailure($0)) }

        let evaluator = AuthorisingEvaluator([.approve], keychain: keychain)
        let result = await unlock(storage, evaluator)
        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(evaluator.prompts, 1)
        XCTAssertEqual(try recordOf(keychain).spki, try SPKI.der(for: legacy), "written after the passed prompt")
        XCTAssertEqual(try SPKI.der(for: keys.publicKey()), try SPKI.der(for: legacy), "and from now on read without the key")
    }

    func testAnEarlierBuildsCopyForAnotherKeyIsGivenUpAfterThePrompt() async throws {
        let keychain = FakeUserAuthKeychain(enforceAtLookup: false)
        keychain.setKey(try rsaPrivateKey(), alias)
        let keys = keys(keychain)
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        try storage.save(key: "st", bytes: content, version: 5)
        // The key was replaced since; the copy still names the old one.
        keychain.setKey(try rsaPrivateKey(), alias)
        keychain.setRecord(nil, alias)
        keychain.enforceAtLookup = true

        let result = await unlock(storage, AuthorisingEvaluator([.approve], keychain: keychain))
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try storage.exists(key: "st"))
        XCTAssertNotNil(keychain.key(alias), "the current key stays")
    }
}
