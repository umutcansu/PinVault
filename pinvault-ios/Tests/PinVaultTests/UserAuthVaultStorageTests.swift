import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of UserAuthVaultStorageTest: ``UserAuthVaultStorage`` with a software
/// stand-in for the Keychain key (``SoftwareUserAuthKeys``) and the prompt
/// closure. The Keychain path runs on the simulator (UserAuthKeychainKeysTests).
final class UserAuthVaultStorageTests: XCTestCase {

    private let inner = MemVaultStore()
    private let keys = SoftwareUserAuthKeys()
    private let content = Data(utf8: "account-statement")
    private let passes = RecordingPrompt.passes()
    private let noCheck: UnlockVerifier = { _, _, _ in nil }

    private func storage(_ policy: UserAuth = .required) -> UserAuthVaultStorage {
        UserAuthVaultStorage(inner: inner, keys: keys, policy: policy)
    }

    private func strict(_ policy: UserAuth = .required) -> UserAuthVaultStorage {
        UserAuthVaultStorage(inner: inner, keys: keys, policy: policy, serverSealedOnly: true)
    }

    // MARK: Sealed here

    func testASealedCopyOpensOnlyThroughThePrompt() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 3)

        XCTAssertFalse(String(decoding: inner.blobs["st"]!, as: UTF8.self).contains("account-statement"), "no plaintext stored")
        XCTAssertNil(try s.load(key: "st"), "load never prompts and never opens a sealed copy")
        XCTAssertTrue(try s.isLocked("st"))
        XCTAssertEqual(try s.getVersion(key: "st"), 3)

        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .unlocked(key: "st", version: 3, bytes: content))
        XCTAssertEqual(passes.shown, 1)
        XCTAssertEqual(passes.kind, .perUse)
        XCTAssertTrue(passes.hadGrant, "a per-use key: the prompt authorises a grant")
    }

    func testATimeBoundKeyOpensWithoutAGrant() async throws {
        keys.kindValue = .timeBound
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)

        guard case .unlocked = await s.unlock("st", authenticate: passes.fn) else { return XCTFail() }
        XCTAssertEqual(passes.kind, .timeBound)
        XCTAssertFalse(passes.hadGrant)
    }

    func testOneKeyForTheWholeDevice() async throws {
        let s = storage()
        try s.save(key: "a", bytes: content, version: 1)
        try s.save(key: "b", bytes: Data(utf8: "other"), version: 1)

        XCTAssertEqual(keys.generated, 1, "both files share the device key")
        guard case .unlocked = await s.unlock("a", authenticate: passes.fn) else { return XCTFail() }
        guard case .unlocked = await s.unlock("b", authenticate: passes.fn) else { return XCTFail() }
    }

    func testACancelledPromptKeepsTheFile() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)

        let cancelled = await s.unlock("st", authenticate: RecordingPrompt { _ in .cancelled }.fn)
        XCTAssertEqual(cancelled, .cancelled(key: "st"))
        XCTAssertTrue(try s.exists(key: "st"))
        guard case .unlocked = await s.unlock("st", authenticate: passes.fn) else { return XCTFail() }
    }

    func testAPromptErrorIsReportedAndKeepsTheFile() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)

        let result = await s.unlock("st", authenticate: RecordingPrompt { _ in .error("Unlock prompt error -8: too many attempts") }.fn)
        XCTAssertEqual(unlockFailure(result).reason, "Unlock prompt error -8: too many attempts")
        XCTAssertTrue(try s.exists(key: "st"))
    }

    func testNoPasscodeIsReported() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        let result = await s.unlock("st", authenticate: RecordingPrompt { _ in .noScreenLock }.fn)
        XCTAssertEqual(unlockFailure(result).reason, "The device has no screen lock; set one to open this file")
    }

    func testRequiredWithoutAPasscodeIsNotStored() {
        keys.screenLock = false
        let s = storage(.required)

        XCTAssertThrowsError(try s.save(key: "st", bytes: content, version: 1)) { error in
            guard case PinVaultError.screenLockRequired(let key, _) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(key, "st")
        }
        XCTAssertFalse(try inner.exists(key: "st"))
    }

    func testIfScreenLockWithoutAPasscodeStoresAnOpenCopy() async throws {
        keys.screenLock = false
        let s = storage(.ifScreenLock)
        try s.save(key: "st", bytes: content, version: 1)

        XCTAssertEqual(try s.load(key: "st"), content)
        XCTAssertFalse(try s.isLocked("st"))
        let prompt = RecordingPrompt.passes()
        let result = await s.unlock("st", authenticate: prompt.fn)
        XCTAssertEqual(result, .unlocked(key: "st", version: 1, bytes: content))
        XCTAssertEqual(prompt.shown, 0, "an open copy needs no prompt")
    }

    func testAnIfScreenLockCopyIsSealedOnceAPasscodeExists() async throws {
        keys.screenLock = false
        let s = storage(.ifScreenLock)
        try s.save(key: "st", bytes: content, version: 4)

        keys.screenLock = true
        XCTAssertEqual(try s.load(key: "st"), content, "the read that seals still returns the content")
        XCTAssertTrue(try s.isLocked("st"))
        XCTAssertEqual(try s.getVersion(key: "st"), 4, "sealing keeps the version")
        XCTAssertNil(try s.load(key: "st"))
        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .unlocked(key: "st", version: 4, bytes: content))
    }

    func testACopyStoredBeforeTheLockWasTurnedOnIsSealedOnFirstRead() async throws {
        try inner.save(key: "st", bytes: content, version: 2)
        let s = storage(.required)

        XCTAssertEqual(try s.load(key: "st"), content)
        XCTAssertTrue(try s.isLocked("st"))
        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .unlocked(key: "st", version: 2, bytes: content))
    }

    func testRequiredRefusesAnOpenCopy() async throws {
        keys.screenLock = false
        try storage(.ifScreenLock).save(key: "st", bytes: content, version: 1)   // the app later tightened the policy

        let s = storage(.required)
        XCTAssertNil(try s.load(key: "st"))
        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .invalidated(key: "st"))
    }

    func testASealedCopyDoesNotOpenUnderAnotherFilesNameAndIsDeleted() async throws {
        let s = storage()
        try s.save(key: "a", bytes: content, version: 1)
        try s.save(key: "b", bytes: Data(utf8: "other"), version: 1)
        inner.setBlob("b", inner.blobs["a"]!)

        unlockFailure(await s.unlock("b", authenticate: passes.fn))
        XCTAssertFalse(try s.exists(key: "b"), "a copy that does not decrypt is gone; the next fetch replaces it")
        XCTAssertTrue(try s.exists(key: "a"))
    }

    // MARK: Missing keys vs. Keychain hiccups

    func testAMissingKeyDeletesTheCopyAndTheNextSaveMakesANewKey() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        keys.retired = true   // the passcode was removed

        let prompt = RecordingPrompt.passes()
        let result = await s.unlock("st", authenticate: prompt.fn)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertEqual(prompt.shown, 0, "no prompt for a key that cannot open anything")
        XCTAssertFalse(try s.exists(key: "st"))

        try s.save(key: "st", bytes: content, version: 1)
        XCTAssertEqual(keys.generated, 2, "a new key replaces the missing one")
        guard case .unlocked = await s.unlock("st", authenticate: passes.fn) else { return XCTFail() }
    }

    func testAKeyReportedGoneWhileUnwrappingStillCountsAsGone() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        keys.unwrapError = UserAuthKeyError.retired("Keystore operation failed")

        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
    }

    func testAKeychainErrorWhileReadingTheKeyKeepsTheCopyAndTheKey() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        let key = keys.key
        keys.stateError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keychain busy")

        let prompt = RecordingPrompt.passes()
        unlockFailure(await s.unlock("st", authenticate: prompt.fn))
        XCTAssertEqual(prompt.shown, 0)
        XCTAssertTrue(try s.exists(key: "st"), "copy kept")
        XCTAssertTrue(keys.key === key, "key kept")

        keys.stateError = nil
        guard case .unlocked = await s.unlock("st", authenticate: passes.fn) else { return XCTFail() }
    }

    func testAKeychainErrorAfterThePromptKeepsTheCopy() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        keys.unwrapError = UserAuthKeyError.notAuthenticated(status: errSecInteractionNotAllowed, message: "Key user not authenticated")

        unlockFailure(await s.unlock("st", authenticate: passes.fn))
        XCTAssertTrue(try s.exists(key: "st"))
        XCTAssertEqual(keys.generated, 1)
        XCTAssertFalse(s.needsFetch("st"), "an authentication failure says nothing about the copy")
    }

    func testAKeychainErrorNeverReplacesTheKeyOnSave() throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        let key = keys.key
        keys.stateError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keychain busy")

        XCTAssertThrowsError(try s.save(key: "st2", bytes: content, version: 1))
        XCTAssertTrue(keys.key === key)
        XCTAssertEqual(keys.generated, 1)
    }

    func testACopySealedWithAKeyThatWasReplacedIsGivenUp() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        keys.delete()
        try keys.ensureKey()   // made for another file after the old key was lost

        let result = await s.unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
    }

    func testACopyInAnUnknownPVUAKindCountsAsRetired() async throws {
        try inner.save(key: "st", bytes: Data(utf8: "PVUA") + Data([0x01]) + Data(count: 40), version: 1)

        XCTAssertTrue(try storage().isLocked("st"))
        let result = await storage().unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try inner.exists(key: "st"))
    }

    func testNothingStoredIsNotFound() async {
        let result = await storage().unlock("st", authenticate: passes.fn)
        XCTAssertEqual(result, .notFound(key: "st"))
    }

    func testClearRemovesTheCopyButKeepsTheDeviceKey() throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        try s.clear(key: "st")
        XCTAssertFalse(try s.exists(key: "st"))
        XCTAssertNotNil(keys.key, "other files may still need it")
    }

    // MARK: Sealed by the server (USER_AUTH)

    private func storeEnvelope(_ s: UserAuthVaultStorage, version: Int = 5,
                               sigs: [SignatureEntry] = [SignatureEntry(keyId: "k1", signature: "c2ln")]) throws {
        try keys.ensureKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: version, signatures: sigs)
    }

    private func envelope(_ bytes: Data? = nil) throws -> Data {
        try SoftwareUserAuthKeys.serverEnvelope(bytes ?? content, keys.publicKey())
    }

    func testAServerSealedCopyIsDecryptedAndVerifiedOnlyAfterThePrompt() async throws {
        let s = storage()
        try storeEnvelope(s)
        XCTAssertNil(try s.load(key: "st"))
        XCTAssertTrue(try s.isLocked("st"))

        let verified = Locked<(String, Int, [SignatureEntry])?>(nil)
        let result = await s.unlock("st", authenticate: passes.fn, verify: { plain, version, sigs in
            verified.set((String(decoding: plain, as: UTF8.self), version, sigs))
            return nil
        })
        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(verified.get()?.0, "account-statement")
        XCTAssertEqual(verified.get()?.1, 5)
        XCTAssertEqual(verified.get()?.2, [SignatureEntry(keyId: "k1", signature: "c2ln")])
    }

    func testAServerSealedCopyKeepsSignaturesWithoutAKeyId() async throws {
        let s = storage()
        try storeEnvelope(s, sigs: [SignatureEntry(keyId: nil, signature: "c2ln"), SignatureEntry(keyId: "k2", signature: "c2ln2")])

        let sigs = Locked<[SignatureEntry]?>(nil)
        _ = await s.unlock("st", authenticate: passes.fn, verify: { _, _, entries in sigs.set(entries); return nil })
        XCTAssertEqual(sigs.get(), [SignatureEntry(keyId: nil, signature: "c2ln"), SignatureEntry(keyId: "k2", signature: "c2ln2")])
    }

    func testAServerSealedCopyThatFailsItsSignatureIsDeleted() async throws {
        let s = storage()
        try storeEnvelope(s)

        let result = await s.unlock("st", authenticate: passes.fn, verify: { _, _, _ in "signature verification failed" })
        XCTAssertTrue(unlockFailure(result).reason.contains("signature verification failed"))
        XCTAssertFalse(try s.exists(key: "st"))
    }

    func testASignatureCheckThatCannotBeMadeKeepsTheCopy() async throws {
        let s = strict()
        try storeEnvelope(s)
        let result = await s.unlock("st", authenticate: passes.fn, verify: { _, _, _ in
            throw PinVaultError.storeUnreadable(message: "locked", cause: nil)
        })
        XCTAssertTrue(unlockFailure(result).reason.hasPrefix("Could not check the signature"))
        XCTAssertTrue(try s.exists(key: "st"), "no verdict, nothing deleted")
    }

    func testAServerSealedCopyStaysSealedWhenThePromptIsCancelled() async throws {
        let s = storage()
        try storeEnvelope(s)
        let verifierRan = Locked(false)

        let result = await s.unlock("st", authenticate: RecordingPrompt { _ in .cancelled }.fn, verify: { _, _, _ in verifierRan.set(true); return nil })
        XCTAssertEqual(result, .cancelled(key: "st"))
        XCTAssertFalse(verifierRan.get(), "nothing is decrypted before the prompt passes")
        XCTAssertTrue(try s.exists(key: "st"))
    }

    func testAMalformedServerEnvelopeIsRefusedAtSave() throws {
        try keys.ensureKey()
        XCTAssertThrowsError(try storage().saveSealedByServer("st", envelope: Data(count: 8), version: 1, signatures: [])) { error in
            guard case PinVaultError.illegalArgument = error else { return XCTFail("\(error)") }
        }
        XCTAssertFalse(try inner.exists(key: "st"))
    }

    // MARK: encryption(USER_AUTH): only server-sealed copies

    func testAUserAuthFileAcceptsNoBlobTheServerDidNotSeal() async throws {
        try keys.ensureKey()
        try storage().save(key: "x", bytes: content, version: 1)
        let planted: [(String, Data)] = [
            ("open", Data(utf8: "PVUA") + Data([0x00]) + content),
            ("earlier", content),
            ("sealed here", inner.blobs["x"]!),
        ]
        for (what, blob) in planted {
            try inner.save(key: "st", bytes: blob, version: 7)
            let s = strict(.ifScreenLock)
            XCTAssertFalse(try s.isLocked("st"), what)
            XCTAssertNil(try s.load(key: "st"), "\(what): load never hands out content")
            XCTAssertFalse(try inner.exists(key: "st"), "\(what): load deletes it")

            try inner.save(key: "st", bytes: blob, version: 7)
            let prompt = RecordingPrompt.passes()
            let result = await s.unlock("st", authenticate: prompt.fn, verify: noCheck)
            XCTAssertEqual(result, .invalidated(key: "st"), what)
            XCTAssertEqual(prompt.shown, 0, "\(what): no prompt")
            XCTAssertFalse(try inner.exists(key: "st"), "\(what): unlock deletes it")
        }
    }

    func testAUserAuthCopyWithoutAVerifierIsNotOpened() async throws {
        let s = strict()
        try storeEnvelope(s)

        unlockFailure(await s.unlock("st", authenticate: passes.fn, verify: nil))
        XCTAssertEqual(passes.shown, 0, "fails before the prompt")
        XCTAssertTrue(try s.exists(key: "st"), "the copy is kept")
        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
    }

    func testAUserAuthFileStoresNothingButTheServersCopy() {
        XCTAssertThrowsError(try strict().save(key: "st", bytes: content, version: 1)) { error in
            guard case PinVaultError.illegalState = error else { return XCTFail("\(error)") }
        }
        XCTAssertFalse(try inner.exists(key: "st"))
    }

    func testACopyIsStampedWithTheKeyItWasSealedFor() async throws {
        let s = strict()
        try keys.ensureKey()
        let registered = Data(repeating: 7, count: 8)
        try s.saveSealedByServer("st", envelope: envelope(), version: 2, signatures: [], sealedFor: registered)

        XCTAssertEqual(try s.sealedKeyId("st"), registered)
        // Not the device's current key: it can never open, so it is given up.
        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
    }

    func testACopySealedForAnotherKeyIsGivenUpAfterThePrompt() async throws {
        let s = strict()
        try keys.ensureKey()
        // Stamped with the current key, but the server wrapped it for another one.
        let other = try rsaPrivateKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, publicOf(other)), version: 2, signatures: [])
        let forgotten = Locked(0)

        let result = await s.unlock("st", authenticate: passes.fn, onSealedForAnotherKey: { forgotten.withLock { $0 += 1 } }, verify: noCheck)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
        XCTAssertEqual(forgotten.get(), 1, "the registration is forgotten, so the next fetch registers again")
        XCTAssertNotNil(keys.key, "the key itself stays")
    }

    func testAKeychainErrorThatIsNotADecodingFailureStillKeepsAUserAuthCopy() async throws {
        let s = strict()
        try storeEnvelope(s)
        keys.unwrapError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")

        unlockFailure(await s.unlock("st", authenticate: passes.fn, verify: noCheck))
        XCTAssertTrue(try s.exists(key: "st"))
    }

    // MARK: The pending slot

    func testTheFirstServerCopyGoesStraightToTheStoredSlot() throws {
        let s = strict()
        try keys.ensureKey()

        XCTAssertFalse(try s.saveSealedByServer("st", envelope: envelope(), version: 1, signatures: []), "nothing to protect yet")
        XCTAssertEqual(try s.getVersion(key: "st"), 1)
        XCTAssertEqual(try s.pendingVersion("st"), 0)
        XCTAssertFalse(try inner.exists(key: "st.pending"))
    }

    func testADownloadBesideAStoredCopyWaitsInThePendingSlotUntilItIsOpened() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        let newer = Data(utf8: "statement-v6")

        XCTAssertTrue(try s.saveSealedByServer("st", envelope: envelope(newer), version: 6, signatures: []))
        XCTAssertEqual(try s.getVersion(key: "st"), 5, "the stored copy is still the one the app sees")
        XCTAssertEqual(try s.pendingVersion("st"), 6)
        XCTAssertTrue(try inner.exists(key: "st.pending"))
        XCTAssertTrue(try s.isLocked("st"))
        XCTAssertNil(try s.load(key: "st"))

        let promoted = Locked<[Int]>([])
        let result = await s.unlock("st", authenticate: passes.fn, onPromoted: { v in promoted.withLock { $0.append(v) } }, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 6, bytes: newer), "the newer copy opens first")
        XCTAssertEqual(promoted.get(), [6])
        XCTAssertEqual(try s.getVersion(key: "st"), 6, "…and is the stored copy now")
        XCTAssertEqual(try s.pendingVersion("st"), 0)
        XCTAssertFalse(try inner.exists(key: "st.pending"))
        let again = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(again, .unlocked(key: "st", version: 6, bytes: newer))
    }

    func testAPendingCopyThatFailsItsSignatureIsDeletedAloneAndTheStoredCopyOpens() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(Data(utf8: "garbage")), version: 6, signatures: [])
        let checked = Locked<[Int]>([])
        let onlyV5Passes: UnlockVerifier = { _, version, _ in
            checked.withLock { $0.append(version) }
            return version == 5 ? nil : "signature verification failed"
        }
        let promoted = Locked(0)
        let prompt = RecordingPrompt.passes()

        let result = await s.unlock("st", authenticate: prompt.fn, onPromoted: { _ in promoted.withLock { $0 += 1 } }, verify: onlyV5Passes)

        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(checked.get(), [6, 5], "the pending copy first, then the stored one")
        XCTAssertEqual(promoted.get(), 0, "a copy that fails is never promoted")
        XCTAssertFalse(try inner.exists(key: "st.pending"), "only the pending copy is gone")
        XCTAssertEqual(try s.getVersion(key: "st"), 5)
        XCTAssertTrue(try s.exists(key: "st"))
        XCTAssertEqual(prompt.shown, 2, "a single-use grant does one operation: the stored copy asks again")
    }

    /// iOS: the grant is an evaluated LAContext, which opens both slots: one prompt.
    func testAReusableGrantOpensTheStoredCopyAfterABadPendingOneWithoutASecondPrompt() async throws {
        keys.reusableGrants = true
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(Data(utf8: "garbage")), version: 6, signatures: [])
        let prompt = RecordingPrompt.passes()

        let result = await s.unlock("st", authenticate: prompt.fn, verify: { _, version, _ in version == 5 ? nil : "signature verification failed" })

        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(prompt.shown, 1)
        XCTAssertEqual(try s.pendingVersion("st"), 0)
    }

    func testATimeBoundKeyOpensTheStoredCopyAfterABadPendingOneWithoutASecondPrompt() async throws {
        keys.kindValue = .timeBound
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(Data(utf8: "garbage")), version: 6, signatures: [])
        let prompt = RecordingPrompt.passes()

        let result = await s.unlock("st", authenticate: prompt.fn, verify: { _, version, _ in version == 5 ? nil : "signature verification failed" })

        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(prompt.shown, 1, "the window is still open")
        XCTAssertEqual(try s.pendingVersion("st"), 0)
    }

    func testAPendingCopySealedForAnotherKeyIsGivenUpAndTheStoredCopyStays() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        let other = try rsaPrivateKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, publicOf(other)), version: 6, signatures: [])
        let forgotten = Locked(0)

        let result = await s.unlock("st", authenticate: passes.fn, onSealedForAnotherKey: { forgotten.withLock { $0 += 1 } }, verify: noCheck)

        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(forgotten.get(), 1, "the registration is made again before the next fetch")
        XCTAssertEqual(try s.pendingVersion("st"), 0)
        XCTAssertEqual(try s.getVersion(key: "st"), 5)
    }

    func testAPendingCopyStampedForAKeyThatIsGoneIsDroppedAlone() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        let gone = Data(repeating: 9, count: 8)
        try s.saveSealedByServer("st", envelope: envelope(), version: 6, signatures: [], sealedFor: gone)
        XCTAssertEqual(try s.pendingSealedKeyId("st"), gone)
        let prompt = RecordingPrompt.passes()

        let result = await s.unlock("st", authenticate: prompt.fn, verify: noCheck)

        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertNil(try s.pendingSealedKeyId("st"))
        XCTAssertEqual(prompt.shown, 1, "given up before any prompt; the stored copy prompts once")
    }

    func testACancelledPromptLeavesBothCopiesWhereTheyAre() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(), version: 6, signatures: [])

        let result = await s.unlock("st", authenticate: RecordingPrompt { _ in .cancelled }.fn, verify: noCheck)
        XCTAssertEqual(result, .cancelled(key: "st"))
        XCTAssertEqual(try s.getVersion(key: "st"), 5)
        XCTAssertEqual(try s.pendingVersion("st"), 6)
    }

    func testAKeychainFaultOnThePendingCopyKeepsBothCopiesAndMarksNothingForDownload() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(), version: 6, signatures: [])
        keys.unwrapError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")

        unlockFailure(await s.unlock("st", authenticate: passes.fn, verify: noCheck))
        XCTAssertEqual(try s.getVersion(key: "st"), 5)
        XCTAssertEqual(try s.pendingVersion("st"), 6)
        XCTAssertFalse(s.needsFetch("st"), "the whole file is there already")

        keys.unwrapError = nil
        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 6, bytes: content))
    }

    func testAPendingDownloadClearsTheMarkLeftByAnInconclusiveFailure() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        keys.unwrapError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")
        unlockFailure(await s.unlock("st", authenticate: passes.fn, verify: noCheck))
        XCTAssertTrue(s.needsFetch("st"))
        keys.unwrapError = nil

        try s.saveSealedByServer("st", envelope: envelope(), version: 5, signatures: [])

        XCTAssertFalse(s.needsFetch("st"), "the whole download arrived, in the pending slot")
        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
    }

    func testClearAndAMissingKeyTakeThePendingCopyToo() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(), version: 6, signatures: [])
        try s.clear(key: "st")
        XCTAssertFalse(try inner.exists(key: "st"))
        XCTAssertFalse(try inner.exists(key: "st.pending"))

        try storeEnvelope(s, version: 5)
        try s.saveSealedByServer("st", envelope: envelope(), version: 6, signatures: [])
        keys.retired = true
        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try inner.exists(key: "st"))
        XCTAssertFalse(try inner.exists(key: "st.pending"))
    }

    func testAPlantedBlobInThePendingSlotIsDeletedUnread() async throws {
        let s = strict()
        try storeEnvelope(s, version: 5)
        try inner.save(key: "st.pending", bytes: Data(utf8: "PVUA") + Data([0x00]) + content, version: 6)

        let result = await s.unlock("st", authenticate: passes.fn, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertFalse(try inner.exists(key: "st.pending"))
    }
}
