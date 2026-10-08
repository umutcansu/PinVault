import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import PinVault

/// Port of UserAuthBindingTest. Two things about a copy sealed on the device:
///  - its GCM tag covers the file name AND the version it is stored as;
///  - after a passed prompt, only a failure that says "this ciphertext was not
///    made for this key" (Security's `errSecParam` from the RSA-OAEP decode)
///    gives a server copy up. A Keychain that merely failed keeps it.
final class UserAuthVaultStorageBindingTests: XCTestCase {

    private let inner = MemVaultStore()
    private let keys = SoftwareUserAuthKeys()
    private let content = Data(utf8: "account-statement")
    private let passes: UserAuthAuthenticate = { _, grant in .succeeded(grant) }
    private let noCheck: UnlockVerifier = { _, _, _ in nil }

    private func storage() -> UserAuthVaultStorage { UserAuthVaultStorage(inner: inner, keys: keys, policy: .required) }

    // MARK: The version is under the tag

    func testASealedCopyOpensOnlyAsTheVersionItWasSealedAs() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 3)
        let opened = await s.unlock("st", authenticate: passes)
        XCTAssertEqual(opened, .unlocked(key: "st", version: 3, bytes: content))

        // The version label is changed in storage (so the server's newer file would look older).
        inner.setVersion("st", 2_000_000)

        let failed = unlockFailure(await s.unlock("st", authenticate: passes))
        XCTAssertTrue(failed.reason.contains("did not decrypt for this file and version"), failed.reason)
        XCTAssertFalse(try s.exists(key: "st"), "the copy is given up; the next fetch starts from zero")
        XCTAssertEqual(try s.getVersion(key: "st"), 0)
    }

    func testASealedCopyDoesNotOpenUnderAnotherFilesName() async throws {
        let s = storage()
        try s.save(key: "public-notes", bytes: Data(utf8: "notes"), version: 1)
        try s.save(key: "st", bytes: content, version: 1)
        inner.setBlob("st", inner.blobs["public-notes"]!)

        unlockFailure(await s.unlock("st", authenticate: passes))
        XCTAssertFalse(try s.exists(key: "st"))
    }

    /// Kind 0x02: the tag covering the file name only (Android builds before the version was bound).
    private func legacySealed(_ key: String, _ bytes: Data) throws -> Data {
        try keys.ensureKey()
        let publicKey = try keys.publicKey()
        let fileKey = SymmetricKey(size: .bits256)
        let box = try AES.GCM.seal(bytes, using: fileKey, nonce: AES.GCM.Nonce(), authenticating: Data("pinvault-user-auth:v2:\(key)".utf8))
        let wrapped = try UserAuthKeyConstants.wrap(fileKey.withUnsafeBytes { Data($0) }, for: publicKey)
        var blob = Data("PVUA".utf8)
        blob.append(0x02)
        blob.append(try UserAuthKeyConstants.keyId(publicKey))
        blob.append(UInt8(wrapped.count >> 8))
        blob.append(UInt8(wrapped.count & 0xFF))
        blob.append(wrapped)
        blob.append(contentsOf: box.nonce)
        blob.append(box.ciphertext)
        blob.append(box.tag)
        return blob
    }

    func testACopySealedByAnEarlierBuildOpensOnceAndIsWrittenAgainWithTheVersionBound() async throws {
        try inner.save(key: "st", bytes: legacySealed("st", content), version: 5)
        let s = storage()
        XCTAssertTrue(try s.isLocked("st"))

        let first = await s.unlock("st", authenticate: passes)
        XCTAssertEqual(first, .unlocked(key: "st", version: 5, bytes: content))
        XCTAssertEqual(inner.blobs["st"]![4], 0x04, "rewritten in the current form")
        XCTAssertEqual(try s.getVersion(key: "st"), 5)
        let second = await s.unlock("st", authenticate: passes)
        XCTAssertEqual(second, .unlocked(key: "st", version: 5, bytes: content))
        // And from now on the version is held to.
        inner.setVersion("st", 6)
        unlockFailure(await s.unlock("st", authenticate: passes))
    }

    func testNewCopiesAreWrittenInTheCurrentForm() throws {
        try storage().save(key: "st", bytes: content, version: 1)
        XCTAssertEqual(inner.blobs["st"]![4], 0x04)
    }

    func testTheLocalLayoutIsTheKotlinOne() throws {
        try storage().save(key: "st", bytes: content, version: 1)
        let blob = [UInt8](inner.blobs["st"]!)
        XCTAssertEqual(Array(blob[0..<4]), Array("PVUA".utf8))
        XCTAssertEqual(Data(blob[5..<13]), try UserAuthKeyConstants.keyId(keys.publicKey()), "the key id: SHA-256(SPKI)[0..8]")
        let wrappedLength = Int(blob[13]) << 8 | Int(blob[14])
        XCTAssertEqual(wrappedLength, 256, "RSA-2048")
        XCTAssertEqual(blob.count, 15 + 256 + 12 + content.count + 16, "IV 12, ciphertext, tag 16")
    }

    // MARK: "Wrong key" versus "the Keychain failed"

    func testSecurityErrSecParamFromTheOAEPDecodeMeansAnotherKey() throws {
        let a = try rsaPrivateKey()
        let b = try rsaPrivateKey()
        let wrapped = try UserAuthKeyConstants.wrap(Data(count: 32), for: publicOf(a))
        XCTAssertThrowsError(try UserAuthKeyConstants.unwrap(wrapped, with: b)) { error in
            guard case UserAuthKeyError.wrongKey = error else { return XCTFail("\(error)") }
            XCTAssertTrue(WrongKeyForCopy.matches(error))
        }
    }

    func testOnlyTheDecodingFailureIsAWrongKey() {
        XCTAssertTrue(WrongKeyForCopy.matches(UserAuthKeyError.wrongKey("RSAdecrypt wrong input")))
        XCTAssertFalse(WrongKeyForCopy.matches(UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")))
        XCTAssertFalse(WrongKeyForCopy.matches(UserAuthKeyError.keychain(status: errSecDecode, message: "binder died")))
        XCTAssertFalse(WrongKeyForCopy.matches(UserAuthKeyError.retired("gone")))
        XCTAssertFalse(WrongKeyForCopy.matches(UserAuthKeyError.notAuthenticated(status: errSecAuthFailed, message: "denied")))
        XCTAssertFalse(WrongKeyForCopy.matches(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))),
                       "a raw status is not classified: only what the unwrap helper named")
        XCTAssertFalse(WrongKeyForCopy.matches(PinVaultError.crypto(message: "padding", cause: nil)))
    }

    func testTheUnwrapFailuresAreClassifiedByTheirStatus() {
        func classify(_ domain: String, _ code: Int) -> UserAuthKeyError {
            UserAuthKeyError.unwrapFailure(NSError(domain: domain, code: code) as CFError)
        }
        guard case .wrongKey = classify(NSOSStatusErrorDomain, Int(errSecParam)) else { return XCTFail() }
        guard case .notAuthenticated = classify(NSOSStatusErrorDomain, Int(errSecAuthFailed)) else { return XCTFail() }
        guard case .notAuthenticated = classify(NSOSStatusErrorDomain, Int(errSecInteractionNotAllowed)) else { return XCTFail() }
        guard case .notAuthenticated = classify(NSOSStatusErrorDomain, Int(errSecUserCanceled)) else { return XCTFail() }
        guard case .notAuthenticated = classify(LAError.errorDomain, LAError.Code.userCancel.rawValue) else { return XCTFail() }
        guard case .retired = classify(NSOSStatusErrorDomain, Int(errSecItemNotFound)) else { return XCTFail() }
        guard case .keychain = classify(NSOSStatusErrorDomain, Int(errSecInternalComponent)) else { return XCTFail() }
        guard case .keychain = classify(NSCocoaErrorDomain, 4) else { return XCTFail() }
    }

    func testAuthenticationFailuresAreNeverAWrongKey() {
        XCTAssertTrue(WrongKeyForCopy.isAuthFailure(UserAuthKeyError.notAuthenticated(status: errSecInteractionNotAllowed, message: "x")))
        XCTAssertTrue(WrongKeyForCopy.isAuthFailure(NSError(domain: LAError.errorDomain, code: LAError.Code.authenticationFailed.rawValue)))
        XCTAssertTrue(WrongKeyForCopy.isAuthFailure(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed))))
        XCTAssertTrue(WrongKeyForCopy.isAuthFailure(UserAuthKeyError.keychain(status: 1, message: "Key user not authenticated")))
        XCTAssertFalse(WrongKeyForCopy.isAuthFailure(UserAuthKeyError.keychain(status: errSecInternalComponent, message: "busy")))
        XCTAssertFalse(WrongKeyForCopy.isAuthFailure(UserAuthKeyError.wrongKey("RSAdecrypt wrong input")))
    }

    func testAKeychainFailureAfterThePromptKeepsTheCopyAndTheRegistration() async throws {
        let s = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        try keys.ensureKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 2, signatures: [])
        let forgotten = Locked(0)

        keys.unwrapError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")
        unlockFailure(await s.unlock("st", authenticate: passes, onSealedForAnotherKey: { forgotten.withLock { $0 += 1 } }, verify: noCheck))
        XCTAssertTrue(try s.exists(key: "st"), "the copy is still there")
        XCTAssertEqual(forgotten.get(), 0, "and so is the registration")
        XCTAssertNotNil(keys.key)

        // The Keychain recovers: the same copy opens.
        keys.unwrapError = nil
        let result = await s.unlock("st", authenticate: passes, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 2, bytes: content))
    }

    func testACopyReallySealedForAnotherKeyIsStillGivenUp() async throws {
        let s = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        try keys.ensureKey()
        let other = try rsaPrivateKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, publicOf(other)), version: 2, signatures: [])
        let forgotten = Locked(0)

        let result = await s.unlock("st", authenticate: passes, onSealedForAnotherKey: { forgotten.withLock { $0 += 1 } }, verify: noCheck)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
        XCTAssertEqual(forgotten.get(), 1)
    }

    // MARK: What may give a copy up after the prompt

    private func serverCopy() throws -> UserAuthVaultStorage {
        let s = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required, serverSealedOnly: true)
        try keys.ensureKey()
        try s.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 2, signatures: [])
        return s
    }

    func testTransientKeychainErrorsNeverGiveAServerCopyUpHoweverOften() async throws {
        let s = try serverCopy()
        let forgotten = Locked(0)
        let transient: [any Error] = [
            UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed"),
            UserAuthKeyError.keychain(status: errSecNotAvailable, message: "no keychain"),
            UserAuthKeyError.notAuthenticated(status: errSecInteractionNotAllowed, message: "Key user not authenticated"),
            UserAuthKeyError.notAuthenticated(status: errSecUserCanceled, message: "cancelled"),
            PinVaultError.crypto(message: "System error", cause: nil),
        ]
        for _ in 0..<2 {
            for error in transient {
                keys.unwrapError = error
                unlockFailure(await s.unlock("st", authenticate: passes, onSealedForAnotherKey: { forgotten.withLock { $0 += 1 } }, verify: noCheck))
            }
        }
        XCTAssertTrue(try s.exists(key: "st"), "the copy is kept")
        XCTAssertEqual(forgotten.get(), 0, "and so is the registration")
        XCTAssertTrue(s.needsFetch("st"), "but the next fetch downloads it whole")
        keys.unwrapError = nil
        let result = await s.unlock("st", authenticate: passes, verify: noCheck)
        XCTAssertEqual(result, .unlocked(key: "st", version: 2, bytes: content))
        XCTAssertFalse(s.needsFetch("st"))
    }

    func testACopySealedOnThisDeviceIsNeverGivenUpAfterThePromptOnlyMarkedForAFetch() async throws {
        let s = storage()
        try s.save(key: "st", bytes: content, version: 1)
        // Even what would mean "another key" for a server copy: this copy's key
        // id was checked against the current key before the prompt.
        for error: any Error in [UserAuthKeyError.wrongKey("RSAdecrypt wrong input"),
                                 UserAuthKeyError.keychain(status: errSecInternalComponent, message: "System error")] {
            keys.unwrapError = error
            unlockFailure(await s.unlock("st", authenticate: passes))
        }
        XCTAssertTrue(try s.exists(key: "st"))
        XCTAssertTrue(s.needsFetch("st"))
        // A missing key still gives it up.
        keys.unwrapError = UserAuthKeyError.retired("Keystore operation failed")
        let result = await s.unlock("st", authenticate: passes)
        XCTAssertEqual(result, .invalidated(key: "st"))
        XCTAssertFalse(try s.exists(key: "st"))
        XCTAssertFalse(s.needsFetch("st"))
    }
}
