import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of UserAuthRouterTest: ``VaultFileRouter`` with `encryption = USER_AUTH`
/// files. The user-auth key is registered before the download, the server's
/// envelope is stored sealed and never decrypted at fetch time, and unlock
/// checks the signature with the same trust the fetch would.
final class VaultFileRouterUserAuthTests: XCTestCase {

    private let signer = TestSigner()
    private let keys = SoftwareUserAuthKeys()
    private let inner = MemVaultStore()
    private let content = Data(utf8: "account-statement")
    private let api = VaultApiStub()
    private let registrations = UserAuthRegistrationsInMemory()
    private let passes: UserAuthAuthenticate = { _, grant in .succeeded(grant) }

    private lazy var block = vaultBlock(signer: signer)

    private func file(_ policy: UserAuth = .required, key: String = "st", configApiId: String = "default") -> VaultFileConfig {
        VaultFileConfig(key: key, endpoint: "api/v1/vault/\(key)", configApiId: configApiId, encryption: .userAuth, userAuth: policy)
    }

    private func strictStorage(_ policy: UserAuth = .required) -> UserAuthVaultStorage {
        UserAuthVaultStorage(inner: inner, keys: keys, policy: policy, serverSealedOnly: true)
    }

    private func router(_ storage: UserAuthVaultStorage, files: [VaultFileConfig]? = nil, block: ConfigApiBlock? = nil,
                        guard vaultGuard: VaultFileGuard? = nil) -> VaultFileRouter {
        let files = files ?? [file()]
        return VaultFileRouter(
            clients: [vaultClient(api, block ?? self.block)], storageFor: { _ in storage }, deviceKeyProvider: nil,
            deviceIdProvider: { "device-1" }, userAuthKeys: keys, files: { files }, registrations: registrations, guard: vaultGuard
        )
    }

    /// A server that seals `content` for whichever user-auth key the device holds.
    private func serverSeals(version: Int = 3, sign: Bool = true, encryption: String = "user_auth", body: Data? = nil) {
        let keys = self.keys
        let signature = sign ? signer.vaultV1("st", version, content) : nil
        let plain = body ?? content
        api.onRegisterUserAuth { _ in }
        api.onDownload { _ in
            VaultFetchResponse(
                content: try SoftwareUserAuthKeys.serverEnvelope(plain, keys.publicKey()),
                version: version, encryption: encryption, signature: signature
            )
        }
    }

    func testAUserAuthFileIsStoredSealedAndOpensOnlyThroughUnlock() async throws {
        let storage = strictStorage()
        serverSeals()
        let router = router(storage)

        let result = await router.fetchFile(file())
        XCTAssertEqual(result, .updated(key: "st", version: 3, bytes: Data()), "the app gets no content from the fetch")
        XCTAssertEqual(api.userAuthRegistrations.count, 1)
        XCTAssertEqual(api.userAuthRegistrations.first?.deviceId, "device-1")
        XCTAssertTrue(api.userAuthRegistrations.first?.publicKeyPem.hasPrefix("-----BEGIN PUBLIC KEY-----\n") == true)
        XCTAssertEqual(api.userAuthRegistrations.first?.attestationChain, [], "iOS keys carry no attestation chain")
        XCTAssertNil(try storage.load(key: "st"))
        XCTAssertTrue(try storage.isLocked("st"))

        let unlocked = await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file()))
        XCTAssertEqual(unlocked, .unlocked(key: "st", version: 3, bytes: content))
    }

    func testUnlockDeletesAUserAuthCopyWhoseSignatureDoesNotMatch() async throws {
        let storage = strictStorage()
        serverSeals()
        let router = router(storage)
        _ = await router.fetchFile(file())

        // Signed for another file name: valid signature, wrong file.
        let wrongTrust = router.unlockVerifier(file(key: "other"))!
        unlockFailure(await storage.unlock("st", authenticate: passes, verify: wrongTrust))
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testAUserAuthFileWithoutASignatureIsRefusedAtFetchWhenAKeyIsConfigured() async throws {
        let storage = strictStorage()
        serverSeals(sign: false)
        let failed = failure(await router(storage).fetchFile(file()))
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.signatureMissing)
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testAnOlderUserAuthVersionIsRefusedAtFetch() async throws {
        let storage = strictStorage()
        serverSeals(version: 5)
        let router = router(storage)
        _ = await router.fetchFile(file())
        serverSeals(version: 4)

        let failed = failure(await router.fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("downgrade"), failed.reason)
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.versionRejected)
        XCTAssertEqual(try storage.getVersion(key: "st"), 5)
    }

    func testAPlainAnswerForAUserAuthFileIsRefused() async throws {
        let storage = strictStorage()
        serverSeals(encryption: "plain")
        let failed = failure(await router(storage).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("encryption=plain"), failed.reason)
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.encryptionMismatch)
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testAnIfScreenLockUserAuthFileCannotBeReceivedWithoutAPasscode() async throws {
        keys.screenLock = false
        let storage = strictStorage(.ifScreenLock)
        serverSeals()

        let failed = failure(await router(storage, files: [file(.ifScreenLock)]).fetchFile(file(.ifScreenLock)))
        guard case PinVaultError.screenLockRequired? = failed.exception as? PinVaultError else { return XCTFail("\(String(describing: failed.exception))") }
        XCTAssertTrue(failed.reason.contains("cannot be received"), failed.reason)
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.screenLock)
        XCTAssertTrue(api.downloads.isEmpty)
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testARequiredUserAuthFileWithoutAPasscodeFailsWithTheRequiredMessage() async throws {
        keys.screenLock = false
        let failed = failure(await router(strictStorage()).fetchFile(file()))
        XCTAssertEqual(failed.reason, PinVaultError.screenLockRequired(key: "st").message)
    }

    func testA412UserAuthKeyRequiredRegistersTheKeyAgainAndRetriesOnce() async throws {
        let storage = strictStorage()
        serverSeals()
        let calls = Locked(0)
        let keys = self.keys
        let signature = signer.vaultV1("st", 3, content)
        let content = self.content
        api.onDownload { _ in
            let call = calls.withLock { $0 += 1; return $0 }
            if call == 1 { throw VaultFetchHTTPError(httpStatus: 412, responseBody: #"{"error":"user_auth_key_required"}"#) }
            return VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 3,
                                      encryption: "user_auth", signature: signature)
        }

        let result = await router(storage).fetchFile(file())
        XCTAssertEqual(result, .updated(key: "st", version: 3, bytes: Data()))
        XCTAssertEqual(calls.get(), 2)
        XCTAssertEqual(api.userAuthRegistrations.count, 2)
    }

    func testASecond412IsNotRetriedAgain() async throws {
        let storage = strictStorage()
        serverSeals()
        api.onDownload { _ in throw VaultFetchHTTPError(httpStatus: 412, responseBody: #"{"error":"user_auth_key_required"}"#) }

        let failed = failure(await router(storage).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("HTTP 412"), failed.reason)
        XCTAssertEqual(failed.code, "http_412")
        XCTAssertEqual(api.downloads.count, 2)
    }

    func testANewKeyIsRegisteredBeforeTheNextFetch() async throws {
        let storage = strictStorage()
        serverSeals(version: 1)
        let router = router(storage)
        _ = await router.fetchFile(file())
        _ = await router.fetchFile(file())
        XCTAssertEqual(api.userAuthRegistrations.count, 1)

        keys.retired = true   // the passcode was removed and set again; the key is gone
        serverSeals(version: 2)
        let result = await router.fetchFile(file())

        XCTAssertEqual(result, .updated(key: "st", version: 2, bytes: Data()))
        XCTAssertEqual(keys.generated, 2)
        XCTAssertEqual(api.userAuthRegistrations.count, 2)
        guard case .unlocked = await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file())) else { return XCTFail() }
    }

    func testARegistrationFailureFailsTheFetchAndDownloadsNothing() async throws {
        let storage = strictStorage()
        api.onRegisterUserAuth { _ in throw VaultFetchHTTPError(httpStatus: 409, responseBody: nil) }

        let failed = failure(await router(storage).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("could not register the user-auth key"), failed.reason)
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.userAuthKey)
        XCTAssertTrue(api.downloads.isEmpty)
    }

    func testARegistrationThatDidNotCompleteIsANetworkFailure() async throws {
        api.onRegisterUserAuth { _ in throw URLError(.timedOut) }
        let failed = failure(await router(strictStorage()).fetchFile(file()))
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.network)
    }

    func testAKeyRefusalIsReportedAsSuch() async throws {
        struct UserAuthKeyExists: VaultKeyRefusalFailure, LocalizedError {
            var errorDescription: String? {
                "The server keeps another user-auth key for this device (HTTP 409 user_auth_key_exists) and replaces it only " +
                    "with a valid key attestation, which this device could not provide. An administrator must reset this " +
                    "device's user-auth key on the server; then fetch again."
            }
        }
        api.onRegisterUserAuth { _ in throw UserAuthKeyExists() }

        let failed = failure(await router(strictStorage()).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("administrator must reset"), failed.reason)
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.userAuthKey)
        XCTAssertNil(registrations.get("default"), "not recorded as registered")
        XCTAssertTrue(api.downloads.isEmpty)
    }

    func testALocallySealedFileHandsOutNoContentFromTheFetch() async throws {
        let storage = UserAuthVaultStorage(inner: inner, keys: keys, policy: .required)
        let local = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", userAuth: .required)
        api.answer(VaultFetchResponse(content: content, version: 2, encryption: "plain", signature: signer.vaultV1("st", 2, content)))

        let result = await router(storage, files: [local]).fetchFile(local)
        XCTAssertEqual(result, .updated(key: "st", version: 2, bytes: Data()))
        XCTAssertTrue(try storage.isLocked("st"))
    }

    func testTheKeyProofCoversUserAuthFiles() {
        let tokenFile = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", accessPolicy: .token,
                                        accessTokenProvider: { "tok-123" }, encryption: .userAuth, userAuth: .required)
        let proof = router(strictStorage()).keyProof("default", [tokenFile])
        XCTAssertEqual(proof, VaultDeviceKeyProof(vaultKey: "st", token: "tok-123"))
        XCTAssertEqual(proof?.description, "DeviceKeyProof(vaultKey=st, token=***)")
    }

    func testTheProofGoesAlongToAnApiThatTakesIt() async throws {
        let storage = strictStorage()
        let proofApi = ProofApiStub()
        let tokenFile = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", accessPolicy: .token,
                                        accessTokenProvider: { "tok-123" }, encryption: .userAuth, userAuth: .required)
        let router = VaultFileRouter(
            clients: [vaultClient(proofApi, block)], storageFor: { _ in storage }, deviceKeyProvider: nil,
            deviceIdProvider: { "device-1" }, userAuthKeys: keys, files: { [tokenFile] }, registrations: registrations
        )
        try await router.ensureUserAuthKeyRegistered("default", deviceId: "device-1")
        XCTAssertEqual(proofApi.recorded.map(\.kind), ["user_auth"])
        XCTAssertEqual(proofApi.recorded.first?.proof, VaultDeviceKeyProof(vaultKey: "st", token: "tok-123"))
    }

    // MARK: Key stamps, races, refusals

    func testACopyIsStampedWithTheKeyRegisteredWithTheServer() async throws {
        let storage = strictStorage()
        serverSeals()
        _ = await router(storage).fetchFile(file())

        XCTAssertEqual(registrations.get("default"), try storage.sealedKeyId("st").map(Hex.encode))
        XCTAssertEqual(Hex.encode(try UserAuthKeyConstants.keyId(keys.publicKey())), registrations.get("default"))
    }

    func testACopySealedForAReplacedKeyIsDownloadedAgainNotAnsweredAlreadyCurrent() async throws {
        let storage = strictStorage()
        serverSeals(version: 3)
        let router = router(storage)
        _ = await router.fetchFile(file())
        let oldStamp = try storage.sealedKeyId("st")

        keys.retired = true   // the key is gone; the next fetch makes and registers a new one
        let result = await router.fetchFile(file())

        XCTAssertEqual(result, .updated(key: "st", version: 3, bytes: Data()), "same version, but the old copy can never open")
        XCTAssertNotEqual(oldStamp, try storage.sealedKeyId("st"))
        guard case .unlocked = await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file())) else { return XCTFail() }
    }

    func testStartsRegistrationAndAnEarlyFetchDoNotRace() async throws {
        let storage = strictStorage()
        serverSeals()
        api.onRegisterUserAuth { _ in try await Task.sleep(nanoseconds: 100_000_000) }
        let router = router(storage)

        async let registering: Void = router.registerUserAuthKeyEverywhere(deviceId: "device-1")
        let fileConfig = file()
        async let fetching = router.fetchFile(fileConfig)
        _ = await (registering, fetching)

        XCTAssertEqual(keys.generated, 1)
        XCTAssertEqual(api.userAuthRegistrations.count, 1)
    }

    func testAForgottenRegistrationIsMadeAgainBeforeTheNextFetch() async throws {
        let storage = strictStorage()
        serverSeals()
        let router = router(storage)
        _ = await router.fetchFile(file())

        router.forgetUserAuthRegistration("default")
        _ = await router.fetchFile(file())
        XCTAssertEqual(api.userAuthRegistrations.count, 2)
    }

    func testTheAttestationChainGoesAlongBase64AndLeafFirst() async throws {
        keys.chain = [Data([1, 2, 3]), Data([4, 5])]
        serverSeals()
        _ = await router(strictStorage()).fetchFile(file())
        XCTAssertEqual(api.userAuthRegistrations.first?.attestationChain, ["AQID", "BAU="])
    }

    func testNoVerifierForAFileOfAnUnknownConfigApiANoOpOneForAnUnsignedApi() throws {
        let router = router(strictStorage())
        XCTAssertNil(router.unlockVerifier(file(configApiId: "gone")))
        let storage = strictStorage()
        let files = [file()]

        let unsigned = VaultFileRouter(
            clients: [vaultClient(api, vaultBlock())], storageFor: { _ in storage }, deviceKeyProvider: nil,
            deviceIdProvider: { "device-1" }, userAuthKeys: keys, files: { files }
        )
        XCTAssertNil(try unsigned.unlockVerifier(file())!(content, 1, []))
    }

    func testTheAttestationChallengeIsSHA256OverThePrefixedDeviceId() {
        XCTAssertEqual(UserAuthKeyConstants.attestationChallenge(deviceId: "device-1"), Hashing.sha256("pinvault-user-auth-key:v1:device-1"))
    }

    // MARK: A version nobody verified yet, and signatures that name the Config API

    func testAUserAuthEnvelopeWithAnAbsurdVersionIsRefusedBeforeItIsStored() async throws {
        let storage = strictStorage()
        serverSeals(version: Int(Int32.max))

        let failed = failure(await router(storage).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("more than 1000000 above"), failed.reason)
        XCTAssertFalse(try storage.exists(key: "st"), "nothing stored: the real file is not blocked as 'older'")
        XCTAssertEqual(try storage.getVersion(key: "st"), 0)

        serverSeals(version: 3)
        let result = await router(storage).fetchFile(file())
        XCTAssertEqual(result, .updated(key: "st", version: 3, bytes: Data()))
    }

    private func serverSealsWithSignatures(v1: String?, v2: String?) {
        let keys = self.keys
        let content = self.content
        api.onRegisterUserAuth { _ in }
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 3,
                               encryption: "user_auth", signature: v1, signatureV2: v2)
        }
    }

    func testAScopedBlockKeepsTheV2SignatureWithAUserAuthCopyAndChecksItAtUnlock() async throws {
        let storage = strictStorage()
        let router = router(storage, block: vaultBlock(signer: signer, serverScope: "prod-mtls"))
        serverSealsWithSignatures(v1: signer.vaultV1("st", 3, content), v2: signer.vaultV2("prod-mtls", "st", 3, content))

        let fetched = await router.fetchFile(file())
        XCTAssertEqual(fetched, .updated(key: "st", version: 3, bytes: Data()))
        let unlocked = await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file()))
        XCTAssertEqual(unlocked, .unlocked(key: "st", version: 3, bytes: content))
    }

    func testAUserAuthCopySignedForAnotherConfigApiFailsAtUnlockAndIsDeleted() async throws {
        let storage = strictStorage()
        let router = router(storage, block: vaultBlock(signer: signer, serverScope: "prod-mtls"))
        serverSealsWithSignatures(v1: nil, v2: signer.vaultV2("staging-mtls", "st", 3, content))

        guard case .updated = await router.fetchFile(file()) else { return XCTFail("stored sealed: nothing can be verified before the prompt") }
        unlockFailure(await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file())))
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testAScopedBlockRefusesAUserAuthFileThatHasOnlyAV1Signature() async throws {
        let storage = strictStorage()
        serverSealsWithSignatures(v1: signer.vaultV1("st", 3, content), v2: nil)

        let failed = failure(await router(storage, block: vaultBlock(signer: signer, serverScope: "prod-mtls")).fetchFile(file()))
        XCTAssertTrue(failed.reason.contains("X-Vault-Signature-V2"), failed.reason)
        XCTAssertFalse(try storage.exists(key: "st"))
    }

    func testACopyKeptAfterAnInconclusiveUnlockFailureIsDownloadedWholeAndReplaced() async throws {
        let storage = strictStorage()
        serverSeals()
        let router = router(storage)
        _ = await router.fetchFile(file())

        // A Keychain fault after the prompt: not "wrong key", so nothing is deleted…
        keys.unwrapError = UserAuthKeyError.keychain(status: errSecInternalComponent, message: "Keystore operation failed")
        unlockFailure(await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file())))
        XCTAssertTrue(try storage.exists(key: "st"))
        XCTAssertTrue(storage.needsFetch("st"))

        // …but the next fetch asks for the whole file, and the same version replaces the copy.
        let before = api.downloads.count
        let result = await router.fetchFile(file())
        XCTAssertEqual(result, .updated(key: "st", version: 3, bytes: Data()))
        XCTAssertEqual(api.askedVersions.dropFirst(before).map { $0 }, [0])
        XCTAssertFalse(storage.needsFetch("st"), "a new copy: the mark is gone")

        keys.unwrapError = nil
        let unlocked = await storage.unlock("st", authenticate: passes, verify: router.unlockVerifier(file()))
        XCTAssertEqual(unlocked, .unlocked(key: "st", version: 3, bytes: content))
    }

    // MARK: A download beside a verified copy waits in the pending slot

    private let meta = VaultFileMetaInMemory()
    private let clock = Locked<Int64>(1_800_000_000_000)

    private func guardWithClock() -> VaultFileGuard {
        let clock = self.clock
        return VaultFileGuard(meta: meta, now: { _ in clock.get() })
    }

    func testANewerUserAuthDownloadLeavesTheVerifiedCopyAndItsConfirmationAloneUntilItIsOpened() async throws {
        let storage = strictStorage()
        let vaultGuard = guardWithClock()
        let router = router(storage, guard: vaultGuard)
        serverSeals(version: 3)
        let first = await router.fetchFile(file())
        XCTAssertEqual(first, .updated(key: "st", version: 3, bytes: Data()))
        let confirmedV3 = meta.confirmedAt("st")
        XCTAssertEqual(confirmedV3, clock.get(), "a first copy is confirmed as it is stored")

        clock.withLock { $0 += 60_000 }
        let served = clock.get()
        serverSeals(version: 4)
        let second = await router.fetchFile(file())
        XCTAssertEqual(second, .updated(key: "st", version: 4, bytes: Data()))
        XCTAssertEqual(try storage.getVersion(key: "st"), 3, "the verified copy is what the app sees")
        XCTAssertEqual(try storage.pendingVersion("st"), 4)
        XCTAssertEqual(meta.confirmedAt("st"), confirmedV3, "nothing unverified refreshes the confirmation")

        clock.withLock { $0 += 60_000 }
        let fileConfig = file()
        let unlocked = await storage.unlock("st", authenticate: passes, onPromoted: { vaultGuard.promoted(fileConfig, version: $0) },
                                            verify: router.unlockVerifier(file()))
        XCTAssertEqual(unlocked, .unlocked(key: "st", version: 4, bytes: content))
        XCTAssertEqual(try storage.getVersion(key: "st"), 4)
        XCTAssertEqual(try storage.pendingVersion("st"), 0)
        XCTAssertEqual(meta.confirmedAt("st"), served, "confirmed as of the download, not as of the unlock")
    }

    func testABadNewerCopyIsDeletedAtUnlockAndTheVerifiedCopyStillOpens() async throws {
        let storage = strictStorage()
        let router = router(storage, guard: guardWithClock())
        serverSeals(version: 3)
        _ = await router.fetchFile(file())
        let confirmedV3 = meta.confirmedAt("st")

        // Other bytes under a signature made for the real content: found out only at unlock.
        let keys = self.keys
        let signature = signer.vaultV1("st", 4, content)
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(Data(utf8: "tampered"), keys.publicKey()), version: 4,
                               encryption: "user_auth", signature: signature)
        }
        let second = await router.fetchFile(file())
        XCTAssertEqual(second, .updated(key: "st", version: 4, bytes: Data()))
        XCTAssertEqual(api.askedVersions, [0, 3])
        XCTAssertTrue(try storage.exists(key: "st"), "the verified copy is untouched")
        XCTAssertEqual(try storage.getVersion(key: "st"), 3)

        // Meanwhile the server is asked with the pending version; its 304 keeps the verified copy confirmed.
        clock.withLock { $0 += 1_000 }
        api.answer(VaultFetchResponse(content: Data(), version: 4, encryption: "user_auth", notModified: true))
        let third = await router.fetchFile(file())
        XCTAssertEqual(third, .alreadyCurrent(key: "st", version: 4))
        XCTAssertEqual(api.askedVersions, [0, 3, 4])
        XCTAssertEqual(meta.confirmedAt("st"), clock.get())

        let result = await storage.unlock("st", authenticate: passes, onPromoted: { _ in XCTFail("a copy that fails its check is never promoted") },
                                          verify: router.unlockVerifier(file()))
        XCTAssertEqual(result, .unlocked(key: "st", version: 3, bytes: content), "the verified copy opens; the bad one is gone")
        XCTAssertEqual(try storage.getVersion(key: "st"), 3)
        XCTAssertEqual(try storage.pendingVersion("st"), 0)
        XCTAssertGreaterThanOrEqual(meta.confirmedAt("st"), confirmedV3)

        // Without a pending copy the server is asked with the verified version again.
        _ = await router.fetchFile(file())
        XCTAssertEqual(api.askedVersions, [0, 3, 4, 3])
    }

    func testAReplacedKeyGivesUpTheStoredCopyWithItsPendingOneAndTheNewDownloadIsTheStoredCopy() async throws {
        let storage = strictStorage()
        let router = router(storage, guard: guardWithClock())
        serverSeals(version: 3)
        _ = await router.fetchFile(file())
        serverSeals(version: 4)
        _ = await router.fetchFile(file())
        XCTAssertEqual(try storage.pendingVersion("st"), 4)

        // The server's key changes hands (an administrator reset, a new registration).
        router.forgetUserAuthRegistration("default")
        keys.delete()
        try keys.ensureKey()
        serverSeals(version: 5)
        let result = await router.fetchFile(file())

        XCTAssertEqual(result, .updated(key: "st", version: 5, bytes: Data()))
        XCTAssertEqual(try storage.getVersion(key: "st"), 5)
        XCTAssertEqual(try storage.pendingVersion("st"), 0)
    }
}
