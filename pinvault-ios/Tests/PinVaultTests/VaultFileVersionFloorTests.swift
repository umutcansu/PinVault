import Foundation
import LocalAuthentication
import XCTest
@testable import PinVault

/// The version floor of a vault file (security review 2026-11-14, V1): the
/// highest version this device accepted with a verified signature is
/// remembered apart from the copy. The downgrade check used to know only the
/// stored copy's version, so once the copy was gone — cleared, deleted by its
/// checks, wiped — any older version the server's key ever signed came back in.
final class VaultFileVersionFloorTests: XCTestCase {

    private let signer = TestSigner()
    private let api = VaultApiStub()
    private let store = MemVaultStore()
    private let meta = VaultFileMetaInMemory()
    private let keys = SoftwareUserAuthKeys()
    private let clock = Locked<Int64>(1_800_000_000_000)
    private let sealedContent = Data(utf8: "account-statement")

    private let flags = VaultFileConfig(key: "flags", endpoint: "api/v1/vault/flags")
    private let sealed = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", encryption: .userAuth, userAuth: .required)

    private func service(files: [VaultFileConfig]? = nil, signed: Bool = true, wipeOnRevocation: Bool = false) -> VaultService {
        let files = files ?? [flags, sealed]
        let block = ConfigApiBlock(id: "default", configUrl: "https://example.test/", bootstrapPins: [],
                                   signaturePublicKey: signed ? signer.pub : nil, clientCertLabel: "vault-cert",
                                   enrollmentUrl: "https://example.test:8091/")
        let config = PinVaultConfig(configApis: [block], deviceAlias: "Test phone", vaultFiles: files,
                                    wipeVaultFilesOnRevocation: wipeOnRevocation)
        let clock = self.clock
        return VaultService(
            config: config,
            clients: [vaultClient(api, block)],
            now: { _ in clock.get() },
            deviceIdentity: { (alias: "Test phone", id: "device-1") },
            defaultStore: store,
            fileStore: store,
            deviceKeys: nil,
            userAuthKeys: files.contains { $0.userAuth != .none } ? keys : nil,
            meta: meta,
            registrations: UserAuthRegistrationsInMemory(),
            evaluator: ScriptedEvaluator([])
        )
    }

    private func serve(_ key: String, _ text: String, version: Int, signed: Bool = true) {
        let bytes = Data(utf8: text)
        api.answer(VaultFetchResponse(content: bytes, version: version, signature: signed ? signer.vaultV1(key, version, bytes) : nil))
    }

    private func serveSealed(version: Int) {
        let keys = self.keys
        let content = sealedContent
        let signature = signer.vaultV1("st", version, content)
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: version,
                               encryption: "user_auth", signature: signature)
        }
    }

    private func floor(_ key: String) -> Int { meta.versionFloor(configApiId: "default", key: key) }

    // MARK: After clearFile

    func testAfterClearFileAnOlderSignedVersionIsRefusedTheSameOneAcceptedAndANewerOneToo() async throws {
        let vault = service()
        serve("flags", "v5", version: 5)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }

        vault.clearFile("flags")
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertEqual(floor("flags"), 5, "the copy is gone, the version it was verified at is not")

        // An older version, validly signed by the same key: what a server (or
        // whoever holds its TLS key) replays.
        serve("flags", "v3", version: 3)
        let refused = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused.code, VaultFileResult.FailureCode.versionRejected)
        XCTAssertEqual(refused.reason, "Vault file 'flags' downgrade rejected: served v3, but this device has already seen " +
            "v5 of it with a valid signature (the copy is gone, the version is remembered).")
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertEqual(api.downloads.last?.currentVersion, 0, "the device still asks for the whole file")

        // The version at the floor is the one the device had: accepted.
        serve("flags", "v5", version: 5)
        let fetched6 = await vault.fetchFile("flags")
        XCTAssertEqual(fetched6, .updated(key: "flags", version: 5, bytes: Data(utf8: "v5")))

        vault.clearFile("flags")
        serve("flags", "v6", version: 6)
        let fetched7 = await vault.fetchFile("flags")
        XCTAssertEqual(fetched7, .updated(key: "flags", version: 6, bytes: Data(utf8: "v6")))
        XCTAssertEqual(floor("flags"), 6)
    }

    func testAnOlderVersionWithABrokenSignatureStillFailsAsASignatureProblem() async throws {
        let vault = service()
        serve("flags", "v5", version: 5)
        _ = await vault.fetchFile("flags")
        vault.clearFile("flags")

        api.answer(VaultFetchResponse(content: Data(utf8: "v3"), version: 3, signature: signer.vaultV1("flags", 3, Data(utf8: "other"))))
        let refused1 = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused1.code, VaultFileResult.FailureCode.signatureInvalid,
                       "the version is judged only once the signature has passed")
    }

    func testAVersionThatFailedItsSignatureRaisesNothing() async throws {
        let vault = service()
        api.answer(VaultFetchResponse(content: Data(utf8: "v9"), version: 9, signature: signer.vaultV1("flags", 9, Data(utf8: "other"))))
        failure(await vault.fetchFile("flags"))
        XCTAssertEqual(floor("flags"), 0, "a forged version header must not lock the real file out")

        serve("flags", "v2", version: 2)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
    }

    func testTheVersionJumpIsCountedFromTheFloorOnceTheCopyIsGone() async throws {
        let vault = service()
        let high = Int(VaultFileRouter.maxVersionJump)
        serve("flags", "a", version: high)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
        vault.clearFile("flags")

        // The file's next version is no "jump" because the device cleared its copy.
        serve("flags", "b", version: high + 1)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
        vault.clearFile("flags")
        serve("flags", "c", version: 2 * high + 2)
        let refused = failure(await vault.fetchFile("flags"))
        XCTAssertTrue(refused.reason.contains("is more than \(high) above stored v\(high + 1)"), refused.reason)
    }

    // MARK: The other ways a copy goes away

    func testACopyDeletedByItsIntegrityCheckKeepsTheFloor() async throws {
        let vault = service()
        serve("flags", "v4", version: 4)
        _ = await vault.fetchFile("flags")
        store.setBlob("flags", Data(utf8: "tampered"))
        XCTAssertNil(vault.loadFile("flags"))
        XCTAssertEqual(vault.fileStatus("flags"), .integrityFailed)

        serve("flags", "v2", version: 2)
        let refused2 = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused2.code, VaultFileResult.FailureCode.versionRejected)
        serve("flags", "v4", version: 4)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
    }

    func testACopyWipedAsStaleKeepsTheFloor() async throws {
        let stale = VaultFileConfig(key: "flags", endpoint: "api/v1/vault/flags", maxOfflineAgeMs: 1_000, wipeWhenStale: true)
        let vault = service(files: [stale])
        serve("flags", "v4", version: 4)
        _ = await vault.fetchFile("flags")
        clock.withLock { $0 += 60_000 }
        vault.wipeStaleFiles()
        XCTAssertFalse(vault.hasFile("flags"))

        serve("flags", "v2", version: 2)
        let refused3 = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused3.code, VaultFileResult.FailureCode.versionRejected)
    }

    func testAWipeOnRevocationKeepsTheFloor() async throws {
        let vault = service(wipeOnRevocation: true)
        serve("flags", "v4", version: 4)
        _ = await vault.fetchFile("flags")
        vault.wipeOnRevocation("default")
        XCTAssertFalse(vault.hasFile("flags"))

        serve("flags", "v2", version: 2)
        let refused4 = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused4.code, VaultFileResult.FailureCode.versionRejected)
    }

    func testAnUnenrollThatWipesKeepsTheFloor() async throws {
        let vault = service()
        serve("flags", "v4", version: 4)
        _ = await vault.fetchFile("flags")
        vault.wipeFiles(usingCertLabel: "vault-cert")
        XCTAssertFalse(vault.hasFile("flags"))

        serve("flags", "v2", version: 2)
        let refused5 = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(refused5.code, VaultFileResult.FailureCode.versionRejected)
        serve("flags", "v4", version: 4)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
    }

    // MARK: Files nothing vouches for

    func testAFileFetchedWithoutSignatureVerificationHasNoFloor() async throws {
        let vault = service(signed: false)
        serve("flags", "v5", version: 5, signed: false)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
        XCTAssertEqual(floor("flags"), 0, "an unsigned block proves nothing about any version")

        vault.clearFile("flags")
        serve("flags", "v3", version: 3, signed: false)
        let fetched8 = await vault.fetchFile("flags")
        XCTAssertEqual(fetched8, .updated(key: "flags", version: 3, bytes: Data(utf8: "v3")))
    }

    func testABackendThatSendsNoVersionRaisesNoFloor() async throws {
        let vault = service()
        // Signed as v0 while the store counts the copies itself.
        serve("flags", "a", version: 0)
        let fetched9 = await vault.fetchFile("flags")
        XCTAssertEqual(fetched9, .updated(key: "flags", version: 1, bytes: Data(utf8: "a")))
        serve("flags", "b", version: 0)
        let fetched10 = await vault.fetchFile("flags")
        XCTAssertEqual(fetched10, .updated(key: "flags", version: 2, bytes: Data(utf8: "b")))
        XCTAssertEqual(floor("flags"), 0, "the floor follows the version the signature names")

        vault.clearFile("flags")
        serve("flags", "a", version: 0)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
    }

    // MARK: Screen-lock files, verified at unlock

    func testAServerSealedFileRaisesTheFloorOnlyWhenItsSignaturePassesAtUnlock() async throws {
        let vault = service()
        serveSealed(version: 4)
        guard case .updated = await vault.fetchFile("st") else { return XCTFail() }
        XCTAssertEqual(floor("st"), 0, "stored unopened: nothing was verified yet")

        // Never unlocked: the device cannot say it has seen v4, so v3 is still taken.
        vault.clearFile("st")
        serveSealed(version: 3)
        guard case .updated = await vault.fetchFile("st") else { return XCTFail() }
        vault.clearFile("st")

        serveSealed(version: 4)
        _ = await vault.fetchFile("st")
        let opened = await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open"))
        XCTAssertEqual(opened, .unlocked(key: "st", version: 4, bytes: sealedContent))
        XCTAssertEqual(floor("st"), 4)

        vault.clearFile("st")
        serveSealed(version: 3)
        let refused = failure(await vault.fetchFile("st"))
        XCTAssertEqual(refused.code, VaultFileResult.FailureCode.versionRejected)
        XCTAssertTrue(refused.reason.contains("already seen v4"), refused.reason)
        XCTAssertFalse(vault.hasFile("st"))

        serveSealed(version: 4)
        guard case .updated = await vault.fetchFile("st") else { return XCTFail() }
    }

    func testAServerSealedCopyThatFailsItsSignatureAtUnlockRaisesNothing() async throws {
        let vault = service()
        let keys = self.keys
        let content = sealedContent
        let signature = signer.vaultV1("st", 7, Data(utf8: "the real content"))
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 7,
                               encryption: "user_auth", signature: signature)
        }
        _ = await vault.fetchFile("st")
        unlockFailure(await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open")))
        XCTAssertEqual(floor("st"), 0)
    }

    // MARK: A superseded copy put back on its own (review 2026-11-17)

    func testAnOlderSignedCopyPutBackOnItsOwnIsRefusedBelowTheFloorWhenLoaded() async throws {
        let vault = service()
        serve("flags", "v3", version: 3)
        _ = await vault.fetchFile("flags")
        let oldBlob = store.blobs["flags"]!
        let oldSignatures = meta.signatures("flags")
        serve("flags", "v5", version: 5)
        guard case .updated = await vault.fetchFile("flags") else { return XCTFail() }
        XCTAssertEqual(floor("flags"), 5)

        // The entries are bound to their names only: the v3 copy and its own
        // signature record come back, the floor does not.
        store.setBlob("flags", oldBlob)
        store.setVersion("flags", 3)
        meta.saveSignatures("flags", oldSignatures)

        XCTAssertNil(vault.loadFile("flags"))
        XCTAssertEqual(vault.fileStatus("flags"), .integrityFailed)
        XCTAssertFalse(vault.hasFile("flags"), "the superseded copy is deleted")
        XCTAssertEqual(floor("flags"), 5, "the floor is kept")
    }

    func testASupersededServerSealedCopyPutBackOnItsOwnIsRefusedAtUnlock() async throws {
        let vault = service()
        serveSealed(version: 3)
        guard case .updated = await vault.fetchFile("st") else { return XCTFail() }
        // A v5 was opened and verified since (floor 5); then the v3 copy came
        // back alone. Its own envelope and signature still verify.
        meta.raiseVersionFloor(configApiId: "default", key: "st", to: 5)

        let opened = await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open"))
        guard case .failed(_, let reason, _) = opened else { return XCTFail("\(opened)") }
        XCTAssertTrue(reason.contains("v5"), reason)
        XCTAssertFalse(vault.hasFile("st"), "the superseded copy is deleted")
        XCTAssertEqual(vault.fileStatus("st"), .integrityFailed)
        XCTAssertEqual(floor("st"), 5, "the floor is kept")
    }

    func testTheServerSealedCopyThatSetTheFloorStillOpens() async throws {
        let vault = service()
        serveSealed(version: 5)
        _ = await vault.fetchFile("st")
        meta.raiseVersionFloor(configApiId: "default", key: "st", to: 5)
        let opened = await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open"))
        XCTAssertEqual(opened, .unlocked(key: "st", version: 5, bytes: sealedContent))
    }

    // MARK: The record itself

    func testTheFloorBelongsToOneFileOfOneConfigApiAndOnlyRises() throws {
        meta.raiseVersionFloor(configApiId: "default", key: "flags", to: 5)
        meta.raiseVersionFloor(configApiId: "default", key: "flags", to: 3)
        XCTAssertEqual(meta.versionFloor(configApiId: "default", key: "flags"), 5)
        XCTAssertEqual(meta.versionFloor(configApiId: "default", key: "other"), 0)
        XCTAssertEqual(meta.versionFloor(configApiId: "staging", key: "flags"), 0, "another Config API's file of the same name")
        XCTAssertNotEqual(VaultFileFloorName.of(configApiId: "a", key: "b:c"), VaultFileFloorName.of(configApiId: "a:b", key: "c"))
    }

    func testThePersistentRecordSurvivesClearAndIsWipedOnlyByTheTestReset() throws {
        let prefs = InMemoryPreferences()
        let persistent = VaultFileMetaPersistent(prefs: prefs)
        try persistent.saveSignatures("flags", StoredSignatures(version: 5, scheme: 1, entries: [SignatureEntry(signature: "c2ln")]))
        try persistent.setConfirmedAt("flags", 1_000)
        try persistent.raiseVersionFloor(configApiId: "default", key: "flags", to: 5)
        try persistent.raiseVersionFloor(configApiId: "mtls", key: "model", to: 2)

        try persistent.clear("flags")
        XCTAssertNil(try persistent.signatures("flags"))
        XCTAssertEqual(try persistent.versionFloor(configApiId: "default", key: "flags"), 5)

        // Another instance over the same store: a restart.
        let reopened = VaultFileMetaPersistent(prefs: prefs)
        try reopened.raiseVersionFloor(configApiId: "default", key: "flags", to: 4)
        XCTAssertEqual(try reopened.versionFloor(configApiId: "default", key: "flags"), 5, "never lowered")
        try reopened.raiseVersionFloor(configApiId: "default", key: "flags", to: 8)
        XCTAssertEqual(try persistent.versionFloor(configApiId: "default", key: "flags"), 8)

        try reopened.wipeVersionFloors()
        XCTAssertEqual(try reopened.versionFloor(configApiId: "default", key: "flags"), 0)
        XCTAssertEqual(try reopened.versionFloor(configApiId: "mtls", key: "model"), 0)
    }

    func testAFloorThatCannotBeReadFailsTheFetchInsteadOfCountingAsNone() async throws {
        final class UnreadableFloors: VaultFileMeta, @unchecked Sendable {
            let inner = VaultFileMetaInMemory()
            func signatures(_ key: String) throws -> StoredSignatures? { inner.signatures(key) }
            func saveSignatures(_ key: String, _ signatures: StoredSignatures?) throws { inner.saveSignatures(key, signatures) }
            func confirmedAt(_ key: String) throws -> Int64 { inner.confirmedAt(key) }
            func setConfirmedAt(_ key: String, _ time: Int64) throws { inner.setConfirmedAt(key, time) }
            func problem(_ key: String) throws -> VaultFileStatus? { inner.problem(key) }
            func setProblem(_ key: String, _ problem: VaultFileStatus?) throws { inner.setProblem(key, problem) }
            func clear(_ key: String) throws { inner.clear(key) }
            func versionFloor(configApiId: String, key: String) throws -> Int {
                throw PinVaultError.storeUnreadable(message: "locked", cause: nil)
            }
            func raiseVersionFloor(configApiId: String, key: String, to version: Int) throws {}
            func wipeVersionFloors() throws {}
        }
        let block = vaultBlock(signer: signer)
        let vaultGuard = VaultFileGuard(meta: UnreadableFloors(), now: { _ in 0 })
        let store = self.store
        let router = VaultFileRouter(clients: [vaultClient(api, block)], storageFor: { _ in store }, deviceKeyProvider: nil,
                                     deviceIdProvider: { "device-1" }, guard: vaultGuard)
        serve("flags", "v3", version: 3)
        let failed = failure(await router.fetchFile(flags))
        XCTAssertTrue(failed.reason.contains("locked"), failed.reason)
        XCTAssertFalse(try store.exists(key: "flags"), "nothing is stored while the floor is unknown")
    }
}
