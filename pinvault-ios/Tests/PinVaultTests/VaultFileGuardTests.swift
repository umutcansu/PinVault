import Foundation
import XCTest
@testable import PinVault

/// Port of VaultFileGuardTest: a stored vault file is checked every time it is
/// read — its signature, the Config API the signature names, how long ago the
/// server confirmed it — not only when it was downloaded. Router and guard
/// together, the way `fetchFile` / `loadFile` use them.
final class VaultFileGuardTests: XCTestCase {

    private let signer = TestSigner()
    private let storage = MemVaultStore()
    private let meta = VaultFileMetaInMemory()
    private let clock = Locked<Int64>(1_800_000_000_000)
    private let removed = Locked<[(String, String)]>([])
    private let api = VaultApiStub()
    private let sevenDays: Int64 = 7 * 24 * 3600 * 1000

    private var now: Int64 {
        get { clock.get() }
        set { clock.set(newValue) }
    }

    private final class Fixture: Sendable {
        let vaultGuard: VaultFileGuard
        let router: VaultFileRouter
        let storage: MemVaultStore

        init(block: ConfigApiBlock, api: VaultApiStub, storage: MemVaultStore, meta: any VaultFileMeta,
             clock: Locked<Int64>, removed: Locked<[(String, String)]>, defaultMaxAgeMs: Int64 = 0) {
            self.storage = storage
            vaultGuard = VaultFileGuard(meta: meta, now: { _ in clock.get() }, defaultMaxOfflineAgeMs: defaultMaxAgeMs) { key, reason in
                removed.withLock { $0.append((key, reason)) }
            }
            router = VaultFileRouter(clients: [vaultClient(api, block)], storageFor: { _ in storage }, deviceKeyProvider: nil,
                                     deviceIdProvider: { "test-device" }, guard: vaultGuard)
        }

        func fetch(_ file: VaultFileConfig) async -> VaultFileResult { await router.fetchFile(file) }

        func load(_ file: VaultFileConfig) -> Data? {
            if case .content(let bytes) = vaultGuard.load(file, storage, router.storedVerifier(file)) { return bytes }
            return nil
        }

        func status(_ file: VaultFileConfig) -> VaultFileStatus { vaultGuard.status(file, storage, router.storedVerifier(file)) }
    }

    private func fixture(_ block: ConfigApiBlock, defaultMaxAgeMs: Int64 = 0, meta: (any VaultFileMeta)? = nil) -> Fixture {
        Fixture(block: block, api: api, storage: storage, meta: meta ?? self.meta, clock: clock, removed: removed, defaultMaxAgeMs: defaultMaxAgeMs)
    }

    private func block(signed: Bool = true, serverScope: String? = nil) -> ConfigApiBlock {
        vaultBlock(signer: signed ? signer : nil, serverScope: serverScope)
    }

    private func file(_ key: String = "flags", maxOfflineAgeMs: Int64? = nil, wipeWhenStale: Bool = false) -> VaultFileConfig {
        VaultFileConfig(key: key, endpoint: "api/v1/vault/\(key)", configApiId: "default", maxOfflineAgeMs: maxOfflineAgeMs, wipeWhenStale: wipeWhenStale)
    }

    private func signedV1(_ key: String, _ version: Int, _ content: Data) -> VaultFetchResponse {
        VaultFetchResponse(content: content, version: version, signature: signer.vaultV1(key, version, content))
    }

    // MARK: Signatures name the Config API (v2)

    func testABlockWithAServerScopeTakesAV2SignatureForThatScope() async throws {
        let content = Data(utf8: "flags-v3")
        let f = fixture(block(serverScope: "prod-tls"))
        api.answer(VaultFetchResponse(content: content, version: 3, signature: signer.vaultV1("flags", 3, content),
                                      signatureV2: signer.vaultV2("prod-tls", "flags", 3, content)))

        guard case .updated = await f.fetch(file()) else { return XCTFail() }
        XCTAssertEqual(meta.signatures("flags")?.scheme, 2, "the v2 signature is what is kept with the copy")
        XCTAssertEqual(f.load(file()), content)
    }

    func testAFileSignedForAnotherConfigApiWithTheSameKeyIsRefused() async throws {
        let content = Data(utf8: "staging-flags")
        let f = fixture(block(serverScope: "prod-tls"))
        api.answer(VaultFetchResponse(content: content, version: 3, signatureV2: signer.vaultV2("staging-tls", "flags", 3, content)))

        let failed = failure(await f.fetch(file()))
        XCTAssertTrue(failed.reason.contains("signature verification FAILED"), failed.reason)
        XCTAssertFalse(try storage.exists(key: "flags"))
    }

    func testABlockWithAServerScopeRefusesAFileThatHasOnlyAV1Signature() async throws {
        let content = Data(utf8: "flags-v3")
        let f = fixture(block(serverScope: "prod-tls"))

        api.answer(signedV1("flags", 3, content))
        let missing = failure(await f.fetch(file()))
        XCTAssertTrue(missing.reason.contains("X-Vault-Signature-V2"), missing.reason)

        // A v1 signature moved into the v2 header is not a v2 signature either.
        api.answer(VaultFetchResponse(content: content, version: 3, signatureV2: signer.vaultV1("flags", 3, content)))
        failure(await f.fetch(file()))
        // Nor are several of them.
        api.answer(VaultFetchResponse(content: content, version: 3,
                                      signatures: [SignatureEntry(keyId: "k", signature: signer.vaultV1("flags", 3, content))],
                                      signaturesV2: [SignatureEntry(keyId: "k", signature: signer.vaultV1("flags", 3, content))]))
        failure(await f.fetch(file()))
        XCTAssertFalse(try storage.exists(key: "flags"))
    }

    func testWithoutAServerScopeV1IsCheckedAsBeforeWhateverV2HeadersComeAlong() async throws {
        let content = Data(utf8: "flags-v3")
        let f = fixture(block())
        api.answer(VaultFetchResponse(content: content, version: 3, signature: signer.vaultV1("flags", 3, content),
                                      signatureV2: "bm90LWEtc2lnbmF0dXJl"))
        guard case .updated = await f.fetch(file()) else { return XCTFail() }
        XCTAssertEqual(meta.signatures("flags")?.scheme, 1)

        // A v2 signature alone does not pass for v1.
        try storage.clear(key: "flags")
        api.answer(VaultFetchResponse(content: content, version: 3, signature: signer.vaultV2("default", "flags", 3, content)))
        failure(await f.fetch(file()))
    }

    func testTheSeveralSignerV2HeaderIsUsedLikeTheV1One() async throws {
        let content = Data(utf8: "flags-v3")
        let f = fixture(block(serverScope: "prod-tls"))
        api.answer(VaultFetchResponse(content: content, version: 3, signaturesV2: [
            SignatureEntry(keyId: "unknown-key", signature: "AAAA"),
            SignatureEntry(keyId: nil, signature: signer.vaultV2("prod-tls", "flags", 3, content)),
        ]))
        guard case .updated = await f.fetch(file()) else { return XCTFail() }
        XCTAssertEqual(meta.signatures("flags")?.entries.count, 2)
    }

    func testSettingAServerScopeLaterSendsAV1CopyBackToTheServer() async throws {
        let content = Data(utf8: "flags-v3")
        api.answer(signedV1("flags", 3, content))
        guard case .updated = await fixture(block()).fetch(file()) else { return XCTFail() }

        // The app is updated: the block now names its Config API.
        let scoped = fixture(block(serverScope: "prod-tls"))
        XCTAssertNil(scoped.load(file()), "a v1 signature says nothing about the Config API")
        XCTAssertEqual(scoped.status(file()), .needsFetch)
        XCTAssertTrue(try storage.exists(key: "flags"), "not deleted: the next fetch replaces it")

        api.answer(VaultFetchResponse(content: content, version: 3, signatureV2: signer.vaultV2("prod-tls", "flags", 3, content)))
        let before = api.downloads.count
        guard case .alreadyCurrent = await scoped.fetch(file()) else { return XCTFail() }
        XCTAssertEqual(Array(api.askedVersions.dropFirst(before)), [0], "asked for the whole file, not 'newer than v3'")
        XCTAssertEqual(scoped.load(file()), content)
    }

    // MARK: The stored copy is verified when it is read

    func testAFetchedFileIsReadBackOnlyWhileItsStoredSignatureStillVerifies() async throws {
        let content = Data(utf8: "truststore")
        let f = fixture(block())
        api.answer(signedV1("ts", 1, content))
        guard case .updated = await f.fetch(file("ts")) else { return XCTFail() }
        XCTAssertEqual(f.status(file("ts")), .available)
        XCTAssertEqual(f.load(file("ts")), content)

        // Someone with access to the app's storage rewrites the copy.
        storage.setBlob("ts", Data(utf8: "attacker-truststore"))

        XCTAssertNil(f.load(file("ts")))
        XCTAssertFalse(try storage.exists(key: "ts"), "the copy is deleted")
        XCTAssertEqual(f.status(file("ts")), .integrityFailed)
        XCTAssertEqual(removed.get().map(\.0), ["ts"])
        XCTAssertTrue(removed.get()[0].1.contains("signature verification failed"), removed.get()[0].1)

        // The next fetch brings the real file back and clears the mark.
        guard case .updated = await f.fetch(file("ts")) else { return XCTFail() }
        XCTAssertEqual(f.status(file("ts")), .available)
        XCTAssertEqual(f.load(file("ts")), content)
    }

    func testAnotherFilesSignedCopyUnderThisFilesNameIsRefused() async throws {
        let f = fixture(block())
        api.answer(signedV1("public-notes", 1, Data(utf8: "public")))
        _ = await f.fetch(file("public-notes"))
        api.answer(signedV1("trusted-hosts", 1, Data(utf8: "trusted")))
        _ = await f.fetch(file("trusted-hosts"))

        // Both validly signed — for their own names.
        storage.setBlob("trusted-hosts", storage.blobs["public-notes"]!)
        meta.saveSignatures("trusted-hosts", meta.signatures("public-notes"))

        XCTAssertNil(f.load(file("trusted-hosts")))
        XCTAssertFalse(try storage.exists(key: "trusted-hosts"))
        XCTAssertEqual(f.load(file("public-notes")), Data(utf8: "public"))
    }

    func testACopyRelabelledWithAnotherVersionIsRefused() async throws {
        let f = fixture(block())
        api.answer(signedV1("flags", 4, Data(utf8: "flags")))
        _ = await f.fetch(file())

        // A version nobody signed, planted so that the server's file looks older.
        storage.setVersion("flags", 900_000)

        XCTAssertNil(f.load(file()))
        XCTAssertFalse(try storage.exists(key: "flags"))
        XCTAssertTrue(removed.get().first?.1.contains("signed as v4") == true)
    }

    func testAnOlderSignedCopyPutBackWithItsOwnSignatureIsTheLimitOfWhatADeviceCanCheck() async throws {
        let f = fixture(block())
        api.answer(signedV1("flags", 1, Data(utf8: "old")))
        _ = await f.fetch(file())
        let oldBlob = storage.blobs["flags"]!
        let oldSignatures = meta.signatures("flags")
        api.answer(signedV1("flags", 2, Data(utf8: "new")))
        _ = await f.fetch(file())

        storage.setBlob("flags", oldBlob)
        storage.setVersion("flags", 1)
        meta.saveSignatures("flags", oldSignatures)

        XCTAssertEqual(f.load(file()), Data(utf8: "old"))
        guard case .updated = await f.fetch(file()) else { return XCTFail("…until the server is asked again") }
        XCTAssertEqual(f.load(file()), Data(utf8: "new"))
    }

    func testACopyWithoutASignatureOnRecordIsNotHandedOutUntilItIsFetchedAgain() async throws {
        let content = Data(utf8: "flags")
        try storage.save(key: "flags", bytes: content, version: 7)   // stored without its signature
        let f = fixture(block())

        XCTAssertNil(f.load(file()))
        XCTAssertEqual(f.status(file()), .needsFetch)
        XCTAssertTrue(try storage.exists(key: "flags"), "kept")
        XCTAssertTrue(removed.get().isEmpty)

        api.answer(signedV1("flags", 7, content))
        let result = await f.fetch(file())
        XCTAssertEqual(result, .alreadyCurrent(key: "flags", version: 7))
        XCTAssertEqual(api.askedVersions, [0], "the device asks for the whole file: 'not modified' would bring no signature")
        XCTAssertEqual(f.load(file()), content)

        // From then on it asks with its version again.
        api.answer(VaultFetchResponse(content: Data(), version: 7, notModified: true))
        _ = await f.fetch(file())
        XCTAssertEqual(api.askedVersions, [0, 7])
    }

    func testRemovingTheSignatureRecordDoesNotMakeACopyTrusted() async throws {
        let f = fixture(block())
        api.answer(signedV1("flags", 1, Data(utf8: "real")))
        _ = await f.fetch(file())

        storage.setBlob("flags", Data(utf8: "attacker"))
        meta.saveSignatures("flags", nil)

        XCTAssertNil(f.load(file()))
        XCTAssertEqual(f.status(file()), .needsFetch)
    }

    func testTheSameContentUnderANewVersionKeepsTheVersionItsSignatureNames() async throws {
        let content = Data(utf8: "flags")
        let f = fixture(block())
        api.answer(signedV1("flags", 1, content))
        _ = await f.fetch(file())

        // The server bumps the version when a file's policy changes.
        api.answer(signedV1("flags", 2, content))
        let result = await f.fetch(file())
        XCTAssertEqual(result, .alreadyCurrent(key: "flags", version: 2))
        XCTAssertEqual(try storage.getVersion(key: "flags"), 2)
        XCTAssertEqual(f.load(file()), content)
    }

    func testFilesOfAnUnsignedBlockAreStoredAndReadAsBefore() async throws {
        let f = fixture(block(signed: false))
        api.answer(VaultFetchResponse(content: Data(utf8: "plain"), version: 1))
        guard case .updated = await f.fetch(file()) else { return XCTFail() }
        XCTAssertNil(meta.signatures("flags"))

        storage.setBlob("flags", Data(utf8: "changed"))
        XCTAssertEqual(f.load(file()), Data(utf8: "changed"), "no signature to hold it to")
        XCTAssertEqual(f.status(file()), .available)
    }

    func testNothingStoredIsNotAFailure() {
        let f = fixture(block())
        XCTAssertNil(f.load(file()))
        XCTAssertEqual(f.status(file()), .notStored)
        XCTAssertTrue(removed.get().isEmpty)
    }

    // MARK: A version nobody could have signed yet

    func testAVersionHeaderFarAboveTheStoredOneIsRefused() async throws {
        let f = fixture(block(signed: false))
        api.answer(VaultFetchResponse(content: Data(utf8: "x"), version: Int(Int32.max)))
        let first = failure(await f.fetch(file()))
        XCTAssertTrue(first.reason.contains("more than 1000000 above"), first.reason)
        XCTAssertFalse(try storage.exists(key: "flags"))

        api.answer(VaultFetchResponse(content: Data(utf8: "x"), version: 1_000_000))
        guard case .updated = await f.fetch(file()) else { return XCTFail("a first version up to the bound is fine") }
        api.answer(VaultFetchResponse(content: Data(utf8: "y"), version: 2_000_001))
        failure(await f.fetch(file()))
        api.answer(VaultFetchResponse(content: Data(utf8: "y"), version: 2_000_000))
        guard case .updated = await f.fetch(file()) else { return XCTFail() }
    }

    // MARK: Offline lifetime

    func testAFileIsReadableForItsOfflineLifetimeAfterTheServerLastConfirmedIt() async throws {
        let content = Data(utf8: "secret")
        let f = fixture(block())
        let secret = file("secret", maxOfflineAgeMs: sevenDays)
        api.answer(signedV1("secret", 1, content))
        _ = await f.fetch(secret)

        now += sevenDays - 1
        XCTAssertEqual(f.load(secret), content)

        now += 2
        XCTAssertNil(f.load(secret), "a device that never came back online stops reading the file")
        XCTAssertEqual(f.status(secret), .stale)
        XCTAssertTrue(try storage.exists(key: "secret"), "kept unless the file asks for a wipe")
        guard case .refused(.stale, _)? = f.vaultGuard.beforeUnlock(secret, storage) else { return XCTFail() }

        // The server says "you have the current version": readable again.
        api.answer(VaultFetchResponse(content: Data(), version: 1, notModified: true))
        guard case .alreadyCurrent = await f.fetch(secret) else { return XCTFail() }
        XCTAssertEqual(f.load(secret), content)
        XCTAssertNil(f.vaultGuard.beforeUnlock(secret, storage))
    }

    func testAFailedFetchConfirmsNothing() async throws {
        let f = fixture(block())
        let secret = file("secret", maxOfflineAgeMs: sevenDays)
        api.answer(signedV1("secret", 1, Data(utf8: "secret")))
        _ = await f.fetch(secret)
        now += sevenDays + 1

        // An answer that does not verify is not the server's confirmation.
        api.answer(VaultFetchResponse(content: Data(utf8: "forged"), version: 2, signature: signer.vaultV1("secret", 2, Data(utf8: "other"))))
        failure(await f.fetch(secret))
        XCTAssertNil(f.load(secret))
        XCTAssertEqual(f.status(secret), .stale)
    }

    func testWipeWhenStaleDeletesTheCopyOnReadOrOnThePeriodicSweep() async throws {
        let f = fixture(block())
        let secret = file("secret", maxOfflineAgeMs: sevenDays, wipeWhenStale: true)
        let kept = file("kept", maxOfflineAgeMs: sevenDays)
        api.answer(signedV1("secret", 1, Data(utf8: "secret")))
        _ = await f.fetch(secret)
        api.answer(signedV1("kept", 1, Data(utf8: "kept")))
        _ = await f.fetch(kept)

        let storage = self.storage
        f.vaultGuard.sweep([secret, kept]) { _ in storage }
        XCTAssertTrue(try storage.exists(key: "secret"), "not stale yet")

        now += sevenDays + 1
        f.vaultGuard.sweep([secret, kept]) { _ in storage }

        XCTAssertFalse(try storage.exists(key: "secret"))
        XCTAssertTrue(try storage.exists(key: "kept"), "only files that asked for it are deleted")
        XCTAssertEqual(f.status(secret), .stale, "the app can tell why it is gone")
        XCTAssertEqual(removed.get().map(\.0), ["secret"])

        // …and on read, for a file the sweep has not seen.
        api.answer(signedV1("secret", 1, Data(utf8: "secret")))
        _ = await f.fetch(secret)
        now += sevenDays + 1
        XCTAssertNil(f.load(secret))
        XCTAssertFalse(try storage.exists(key: "secret"))
    }

    func testACopyWithNoConfirmationOnRecordCountsAsStaleOnceALimitIsSet() throws {
        try storage.save(key: "secret", bytes: Data(utf8: "secret"), version: 1)   // stored before the app set a limit
        let f = fixture(block(signed: false))
        XCTAssertEqual(f.load(file("secret")), Data(utf8: "secret"), "no limit: unlimited, as before")
        XCTAssertNil(f.load(file("secret", maxOfflineAgeMs: sevenDays)))
        XCTAssertEqual(f.status(file("secret", maxOfflineAgeMs: sevenDays)), .stale)
    }

    func testTheConfigsDefaultAppliesUnlessTheFileSetsItsOwn() async throws {
        let f = fixture(block(signed: false), defaultMaxAgeMs: sevenDays)
        api.answer(VaultFetchResponse(content: Data(utf8: "a"), version: 1))
        _ = await f.fetch(file("a"))
        _ = await f.fetch(file("b"))
        _ = await f.fetch(file("c"))
        now += sevenDays + 1

        XCTAssertNil(f.load(file("a")), "the default")
        XCTAssertEqual(f.load(file("b", maxOfflineAgeMs: 2 * sevenDays)), Data(utf8: "a"), "its own, longer limit")
        XCTAssertEqual(f.load(file("c", maxOfflineAgeMs: 0)), Data(utf8: "a"), "0 = no limit for this file")
    }

    func testAConfirmationThatLiesAheadOfTheClockNeedsANewOneAndDeletesNothing() async throws {
        let f = fixture(block(signed: false))
        let secret = file("secret", maxOfflineAgeMs: sevenDays, wipeWhenStale: true)
        api.answer(VaultFetchResponse(content: Data(utf8: "s"), version: 1))
        _ = await f.fetch(secret)                          // confirmed while the clock ran 30 days ahead
        now -= 30 * 24 * 3600 * 1000                       // the trusted clock was corrected downwards

        XCTAssertNil(f.load(secret))
        XCTAssertEqual(f.status(secret), .stale)
        guard case .refused(.stale, _)? = f.vaultGuard.beforeUnlock(secret, storage) else { return XCTFail() }
        let storage = self.storage
        f.vaultGuard.sweep([secret]) { _ in storage }
        XCTAssertTrue(try storage.exists(key: "secret"), "a time that cannot be trusted proves no staleness: not wiped")
        XCTAssertTrue(removed.get().isEmpty)

        // The server confirms it again: the record is the clock's time, readable again.
        api.answer(VaultFetchResponse(content: Data(), version: 1, notModified: true))
        _ = await f.fetch(secret)
        XCTAssertEqual(meta.confirmedAt("secret"), now)
        XCTAssertEqual(f.load(secret), Data(utf8: "s"))
    }

    func testATrustedClockThatRestartsALittleBehindIsNotAConfirmationInTheFuture() async throws {
        let f = fixture(block(signed: false))
        let secret = file("secret", maxOfflineAgeMs: sevenDays)
        api.answer(VaultFetchResponse(content: Data(utf8: "s"), version: 1))
        _ = await f.fetch(secret)
        // After a reboot the trusted clock resumes from its persisted reference, up to one step behind.
        now -= TrustedClock.persistStepMs
        XCTAssertEqual(f.load(secret), Data(utf8: "s"))
    }

    // MARK: A store that cannot be read is not a verdict

    private final class UnreadableMeta: VaultFileMeta, @unchecked Sendable {
        let inner: VaultFileMetaInMemory
        let unreadable = Locked(false)

        init(_ inner: VaultFileMetaInMemory) { self.inner = inner }

        private func check() throws {
            if unreadable.get() { throw PinVaultError.storeUnreadable(message: "locked", cause: nil) }
        }

        func signatures(_ key: String) throws -> StoredSignatures? { try check(); return inner.signatures(key) }
        func saveSignatures(_ key: String, _ signatures: StoredSignatures?) throws { inner.saveSignatures(key, signatures) }
        func confirmedAt(_ key: String) throws -> Int64 { try check(); return inner.confirmedAt(key) }
        func setConfirmedAt(_ key: String, _ time: Int64) throws { inner.setConfirmedAt(key, time) }
        func problem(_ key: String) throws -> VaultFileStatus? { try check(); return inner.problem(key) }
        func setProblem(_ key: String, _ problem: VaultFileStatus?) throws { inner.setProblem(key, problem) }
        func clear(_ key: String) throws { inner.clear(key) }
    }

    func testWhileTheStorageIsUnreadableNothingIsHandedOutAndNothingIsDeleted() async throws {
        let locked = UnreadableMeta(meta)
        let f = fixture(block(), meta: locked)
        let secret = file("secret", maxOfflineAgeMs: sevenDays, wipeWhenStale: true)
        api.answer(signedV1("secret", 1, Data(utf8: "secret")))
        _ = await f.fetch(secret)

        locked.unreadable.set(true)
        XCTAssertNil(f.load(secret))
        XCTAssertEqual(f.status(secret), .storageUnavailable)
        guard case .refused(.storageUnavailable, _)? = f.vaultGuard.beforeUnlock(secret, storage) else { return XCTFail() }
        let storage = self.storage
        f.vaultGuard.sweep([secret]) { _ in storage }
        XCTAssertTrue(try storage.exists(key: "secret"), "'cannot read when it was confirmed' is not 'never confirmed'")
        XCTAssertTrue(removed.get().isEmpty)

        locked.unreadable.set(false)
        XCTAssertEqual(f.load(secret), Data(utf8: "secret"))
    }

    // MARK: The served encryption may not be weaker than the declared one

    func testAnEndToEndFileTheServerServesAsPlainIsRefused() async throws {
        let f = fixture(block(signed: false))
        let e2e = VaultFileConfig(key: "e2e", endpoint: "api/v1/vault/e2e", configApiId: "default", encryption: .endToEnd)
        for served in ["plain", "at_rest", "PLAIN"] {
            api.answer(VaultFetchResponse(content: Data(utf8: "secret in the clear"), version: 1, encryption: served))
            let failed = failure(await f.fetch(e2e))
            XCTAssertTrue(failed.reason.contains("for an end_to_end file; refused"), failed.reason)
            XCTAssertFalse(try storage.exists(key: "e2e"))
        }
    }
}
