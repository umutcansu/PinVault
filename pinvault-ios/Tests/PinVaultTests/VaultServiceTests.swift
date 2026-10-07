import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import PinVault

/// The facade-level vault flow (Kotlin `PinVault.fetchFile` / `loadFile` /
/// `unlockFile` / `clearFile` / wipes) through ``VaultService`` with in-memory
/// stores and keys, a scripted LocalAuthentication evaluator and a stub API.
final class VaultServiceTests: XCTestCase {

    private let signer = TestSigner()
    private let api = VaultApiStub()
    private let prefsStore = MemVaultStore()
    private let fileStore = MemVaultStore()
    private let meta = VaultFileMetaInMemory()
    private let keys = SoftwareUserAuthKeys()
    private let removed = Locked<[(String, VaultFileResult)]>([])
    private let content = Data(utf8: "account-statement")

    private let plain = VaultFileConfig(key: "flags", endpoint: "api/v1/vault/flags", updateWithPins: true,
                                        accessPolicy: .token, accessTokenProvider: { "tok-flags" })
    private let big = VaultFileConfig(key: "model", endpoint: "api/v1/vault/model", storageStrategy: .encryptedFile)
    private let locked = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", encryption: .userAuth, userAuth: .required)

    private func service(
        files: [VaultFileConfig]? = nil,
        block: ConfigApiBlock? = nil,
        evaluator: ScriptedEvaluator = ScriptedEvaluator([]),
        refusal: (@Sendable (GuardedOperation) -> PinVaultError?)? = nil,
        deviceKeys: (any DeviceKeyProvider)? = nil,
        wipeOnRevocation: Bool = false,
        reportTimeout: UInt64 = 5_000_000_000
    ) -> VaultService {
        let files = files ?? [plain, big, locked]
        let block = block ?? ConfigApiBlock(id: "default", configUrl: "https://example.test/", bootstrapPins: [],
                                            signaturePublicKey: signer.pub, clientCertLabel: "vault-cert",
                                            enrollmentUrl: "https://example.test:8091/")
        let config = PinVaultConfig(configApis: [block], deviceAlias: "Test phone", vaultFiles: files,
                                    wipeVaultFilesOnRevocation: wipeOnRevocation)
        let removed = self.removed
        return VaultService(
            config: config,
            clients: [vaultClient(api, block)],
            now: { _ in 1_800_000_000_000 },
            environmentRefusal: refusal ?? { _ in nil },
            onFileRemoved: { key, result in removed.withLock { $0.append((key, result)) } },
            deviceIdentity: { (alias: "Test phone", id: "device-1") },
            defaultStore: prefsStore,
            fileStore: fileStore,
            deviceKeys: deviceKeys,
            userAuthKeys: files.contains { $0.userAuth != .none } ? keys : nil,
            meta: meta,
            registrations: UserAuthRegistrationsInMemory(),
            evaluator: evaluator,
            reportTimeoutNanoseconds: reportTimeout
        )
    }

    private func serve(_ key: String, _ bytes: Data, version: Int) {
        api.answer(VaultFetchResponse(content: bytes, version: version, signature: signer.vaultV1(key, version, bytes)))
    }

    private func serveSealed(version: Int) {
        let keys = self.keys
        let content = self.content
        let signature = signer.vaultV1("st", version, content)
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: version,
                               encryption: "user_auth", signature: signature)
        }
    }

    // MARK: Fetch and the distribution report

    func testAFetchStoresTheFileAndReportsWhatHappenedWithoutItsText() async throws {
        let vault = service()
        serve("flags", Data(utf8: "on"), version: 3)

        let result = await vault.fetchFile("flags")
        XCTAssertEqual(result, .updated(key: "flags", version: 3, bytes: Data(utf8: "on")))
        XCTAssertEqual(vault.loadFile("flags"), Data(utf8: "on"))
        XCTAssertEqual(vault.loadFileAsString("flags"), "on")
        XCTAssertEqual(api.downloads.first?.accessToken, "tok-flags")
        XCTAssertEqual(api.downloads.first?.deviceId, "device-1")

        let report = try XCTUnwrap(api.reports.first)
        XCTAssertEqual(report, VaultDownloadReport(
            key: "flags", version: 3, status: "downloaded", deviceManufacturer: "Apple", deviceModel: DeviceInfo.model,
            enrollmentLabel: "vault-cert", deviceId: "device-1", deviceAlias: "Test phone", failureReason: nil, authMethod: "token"
        ))

        api.answer(VaultFetchResponse(content: Data(), version: 3, notModified: true))
        _ = await vault.fetchFile("flags")
        XCTAssertEqual(api.reports.last?.status, "cached")

        api.onDownload { _ in throw VaultFetchHTTPError(httpStatus: 401, responseBody: #"{"error":"invalid or revoked token"}"#) }
        _ = await vault.fetchFile("flags")
        XCTAssertEqual(api.reports.last?.status, "failed")
        XCTAssertEqual(api.reports.last?.failureReason, "http_401", "the class, never the server's text")
        XCTAssertEqual(api.reports.last?.version, 0)
    }

    func testAnUnknownFileIsNotFetched() async {
        let result = await service().fetchFile("nope")
        XCTAssertEqual(result, .failed(key: "nope", reason: "Vault file 'nope' not registered in config"))
        XCTAssertTrue(api.downloads.isEmpty)
    }

    func testTheEnvironmentGuardRefusesTheFetchAndTheRefusalIsReported() async throws {
        let vault = service(refusal: { $0 == .fetchFile ? .untrustedEnvironment(operation: $0) : nil })
        serve("flags", Data(utf8: "on"), version: 1)

        let failed = failure(await vault.fetchFile("flags"))
        XCTAssertEqual(failed.reason, "The app's environment guard refused FETCH_FILE on this device")
        XCTAssertTrue(api.downloads.isEmpty, "nothing downloaded")
        XCTAssertEqual(api.reports.first?.status, "failed")
        XCTAssertEqual(api.reports.first?.failureReason, "other")
    }

    func testASlowReportDoesNotHoldTheFetchUp() async throws {
        let vault = service(reportTimeout: 200_000_000)
        serve("flags", Data(utf8: "on"), version: 1)
        api.onReport { _ in try await Task.sleep(nanoseconds: 10_000_000_000) }

        let started = Date()
        let result = await vault.fetchFile("flags")
        XCTAssertEqual(result, .updated(key: "flags", version: 1, bytes: Data(utf8: "on")))
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "the report waited at most its budget")
    }

    func testSyncAllFetchesTheUpdateWithPinsFilesAndHandsEachResultOn() async throws {
        let vault = service()
        serve("flags", Data(utf8: "on"), version: 2)
        let notified = Locked<[String]>([])
        let results = await vault.syncAllFiles { key, _ in notified.withLock { $0.append(key) } }
        XCTAssertEqual(Array(results.keys), ["flags"])
        XCTAssertEqual(notified.get(), ["flags"])
    }

    // MARK: Storage per file

    func testEachStrategyGoesToItsStoreAndALockedFileIsWrapped() async throws {
        let custom = MemVaultStore()
        let own = VaultFileConfig(key: "own", endpoint: "api/v1/vault/own", storageProvider: custom)
        let vault = service(files: [plain, big, locked, own])
        XCTAssertTrue(vault.storageFor("flags") as AnyObject === prefsStore)
        XCTAssertTrue(vault.storageFor("model") as AnyObject === fileStore)
        XCTAssertTrue(vault.storageFor("own") as AnyObject === custom)
        let wrapped = try XCTUnwrap(vault.storageFor("st") as? UserAuthVaultStorage)
        XCTAssertTrue(wrapped.serverSealedOnly)
        XCTAssertTrue(wrapped.inner as AnyObject === prefsStore)
        XCTAssertTrue(vault.storageFor("unknown") as AnyObject === prefsStore)

        serve("model", Data(utf8: "weights"), version: 1)
        _ = await vault.fetchFile("model")
        XCTAssertEqual(try fileStore.load(key: "model"), Data(utf8: "weights"))
        XCTAssertNil(try prefsStore.load(key: "model"))
    }

    // MARK: Reads

    func testStatusLoadHasVersionAndClear() async throws {
        let vault = service()
        XCTAssertEqual(vault.fileStatus("flags"), .notStored)
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertEqual(vault.fileVersion("flags"), 0)

        serve("flags", Data(utf8: "on"), version: 4)
        _ = await vault.fetchFile("flags")
        XCTAssertEqual(vault.fileStatus("flags"), .available)
        XCTAssertTrue(vault.hasFile("flags"))
        XCTAssertEqual(vault.fileVersion("flags"), 4)
        XCTAssertFalse(vault.isFileLocked("flags"))
        XCTAssertNotNil(meta.signatures("flags"))

        vault.clearFile("flags")
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertNil(meta.signatures("flags"), "what was remembered about it goes too")
        XCTAssertEqual(vault.fileStatus("flags"), .notStored)
    }

    func testATamperedCopyIsRefusedOnReadAndTheListenerIsTold() async throws {
        let vault = service()
        serve("flags", Data(utf8: "on"), version: 1)
        _ = await vault.fetchFile("flags")
        prefsStore.setBlob("flags", Data(utf8: "off"))

        XCTAssertNil(vault.loadFile("flags"))
        XCTAssertEqual(vault.fileStatus("flags"), .integrityFailed)
        XCTAssertEqual(removed.get().map(\.0), ["flags"])
        guard case .failed(_, let reason, _, _) = removed.get().first?.1 else { return XCTFail() }
        XCTAssertTrue(reason.contains("failed its check when read"), reason)
    }

    // MARK: Unlock

    func testAServerSealedFileIsFetchedLockedAndOpensAfterThePrompt() async throws {
        let evaluator = ScriptedEvaluator([.approve])
        let vault = service(evaluator: evaluator)
        serveSealed(version: 2)

        let fetched = await vault.fetchFile("st")
        XCTAssertEqual(fetched, .updated(key: "st", version: 2, bytes: Data()))
        XCTAssertEqual(api.userAuthRegistrations.count, 1)
        XCTAssertTrue(vault.isFileLocked("st"))
        XCTAssertEqual(vault.fileStatus("st"), .locked)
        XCTAssertNil(vault.loadFile("st"), "loadFile never opens a locked file")

        let prompt = VaultFileUnlockPrompt(title: "Open statement", negativeButtonText: "Not now")
        let result = await vault.unlockFile(key: "st", prompt: prompt)
        XCTAssertEqual(result, .unlocked(key: "st", version: 2, bytes: content))
        XCTAssertEqual(evaluator.prompts, [prompt])
    }

    func testARejectedOrCancelledPromptKeepsTheFileSealed() async throws {
        let vault = service(evaluator: ScriptedEvaluator([.fail(.authenticationFailed), .fail(.userCancel), .approve]))
        serveSealed(version: 2)
        _ = await vault.fetchFile("st")
        let prompt = VaultFileUnlockPrompt(title: "Open")

        unlockFailure(await vault.unlockFile(key: "st", prompt: prompt))
        let cancelled = await vault.unlockFile(key: "st", prompt: prompt)
        XCTAssertEqual(cancelled, .cancelled(key: "st"))
        XCTAssertTrue(vault.hasFile("st"))
        let opened = await vault.unlockFile(key: "st", prompt: prompt)
        XCTAssertEqual(opened, .unlocked(key: "st", version: 2, bytes: content))
    }

    func testACopyThatFailsItsSignatureAtUnlockIsDeletedAndReported() async throws {
        let vault = service(evaluator: ScriptedEvaluator([.approve]))
        let keys = self.keys
        let signature = signer.vaultV1("st", 2, Data(utf8: "the real content"))
        let content = self.content
        api.onDownload { _ in
            VaultFetchResponse(content: try SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 2,
                               encryption: "user_auth", signature: signature)
        }
        _ = await vault.fetchFile("st")

        let failed = unlockFailure(await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open")))
        XCTAssertTrue(failed.reason.contains("signature verification failed"), failed.reason)
        XCTAssertFalse(vault.hasFile("st"))
        XCTAssertEqual(vault.fileStatus("st"), .integrityFailed)
        XCTAssertEqual(removed.get().map(\.0), ["st"])
    }

    func testAFileWithoutALockComesBackWithoutAPrompt() async throws {
        let evaluator = ScriptedEvaluator([])
        let vault = service(evaluator: evaluator)
        serve("flags", Data(utf8: "on"), version: 1)
        _ = await vault.fetchFile("flags")
        let result = await vault.unlockFile(key: "flags", prompt: VaultFileUnlockPrompt(title: "Open"))
        XCTAssertEqual(result, .unlocked(key: "flags", version: 1, bytes: Data(utf8: "on")))
        XCTAssertTrue(evaluator.prompts.isEmpty)
        let missing = await vault.unlockFile(key: "model", prompt: VaultFileUnlockPrompt(title: "Open"))
        XCTAssertEqual(missing, .notFound(key: "model"))
    }

    func testTheEnvironmentGuardRefusesTheUnlockBeforeThePrompt() async throws {
        let evaluator = ScriptedEvaluator([.approve])
        let vault = service(evaluator: evaluator, refusal: { $0 == .unlockFile ? .untrustedEnvironment(operation: $0) : nil })
        serveSealed(version: 2)
        _ = await vault.fetchFile("st")
        unlockFailure(await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open")))
        XCTAssertTrue(evaluator.prompts.isEmpty, "the content never reaches memory")
    }

    func testAStaleFileShowsNoPrompt() async throws {
        let stale = VaultFileConfig(key: "st", endpoint: "api/v1/vault/st", encryption: .userAuth, userAuth: .required, maxOfflineAgeMs: 1)
        let evaluator = ScriptedEvaluator([.approve])
        let vault = service(files: [stale], evaluator: evaluator)
        let wrapped = try XCTUnwrap(vault.storageFor("st") as? UserAuthVaultStorage)
        try keys.ensureKey()
        try wrapped.saveSealedByServer("st", envelope: SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version: 1, signatures: [])
        // Never confirmed on record: stale.
        let result = await vault.unlockFile(key: "st", prompt: VaultFileUnlockPrompt(title: "Open"))
        XCTAssertEqual(result, .stale(key: "st"))
        XCTAssertTrue(evaluator.prompts.isEmpty)
    }

    // MARK: Start, revocation, unenroll

    func testStartRegistersTheDeviceKeyAndTheScreenLockKey() async throws {
        let deviceKeys = DeviceKeys.software(alias: "service-start")
        try deviceKeys.ensureKeyPair()
        let e2e = VaultFileConfig(key: "e2e", endpoint: "api/v1/vault/e2e", encryption: .endToEnd)
        let vault = service(files: [e2e, locked], deviceKeys: deviceKeys)

        await vault.registerKeysAtStart()

        XCTAssertEqual(api.deviceRegistrations.map(\.publicKeyPem), [try deviceKeys.getPublicKeyPem()])
        XCTAssertEqual(api.deviceRegistrations.first?.deviceId, "device-1")
        XCTAssertEqual(api.userAuthRegistrations.count, 1)
        XCTAssertEqual(api.userAuthRegistrations.first?.publicKeyPem, try SPKI.pem(for: keys.publicKey()))
    }

    func testRevocationWipesOnlyWhenTheConfigAsksForIt() async throws {
        serve("flags", Data(utf8: "on"), version: 1)
        let keeping = service()
        _ = await keeping.fetchFile("flags")
        keeping.wipeOnRevocation("default")
        XCTAssertTrue(keeping.hasFile("flags"))

        let wiping = service(wipeOnRevocation: true)
        wiping.wipeOnRevocation("default")
        XCTAssertFalse(wiping.hasFile("flags"))
        XCTAssertNil(meta.signatures("flags"))
    }

    func testUnenrollWipesTheFilesOfTheBlocksThatUseTheLabelAndDropsTheScreenLockKey() async throws {
        let vault = service(evaluator: ScriptedEvaluator([.approve]))
        serve("flags", Data(utf8: "on"), version: 1)
        _ = await vault.fetchFile("flags")
        serveSealed(version: 1)
        _ = await vault.fetchFile("st")
        XCTAssertNotNil(keys.key)

        vault.wipeFiles(usingCertLabel: "other-label")
        XCTAssertTrue(vault.hasFile("flags"), "no block uses that label")

        vault.wipeFiles(usingCertLabel: "vault-cert")
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertFalse(vault.hasFile("st"))
        XCTAssertNil(keys.key, "no locked file left: the screen-lock key goes")

        // The next fetch makes a new key and registers it again.
        serveSealed(version: 1)
        guard case .updated = await vault.fetchFile("st") else { return XCTFail() }
        XCTAssertEqual(api.userAuthRegistrations.count, 2)
    }

    func testTheSweepWipesStaleFilesThatAskForIt() async throws {
        let wiped = VaultFileConfig(key: "flags", endpoint: "api/v1/vault/flags", maxOfflineAgeMs: 1, wipeWhenStale: true)
        let vault = service(files: [wiped])
        try prefsStore.save(key: "flags", bytes: Data(utf8: "on"), version: 1)
        vault.wipeStaleFiles()
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertEqual(vault.fileStatus("flags"), .stale)
    }
}
