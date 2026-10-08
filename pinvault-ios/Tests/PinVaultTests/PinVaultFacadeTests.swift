import XCTest
@_spi(PinVaultE2E) @testable import PinVault

/// The façade before the later layers: the environment guard (port of
/// EnvironmentGuardTest), the "not initialised" answers, and the E2E hooks.
final class PinVaultFacadeTests: XCTestCase {

    private let pins = [HostPin(hostname: "api.example.com", sha256: [pin("A"), pin("E")])]

    private func config(_ guardBody: (@Sendable (GuardedOperation) throws -> Bool)? = nil) throws -> PinVaultConfig {
        let builder = PinVaultConfig.Builder().configApi("api", url: "https://api.example.com/") { $0.bootstrapPins(self.pins).allowUnsigned() }
        if let guardBody { builder.environmentGuard(guardBody) }
        return try builder.build()
    }

    func testNoGuardRefusesNothing() throws {
        let vault = PinVault()
        for operation in GuardedOperation.allCases {
            XCTAssertNil(vault.environmentRefusal(try config(), operation))
        }
    }

    func testTheGuardIsAskedWithTheOperationAndItsNoRefusesOnlyThatOne() throws {
        let vault = PinVault()
        let asked = Locked<[GuardedOperation]>([])
        let cfg = try config { operation in
            asked.withLock { $0.append(operation) }
            return operation == .start
        }
        XCTAssertNil(vault.environmentRefusal(cfg, .start))
        let refused = try XCTUnwrap(vault.environmentRefusal(cfg, .enroll))
        guard case .untrustedEnvironment(let operation, _, _) = refused else { return XCTFail("\(refused)") }
        XCTAssertEqual(operation, .enroll)
        XCTAssertEqual(refused.message, "The app's environment guard refused ENROLL on this device")
        XCTAssertEqual(refused.exceptionName, "UntrustedEnvironmentException")
        XCTAssertEqual(asked.get(), [.start, .enroll])
    }

    func testAGuardThatThrowsRefuses() throws {
        struct DetectorCrashed: Error {}
        let refused = try XCTUnwrap(PinVault().environmentRefusal(try config { _ in throw DetectorCrashed() }, .fetchFile))
        guard case .untrustedEnvironment(let operation, let message, let cause) = refused else { return XCTFail("\(refused)") }
        XCTAssertEqual(operation, .fetchFile)
        XCTAssertTrue(cause is DetectorCrashed)
        XCTAssertEqual(message, "The app's environment guard failed for FETCH_FILE (DetectorCrashed); refused")
    }

    func testReadingAStoredCopyIsAnOperationOfItsOwn() throws {
        let cfg = try config { $0 != .loadFile }
        XCTAssertNil(PinVault().environmentRefusal(cfg, .fetchFile))
        let refused = try XCTUnwrap(PinVault().environmentRefusal(cfg, .loadFile))
        guard case .untrustedEnvironment(.loadFile, _, _) = refused else { return XCTFail("\(refused)") }
        XCTAssertEqual(GuardedOperation.loadFile.rawValue, "LOAD_FILE", "the Kotlin name")
    }

    func testStartIsRefusedBeforeAnythingIsSetUp() async throws {
        let result = await PinVault().start(config: try config { _ in false })
        guard case .failed(_, let exception) = result else { return XCTFail("\(result)") }
        guard case .untrustedEnvironment(.start, _, _)? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
    }

    func testEnrollmentBeforeStartIsRefusedAndNothingIsSent() async throws {
        let result = await PinVault().enrollForResult(config: try config { $0 != .enroll }, token: "token")
        guard case .failed(_, let cause) = result else { return XCTFail("\(result)") }
        guard case .untrustedEnvironment(.enroll, _, _)? = cause as? PinVaultError else { return XCTFail("\(String(describing: cause))") }
    }

    func testStaticPinsAreValidatedAtStart() async {
        let result = await PinVault().start(config: PinVaultConfig.static(HostPin(hostname: "*.com", sha256: [pin("A"), pin("B")])))
        guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.hasPrefix("Static pins are not valid: Hostname '*.com' is a wildcard"), reason)
        guard case .invalidPinFormat? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
    }

    func testBeforeStartGettersAreEmptyAndOperationsFail() async throws {
        // Isolated: the simulator's Keychain may keep an identity key of an earlier run.
        let vault = try isolatedPinVault(self)
        XCTAssertEqual(vault.currentVersion(), 0)
        XCTAssertTrue(vault.hostPinVersions().isEmpty)
        XCTAssertTrue(vault.currentPins.isEmpty)
        XCTAssertNil(vault.pinsForHost("api.example.com"))
        XCTAssertFalse(vault.isForceUpdate())
        XCTAssertNil(vault.signingStatus())
        XCTAssertFalse(vault.isEnrolled())
        XCTAssertFalse(vault.isEnrollmentPending())
        XCTAssertNil(vault.enrollmentVerificationCode())
        XCTAssertNil(vault.enrolledClientCN())
        XCTAssertNil(vault.enrolledClientNotAfter())
        XCTAssertNil(vault.identityKeySecurityLevel())
        XCTAssertNil(vault.loadFile("flags"))
        XCTAssertNil(vault.loadFileAsString("flags"))
        XCTAssertFalse(vault.hasFile("flags"))
        XCTAssertEqual(vault.fileVersion("flags"), 0)
        XCTAssertEqual(vault.fileStatus("flags"), .notStored)
        XCTAssertFalse(vault.isFileLocked("flags"))
        XCTAssertFalse(vault.schedulePeriodicUpdates())
        XCTAssertEqual(vault.attestationHeaderName(), "PinVault-Token")

        let update = await vault.updateNow()
        XCTAssertEqual(update, .failed(reason: "PinVault not initialized. Call PinVault.start() first.",
                                       exception: PinVaultError.illegalState("PinVault not initialized. Call PinVault.start() first.")))
        let fetch = await vault.fetchFile("flags")
        guard case .failed(let key, _, _, _) = fetch else { return XCTFail("\(fetch)") }
        XCTAssertEqual(key, "flags")
        let unlock = await vault.unlockFile(key: "flags", prompt: VaultFileUnlockPrompt(title: "Aç"))
        XCTAssertEqual(unlock.key, "flags")
        let synced = await vault.syncAllFiles()
        XCTAssertTrue(synced.isEmpty)

        let attest = await vault.attestNow()
        XCTAssertEqual(attest.result, .failed)
        XCTAssertEqual(attest.lastError, "PinVault not initialized")
        XCTAssertEqual(vault.attestationStatus(configApiId: "api").result, .failed)
        let token = await vault.fetchAttestationToken()
        XCTAssertEqual(token, .failed(message: "PinVault not initialized"))
        let renewal = await vault.renewClientCertIfNeeded()
        XCTAssertEqual(renewal, .failed(reason: "PinVault not initialized"))
        let enroll = await vault.enrollForResult(token: "t")
        XCTAssertEqual(enroll, .failed(message: "PinVault is not initialized: call init first, or enroll with the config before init"))
        let tasks = await vault.scheduledTasks()
        XCTAssertTrue(tasks.isEmpty)

        do {
            _ = try await vault.session().data(from: URL(string: "https://api.example.com/")!)
            XCTFail("a session before start must refuse")
        } catch let error as PinVaultError {
            XCTAssertEqual(error.exceptionName, "SSLHandshakeException")
        }
        vault.reset()
        vault.unenroll(label: nil, wipeVaultFiles: true)
    }

    func testEnrollmentBeforeStartAppliesTheBlockRules() async throws {
        let http = try PinVaultConfig.Builder()
            .configApi("api", url: "http://api.example.com/") { $0.bootstrapPins(self.pins).allowUnsigned() }
            .build()
        let result = try await isolatedPinVault(self).enrollForResult(config: http, token: "t")
        guard case .failed(let message, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(message.contains("configUrl must be an https:// URL"), message)
        let none = await PinVault().checkPendingEnrollment(config: PinVaultConfig.static(pins[0]))
        XCTAssertEqual(none, .failed(message: "The config has no Config API block"))
    }

    func testE2EHooksStoreTheirValues() async {
        let vault = PinVault()
        XCTAssertEqual(vault.e2eClockOffsetMs, 0)
        let before = vault.e2eGeneration
        vault.e2eSetClockOffset(seconds: 3_600)
        vault.e2eSetRedirects(["192.168.1.10:6651": "127.0.0.1:6661"])
        XCTAssertEqual(vault.e2eClockOffsetMs, 3_600_000)
        XCTAssertEqual(vault.e2eRedirect(for: "192.168.1.10:6651"), "127.0.0.1:6661")
        XCTAssertNil(vault.e2eRedirect(for: "192.168.1.10:6652"))
        XCTAssertEqual(vault.e2eGeneration, before + 2)
        vault.e2eSetRedirects(["192.168.1.10:6651": "127.0.0.1:6661"])
        XCTAssertEqual(vault.e2eGeneration, before + 2, "no change, no rebuild")

        let notified = Locked(0)
        vault.e2eSetScheduledTasksObserver { notified.withLock { $0 += 1 } }
        vault.notifyScheduledTasksChanged()
        XCTAssertEqual(notified.get(), 1)
        await vault.e2eRunPeriodicWorkNow()
        _ = vault.e2eDeviceId()
    }

    func testTheShapeOfTheAPIIsStable() {
        XCTAssertTrue(PinVault.shared === PinVault.shared)
        XCTAssertEqual(PinVault.backgroundTaskIdentifier, "io.github.umutcansu.pinvault.refresh")
        XCTAssertFalse(PinVault().registerBackgroundTask(), "no BGTaskSchedulerPermittedIdentifiers in the test bundle")
    }
}
