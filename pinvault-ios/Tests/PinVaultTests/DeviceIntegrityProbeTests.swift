import XCTest
@testable import PinVault

/// The report the probes end up in (`ATTESTATION.md` §3, `PORTING.md` §4):
/// its exact shape, the verdict provider, and whole devices simulated through
/// the readers — a genuine iPhone, a jailbroken and hooked one, a debugger, the simulator.
final class DeviceIntegrityProbeTests: XCTestCase {

    static let topKeys = ["sdkVersion", "reportTime", "app", "device", "signals"]
    static let appKeys = ["packageName", "bundleId", "teamId", "versionCode", "versionName", "signerSha256", "installer", "debuggable"]
    static let deviceKeys = [
        "platform", "osVersion", "manufacturer", "brand", "model", "device", "product", "hardware", "fingerprint",
        "sdkInt", "securityPatch", "verifiedBootState", "keySecurityLevel", "keyAttested",
    ]

    /// A genuine iPhone 16 Pro on iOS 26.5, App Store install, no profile.
    static func iPhone(
        files: Set<String> = [],
        writable: Bool = false,
        environment: [String: String] = [:],
        simulator: Bool = false,
        debug: Bool = false,
        traced: Bool = false,
        images: [String] = ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/UIKit.framework/UIKit"],
        fridaPort: Bool = false,
        profile: ProvisioningProfile? = nil,
        receipt: String? = "receipt",
        accessGroup: String? = "ABCDE12345.com.example.sampleclient",
        bundleId: String? = "com.example.sampleclient"
    ) -> IntegrityProbeInputs {
        IntegrityProbeInputs(
            fileExists: { files.contains($0) },
            canWriteOutsideSandbox: { writable },
            environment: { environment },
            isSimulatorBuild: simulator,
            isDebugBuild: debug,
            onMacHost: simulator,
            isTraced: { traced },
            loadedImages: { images },
            localPortOpen: { $0 == HookingProbe.fridaPort && fridaPort },
            provisioningProfile: { profile },
            receiptName: { receipt },
            keychainAccessGroup: { accessGroup },
            bundleId: { bundleId },
            bundleVersion: { "412" },
            shortVersion: { "4.1.2" },
            osName: "iOS",
            osVersion: { "26.5" },
            osBuild: { "23F79" },
            machine: { "iPhone17,1" },
            deviceModel: { "iPhone" }
        )
    }

    private func report(
        _ inputs: IntegrityProbeInputs,
        provider: (any IntegrityVerdictProvider)? = nil,
        key: (any ClientIdentityKeyProvider)? = TestIdentityKey(level: .secureEnclave),
        expectedBundleIds: [String] = [],
        expectedTeamIds: [String] = [],
        timeoutMs: Int64 = DeviceIntegrityProbe.verdictTimeoutMs
    ) async -> (IntegrityReport, [String: Any]) {
        let probe = DeviceIntegrityProbe(
            expectedBundleIds: expectedBundleIds, expectedTeamIds: expectedTeamIds, verdictProvider: provider,
            clock: { 1_759_660_801_234 }, inputs: inputs, verdictTimeoutMs: timeoutMs
        )
        let report = await probe.report(nonce: "nonce-1", deviceId: "device-07", scope: "api", key: key)
        let json = LenientJSON.object(Data(report.jsonString().utf8)) ?? [:]
        return (report, json)
    }

    private func signals(_ json: [String: Any]) -> [String: [String: Any]] {
        (json["signals"] as? [String: [String: Any]]) ?? [:]
    }

    private func flag(_ json: [String: Any], _ name: String) -> Bool {
        signals(json)[name]?["flag"] as? Bool ?? false
    }

    private func evidence(_ json: [String: Any], _ name: String) -> [String] {
        signals(json)[name]?["evidence"] as? [String] ?? []
    }

    /// The keys of `object` in the order they appear in `text` (JSONSerialization drops the order).
    private func orderedKeys(of text: String, in keys: [String]) -> [String] {
        keys.sorted { (text.range(of: "\"\($0)\":")?.lowerBound ?? text.endIndex) < (text.range(of: "\"\($1)\":")?.lowerBound ?? text.endIndex) }
    }

    // MARK: Shape

    func testTheReportHasEveryBlockAndEverySignalOfTheDesignInTheIosShape() async throws {
        let (report, json) = await report(Self.iPhone())
        XCTAssertEqual(Set(json.keys), Set(Self.topKeys), "no verdictProvider without a provider")
        XCTAssertEqual(json["sdkVersion"] as? String, IntegrityReport.sdkVersion)
        XCTAssertEqual((json["reportTime"] as? NSNumber)?.int64Value, 1_759_660_801_234)

        let app = try XCTUnwrap(json["app"] as? [String: Any])
        XCTAssertEqual(Set(app.keys), Set(Self.appKeys))
        XCTAssertEqual(app["packageName"] as? String, "com.example.sampleclient")
        XCTAssertEqual(app["bundleId"] as? String, "com.example.sampleclient")
        XCTAssertEqual(app["teamId"] as? String, "ABCDE12345", "from the keychain access group without a profile")
        XCTAssertEqual(app["versionCode"] as? Int, 412)
        XCTAssertEqual(app["versionName"] as? String, "4.1.2")
        XCTAssertEqual(app["signerSha256"] as? [String], [])
        XCTAssertEqual(app["installer"] as? String, "app-store")
        XCTAssertEqual(app["debuggable"] as? Bool, false)

        let device = try XCTUnwrap(json["device"] as? [String: Any])
        XCTAssertEqual(Set(device.keys), Set(Self.deviceKeys))
        XCTAssertEqual(device["platform"] as? String, "ios")
        XCTAssertEqual(device["osVersion"] as? String, "26.5")
        XCTAssertEqual(device["manufacturer"] as? String, "Apple")
        XCTAssertEqual(device["brand"] as? String, "Apple")
        XCTAssertEqual(device["model"] as? String, "iPhone17,1")
        XCTAssertEqual(device["device"] as? String, "iPhone")
        XCTAssertEqual(device["product"] as? String, "iPhone17,1")
        XCTAssertEqual(device["hardware"] as? String, "iPhone17,1")
        XCTAssertEqual(device["fingerprint"] as? String, "iOS/26.5/23F79")
        XCTAssertEqual(device["sdkInt"] as? Int, 26)
        XCTAssertTrue(device["securityPatch"] is NSNull)
        XCTAssertTrue(device["verifiedBootState"] is NSNull)
        XCTAssertEqual(device["keySecurityLevel"] as? String, "secure_enclave")
        XCTAssertEqual(device["keyAttested"] as? Bool, false)

        // Every signal key, in the order of §3, each with a flag and an evidence list.
        XCTAssertEqual(Set(signals(json).keys), Set(IntegrityReport.signalKeys))
        let text = report.jsonString()
        let signalsText = String(text[try XCTUnwrap(text.range(of: #""signals":"#)).upperBound...])
        XCTAssertEqual(orderedKeys(of: signalsText, in: IntegrityReport.signalKeys), IntegrityReport.signalKeys)
        let deviceText = String(text[try XCTUnwrap(text.range(of: #""device":{"#)).upperBound...])
        XCTAssertEqual(orderedKeys(of: deviceText, in: Self.deviceKeys), Self.deviceKeys)
        XCTAssertEqual(orderedKeys(of: text, in: Self.topKeys), Self.topKeys)
        for name in IntegrityReport.signalKeys {
            let signal = try XCTUnwrap(signals(json)[name], name)
            XCTAssertEqual(Set(signal.keys), ["flag", "evidence"], name)
            XCTAssertNotNil(signal["flag"] as? Bool, name)
            XCTAssertNotNil(signal["evidence"] as? [String], name)
        }
        // A genuine iPhone raises nothing; the Android-only signals say so.
        XCTAssertEqual(IntegrityReport.signalKeys.filter { flag(json, $0) }, [])
        XCTAssertEqual(evidence(json, "cloner"), ["n/a:ios"])
        XCTAssertEqual(evidence(json, "adb_enabled"), ["n/a:ios"])
        XCTAssertEqual(evidence(json, "key_unattested"), ["app-attest:none"])
        XCTAssertEqual(evidence(json, "old_patch_level"), [])
    }

    func testTheStringIsStableSoTheOneHashedIsTheOneSent() async {
        let (report, _) = await report(Self.iPhone())
        XCTAssertEqual(report.jsonString(), report.jsonString())
        XCTAssertTrue(report.jsonString().hasPrefix(#"{"sdkVersion":"2.4.0","reportTime":1759660801234,"app":{"packageName":"com.example.sampleclient","#))
        XCTAssertFalse(report.jsonString().contains("\n"))
    }

    func testANullTeamIdAndAMissingSignalAreStillPresent() async throws {
        var (report, json) = await report(Self.iPhone(accessGroup: "com.example.sampleclient"))
        let app = try XCTUnwrap(json["app"] as? [String: Any])
        XCTAssertTrue(app["teamId"] is NSNull, "an unsigned build's access group names no team")
        report.signals.removeValue(forKey: "rooted")
        let reparsed = try XCTUnwrap(LenientJSON.object(Data(report.jsonString().utf8)))
        XCTAssertEqual(evidence(reparsed, "rooted"), ["error:rooted"])
        XCTAssertFalse(flag(reparsed, "rooted"))
    }

    func testTheProfileGivesTheTeamIdAndGetTaskAllow() async throws {
        let profile = ProvisioningProfile(teamIdentifier: "FGHIJ67890", applicationIdentifierPrefix: "FGHIJ67890", applicationIdentifier: "FGHIJ67890.com.example.sampleclient", getTaskAllow: true)
        let (_, json) = await report(Self.iPhone(profile: profile, receipt: "sandboxReceipt"))
        let app = try XCTUnwrap(json["app"] as? [String: Any])
        XCTAssertEqual(app["teamId"] as? String, "FGHIJ67890", "the profile wins over the access group")
        XCTAssertEqual(app["installer"] as? String, "provisioned")
        XCTAssertEqual(app["debuggable"] as? Bool, true)
        XCTAssertEqual(evidence(json, "debuggable"), ["entitlement:get-task-allow"])
        XCTAssertEqual(evidence(json, "unknown_installer"), ["installer:provisioned"])
    }

    // MARK: Simulated devices

    func testAJailbrokenAndHookedDeviceRaisesItsSignals() async throws {
        let (_, json) = await report(Self.iPhone(
            files: ["/var/jb", "/Applications/Sileo.app", "/usr/sbin/sshd"],
            writable: true,
            environment: ["DYLD_INSERT_LIBRARIES": "/var/jb/usr/lib/TweakInject.dylib"],
            images: ["/usr/lib/libSystem.B.dylib", "/var/jb/usr/lib/libellekit.dylib", "/var/jb/usr/lib/frida/frida-agent.dylib"],
            fridaPort: true
        ))
        XCTAssertTrue(flag(json, "rooted"))
        XCTAssertEqual(evidence(json, "rooted"), ["file:/Applications/Sileo.app", "file:/var/jb", "file:/usr/sbin/sshd", "fs:/private-writable"])
        XCTAssertTrue(flag(json, "hooking_framework"))
        XCTAssertEqual(evidence(json, "hooking_framework"), ["dyld:ellekit", "dyld-path:libellekit.dylib", "dyld:frida", "dyld-path:frida-agent.dylib", "env:DYLD_INSERT_LIBRARIES", "port:27042"])
        XCTAssertFalse(flag(json, "emulator"))
        XCTAssertFalse(flag(json, "debugger"))
    }

    func testADebuggerIsSeen() async {
        let (_, json) = await report(Self.iPhone(traced: true))
        XCTAssertTrue(flag(json, "debugger"))
        XCTAssertEqual(evidence(json, "debugger"), ["sysctl:p_traced"])
    }

    func testTheSimulatorIsAnEmulatorFromAnUnknownInstallerAndItsMacFilesAreNotAJailbreak() async throws {
        let (_, json) = await report(Self.iPhone(
            files: ["/bin/bash", "/usr/sbin/sshd"],
            environment: ["SIMULATOR_DEVICE_NAME": "PinVault-L5", "SIMULATOR_MODEL_IDENTIFIER": "iPhone17,1"],
            simulator: true, debug: true, receipt: nil, accessGroup: nil
        ))
        XCTAssertTrue(flag(json, "emulator"))
        XCTAssertEqual(evidence(json, "emulator"), ["build:simulator", "env:SIMULATOR_DEVICE_NAME"])
        XCTAssertFalse(flag(json, "rooted"), "the Mac's bash and sshd are the host's")
        XCTAssertEqual(evidence(json, "unknown_installer"), ["installer:simulator"])
        XCTAssertEqual(evidence(json, "debuggable"), ["build:debug"])
        let app = try XCTUnwrap(json["app"] as? [String: Any])
        XCTAssertEqual(app["installer"] as? String, "simulator")
        XCTAssertEqual(app["debuggable"] as? Bool, true)
    }

    func testAppIntegrityOnTheDeviceFollowsTheExpectedIds() async {
        let (_, genuine) = await report(Self.iPhone(), expectedBundleIds: ["com.example.sampleclient"], expectedTeamIds: ["ABCDE12345"])
        XCTAssertFalse(flag(genuine, "app_integrity"))
        let (_, resigned) = await report(Self.iPhone(accessGroup: "ZZZZZ99999.com.example.sampleclient"), expectedTeamIds: ["ABCDE12345"])
        XCTAssertEqual(evidence(resigned, "app_integrity"), ["team:ZZZZZ99999"])
        let (_, notJudged) = await report(Self.iPhone(bundleId: "com.evil.clone"))
        XCTAssertFalse(flag(notJudged, "app_integrity"), "without expectations the server judges")
    }

    func testAProbeWhoseReaderThrowsReportsAnErrorNotACleanSignal() async throws {
        var inputs = Self.iPhone()
        inputs.canWriteOutsideSandbox = { throw ProbeReadError("denied") }
        inputs.isTraced = { throw ProbeReadError("sysctl failed") }
        inputs.provisioningProfile = { throw ProbeReadError("unreadable profile") }
        let (_, json) = await report(inputs)
        XCTAssertEqual(evidence(json, "rooted"), ["error:rooted"])
        XCTAssertFalse(flag(json, "rooted"))
        XCTAssertEqual(evidence(json, "debugger"), ["error:debugger"])
        XCTAssertEqual(evidence(json, "debuggable"), ["error:debuggable"], "a profile that cannot be read is not a clean one")
        let app = try XCTUnwrap(json["app"] as? [String: Any])
        XCTAssertEqual(app["installer"] as? String, "provisioned", "a profile is there, unread")
    }

    // MARK: Keys and verdicts

    func testASoftwareKeyOrNoKeyIsReported() async throws {
        let (_, software) = await report(Self.iPhone(), key: TestIdentityKey(level: .software))
        XCTAssertTrue(flag(software, "software_key"))
        XCTAssertEqual(evidence(software, "software_key"), ["key:software"])
        let (_, noKey) = await report(Self.iPhone(), key: nil)
        XCTAssertEqual((noKey["device"] as? [String: Any])?["keySecurityLevel"] as? String, "unknown")
        XCTAssertTrue(flag(noKey, "software_key"))
    }

    func testAVerdictGoesAlongVerbatimBoundToTheNonce() async throws {
        let provider = RecordingVerdictProvider(verdict: IntegrityVerdict(name: "play-integrity", token: "eyJ.token"))
        let (_, json) = await report(Self.iPhone(), provider: provider)
        XCTAssertEqual(provider.nonces, ["nonce-1"])
        let verdict = try XCTUnwrap(json["verdictProvider"] as? [String: Any])
        XCTAssertEqual(verdict["name"] as? String, "play-integrity")
        XCTAssertEqual(verdict["token"] as? String, "eyJ.token")
        XCTAssertEqual((json["device"] as? [String: Any])?["keyAttested"] as? Bool, false, "not App Attest")
        XCTAssertEqual(evidence(json, "key_unattested"), ["app-attest:none"])
    }

    func testAnAppAttestVerdictIsBoundToTheReportAndMarksTheKeyAttested() async throws {
        let service = FakeAppAttestService()
        let provider = AppAttestVerdictProvider(service: service, store: { InMemoryPreferences() }, deviceId: { "ignored" })
        let probe = DeviceIntegrityProbe(verdictProvider: provider, clock: { 1 }, inputs: Self.iPhone())
        let (_, json) = await report(Self.iPhone(), provider: provider)
        // v2: the report is built first and carries no token…
        XCTAssertNil(json["verdictProvider"])
        XCTAssertTrue(service.attested.isEmpty, "nothing is attested before the report exists")
        // …the verdict is then bound to the canonical string, which carries the report's digest.
        let bound = await probe.roundVerdict(canonical: "pinvault-attest:v1:n:d:abc", scope: "api")
        let verdict = try XCTUnwrap(bound)
        XCTAssertEqual(verdict.name, "app-attest")
        XCTAssertEqual(service.attested.first?.clientDataHash, AppAttestToken.roundClientDataHashV2(canonical: "pinvault-attest:v1:n:d:abc"))
        XCTAssertEqual((json["device"] as? [String: Any])?["keyAttested"] as? Bool, true)
        XCTAssertEqual(evidence(json, "key_unattested"), [])
        XCTAssertFalse(flag(json, "key_unattested"))
    }

    func testAProviderThatFailsAnswersNothingOrTakesTooLongLeavesTheReportWithoutAVerdict() async {
        let (_, failing) = await report(Self.iPhone(), provider: RecordingVerdictProvider(error: ProbeReadError("no service")))
        XCTAssertNil(failing["verdictProvider"])
        let (_, empty) = await report(Self.iPhone(), provider: RecordingVerdictProvider(verdict: nil))
        XCTAssertNil(empty["verdictProvider"])

        let started = Date()
        let (_, slow) = await report(Self.iPhone(), provider: StubbornVerdictProvider(), timeoutMs: 150)
        XCTAssertNil(slow["verdictProvider"])
        XCTAssertLessThan(Date().timeIntervalSince(started), 2.0, "the deadline holds even when the provider ignores cancellation")
    }

    // MARK: This host

    func testTheLiveProbeOnThisHostReportsWhatItIs() async throws {
        let probe = DeviceIntegrityProbe(clock: { 1 })
        let report = await probe.report(nonce: "n", deviceId: "d", scope: "api", key: nil)
        let json = try XCTUnwrap(LenientJSON.object(Data(report.jsonString().utf8)))
        XCTAssertEqual(Set(signals(json).keys), Set(IntegrityReport.signalKeys))
        XCTAssertEqual((json["device"] as? [String: Any])?["platform"] as? String, "ios")
        XCTAssertEqual((json["device"] as? [String: Any])?["manufacturer"] as? String, "Apple")
        XCTAssertEqual(evidence(json, "cloner"), ["n/a:ios"])
        XCTAssertFalse(flag(json, "rooted"), "\(evidence(json, "rooted"))")
        #if targetEnvironment(simulator)
        XCTAssertTrue(flag(json, "emulator"), "the simulator must report emulator")
        XCTAssertTrue(evidence(json, "emulator").contains("build:simulator"))
        XCTAssertEqual((json["app"] as? [String: Any])?["installer"] as? String, "simulator")
        XCTAssertTrue(((json["device"] as? [String: Any])?["fingerprint"] as? String)?.hasPrefix("iOS/") == true)
        #else
        XCTAssertFalse(flag(json, "emulator"), "\(evidence(json, "emulator"))")
        #endif
    }
}

/// A provider that records the nonces it was asked with.
final class RecordingVerdictProvider: IntegrityVerdictProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _nonces: [String] = []
    private let verdict: IntegrityVerdict?
    private let error: (any Error)?

    init(verdict: IntegrityVerdict? = nil, error: (any Error)? = nil) {
        self.verdict = verdict
        self.error = error
    }

    var nonces: [String] { lock.lock(); defer { lock.unlock() }; return _nonces }

    func verdict(nonce: String) async throws -> IntegrityVerdict? {
        lock.withLock { _nonces.append(nonce) }
        if let error { throw error }
        return verdict
    }
}

/// A provider that never answers in time and ignores cancellation.
private struct StubbornVerdictProvider: IntegrityVerdictProvider {
    func verdict(nonce: String) async throws -> IntegrityVerdict? {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { continuation.resume() }
        }
        return IntegrityVerdict(name: "late", token: "late")
    }
}
