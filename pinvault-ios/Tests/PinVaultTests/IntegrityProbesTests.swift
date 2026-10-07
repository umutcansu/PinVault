import XCTest
@testable import PinVault

/// The iOS integrity probes over fake readers — positive and negative
/// evidence for each (Kotlin `ProbesTest`, iOS probes of `PORTING.md` §4).
final class IntegrityProbesTests: XCTestCase {

    private let none: (String) -> Bool = { _ in false }

    // MARK: rooted

    func testACleanDeviceRaisesNoJailbreakEvidence() throws {
        let signal = try JailbreakProbe(fileExists: none, canWriteOutsideSandbox: { false }, onMacHost: false).probe()
        XCTAssertFalse(signal.flag)
        XCTAssertTrue(signal.evidence.isEmpty)
    }

    func testPackageManagersRootlessRootsAptSshdBashAndASandboxEscapeAreEvidence() throws {
        let files: Set<String> = ["/Applications/Sileo.app", "/var/jb", "/private/var/lib/apt", "/usr/sbin/sshd", "/bin/bash", "/etc/apt"]
        let signal = try JailbreakProbe(fileExists: { files.contains($0) }, canWriteOutsideSandbox: { true }, onMacHost: false).probe()
        XCTAssertTrue(signal.flag)
        XCTAssertEqual(signal.evidence, [
            "file:/Applications/Sileo.app", "file:/var/jb", "file:/private/var/lib/apt", "file:/usr/sbin/sshd",
            "file:/bin/bash", "file:/etc/apt", "fs:/private-writable",
        ])
        XCTAssertEqual(
            try JailbreakProbe(fileExists: { $0 == "/Applications/Cydia.app" }, canWriteOutsideSandbox: { false }, onMacHost: false).probe().evidence,
            ["file:/Applications/Cydia.app"]
        )
    }

    func testOnAMacHostTheMacsOwnBashAndSshdAreNotEvidence() throws {
        let files: Set<String> = ["/usr/sbin/sshd", "/bin/bash"]
        let mac = try JailbreakProbe(fileExists: { files.contains($0) }, canWriteOutsideSandbox: { false }, onMacHost: true).probe()
        XCTAssertFalse(mac.flag)
        // A jailbreak artefact still counts there.
        let zebra = try JailbreakProbe(fileExists: { $0 == "/Applications/Zebra.app" || files.contains($0) }, canWriteOutsideSandbox: { false }, onMacHost: true).probe()
        XCTAssertEqual(zebra.evidence, ["file:/Applications/Zebra.app"])
    }

    func testTheLiveReadersSeeNoJailbreakOnThisHost() throws {
        // The sandbox (iOS) or the permissions of /private (macOS) refuse the write.
        XCTAssertFalse(try LiveIntegrityReaders.canWriteOutsideSandbox())
        XCTAssertFalse(LiveIntegrityReaders.fileExists("/Applications/Cydia.app/\(UUID().uuidString)"))
        XCTAssertTrue(LiveIntegrityReaders.fileExists("/usr/lib"))
    }

    // MARK: emulator

    func testADeviceIsNotASimulator() {
        let signal = SimulatorProbe(isSimulatorBuild: false, environment: ["HOME": "/var/mobile"]).probe()
        XCTAssertFalse(signal.flag)
        XCTAssertTrue(signal.evidence.isEmpty)
    }

    func testTheSimulatorBuildAndItsEnvironmentAreEvidence() {
        XCTAssertEqual(SimulatorProbe(isSimulatorBuild: true, environment: [:]).probe().evidence, ["build:simulator"])
        XCTAssertEqual(
            SimulatorProbe(isSimulatorBuild: true, environment: ["SIMULATOR_DEVICE_NAME": "iPhone 16 Pro"]).probe().evidence,
            ["build:simulator", "env:SIMULATOR_DEVICE_NAME"]
        )
        XCTAssertTrue(SimulatorProbe(isSimulatorBuild: false, environment: ["SIMULATOR_DEVICE_NAME": "iPhone 16 Pro"]).probe().flag)
        XCTAssertFalse(SimulatorProbe(isSimulatorBuild: false, environment: ["SIMULATOR_DEVICE_NAME": ""]).probe().flag)
    }

    // MARK: debugger

    func testADebuggerIsATracedProcess() throws {
        XCTAssertFalse(try DebuggerProbe(isTraced: { false }).probe().flag)
        let traced = try DebuggerProbe(isTraced: { true }).probe()
        XCTAssertTrue(traced.flag)
        XCTAssertEqual(traced.evidence, ["sysctl:p_traced"])
    }

    func testTheSysctlReaderAnswersForThisProcess() throws {
        // Whatever the answer (a test run may sit under a debugger), the read itself works.
        _ = try LiveIntegrityReaders.isTraced()
    }

    // MARK: debuggable

    func testDebuggableFollowsGetTaskAllowOrOnTheSimulatorTheBuild() {
        let development = DebuggableProbe(getTaskAllow: true, isSimulatorBuild: false, isDebugBuild: false)
        XCTAssertTrue(development.debuggable)
        XCTAssertEqual(development.probe().evidence, ["entitlement:get-task-allow"])

        let adHoc = DebuggableProbe(getTaskAllow: false, isSimulatorBuild: false, isDebugBuild: true)
        XCTAssertFalse(adHoc.debuggable)
        XCTAssertFalse(adHoc.probe().flag)

        // App Store / TestFlight: no profile, never get-task-allow.
        XCTAssertFalse(DebuggableProbe(getTaskAllow: nil, isSimulatorBuild: false, isDebugBuild: true).probe().flag)

        let simulatorDebug = DebuggableProbe(getTaskAllow: nil, isSimulatorBuild: true, isDebugBuild: true)
        XCTAssertTrue(simulatorDebug.debuggable)
        XCTAssertEqual(simulatorDebug.probe().evidence, ["build:debug"])
        XCTAssertFalse(DebuggableProbe(getTaskAllow: nil, isSimulatorBuild: true, isDebugBuild: false).probe().flag)
    }

    // MARK: hooking_framework

    private func hooking(
        images: [String] = ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Foundation.framework/Foundation", "/private/var/containers/Bundle/Application/X/App.app/App"],
        environment: [String: String] = [:],
        port: Bool = false
    ) -> IntegritySignal {
        HookingProbe(loadedImages: { images }, environment: environment, fridaPortOpen: { port }).probe()
    }

    func testAnUnhookedProcessShowsNothing() {
        let signal = hooking()
        XCTAssertFalse(signal.flag)
        XCTAssertTrue(signal.evidence.isEmpty)
    }

    func testFridaInTheImagesItsPortAndInsertedLibrariesAreEvidence() {
        let signal = hooking(
            images: ["/usr/lib/libSystem.B.dylib", "/private/var/containers/Bundle/Application/X/App.app/Frameworks/FridaGadget.dylib"],
            environment: ["DYLD_INSERT_LIBRARIES": "/usr/lib/frida/frida-agent.dylib"],
            port: true
        )
        XCTAssertTrue(signal.flag)
        XCTAssertEqual(signal.evidence, ["dyld:frida", "dyld:fridagadget", "env:DYLD_INSERT_LIBRARIES", "port:27042"])
    }

    func testSubstrateSubstituteLibhookerEllekitCycriptAndSslKillSwitchAreEvidence() {
        let signal = hooking(images: [
            "/usr/lib/libsubstrate.dylib", "/usr/lib/libsubstitute.dylib", "/usr/lib/libhooker.dylib",
            "/var/jb/usr/lib/libellekit.dylib", "/usr/lib/libcycript.dylib", "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.dylib",
        ])
        XCTAssertEqual(signal.evidence, [
            "dyld:substrate", "dyld:substitute", "dyld:libhooker", "dyld:ellekit", "dyld:cycript", "dyld:substrate", "dyld:sslkillswitch",
        ].distinctPreservingOrder())
        // Only the file name counts: a directory named after a marker is not a hook.
        XCTAssertFalse(hooking(images: ["/Users/dev/frida-notes/App.app/App"]).flag)
        XCTAssertFalse(hooking(environment: ["DYLD_INSERT_LIBRARIES": ""]).flag)
    }

    func testTheLiveImageListAndPortCheckWork() {
        XCTAssertTrue(LiveIntegrityReaders.loadedImages().contains { $0.contains("libSystem") || $0.contains("Foundation") })
        // Nothing listens on Frida's port on a build machine; the check answers quickly.
        let started = Date()
        _ = LiveIntegrityReaders.localPortOpen(HookingProbe.fridaPort)
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.0)
    }

    func testThePortCheckSeesAListener() throws {
        let listener = try LocalListener()
        defer { listener.close() }
        XCTAssertTrue(LiveIntegrityReaders.localPortOpen(listener.port))
    }

    // MARK: app_integrity

    func testAppIntegrityIsJudgedOnTheDeviceOnlyWhenTheAppNamedItsIds() {
        let bundle = "com.example.sampleclient"
        let team = "ABCDE12345"
        XCTAssertFalse(AppIntegrityProbe(bundleId: bundle, teamId: team, expectedBundleIds: [], expectedTeamIds: []).probe().flag)
        XCTAssertFalse(AppIntegrityProbe(bundleId: bundle, teamId: team, expectedBundleIds: [bundle], expectedTeamIds: [team]).probe().flag)
        XCTAssertFalse(AppIntegrityProbe(bundleId: bundle, teamId: nil, expectedBundleIds: [bundle, "com.other"], expectedTeamIds: []).probe().flag)

        let clone = AppIntegrityProbe(bundleId: "com.evil.clone", teamId: "ZZZZZ99999", expectedBundleIds: [bundle], expectedTeamIds: [team]).probe()
        XCTAssertTrue(clone.flag)
        XCTAssertEqual(clone.evidence, ["bundle:com.evil.clone", "team:ZZZZZ99999"])

        let unreadable = AppIntegrityProbe(bundleId: nil, teamId: nil, expectedBundleIds: [bundle], expectedTeamIds: [team]).probe()
        XCTAssertEqual(unreadable.evidence, ["bundle:unreadable", "team:unreadable"])
    }

    // MARK: unknown_installer

    func testTheAppStoreAndTestFlightAreKnownAnythingElseIsNot() {
        XCTAssertEqual(AppInstaller.resolve(isSimulator: false, hasEmbeddedProfile: false, receiptName: "receipt"), .appStore)
        XCTAssertEqual(AppInstaller.resolve(isSimulator: false, hasEmbeddedProfile: false, receiptName: "sandboxReceipt"), .testFlight)
        XCTAssertEqual(AppInstaller.resolve(isSimulator: false, hasEmbeddedProfile: true, receiptName: "sandboxReceipt"), .provisioned)
        XCTAssertEqual(AppInstaller.resolve(isSimulator: true, hasEmbeddedProfile: false, receiptName: "receipt"), .simulator)
        XCTAssertEqual(AppInstaller.resolve(isSimulator: false, hasEmbeddedProfile: false, receiptName: nil), .unknown)

        XCTAssertFalse(InstallerProbe(installer: .appStore).probe().flag)
        XCTAssertFalse(InstallerProbe(installer: .testFlight).probe().flag)
        XCTAssertEqual(InstallerProbe(installer: .provisioned).probe().evidence, ["installer:provisioned"])
        XCTAssertEqual(InstallerProbe(installer: .simulator).probe().evidence, ["installer:simulator"])
        XCTAssertEqual(InstallerProbe(installer: .unknown).probe().evidence, ["installer:unknown"])
    }

    // MARK: software_key / key_unattested

    func testKeySignalsFollowTheKeysLevelAndTheAppAttestVerdict() {
        XCTAssertFalse(KeyProbe(level: .secureEnclave, appAttestVerdict: true).softwareKey().flag)
        XCTAssertEqual(KeyProbe(level: .software, appAttestVerdict: true).softwareKey().evidence, ["key:software"])
        XCTAssertEqual(KeyProbe(level: .unknown, appAttestVerdict: false).softwareKey().evidence, ["key:unknown"])
        // key_unattested is the server's call on iOS (App Attest lifts it there): never raised here.
        XCTAssertEqual(KeyProbe(level: .secureEnclave, appAttestVerdict: true).keyUnattested(), .clean)
        XCTAssertEqual(KeyProbe(level: .secureEnclave, appAttestVerdict: false).keyUnattested(), IntegritySignal(false, ["app-attest:none"]))
    }

    // MARK: The provisioning profile and the team id

    private let profilePlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>AppIDName</key><string>Sample</string>
        <key>ApplicationIdentifierPrefix</key><array><string>ABCDE12345</string></array>
        <key>Entitlements</key>
        <dict>
            <key>application-identifier</key><string>ABCDE12345.com.example.sampleclient</string>
            <key>get-task-allow</key><true/>
            <key>com.apple.developer.team-identifier</key><string>ABCDE12345</string>
        </dict>
        <key>TeamIdentifier</key><array><string>ABCDE12345</string></array>
    </dict>
    </plist>
    """

    func testTheProfileIsCutOutOfItsSignatureEnvelope() throws {
        // A CMS envelope: DER bytes before and after the XML plist.
        var data = Data([0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x80])
        data.append(Data(profilePlist.utf8))
        data.append(Data([0x00, 0x00, 0xA0, 0x82, 0x0B, 0x1F, 0x30, 0x82]))
        let profile = try XCTUnwrap(ProvisioningProfile.parse(data))
        XCTAssertEqual(profile.teamIdentifier, "ABCDE12345")
        XCTAssertEqual(profile.applicationIdentifierPrefix, "ABCDE12345")
        XCTAssertEqual(profile.applicationIdentifier, "ABCDE12345.com.example.sampleclient")
        XCTAssertEqual(profile.getTaskAllow, true)
        XCTAssertEqual(profile.teamId, "ABCDE12345")

        let distribution = try XCTUnwrap(ProvisioningProfile.parse(Data(profilePlist.replacingOccurrences(of: "<true/>", with: "<false/>").utf8)))
        XCTAssertEqual(distribution.getTaskAllow, false)
        XCTAssertNil(ProvisioningProfile.parse(Data("not a profile".utf8)))
        XCTAssertNil(ProvisioningProfile.parse(Data("<?xml version=\"1.0\"?><plist><dict>".utf8)), "cut short")
    }

    func testTheTeamIdComesFromTheProfileOrTheKeychainAccessGroup() {
        XCTAssertEqual(ProvisioningProfile(teamIdentifier: nil, applicationIdentifierPrefix: nil, applicationIdentifier: "ABCDE12345.com.x").teamId, "ABCDE12345")
        XCTAssertNil(ProvisioningProfile(teamIdentifier: "not-a-team", applicationIdentifierPrefix: nil, applicationIdentifier: nil).teamId)
        XCTAssertEqual(TeamId.fromAccessGroup("ABCDE12345.com.example.sampleclient"), "ABCDE12345")
        XCTAssertNil(TeamId.fromAccessGroup("com.example.sampleclient"), "an unsigned build's group names no team")
        XCTAssertNil(TeamId.fromAccessGroup("abcde12345.com.x"))
        XCTAssertNil(TeamId.fromAccessGroup(nil))
        XCTAssertTrue(TeamId.isValid("ABCDE12345"))
        XCTAssertFalse(TeamId.isValid("ABCDE1234"))
    }

    // MARK: The JSON

    func testStringsAreEscapedAndOrderIsKept() throws {
        let json = IntegrityJSON.object([
            .init("z", .string("a\"b\\c\nd\u{01}é/")),
            .init("a", .int(-5)),
            .init("n", .null),
            .init("l", .array([.bool(true), .strings(["x"])])),
        ])
        XCTAssertEqual(json.serialized, #"{"z":"a\"b\\c\nd\u0001é/","a":-5,"n":null,"l":[true,["x"]]}"#)
        let parsed = try XCTUnwrap(LenientJSON.object(Data(json.serialized.utf8)))
        XCTAssertEqual(parsed["z"] as? String, "a\"b\\c\nd\u{01}é/")
    }

    func testLenientReadsConvertLikeOrgJson() throws {
        let object = try XCTUnwrap(LenientJSON.object(Data(#"{"n":300,"s":"120","d":2.5,"b":true,"x":null,"a":["w"," ",7]}"#.utf8)))
        XCTAssertEqual(LenientJSON.long(object, "n"), 300)
        XCTAssertEqual(LenientJSON.long(object, "s"), 120)
        XCTAssertEqual(LenientJSON.long(object, "d"), 2)
        XCTAssertEqual(LenientJSON.long(object, "b", 9), 9)
        XCTAssertEqual(LenientJSON.long(object, "missing", 4), 4)
        XCTAssertEqual(LenientJSON.string(object, "n"), "300")
        XCTAssertEqual(LenientJSON.string(object, "b"), "true")
        XCTAssertEqual(LenientJSON.string(object, "x"), "")
        XCTAssertNil(LenientJSON.nonBlankString(object, "x"))
        XCTAssertFalse(LenientJSON.hasValue(object, "x"))
        XCTAssertTrue(LenientJSON.hasValue(object, "n"))
        XCTAssertEqual(LenientJSON.strings(object, "a"), ["w", "7"])
    }
}

/// A TCP listener on 127.0.0.1 (an ephemeral port), for the port check.
private final class LocalListener {
    let fd: Int32
    let port: UInt16

    init() throws {
        let socketFd = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFd >= 0 else { throw ProbeReadError("socket") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(socketFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(socketFd, 1) == 0 else { Darwin.close(socketFd); throw ProbeReadError("bind/listen") }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(socketFd, $0, &length) }
        }
        fd = socketFd
        port = UInt16(bigEndian: actual.sin_port)
    }

    func close() { Darwin.close(fd) }
}
