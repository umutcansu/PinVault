import CryptoKit
import XCTest
@testable import PinVault

/// Attestation rounds of this library, kept as fixtures the PinVault server's
/// own tests feed to `AttestationService` (`demo-server/src/test/resources/ios-interop/`,
/// `IosClientInteropTest.kt`): the exact POST body the manager sent — the
/// probe's report string, signed by the device key over the canonical string
/// — with a nonce in the server's format under a fixed key, and the App Attest
/// key a round asserted with.
///
/// Regenerate after a change to the report or the request:
///
///     PINVAULT_INTEROP_FIXTURE_DIR=$PWD/demo-server/src/test/resources/ios-interop \
///       swift test --filter AttestationInteropFixtureTests
///
/// (on the simulator: `TEST_RUNNER_PINVAULT_INTEROP_FIXTURE_DIR=…` with
/// `xcodebuild test`, which adds `simulator-live.json`). Without the variable
/// the rounds still run and the committed fixtures are checked against the
/// current report shape and their own signatures.
final class AttestationInteropFixtureTests: XCTestCase {

    /// The nonce key the server test gives its `AttestationNonces`: SHA-256 of this text.
    static let nonceKeyText = "pinvault-ios-interop-nonce-key"
    static var nonceKey: Data { Data(SHA256.hash(data: Data(nonceKeyText.utf8))) }
    /// When the rounds happened (epoch ms); the server test's clock is one second later.
    static let fixtureTime: Int64 = 1_800_000_000_000
    static let configApiId = "default-tls"
    static let deviceId = "6f1c2b6a-0e2f-4c1a-9a7e-3d1f0c6b9e21"
    static let appId = "ABCDE12345.com.example.sampleclient"

    static var committedDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("demo-server/src/test/resources/ios-interop")
    }

    private var outputDirectory: URL? {
        ProcessInfo.processInfo.environment["PINVAULT_INTEROP_FIXTURE_DIR"].flatMap { $0.isEmpty ? nil : URL(fileURLWithPath: $0) }
    }

    /// One round through the real manager and probe; the fixture as JSON text.
    private func round(
        scenario: String,
        inputs: IntegrityProbeInputs?,
        keyLevel: KeySecurityLevel,
        appAttest: Bool
    ) async throws -> String {
        let api = FakeAttestationApi()
        let nonce = ServerNonce.make(key: Self.nonceKey, timestampMs: Self.fixtureTime)
        api.enqueue(.json(#"{"nonce":"\#(nonce)","expiresIn":120,"serverTime":\#(Self.fixtureTime)}"#))
        api.enqueue(.json(#"{"result":"pass","arc":"00000000","warnings":[],"token":"eyJ.fixture","tokenTtlSeconds":300,"nextAttestIn":300}"#))

        var appAttestJson = IntegrityJSON.null
        var provider: (any IntegrityVerdictProvider)?
        let service = FakeAppAttestService(appId: Self.appId)
        if appAttest {
            // An earlier round attested the key and the server confirmed it: this round asserts.
            let attestProvider = AppAttestVerdictProvider(service: service, store: { nil }, deviceId: { nil })
            _ = try await attestProvider.verdict(nonce: "earlier-round", deviceId: Self.deviceId, scope: Self.configApiId)
            attestProvider.roundAnswered(scope: Self.configApiId, warnings: [], rejectionReasons: [])
            let keyId = try XCTUnwrap(attestProvider.key(scope: Self.configApiId)?.keyId)
            appAttestJson = .object([
                .init("keyId", .string(keyId)),
                .init("publicKey", .string(try XCTUnwrap(service.publicKeySpki(keyId)))),
                .init("appId", .string(Self.appId)),
            ])
            provider = attestProvider
        }

        let probe = inputs.map {
            DeviceIntegrityProbe(verdictProvider: provider, clock: { Self.fixtureTime }, inputs: $0)
        } ?? DeviceIntegrityProbe(verdictProvider: provider, clock: { Self.fixtureTime })
        let key = TestIdentityKey(level: keyLevel)
        let roundAware = provider as? any AttestationRoundVerdictProvider
        let manager = AttestationManager(
            block: try attestingBlock(Self.configApiId, url: "https://192.168.1.10:6651/"),
            api: api,
            identityKey: { key },
            deviceId: { Self.deviceId },
            currentConfigVersion: { 0 },
            currentIssuedAt: { 0 },
            liveConfig: { nil },
            buildReport: { nonce, deviceId, key in
                await probe.report(nonce: nonce, deviceId: deviceId, scope: Self.configApiId, key: key).jsonString()
            },
            applyConfig: { _ in .alreadyCurrent },
            onVerdict: { roundAware?.roundAnswered(scope: Self.configApiId, warnings: $0, rejectionReasons: $1) },
            clock: { Self.fixtureTime },
            jitter: { 0.5 }
        )
        let status = await manager.attestNow()
        XCTAssertEqual(status.result, .pass, scenario)
        let body = try XCTUnwrap(api.calls.last?.body)
        if appAttest {
            XCTAssertEqual(service.asserted.last?.clientDataHash, AppAttestToken.roundClientDataHash(nonce: nonce, deviceId: Self.deviceId))
        }

        return IntegrityJSON.object([
            .init("scenario", .string(scenario)),
            .init("configApiId", .string(Self.configApiId)),
            .init("nonceKey", .string(Self.nonceKeyText)),
            .init("time", .int(Self.fixtureTime)),
            .init("body", .string(String(decoding: body, as: UTF8.self))),
            .init("appAttest", appAttestJson),
        ]).serialized
    }

    private func write(_ scenario: String, _ text: String) throws {
        try check(text, scenario)
        guard let directory = outputDirectory else { return }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data((text + "\n").utf8).write(to: directory.appendingPathComponent("\(scenario).json"))
    }

    // MARK: The rounds

    func testFixtureOfAGenuineIphoneWithAppAttest() async throws {
        let text = try await round(scenario: "iphone-app-attest", inputs: DeviceIntegrityProbeTests.iPhone(), keyLevel: .secureEnclave, appAttest: true)
        try write("iphone-app-attest", text)
    }

    func testFixtureOfAGenuineIphoneWithoutAppAttest() async throws {
        let text = try await round(scenario: "iphone-plain", inputs: DeviceIntegrityProbeTests.iPhone(), keyLevel: .secureEnclave, appAttest: false)
        try write("iphone-plain", text)
    }

    func testFixtureOfAJailbrokenHookedDebuggedIphone() async throws {
        let profile = ProvisioningProfile(teamIdentifier: "ABCDE12345", applicationIdentifierPrefix: "ABCDE12345",
                                          applicationIdentifier: Self.appId, getTaskAllow: true)
        let inputs = DeviceIntegrityProbeTests.iPhone(
            files: ["/var/jb", "/Applications/Sileo.app"],
            writable: true,
            environment: ["DYLD_INSERT_LIBRARIES": "/var/jb/usr/lib/TweakInject.dylib"],
            traced: true,
            images: ["/usr/lib/libSystem.B.dylib", "/var/jb/usr/lib/frida/frida-agent.dylib"],
            fridaPort: true,
            profile: profile
        )
        let text = try await round(scenario: "iphone-jailbroken", inputs: inputs, keyLevel: .software, appAttest: false)
        try write("iphone-jailbroken", text)
    }

    func testFixtureOfTheSimulator() async throws {
        let inputs = DeviceIntegrityProbeTests.iPhone(
            environment: ["SIMULATOR_DEVICE_NAME": "PinVault-L5"], simulator: true, debug: true, receipt: nil, accessGroup: nil
        )
        let text = try await round(scenario: "simulator", inputs: inputs, keyLevel: .secureEnclave, appAttest: false)
        try write("simulator", text)
    }

    /// The live probe of the machine the tests run on: a Mac, or the simulator.
    func testFixtureOfThisHost() async throws {
        #if targetEnvironment(simulator)
        let scenario = "simulator-live"
        #else
        let scenario = "macos-live"
        #endif
        let text = try await round(scenario: scenario, inputs: nil, keyLevel: .secureEnclave, appAttest: false)
        try write(scenario, text)
    }

    /// The App Attest tokens of both providers with the client data hash each
    /// handed to DeviceCheck: the server parses the tokens and computes the
    /// same hashes (`AppAttestVerifier.parseToken`, `roundClientDataHash`, `enrollmentClientDataHash`).
    func testFixtureOfAppAttestTokens() async throws {
        let service = FakeAppAttestService(appId: Self.appId)
        let provider = AppAttestVerdictProvider(service: service, store: { nil }, deviceId: { nil })
        let nonce = ServerNonce.make(key: Self.nonceKey, timestampMs: Self.fixtureTime)
        let first = try await provider.verdict(nonce: nonce, deviceId: Self.deviceId, scope: Self.configApiId)
        let attestation = try XCTUnwrap(first)
        let attestationHash = try XCTUnwrap(service.attested.last?.clientDataHash)
        provider.roundAnswered(scope: Self.configApiId, warnings: [], rejectionReasons: [])
        let second = try await provider.verdict(nonce: nonce, deviceId: Self.deviceId, scope: Self.configApiId)
        let assertion = try XCTUnwrap(second)
        let assertionHash = try XCTUnwrap(service.asserted.last?.clientDataHash)
        let keyId = try XCTUnwrap(provider.key(scope: Self.configApiId)?.keyId)

        let requestHash = Base64.encodeURL(Hashing.sha256("pinvault-integrity:v1:\(Self.deviceId):csr"))
        XCTAssertEqual(requestHash.count, 43)
        let enrollment = try await AppAttestIntegrityTokenProvider(service: service).token(requestHash: requestHash)
        let enrollmentToken = try XCTUnwrap(enrollment)
        let enrollmentHash = try XCTUnwrap(service.attested.last?.clientDataHash)

        let text = IntegrityJSON.object([
            .init("scenario", .string("app-attest-tokens")),
            .init("nonce", .string(nonce)),
            .init("deviceId", .string(Self.deviceId)),
            .init("appId", .string(Self.appId)),
            .init("keyId", .string(keyId)),
            .init("publicKey", .string(try XCTUnwrap(service.publicKeySpki(keyId)))),
            .init("attestationToken", .string(attestation.token)),
            .init("attestationClientDataHash", .string(Base64.encode(attestationHash))),
            .init("assertionToken", .string(assertion.token)),
            .init("assertionClientDataHash", .string(Base64.encode(assertionHash))),
            .init("requestHash", .string(requestHash)),
            .init("enrollmentToken", .string(enrollmentToken)),
            .init("enrollmentClientDataHash", .string(Base64.encode(enrollmentHash))),
        ]).serialized
        guard let directory = outputDirectory else { return }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data((text + "\n").utf8).write(to: directory.appendingPathComponent("app-attest-tokens.json"))
    }

    // MARK: The committed fixtures

    func testTheCommittedFixturesMatchTheCurrentReportAndVerify() throws {
        let directory = Self.committedDirectory
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            throw XCTSkip("the repository's fixture directory is not readable here (\(directory.path))")
        }
        XCTAssertTrue(names.contains("app-attest-tokens.json"))
        let fixtures = names.filter { $0.hasSuffix(".json") && $0 != "app-attest-tokens.json" }.sorted()
        XCTAssertTrue(Set(fixtures).isSuperset(of: ["iphone-app-attest.json", "iphone-plain.json", "iphone-jailbroken.json", "simulator.json"]), "\(fixtures)")
        for name in fixtures {
            try check(String(decoding: try Data(contentsOf: directory.appendingPathComponent(name)), as: UTF8.self), name)
        }
    }

    /// A fixture's body has the request fields, a report in the current shape,
    /// a nonce the server's key made and a signature the device key made.
    private func check(_ text: String, _ name: String) throws {
        let fixture = try XCTUnwrap(LenientJSON.object(Data(text.utf8)), name)
        let body = try XCTUnwrap(LenientJSON.object(Data(try XCTUnwrap(fixture["body"] as? String).utf8)), name)
        XCTAssertEqual(Set(body.keys), ["v", "nonce", "deviceId", "publicKey", "report", "signature", "currentConfigVersion", "currentIssuedAt"], name)
        let nonce = try XCTUnwrap(body["nonce"] as? String)
        let raw = try XCTUnwrap(Base64.decodeURL(nonce), name)
        XCTAssertEqual(raw.count, 40, name)
        let mac = Data(HMAC<SHA256>.authenticationCode(for: raw.prefix(24), using: SymmetricKey(data: Self.nonceKey))).prefix(16)
        XCTAssertEqual(raw.suffix(16), mac, "\(name): a nonce of the fixture key")

        let report = try XCTUnwrap(body["report"] as? String)
        let json = try XCTUnwrap(LenientJSON.object(Data(report.utf8)), name)
        XCTAssertTrue(Set(json.keys) == Set(DeviceIntegrityProbeTests.topKeys) || Set(json.keys) == Set(DeviceIntegrityProbeTests.topKeys + ["verdictProvider"]), name)
        XCTAssertEqual(Set((json["app"] as? [String: Any])?.keys.map { $0 } ?? []), Set(DeviceIntegrityProbeTests.appKeys), "\(name): regenerate the fixtures")
        XCTAssertEqual(Set((json["device"] as? [String: Any])?.keys.map { $0 } ?? []), Set(DeviceIntegrityProbeTests.deviceKeys), "\(name): regenerate the fixtures")
        XCTAssertEqual(Set((json["signals"] as? [String: Any])?.keys.map { $0 } ?? []), Set(IntegrityReport.signalKeys), name)
        XCTAssertEqual(json["sdkVersion"] as? String, IntegrityReport.sdkVersion, "\(name): regenerate the fixtures")

        let deviceId = try XCTUnwrap(body["deviceId"] as? String)
        let canonical = AttestationManager.canonicalString(nonce: nonce, deviceId: deviceId, report: report)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: XCTUnwrap(Data(base64Encoded: XCTUnwrap(body["publicKey"] as? String))))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Data(base64Encoded: XCTUnwrap(body["signature"] as? String))))
        XCTAssertTrue(publicKey.isValidSignature(signature, for: Data(canonical.utf8)), "\(name): the signature over the canonical string")
    }
}
