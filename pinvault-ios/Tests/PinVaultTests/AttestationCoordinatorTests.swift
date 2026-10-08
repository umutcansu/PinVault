import CryptoKit
import XCTest
@testable import PinVault

/// The façade-level attestation flow (Kotlin `PinVault.attestNow`,
/// `fetchAttestationToken`, `attestationStatus`, init and the periodic
/// worker) over `AttestationCoordinator`, with every collaborator injected:
/// per-block APIs, device id, clock, event dispatch, the probe.
final class AttestationCoordinatorTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000

    /// A custom backend: a plain `CertificateConfigApi` without the attest endpoints.
    private struct CustomApi: CertificateConfigApi {
        func healthCheck() async throws -> Bool { true }
        func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { CertificateConfig(pins: []) }
        func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
        func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
        func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
            throw PinVaultError.illegalState("no")
        }
    }

    /// The library's own client: a `CertificateConfigApi` with the attest endpoints.
    private final class OwnApi: CertificateConfigApi, AttestationApi, @unchecked Sendable {
        let attestation = FakeAttestationApi()
        func healthCheck() async throws -> Bool { true }
        func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { CertificateConfig(pins: []) }
        func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
        func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
        func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
            throw PinVaultError.illegalState("no")
        }
        func attestChallenge() async throws -> Data { try await attestation.attestChallenge() }
        func attest(body: Data) async throws -> Data { try await attestation.attest(body: body) }
    }

    private func config() throws -> PinVaultConfig {
        try PinVaultConfig.Builder()
            .configApi("tls", url: "https://config.example.com:8091/") { block in
                block.allowUnpinnedConfigApi().allowUnsigned().attestation().tokenHosts("api.example.com")
            }
            .configApi("mtls", url: "https://config.example.com:8092/") { block in
                block.allowUnpinnedConfigApi().allowUnsigned().attestation().tokenHosts("*.cdn.example.com", "files.example.com:8443")
            }
            .configApi("custom", url: "https://custom.example.com/") { block in
                block.allowUnpinnedConfigApi().allowUnsigned().attestation()
            }
            .configApi("plain", url: "https://plain.example.com/") { block in
                block.allowUnpinnedConfigApi().allowUnsigned()
            }
            .expectedBundleId("com.example.sampleclient")
            .build()
    }

    private struct Setup {
        let coordinator: AttestationCoordinator
        let apis: [String: OwnApi]
        let events: AttestCollector<PinVaultConnectionEvent>
        let keys: [String: TestIdentityKey]
    }

    private func setup(probe: DeviceIntegrityProbe? = nil, deviceId: String? = "device-07") throws -> Setup {
        let apis = ["tls": OwnApi(), "mtls": OwnApi()]
        let keys = ["tls": TestIdentityKey(level: .secureEnclave), "mtls": TestIdentityKey(level: .secureEnclave), "custom": TestIdentityKey()]
        let events = AttestCollector<PinVaultConnectionEvent>()
        let now = self.now
        let coordinator = AttestationCoordinator(
            config: try config(),
            api: { block -> (any CertificateConfigApi)? in
                if block.id == "custom" { return CustomApi() }
                return apis[block.id]
            },
            identityKey: { block in keys[block.id]! },
            deviceId: { deviceId },
            clock: { now },
            onEvent: { events.append($0) },
            currentConfigVersion: { _ in 3 },
            currentIssuedAt: { _ in 42 },
            liveConfig: { _ in nil },
            applyConfig: { _, _ in .alreadyCurrent },
            probe: probe ?? DeviceIntegrityProbe(
                expectedBundleIds: ["com.example.sampleclient"],
                clock: { now },
                inputs: DeviceIntegrityProbeTests.iPhone()
            ),
            jitter: { 0.5 },
            sleep: { _ in try await Task.sleep(nanoseconds: 60_000_000_000) }
        )
        return Setup(coordinator: coordinator, apis: apis, events: events, keys: keys)
    }

    private func enqueuePass(_ api: OwnApi, token: String) {
        api.attestation.enqueue(.json(#"{"nonce":"nonce-\#(token)","serverTime":\#(now)}"#))
        api.attestation.enqueue(.json(#"{"result":"pass","arc":"7f3a9c1e","warnings":[],"token":"\#(token)","tokenTtlSeconds":300,"nextAttestIn":300,"policyVersion":1}"#))
    }

    func testOnlyBlocksWithAttestationGetAManagerAndACustomApiIsUnsupported() throws {
        let s = try setup()
        XCTAssertEqual(s.coordinator.managers.map(\.block.id), ["tls", "mtls", "custom"])
        XCTAssertTrue(s.coordinator.manager("tls")?.supported == true)
        XCTAssertTrue(s.coordinator.manager("custom")?.supported == false)
        XCTAssertNil(s.coordinator.manager("plain"))
        XCTAssertEqual(s.coordinator.tokenSources.count, 3)
        XCTAssertNotNil(s.coordinator.tokenInterceptor())

        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: nil).result, .notAttested, "the default block")
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "custom").result, .unsupported)
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "custom").lastError, AttestationManager.unsupportedReason)
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "plain").lastError, "Config API 'plain' does not attest: call attestation() on the block")
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "nope").lastError, "No Config API block 'nope'")
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "nope").result, .unsupported)
    }

    func testAttestNowRunsTheRoundOfTheNamedOrDefaultBlockWithTheProbesReport() async throws {
        let s = try setup()
        enqueuePass(s.apis["tls"]!, token: "eyJ.tls")

        let status = await s.coordinator.attestNow(configApiId: nil)
        XCTAssertEqual(status.result, .pass)
        XCTAssertEqual(status.configApiId, "tls")
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "tls"), status)

        // The body carries the probe's report, signed by the block's key over the canonical string.
        let body = try XCTUnwrap(s.apis["tls"]!.attestation.attestBodies.first)
        XCTAssertEqual(body["deviceId"] as? String, "device-07")
        XCTAssertEqual(body["currentConfigVersion"] as? Int, 3)
        XCTAssertEqual((body["currentIssuedAt"] as? NSNumber)?.int64Value, 42)
        let report = try XCTUnwrap(body["report"] as? String)
        let reportJson = try XCTUnwrap(LenientJSON.object(Data(report.utf8)))
        XCTAssertEqual((reportJson["device"] as? [String: Any])?["platform"] as? String, "ios")
        XCTAssertEqual((reportJson["device"] as? [String: Any])?["keySecurityLevel"] as? String, "secure_enclave")
        XCTAssertEqual((reportJson["app"] as? [String: Any])?["bundleId"] as? String, "com.example.sampleclient")
        let canonical = AttestationManager.canonicalString(nonce: "nonce-eyJ.tls", deviceId: "device-07", report: report)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Data(base64Encoded: XCTUnwrap(body["signature"] as? String))))
        XCTAssertTrue(try s.keys["tls"]!.signingKey.publicKey.isValidSignature(signature, for: Data(canonical.utf8)))

        guard case let .attestation(id, eventStatus, _, _, _, _, _, _, _)? = s.events.values.first else { return XCTFail("no event") }
        XCTAssertEqual(id, "tls")
        XCTAssertEqual(eventStatus, .pass)

        let custom = await s.coordinator.attestNow(configApiId: "custom")
        XCTAssertEqual(custom.result, .unsupported)
        let plain = await s.coordinator.attestNow(configApiId: "plain")
        XCTAssertEqual(plain.result, .unsupported)
        XCTAssertEqual(s.events.count, 1, "nothing attested for those")
    }

    func testFetchAttestationTokenPicksTheBlockWhoseTokenHostsCoverTheHost() async throws {
        let s = try setup()
        enqueuePass(s.apis["tls"]!, token: "eyJ.tls")
        enqueuePass(s.apis["mtls"]!, token: "eyJ.mtls")

        let tls = await s.coordinator.fetchAttestationToken(host: "api.example.com")
        XCTAssertEqual(tls, .token(value: "eyJ.tls", expiresAt: now + 300_000))
        let mtls = await s.coordinator.fetchAttestationToken(host: "img.cdn.example.com")
        XCTAssertEqual(mtls, .token(value: "eyJ.mtls", expiresAt: now + 300_000))
        let byPort = await s.coordinator.fetchAttestationToken(host: "files.example.com:8443")
        XCTAssertEqual(byPort, .token(value: "eyJ.mtls", expiresAt: now + 300_000), "a host:port token host")
        let otherPort = await s.coordinator.fetchAttestationToken(host: "files.example.com:443")
        XCTAssertEqual(otherPort, .unsupported)
        let nobody = await s.coordinator.fetchAttestationToken(host: "elsewhere.example.org")
        XCTAssertEqual(nobody, .unsupported)
        let defaultBlock = await s.coordinator.fetchAttestationToken(host: nil)
        XCTAssertEqual(defaultBlock, .token(value: "eyJ.tls", expiresAt: now + 300_000), "nil = the default block")
        XCTAssertEqual(s.apis["tls"]!.attestation.attestBodies.count, 1, "the held token is reused")
    }

    func testAttestAtStartAttestsEveryBlockAndStartsTheirLoopsAndResetStopsThem() async throws {
        let s = try setup()
        enqueuePass(s.apis["tls"]!, token: "eyJ.tls")
        s.apis["mtls"]!.attestation.enqueue(.json(#"{"nonce":"n"}"#))
        s.apis["mtls"]!.attestation.enqueue(.json(#"{"result":"reject","arc":"0badbeef","rejectionReasons":["rooted"],"nextAttestIn":300}"#))

        await s.coordinator.attestAtStart()

        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "tls").result, .pass)
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "mtls").result, .reject, "a reject never fails start")
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "custom").result, .unsupported)
        XCTAssertTrue(s.coordinator.manager("tls")!.isRunning)
        XCTAssertTrue(s.coordinator.manager("mtls")!.isRunning)
        XCTAssertFalse(s.coordinator.manager("custom")!.isRunning)

        s.coordinator.stopAll()
        XCTAssertFalse(s.coordinator.manager("tls")!.isRunning)
        s.coordinator.resetAll()
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "tls").result, .notAttested)
        XCTAssertEqual(s.coordinator.attestationStatus(configApiId: "custom").result, .unsupported)
    }

    func testTheAppAttestProviderHearsTheVerdictOfItsBlock() async throws {
        let service = FakeAppAttestService()
        let store = InMemoryPreferences()
        let provider = AppAttestVerdictProvider(service: service, store: { store }, deviceId: { nil })
        let probe = DeviceIntegrityProbe(verdictProvider: provider, clock: { 1 }, inputs: DeviceIntegrityProbeTests.iPhone())
        let s = try setup(probe: probe)

        enqueuePass(s.apis["tls"]!, token: "eyJ.1")
        _ = await s.coordinator.attestNow(configApiId: "tls")
        XCTAssertEqual(provider.key(scope: "tls")?.state, .confirmed, "the pass confirmed the attestation")
        // v2: the token travels beside the report and its hash covers the report.
        let firstBody = s.apis["tls"]!.attestation.attestBodies[0]
        XCTAssertFalse(try XCTUnwrap(firstBody["report"] as? String).contains("verdictProvider"))
        let firstToken = try XCTUnwrap((firstBody["verdictProvider"] as? [String: Any])?["token"] as? String)
        XCTAssertTrue(firstToken.contains(#""attestation":"#))
        XCTAssertEqual(service.attested.last?.clientDataHash, try Self.roundHashV2(firstBody))

        // The server does not know the key: it says so in the warnings, the provider starts over.
        s.apis["tls"]!.attestation.enqueue(.json(#"{"nonce":"nonce-2"}"#))
        s.apis["tls"]!.attestation.enqueue(.json(#"{"result":"pass","warnings":["app_attest","app_attest_unknown_key"],"token":"eyJ.2","tokenTtlSeconds":300}"#))
        _ = await s.coordinator.attestNow(configApiId: "tls")
        let second = s.apis["tls"]!.attestation.attestBodies[1]
        XCTAssertTrue(try XCTUnwrap((second["verdictProvider"] as? [String: Any])?["token"] as? String).contains(#""assertion":"#))
        XCTAssertEqual(service.asserted.last?.clientDataHash, try Self.roundHashV2(second))
        XCTAssertNil(provider.key(scope: "tls"))
        XCTAssertNil(provider.key(scope: "mtls"), "another block's key is its own")
    }

    func testAServerThatWantsTheKeyRegisteredGetsAFreshAppAttestAttestationNextRound() async throws {
        let service = FakeAppAttestService()
        let store = InMemoryPreferences()
        let provider = AppAttestVerdictProvider(service: service, store: { store }, deviceId: { nil })
        let probe = DeviceIntegrityProbe(verdictProvider: provider, clock: { 1 }, inputs: DeviceIntegrityProbeTests.iPhone())
        let s = try setup(probe: probe)
        let api = s.apis["tls"]!.attestation

        enqueuePass(s.apis["tls"]!, token: "eyJ.1")
        _ = await s.coordinator.attestNow(configApiId: "tls")
        let firstKey = try XCTUnwrap(provider.key(scope: "tls"))
        XCTAssertEqual(firstKey.state, .confirmed)

        // The server forgot the device and registers keys only with an attestation (ATTESTATION_KEY_POLICY=enforce).
        api.enqueue(.json(#"{"nonce":"nonce-2"}"#))
        api.enqueue(.http(403, #"{"error":"attestation_required","message":"This server registers only attested keys."}"#))
        let refused = await s.coordinator.attestNow(configApiId: "tls")
        XCTAssertEqual(refused.result, .failed)
        XCTAssertNil(provider.key(scope: "tls"), "the asserting key is dropped")

        // The next round's report carries a new key's attestation, made for that round.
        enqueuePass(s.apis["tls"]!, token: "eyJ.3")
        _ = await s.coordinator.attestNow(configApiId: "tls")
        let body = try XCTUnwrap(api.attestBodies.last)
        let token = try XCTUnwrap(LenientJSON.object(Data(try XCTUnwrap((body["verdictProvider"] as? [String: Any])?["token"] as? String).utf8)))
        XCTAssertNotNil(token["attestation"])
        XCTAssertNotEqual(token["keyId"] as? String, firstKey.keyId)
        XCTAssertEqual(service.attested.last?.clientDataHash, try Self.roundHashV2(body))
    }

    func testOtherRefusalsKeepTheAppAttestKey() async throws {
        let service = FakeAppAttestService()
        let store = InMemoryPreferences()
        let provider = AppAttestVerdictProvider(service: service, store: { store }, deviceId: { nil })
        let probe = DeviceIntegrityProbe(verdictProvider: provider, clock: { 1 }, inputs: DeviceIntegrityProbeTests.iPhone())
        let s = try setup(probe: probe)
        enqueuePass(s.apis["tls"]!, token: "eyJ.1")
        _ = await s.coordinator.attestNow(configApiId: "tls")
        let api = s.apis["tls"]!.attestation
        api.enqueue(.json(#"{"nonce":"nonce-2"}"#))
        api.enqueue(.http(400, #"{"error":"nonce_expired"}"#))
        _ = await s.coordinator.attestNow(configApiId: "tls")
        XCTAssertEqual(provider.key(scope: "tls")?.state, .confirmed)
    }

    func testNoAttestingBlockMeansNoInterceptorAndNoProbe() throws {
        let config = try PinVaultConfig.Builder()
            .configApi("plain", url: "https://plain.example.com/") { $0.allowUnpinnedConfigApi().allowUnsigned() }
            .build()
        let coordinator = AttestationCoordinator(
            config: config, api: { _ in nil }, identityKey: { _ in TestIdentityKey() }, deviceId: { nil }, clock: { 0 },
            onEvent: { _ in }, currentConfigVersion: { _ in 0 }, currentIssuedAt: { _ in 0 }, liveConfig: { _ in nil },
            applyConfig: { _, _ in .alreadyCurrent }
        )
        XCTAssertTrue(coordinator.managers.isEmpty)
        XCTAssertNil(coordinator.tokenInterceptor())
        XCTAssertEqual(coordinator.attestationStatus(configApiId: nil).result, .unsupported)
    }

    func testTheDefaultProbeUsesTheAppsProviderOrAppAttest() throws {
        let custom = RecordingVerdictProvider()
        let withProvider = try PinVaultConfig.Builder()
            .configApi("a", url: "https://a.example.com/") { $0.allowUnpinnedConfigApi().allowUnsigned().attestation() }
            .integrityVerdictProvider(custom)
            .build()
        XCTAssertTrue(DeviceIntegrityProbe.forConfig(withProvider).verdictProvider as AnyObject === custom)
        let without = try PinVaultConfig.Builder()
            .configApi("a", url: "https://a.example.com/") { $0.allowUnpinnedConfigApi().allowUnsigned().attestation() }
            .build()
        XCTAssertTrue(DeviceIntegrityProbe.forConfig(without).verdictProvider is AppAttestVerdictProvider)
    }

    /// The v2 client data hash of an attest request body: over its canonical string.
    static func roundHashV2(_ body: [String: Any]) throws -> Data {
        let canonical = AttestationManager.canonicalString(
            nonce: try XCTUnwrap(body["nonce"] as? String),
            deviceId: try XCTUnwrap(body["deviceId"] as? String),
            report: try XCTUnwrap(body["report"] as? String)
        )
        return AppAttestToken.roundClientDataHashV2(canonical: canonical)
    }
}
