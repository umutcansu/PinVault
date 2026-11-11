import Foundation
import XCTest
@testable import PinVault

/// Port of SignedConfigViewBindingTest. M6: a signed config is bound to the
/// request it answers (`view` inside the payload). Whoever can answer as the
/// Config API without the signing key holds genuine, fresh, signed narrow
/// views — of another request, another device — and must not be able to make
/// them stick.
final class SignedConfigViewBindingTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private let pin1 = pin("A"), pin2 = pin("B")
    private let key = TestSigner()

    /// A custom backend (SignedConfigSource): the check is on the payload, not on the transport.
    private final class Api: CertificateConfigApi, SignedConfigSource, @unchecked Sendable {
        struct Request: Equatable {
            let hosts: [String]?
            let deviceId: String?
        }

        private let lock = NSLock()
        private var _next: SignedConfigResponse?
        private var _offline = false
        private var _requests: [Request] = []

        var next: SignedConfigResponse? {
            get { lock.withLock { _next } }
            set { lock.withLock { _next = newValue } }
        }
        var offline: Bool {
            get { lock.withLock { _offline } }
            set { lock.withLock { _offline = newValue } }
        }
        var requests: [Request] { lock.withLock { _requests } }

        private func answer(_ request: Request) throws -> SignedConfigResponse {
            let (offline, next) = lock.withLock { () -> (Bool, SignedConfigResponse?) in
                _requests.append(request)
                return (_offline, _next)
            }
            if offline { throw PinVaultError.io(message: "offline") }
            return next!
        }

        func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse {
            try answer(Request(hosts: nil, deviceId: nil))
        }

        func fetchScopedSignedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> SignedConfigResponse {
            try answer(Request(hosts: hosts, deviceId: deviceId))
        }

        func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
            throw PinVaultError.illegalState("signed block")
        }

        func healthCheck() async throws -> Bool { true }
        func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
        func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
        func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
            EnrollmentResult(p12Bytes: Data())
        }
    }

    private var store: CertificateConfigStore!
    private var api: Api!
    private var provider: HttpClientProvider!

    override func setUp() {
        store = CertificateConfigStore(prefs: InMemoryPreferences())
        let now = self.now
        store.clock = { now }
        api = Api()
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    private func updater(wantPinsFor: [String] = [], deviceId: String? = "dev-1") -> SSLCertificateUpdater {
        let now = self.now
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [key.pub], builtInThreshold: 1,
                                   recoveryKeys: [], recoveryThreshold: 1, store: nil)
        return SSLCertificateUpdater(
            configApi: api, configStore: store, httpClientProvider: provider, maxRetryCount: 1,
            wantPinsFor: wantPinsFor, deviceIdProvider: { deviceId }, clock: { now },
            verifier: SignedConfigVerifier(trust: trust, clock: { now }), sleep: { _ in }
        )
    }

    /// A payload as the server writes it: `view` last, absent for the full config.
    private func payload(_ issuedAt: Int64, _ hosts: [String], version: Int = 1, view: String? = nil) -> String {
        var text = signedPayload(
            version: version, issuedAt: issuedAt, expiresAt: issuedAt + hour,
            pins: [pin1, pin2], hosts: hosts.map { ($0, version) }, scope: "default-tls"
        )
        if let view {
            text.removeLast()
            text += #","view":"# + view + "}"
        }
        return text
    }

    private func view(_ hosts: String..., deviceId: String? = "dev-1", extra: [(String, String)] = []) -> String {
        var members = [("hosts", JSONText.array(hosts.map(JSONText.string)))]
        if let deviceId { members.append(("deviceId", JSONText.string(deviceId))) }
        return JSONText.object(members + extra)
    }

    private func signed(_ payload: String) -> SignedConfigResponse {
        SignedConfigResponse(payload: payload, signature: key.sign(payload), keyId: key.id)
    }

    private func serve(_ payload: String, with updater: SSLCertificateUpdater) async -> UpdateResult {
        api.next = signed(payload)
        api.offline = false
        return await updater.updateNow()
    }

    private func newProcess() {
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    private func storedHosts() throws -> Set<String>? { try store.load().map { Set($0.pins.map(\.hostname)) } }
    private func activeHosts() -> Set<String>? { provider.currentConfig.map { Set($0.pins.map(\.hostname)) } }

    private func assertRefused(_ result: UpdateResult, file: StaticString = #filePath, line: UInt = #line) {
        guard case .failed(let reason, let exception) = result else {
            return XCTFail("expected a refusal, got \(result)", file: file, line: line)
        }
        guard case .configViewMismatch? = exception as? PinVaultError else {
            return XCTFail("typed refusal, got \(String(describing: exception))", file: file, line: line)
        }
        XCTAssertTrue(reason.contains("Signed config rejected"), reason, file: file, line: line)
    }

    // MARK: The attack: a full-config device handed a genuine narrow view

    func testAFullConfigBlockRefusesANewerGenuineNarrowedEnvelopeStoredConfigAndPinsUnchanged() async throws {
        let full = updater()
        let first = await serve(payload(now - 10, ["a.test", "b.test"]), with: full)
        XCTAssertEqual(first, .updated(newVersion: 1))
        let envelopeBefore = try XCTUnwrap(try store.loadEnvelope()).payload

        // Newer, genuinely signed, fresh — but the answer to someone else's `?hosts=a.test`.
        let narrow = payload(now, ["a.test"], version: 2, view: view("a.test"))
        assertRefused(await serve(narrow, with: full))

        XCTAssertEqual(try storedHosts(), ["a.test", "b.test"])
        XCTAssertEqual(activeHosts(), ["a.test", "b.test"])
        XCTAssertEqual(try store.loadEnvelope()?.payload, envelopeBefore)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - 10)
        XCTAssertEqual(try store.getVersionWatermarks()["a.test"] ?? 1, 1, "the refused version 2 left no watermark")
        // The full request was made: no hosts, no device id.
        XCTAssertEqual(api.requests.last, Api.Request(hosts: nil, deviceId: nil))
    }

    func testANarrowedViewWithTheVerySamePinsIsRefusedTooNeverAlreadyCurrent() async throws {
        let full = updater()
        _ = await serve(payload(now - 10, ["a.test", "b.test"]), with: full)
        assertRefused(await serve(payload(now, ["a.test", "b.test"], view: view("a.test", "b.test")), with: full))
        // The same issuedAt as the stored config, the same pins: still not "the same config served again".
        assertRefused(await serve(payload(now - 10, ["a.test", "b.test"], view: view("a.test", "b.test")), with: full))
        // Only a device-id view, no host list: still narrowed by an ACL.
        assertRefused(await serve(payload(now + 1, ["a.test", "b.test"], view: #"{"deviceId":"dev-1"}"#), with: full))
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - 10)
    }

    func testAFullConfigBlockRefusesANarrowedViewOnItsVeryFirstFetch() async throws {
        assertRefused(await serve(payload(now, ["a.test"], view: view("a.test")), with: updater()))
        XCTAssertNil(try store.load())
        XCTAssertNil(provider.currentConfig)
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
    }

    // MARK: A scoped block

    func testAScopedBlockAcceptsItsOwnViewWhateverTheSpellingOfItsWantPinsFor() async throws {
        let scoped = updater(wantPinsFor: ["B.test", "a.test", "b.test "])
        let result = await serve(payload(now, ["a.test", "b.test"], view: view("a.test", "b.test")), with: scoped)
        XCTAssertEqual(result, .updated(newVersion: 1))
        XCTAssertEqual(api.requests.last, Api.Request(hosts: ["B.test", "a.test", "b.test "], deviceId: "dev-1"))
    }

    func testAScopedBlockRefusesAnotherSetsViewAnotherDevicesViewAndMalformedViews() async throws {
        let scoped = updater(wantPinsFor: ["a.test", "b.test"])
        let first = await serve(payload(now - 100, ["a.test", "b.test"], view: view("a.test", "b.test")), with: scoped)
        XCTAssertEqual(first, .updated(newVersion: 1))

        // Another host set.
        assertRefused(await serve(payload(now - 90, ["a.test"], view: view("a.test")), with: scoped))
        // Another device.
        assertRefused(await serve(payload(now - 80, ["a.test"], view: view("a.test", "b.test", deviceId: "dev-2")), with: scoped))
        // No device id where this block sent one.
        assertRefused(await serve(payload(now - 70, ["a.test"], view: view("a.test", "b.test", deviceId: nil)), with: scoped))
        // Not canonical (order) = not what this server writes for this request.
        assertRefused(await serve(payload(now - 60, ["a.test"], view: view("b.test", "a.test")), with: scoped))
        // A narrowing this client does not understand.
        assertRefused(await serve(payload(now - 50, ["a.test"], view: view("a.test", "b.test", extra: [("aclVersion", "3")])), with: scoped))
        // Malformed.
        assertRefused(await serve(payload(now - 40, ["a.test"], view: #"{"hosts":"a.test,b.test","deviceId":"dev-1"}"#), with: scoped))
        assertRefused(await serve(payload(now - 30, ["a.test"], view: #""a.test""#), with: scoped))

        XCTAssertEqual(try storedHosts(), ["a.test", "b.test"])
        XCTAssertEqual(activeHosts(), ["a.test", "b.test"])
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - 100)
    }

    func testAScopedBlockWithoutADeviceIdRefusesAViewThatNamesOne() async throws {
        let scoped = updater(wantPinsFor: ["a.test"], deviceId: nil)
        assertRefused(await serve(payload(now, ["a.test"], view: view("a.test", deviceId: "dev-1")), with: scoped))
        let own = await serve(payload(now + 1, ["a.test"], view: view("a.test", deviceId: nil)), with: scoped)
        XCTAssertEqual(own, .updated(newVersion: 1))
        XCTAssertEqual(api.requests.last, Api.Request(hosts: ["a.test"], deviceId: nil))
    }

    func testAScopedBlockAcceptsAPayloadWithoutViewAFullViewOrAServerBefore290() async throws {
        let scoped = updater(wantPinsFor: ["a.test"])
        let result = await serve(payload(now, ["a.test", "b.test"]), with: scoped)
        XCTAssertEqual(result, .updated(newVersion: 1))
        XCTAssertEqual(try storedHosts(), ["a.test", "b.test"])
    }

    // MARK: The stored envelope, re-verified at every load

    func testWantPinsForGrownInAnAppUpdateTheStoredViewIsDiscardedAndFetchedAgain() async throws {
        _ = await serve(payload(now - 10, ["a.test"], view: view("a.test")), with: updater(wantPinsFor: ["a.test"]))

        // Same list, offline: the stored view still answers the request, the app starts.
        newProcess()
        api.offline = true
        let offline = try await updater(wantPinsFor: ["a.test"]).initializeAndUpdate()
        XCTAssertEqual(offline, .ready(version: 1))

        // New release asks for one more host, online: discarded, fetched again, ready.
        newProcess()
        api.next = signed(payload(now, ["a.test", "b.test"], view: view("a.test", "b.test")))
        api.offline = false
        let online = try await updater(wantPinsFor: ["a.test", "b.test"]).initializeAndUpdate()
        XCTAssertEqual(online, .ready(version: 1))
        XCTAssertEqual(try storedHosts(), ["a.test", "b.test"])
        XCTAssertEqual(activeHosts(), ["a.test", "b.test"])
        XCTAssertEqual(api.requests.last, Api.Request(hosts: ["a.test", "b.test"], deviceId: "dev-1"))
    }

    func testWantPinsForChangedAndOfflineNoUsableConfigTheWatermarksStay() async throws {
        _ = await serve(payload(now - 10, ["a.test"], version: 4, view: view("a.test")), with: updater(wantPinsFor: ["a.test"]))

        newProcess()
        api.offline = true
        let result = try await updater(wantPinsFor: ["a.test", "b.test"]).initializeAndUpdate()
        guard case .failed(let reason, let exception) = result else { return XCTFail("expected failed, got \(result)") }
        guard case .noConfigAvailable? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
        XCTAssertTrue(reason.contains("another host set or device"), reason)
        XCTAssertNil(provider.currentConfig)
        XCTAssertNil(try store.load())
        // A genuine config once accepted: its issuedAt and versions stay as the replay watermarks.
        XCTAssertEqual(try store.getCurrentIssuedAt(), now - 10)
        XCTAssertEqual(try store.getVersionWatermarks()["a.test"], 4)
    }

    func testAStoredNarrowedViewIsDiscardedByABlockThatNowAsksForTheFullConfig() async throws {
        _ = await serve(payload(now - 10, ["a.test"], view: view("a.test")), with: updater(wantPinsFor: ["a.test"]))
        newProcess()
        api.next = signed(payload(now, ["a.test", "b.test"]))
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 1))
        XCTAssertEqual(try storedHosts(), ["a.test", "b.test"])
    }

    func testAStoredFullConfigStillStartsABlockThatBecameScoped() async throws {
        _ = await serve(payload(now - 10, ["a.test", "b.test"]), with: updater())
        newProcess()
        api.offline = true
        let started = try await updater(wantPinsFor: ["a.test"]).initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 1))
    }

    // MARK: The config inside an attestation answer

    func testApplySignedAFullBlockRefusesANarrowedEmbeddedConfig() async throws {
        let full = updater()
        assertRefused(await full.applySigned(signed(payload(now, ["a.test"], view: view("a.test"))), requestDeviceId: "dev-1"))
        assertRefused(await full.applySigned(signed(payload(now, ["a.test"], view: view("a.test")))))
        XCTAssertNil(try store.load())
        // Its own (full) config is taken.
        let own = await full.applySigned(signed(payload(now, ["a.test", "b.test"])), requestDeviceId: "dev-1")
        XCTAssertEqual(own, .updated(newVersion: 1))
        XCTAssertEqual(api.requests, [], "no fetch: the config came in the attestation answer")
    }

    func testApplySignedAScopedBlockTakesTheViewForTheDeviceIdItsAttestationRequestNamed() async throws {
        let scoped = updater(wantPinsFor: ["a.test"], deviceId: nil)
        // The attestation request named "unknown-device" (no usable device id): the view answers that.
        let embedded = signed(payload(now, ["a.test"], view: view("a.test", deviceId: AttestationManager.unknownDeviceId)))
        let first = await scoped.applySigned(embedded, requestDeviceId: AttestationManager.unknownDeviceId)
        XCTAssertEqual(first, .updated(newVersion: 1))
        // Another device's embedded view is refused, the config in use stays.
        let other = signed(payload(now + 1, ["a.test"], version: 2, view: view("a.test", deviceId: "dev-9")))
        assertRefused(await scoped.applySigned(other, requestDeviceId: AttestationManager.unknownDeviceId))
        // As is a view of another host set.
        let otherSet = signed(payload(now + 2, ["a.test"], version: 2, view: view("a.test", "b.test", deviceId: AttestationManager.unknownDeviceId)))
        assertRefused(await scoped.applySigned(otherSet, requestDeviceId: AttestationManager.unknownDeviceId))
        XCTAssertEqual(provider.currentConfig?.pins.first?.version, 1)

        // And the stored attestation view starts the app offline (the attestation form of "no id").
        newProcess()
        api.offline = true
        let started = try await updater(wantPinsFor: ["a.test"], deviceId: nil).initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 1))
    }

    func testApplySignedWithoutARequestDeviceIdChecksAgainstTheFetchDeviceId() async throws {
        let scoped = updater(wantPinsFor: ["a.test"], deviceId: "dev-1")
        let mine = await scoped.applySigned(signed(payload(now, ["a.test"], view: view("a.test", deviceId: "dev-1"))))
        XCTAssertEqual(mine, .updated(newVersion: 1))
        assertRefused(await scoped.applySigned(signed(payload(now + 1, ["a.test"], version: 2, view: view("a.test", deviceId: "dev-2")))))
    }
}
