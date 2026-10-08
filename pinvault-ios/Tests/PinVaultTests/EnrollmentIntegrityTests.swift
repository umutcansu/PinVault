import XCTest
@testable import PinVault

/// The app's integrity token goes along with the enrollment request, bound to
/// that request's CSR and device id; a provider that gives nothing (or fails)
/// leaves the request as it was; a custom API that predates the token still
/// gets its call (Kotlin `EnrollmentIntegrityTest`).
final class EnrollmentIntegrityTests: XCTestCase {

    private let label = "default"
    private let deviceUid = "a1b2c3d4e5f60718"
    private var store: ClientCertSecureStore!
    private var key: (any ClientIdentityKeyProvider)!

    override func setUpWithError() throws {
        store = try testCertStore(self, strict: true)
        key = ClientIdentityKeys.software(label: uniqueLabel("enroll-int-test"))
    }

    override func tearDown() {
        try? key.clear()
    }

    /// An API that takes the token (`takesIntegrityToken`) or predates it, answering a chain.
    private func api(takesIntegrityToken: Bool = true) -> ScriptedEnrollmentApi {
        let api = ScriptedEnrollmentApi(takesIntegrityToken: takesIntegrityToken)
        for _ in 0..<4 { api.answer(placeholderChain) }
        return api
    }

    @discardableResult
    private func send(
        _ integrity: (any IntegrityTokenProvider)?,
        through api: ScriptedEnrollmentApi,
        deviceId: String? = nil,
        uid: String? = "a1b2c3d4e5f60718"
    ) async throws -> EnrollmentResult {
        let key = self.key!
        return try await EnrollmentRequests.send(
            api: api, certStore: store, key: key, certLabel: label, token: "tok", deviceId: deviceId,
            deviceAlias: "iPhone", deviceUid: uid, integrity: integrity
        ) {
            try key.ensureKeyPair(attestationChallenge: nil)
            return try Pkcs10Csr.encode(commonName: "device", key: key)
        }
    }

    private final class Asked: @unchecked Sendable {
        let hashes = Locked<[String]>([])
    }

    func testTheTokenIsAskedForWithTheRequestHashOfThisCsrAndSentAlong() async throws {
        let api = api()
        let asked = Asked()
        try await send(ClosureIntegrityTokenProvider { hash in
            asked.hashes.withLock { $0.append(hash) }
            return "verdict-for-\(hash)"
        }, through: api)

        let call = try XCTUnwrap(api.calls.first)
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertEqual(call.arity, 8)
        let expected = IntegrityRequestHash.of(deviceId: deviceUid, csrDer: call.csr)
        XCTAssertEqual(asked.hashes.get(), [expected])
        XCTAssertEqual(call.integrityToken, "verdict-for-\(expected)")
    }

    func testWithoutADeviceUidTheHashIsBoundToTheDeviceId() async throws {
        let api = api()
        let asked = Asked()
        try await send(ClosureIntegrityTokenProvider { hash in
            asked.hashes.withLock { $0.append(hash) }
            return "t"
        }, through: api, deviceId: "ios-id-1", uid: nil)
        XCTAssertEqual(asked.hashes.get(), [IntegrityRequestHash.of(deviceId: "ios-id-1", csrDer: api.calls[0].csr)])
    }

    func testNoProviderTheRequestIsSentAsBefore() async throws {
        let api = api()
        try await send(nil, through: api)
        XCTAssertEqual(api.calls.map(\.arity), [7])
    }

    func testAProviderThatGivesNothingOrFailsTheRequestGoesWithoutAToken() async throws {
        let api = api()
        try await send(ClosureIntegrityTokenProvider { _ in nil }, through: api)
        try await send(ClosureIntegrityTokenProvider { _ in "   " }, through: api)
        try await send(ClosureIntegrityTokenProvider { _ in throw PinVaultError.illegalState("App Attest unavailable") }, through: api)
        XCTAssertEqual(api.calls.map(\.arity), [7, 7, 7])
    }

    func testAnApiWrittenBeforeTheTokenStillGetsItsCall() async throws {
        let api = api(takesIntegrityToken: false)
        try await send(ClosureIntegrityTokenProvider { _ in "t" }, through: api)
        XCTAssertEqual(api.calls.map(\.arity), [7])
        XCTAssertNil(api.calls[0].integrityToken)
    }

    func testAnIntegrityRefusalIsAttestationFailedAndDoesNotMakeANewKey() async throws {
        let api = ScriptedEnrollmentApi()
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "integrity_invalid", serverMessage: "device_integrity"))
        let refusal = await expectRefusal("integrity_invalid") {
            try await self.send(ClosureIntegrityTokenProvider { _ in "t" }, through: api)
        }
        XCTAssertEqual(refusal?.refusal, .attestationFailed)
        // One request: a new key would get the same verdict.
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertEqual(api.calls[0].arity, 8)
        XCTAssertEqual(EnrollmentRefusal.from(httpStatus: 403, serverError: "integrity_required"), .attestationFailed)
    }
}
