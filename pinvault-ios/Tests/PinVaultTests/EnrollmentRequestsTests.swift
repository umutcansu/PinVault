import XCTest
@testable import PinVault

/// A device told to wait for approval: the request id is remembered and sent
/// back with a CSR from the same key; a request that is over is forgotten
/// together with its key (Kotlin `EnrollmentRequestsTest`).
final class EnrollmentRequestsTests: XCTestCase {

    private let label = "default"
    private var store: ClientCertSecureStore!
    private var key: (any ClientIdentityKeyProvider)!
    private var api: ScriptedEnrollmentApi!

    override func setUpWithError() throws {
        store = try testCertStore(self, strict: true)
        key = ClientIdentityKeys.software(label: uniqueLabel("enroll-req-test"))
        api = ScriptedEnrollmentApi(takesIntegrityToken: false)
    }

    override func tearDown() {
        try? key.clear()
    }

    /// The SPKI pin of the key each call was signed with.
    private func spki(_ call: ScriptedEnrollmentApi.Call) throws -> String {
        SPKI.pin(try ParsedCsr(call.csr).spki)
    }

    private func send(_ token: String?, deviceId: String? = nil) async throws -> EnrollmentResult {
        let key = self.key!
        return try await EnrollmentRequests.send(
            api: api, certStore: store, key: key, certLabel: label, token: token, deviceId: deviceId,
            deviceAlias: "iPhone", deviceUid: "uid-1"
        ) {
            try key.ensureKeyPair()
            return try Pkcs10Csr.encode(commonName: "device", key: key)
        }
    }

    func testAWaitIsRememberedAndTheNextAttemptAsksByItsRequestIdWithTheSameKey() async throws {
        api.answer(throwing: .enrollmentPending(requestId: "r1", clientId: "field-x", retryAfterSeconds: 15))
        api.answer(placeholderChain)

        let pending = await expectPending { try await self.send("K7QM2-XRT9V-4NWDP-J6E8B-HC3MA") }
        XCTAssertEqual(pending?.requestId, "r1")
        XCTAssertEqual(try store.loadPendingRequest(label), .init(requestId: "r1", clientId: "field-x"))
        XCTAssertTrue(key.exists())

        let answer = try await send(nil)
        XCTAssertEqual(answer, placeholderChain)
        let calls = api.calls
        XCTAssertEqual(calls[0].token, "K7QM2-XRT9V-4NWDP-J6E8B-HC3MA")
        XCTAssertNil(calls[0].requestId)
        XCTAssertEqual(calls[1].requestId, "r1")
        XCTAssertNil(calls[1].token)
        XCTAssertEqual(try spki(calls[0]), try spki(calls[1]), "the same key asks again")

        // Storing the credential forgets the wait.
        try store.saveChain(label, pemChain: placeholderChain.certificateChainPem!)
        XCTAssertNil(try store.loadPendingRequest(label))
    }

    func testAWaitComesBackWithTheCodeOfThisDevicesKey() async throws {
        api.answer(throwing: .enrollmentPending(requestId: "r1", clientId: "device-x"))
        let pending = await expectPending { try await self.send(nil, deviceId: "ios-1") }
        XCTAssertEqual(pending?.code, try VerificationCode.of(publicKey: key.publicKey()))
    }

    func testACodeInTheAnswerGivesWayToTheOneFromThisDevicesKey() async throws {
        api.answer(throwing: .enrollmentPending(requestId: "r1", clientId: "device-x", verificationCode: "0000-0000"))
        let pending = await expectPending { try await self.send(nil, deviceId: "ios-1") }
        XCTAssertEqual(pending?.code, try VerificationCode.of(publicKey: key.publicKey()))
    }

    func testALapsedCodelessRequestIsForgottenWithItsKeyAndTheDeviceAsksAgainAtOnce() async throws {
        try store.savePendingRequest(label, requestId: "r1", clientId: "device-x")
        api.answer(throwing: .enrollmentRefused(httpStatus: 410, serverError: "enrollment_request_expired"))
        api.answer(throwing: .enrollmentPending(requestId: "r2", clientId: "device-y"))

        let pending = await expectPending { try await self.send(nil, deviceId: "ios-1") }
        XCTAssertEqual(pending?.requestId, "r2")
        let calls = api.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].requestId, "r1")
        XCTAssertNil(calls[1].requestId)
        XCTAssertNotEqual(try spki(calls[0]), try spki(calls[1]), "a new key for the new request")
        XCTAssertEqual(try store.loadPendingRequest(label)?.requestId, "r2")
    }

    func testALapsedRequestWithNoWayToAskAgainJustEnds() async throws {
        try key.ensureKeyPair()
        try store.savePendingRequest(label, requestId: "r1", clientId: nil)
        api.answer(throwing: .enrollmentRefused(httpStatus: 410, serverError: "enrollment_request_expired"))

        let refusal = await expectRefusal("enrollment_request_expired") { try await self.send(nil) }
        XCTAssertEqual(refusal?.refusal, .expired)
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertNil(try store.loadPendingRequest(label))
        XCTAssertFalse(key.exists())
    }

    func testARejectedRequestIsForgottenTogetherWithItsKey() async throws {
        try key.ensureKeyPair()
        try store.savePendingRequest(label, requestId: "r1", clientId: "field-x")
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "enrollment_rejected"))

        let refusal = await expectRefusal("enrollment_rejected") { try await self.send(nil) }
        XCTAssertEqual(refusal?.refusal, .rejected)
        XCTAssertNil(try store.loadPendingRequest(label))
        XCTAssertFalse(key.exists(), "the next attempt is a new request over a new key")
    }

    func testARequestTheServerNoLongerKnowsStartsOverAtOnceWhenACodeIsAtHand() async throws {
        try store.savePendingRequest(label, requestId: "r1", clientId: "field-x")
        api.answer(throwing: .enrollmentRefused(httpStatus: 404, serverError: "enrollment_request_not_found"))
        api.answer(throwing: .enrollmentPending(requestId: "r2", clientId: "field-y"))

        let pending = await expectPending { try await self.send("CODE") }
        XCTAssertEqual(pending?.requestId, "r2")
        let calls = api.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].requestId, "r1")
        XCTAssertNil(calls[1].requestId)
        XCTAssertEqual(calls[1].token, "CODE")
        XCTAssertNotEqual(try spki(calls[0]), try spki(calls[1]), "a new key for the new request")
        XCTAssertEqual(try store.loadPendingRequest(label)?.requestId, "r2")
    }

    func testWithoutACodeARequestTheServerNoLongerKnowsIsSimplyOver() async throws {
        try store.savePendingRequest(label, requestId: "r1", clientId: nil)
        api.answer(throwing: .enrollmentRefused(httpStatus: 404, serverError: "enrollment_request_not_found"))

        await expectRefusal("enrollment_request_not_found") { try await self.send(nil) }
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertNil(try store.loadPendingRequest(label))
    }

    func testOtherRefusalsKeepTheRequestAndTheKey() async throws {
        try store.savePendingRequest(label, requestId: "r1", clientId: "field-x")
        api.answer(throwing: .enrollmentRefused(httpStatus: 409, serverError: "device_already_enrolled"))

        await expectRefusal("device_already_enrolled") { try await self.send(nil) }
        XCTAssertEqual(try store.loadPendingRequest(label)?.requestId, "r1")
        XCTAssertTrue(key.exists())
    }

    func testARefusedTokenEnrollmentKeepsTheKey() async throws {
        api.answer(throwing: .enrollmentRefused(httpStatus: 401, serverError: "Gecersiz token"))
        let refusal = await expectRefusal("Gecersiz token") { try await self.send("used-token") }
        XCTAssertEqual(refusal?.refusal, .invalidToken)
        XCTAssertTrue(key.exists())
        XCTAssertNil(try store.loadPendingRequest(label))
    }
}
