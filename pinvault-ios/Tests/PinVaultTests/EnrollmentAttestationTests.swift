import XCTest
@testable import PinVault

/// The enrollment request carries the device key's attestation when the key
/// has one, and a key the server made is taken only by a block that asked for
/// it (Kotlin `EnrollmentAttestationTest`).
///
/// iOS keys carry no attestation chain (App Attest is separate); the
/// in-memory key plays an Android-like key that does, through
/// `InMemoryClientIdentityKeyProvider.attestation`, so the request logic is
/// held to the same rules.
final class EnrollmentAttestationTests: XCTestCase {

    private let label = "default"
    private let deviceUid = "a1b2c3d4e5f60718"
    private var store: ClientCertSecureStore!
    private var key: (any ClientIdentityKeyProvider)!
    private var api: ScriptedEnrollmentApi!
    private let p12 = EnrollmentResult(p12Bytes: Data([1, 2, 3]), p12Hash: "hash", p12Password: "one-off")

    private var challenge: Data { ClientIdentityKeys.attestationChallenge(deviceUid: deviceUid) }

    override func setUpWithError() throws {
        store = try testCertStore(self, strict: true)
        key = ClientIdentityKeys.software(label: uniqueLabel("enroll-att-test"))
        api = ScriptedEnrollmentApi(takesIntegrityToken: false)
        let p12 = self.p12
        api.onEnroll = { p12 }
        // This "device" attests: the chain is the challenge itself, then a root.
        InMemoryClientIdentityKeyProvider.attestation = { challenge in [challenge, Data("root".utf8)] }
    }

    override func tearDown() {
        try? key.clear()
        InMemoryClientIdentityKeyProvider.attestation = nil
    }

    private func spki(_ call: ScriptedEnrollmentApi.Call) throws -> String {
        SPKI.pin(try ParsedCsr(call.csr).spki)
    }

    private func send(
        token: String? = "tok",
        allowServerGeneratedKey: Bool = false,
        buildCsr: (() throws -> Data?)? = nil
    ) async throws -> EnrollmentResult {
        let key = self.key!
        let challenge = self.challenge
        return try await EnrollmentRequests.send(
            api: api, certStore: store, key: key, certLabel: label, token: token, deviceId: nil,
            deviceAlias: "iPhone", deviceUid: deviceUid, allowServerGeneratedKey: allowServerGeneratedKey
        ) {
            if let buildCsr { return try buildCsr() }
            try key.ensureKeyPair(attestationChallenge: challenge)
            return try Pkcs10Csr.encode(commonName: "device", key: key)
        }
    }

    // MARK: The challenge

    func testTheChallengeIsSha256OfThePrefixAndTheDeviceIdTheRequestCarries() {
        XCTAssertEqual(challenge, Hashing.sha256("pinvault-identity-key:v1:\(deviceUid)"))
        XCTAssertEqual(challenge.count, 32)
        XCTAssertNotEqual(challenge, ClientIdentityKeys.attestationChallenge(deviceUid: "another-device"))
    }

    // MARK: The chain goes along

    func testTheRequestCarriesTheChainOfTheKeyItIsSignedWithLeafFirst() async throws {
        api.answer(placeholderChain)
        let answer = try await send()
        XCTAssertEqual(answer, placeholderChain)
        XCTAssertEqual(api.calls.first?.attestation, [challenge.base64EncodedString(), Data("root".utf8).base64EncodedString()])
    }

    func testADeviceThatCannotAttestSendsNoChain() async throws {
        InMemoryClientIdentityKeyProvider.attestation = nil
        api.answer(placeholderChain)
        _ = try await send()
        XCTAssertEqual(api.calls.first?.attestation, [])
    }

    func testTheSecureEnclaveKeyCarriesNoChain() {
        // What the device sends: no attestation (the API client omits the empty field).
        XCTAssertEqual(ClientIdentityKeys.secureEnclave(label: uniqueLabel("no-chain")).attestationChain(), [])
    }

    func testAskingAgainForAWaitingRequestUsesTheSameKeyAndTheSameChain() async throws {
        api.answer(throwing: .enrollmentPending(requestId: "r1", clientId: "field-x"))
        api.answer(placeholderChain)
        await expectPending { try await self.send(token: "K7QM2-XRT9V-4NWDP-J6E8B-HC3MA") }
        let answer = try await send(token: nil)
        XCTAssertEqual(answer, placeholderChain)
        let calls = api.calls
        XCTAssertEqual(calls[1].requestId, "r1")
        XCTAssertEqual(try spki(calls[0]), try spki(calls[1]))
        XCTAssertEqual(calls[0].attestation, calls[1].attestation)
    }

    // MARK: A key without a chain

    func testARefusedKeyWithoutAChainIsReplacedOnceAndTheRequestSentAgain() async throws {
        try key.ensureKeyPair()   // made without a challenge: no chain
        let oldKey = try key.spkiSha256()
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required"))
        api.answer(placeholderChain)

        let answer = try await send()
        XCTAssertEqual(answer, placeholderChain)

        let calls = api.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].attestation, [])
        XCTAssertEqual(try spki(calls[0]), oldKey)
        XCTAssertNotEqual(try spki(calls[1]), oldKey, "a new key")
        XCTAssertEqual(calls[1].attestation, [challenge.base64EncodedString(), Data("root".utf8).base64EncodedString()], "with its chain")
    }

    func testADeviceThatStillCannotAttestIsNotAskedTwice() async throws {
        InMemoryClientIdentityKeyProvider.attestation = nil
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required"))
        let refusal = await expectRefusal("attestation_required") { try await self.send() }
        XCTAssertEqual(refusal?.refusal, .attestationFailed)
        XCTAssertEqual(api.calls.count, 1, "one request, no second one with the same empty chain")
    }

    func testARefusedChainIsNotRetried() async throws {
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_invalid", serverMessage: "not_hardware_backed"))
        let refusal = await expectRefusal("attestation_invalid") { try await self.send() }
        guard case .enrollmentRefused(_, _, let message)? = refusal else { return XCTFail() }
        XCTAssertEqual(message, "not_hardware_backed")
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertTrue(key.exists(), "the key stays: it was attested, the server just does not accept it")
    }

    func testAWaitingRequestKeepsItsKeyEvenWhenRefusedForAttestation() async throws {
        try key.ensureKeyPair()
        let spki = try key.spkiSha256()
        try store.savePendingRequest(label, requestId: "r1", clientId: "field-x")
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required"))
        await expectRefusal("attestation_required") { try await self.send(token: nil) }
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertEqual(try key.spkiSha256(), spki, "the request is tied to this key")
    }

    // MARK: A key the server made

    func testAP12AnswerToACsrIsRefusedUnlessTheBlockAllowsAServerMadeKey() async throws {
        api.answer(p12)
        do {
            _ = try await send()
            XCTFail("a P12 answer must not be accepted")
        } catch let error as ServerGeneratedKeyRefusedError {
            XCTAssertTrue(error.message.contains("allowServerGeneratedKey"), error.message)
        }

        api.answer(p12)
        let answer = try await send(allowServerGeneratedKey: true)
        XCTAssertEqual(answer, p12)
    }

    func testWithoutACsrNothingIsSentUnlessTheBlockAllowsAServerMadeKey() async throws {
        do {
            _ = try await send(buildCsr: { nil })
            XCTFail("P12 enrollment must not be tried")
        } catch let error as ServerGeneratedKeyRefusedError {
            XCTAssertTrue(error.message.contains("allowServerGeneratedKey"), error.message)
        }
        XCTAssertEqual(api.p12Calls, 0)
        XCTAssertTrue(api.calls.isEmpty)

        let answer = try await send(allowServerGeneratedKey: true, buildCsr: { nil })
        XCTAssertEqual(answer, p12)
        XCTAssertEqual(api.p12Calls, 1)
    }

    func testABackendThatTakesNoCsrIsUsedOnlyWithTheOptIn() async throws {
        api.answer(nil)
        do {
            _ = try await send()
            XCTFail("enroll() must not be called")
        } catch is ServerGeneratedKeyRefusedError {
        }
        XCTAssertEqual(api.p12Calls, 0)

        api.answer(nil)
        let answer = try await send(allowServerGeneratedKey: true)
        XCTAssertEqual(answer, p12)
        XCTAssertEqual(api.p12Calls, 1)
    }
}
