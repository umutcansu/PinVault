import XCTest
@testable import PinVault

/// App Attest in place of Android Key Attestation at enrollment (PORTING.md
/// §6): a new enrollment request carries `appAttestation`, the App Attest
/// token of a fresh key whose client data hash is SHA256(UTF8(the integrity
/// request hash)); nothing when App Attest gives nothing; never on a pending
/// pick-up; a fresh one on the retry after an attestation refusal.
final class EnrollmentAppAttestationTests: XCTestCase {

    /// A backend whose enrollment body carries `appAttestation` (the library's own client, L2).
    private final class AttestedApi: ScriptedEnrollmentApi, AppAttestedEnrollmentApi, @unchecked Sendable {
        func enrollWithCsr(
            token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
            csrDer: Data, requestId: String?, attestationChain: [String], integrityToken: String?, appAttestation: String
        ) async throws -> EnrollmentResult? {
            try record(Call(
                token: token, deviceId: deviceId, deviceUid: deviceUid, requestId: requestId, csr: csrDer,
                attestation: attestationChain, integrityToken: integrityToken, arity: 9, appAttestation: appAttestation
            ))
        }
    }

    /// App Attest standing in: records the client data hashes, answers from a script.
    private final class AppAttest: @unchecked Sendable {
        let hashes = Locked<[Data]>([])
        let answers: Locked<[String?]>

        init(_ answers: [String?]) {
            self.answers = Locked(answers)
        }

        var source: EnrollmentAppAttestation.Source {
            { [self] hash in
                hashes.withLock { $0.append(hash) }
                return answers.withLock { $0.isEmpty ? nil : $0.removeFirst() }
            }
        }

        /// A token of the PORTING.md §6 shape for the n-th attestation.
        static func token(_ n: Int) -> String {
            #"{"provider":"app-attest","keyId":"a2V5LQ\#(n)==","attestation":"o2NmbXRvYXBwbGUtYXBwYXR0ZXN0\#(n)"}"#
        }
    }

    private let label = "default"
    private let deviceUid = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private var store: ClientCertSecureStore!
    private var key: (any ClientIdentityKeyProvider)!

    override func setUpWithError() throws {
        store = try testCertStore(self, strict: true)
        key = ClientIdentityKeys.software(label: uniqueLabel("app-attest"))
    }

    override func tearDown() {
        try? key.clear()
    }

    @discardableResult
    private func send(
        _ api: ScriptedEnrollmentApi,
        appAttest: AppAttest?,
        token: String? = "tok",
        integrity: (any IntegrityTokenProvider)? = nil
    ) async throws -> EnrollmentResult {
        let key = self.key!
        return try await EnrollmentRequests.send(
            api: api, certStore: store, key: key, certLabel: label, token: token, deviceId: nil,
            deviceAlias: "iPhone", deviceUid: deviceUid, integrity: integrity, appAttestation: appAttest?.source
        ) {
            try key.ensureKeyPair()
            return try Pkcs10Csr.encode(commonName: "device", key: key)
        }
    }

    private func expectedHash(_ call: ScriptedEnrollmentApi.Call) -> Data {
        Hashing.sha256(Data(IntegrityRequestHash.of(deviceId: deviceUid, csrDer: call.csr).utf8))
    }

    func testANewRequestCarriesTheAttestationBoundToItsIntegrityRequestHash() async throws {
        let api = AttestedApi()
        api.answer(placeholderChain)
        let appAttest = AppAttest([AppAttest.token(1)])
        let integrityHashes = Locked<[String]>([])
        try await send(api, appAttest: appAttest, integrity: ClosureIntegrityTokenProvider { hash in
            integrityHashes.withLock { $0.append(hash) }
            return "verdict"
        })

        let call = try XCTUnwrap(api.calls.first)
        XCTAssertEqual(call.arity, 9)
        XCTAssertEqual(call.appAttestation, AppAttest.token(1), "sent as App Attest gave it")
        XCTAssertEqual(call.integrityToken, "verdict")
        XCTAssertEqual(call.attestation, [], "no Android chain next to it")
        // clientDataHash = SHA256(UTF8(integrityRequestHash)): the CSR and the device id.
        let requestHash = IntegrityRequestHash.of(deviceId: deviceUid, csrDer: call.csr)
        XCTAssertEqual(appAttest.hashes.get(), [Hashing.sha256(Data(requestHash.utf8))])
        XCTAssertEqual(appAttest.hashes.get().first?.count, 32)
        XCTAssertEqual(integrityHashes.get(), [requestHash], "the integrity token is bound to the same request hash")

        // The body field's shape (PORTING.md §6).
        let token = try JSONSerialization.jsonObject(with: Data(try XCTUnwrap(call.appAttestation).utf8)) as? [String: String]
        XCTAssertEqual(token?["provider"], "app-attest")
        XCTAssertNotNil(token?["keyId"])
        XCTAssertNotNil(token?["attestation"])
    }

    func testTheBodyCarriesTheTokenAsAJsonStringValueLikeTheIntegrityToken() async throws {
        let api = AttestedApi()
        api.answer(placeholderChain)
        try await send(api, appAttest: AppAttest([AppAttest.token(3)]), integrity: ClosureIntegrityTokenProvider { _ in "verdict" })
        let call = try XCTUnwrap(api.calls.first)
        // What the API client puts into the body: both tokens as string members.
        let body: [String: Any] = [
            "csr": call.csr.base64EncodedString(),
            "integrityToken": try XCTUnwrap(call.integrityToken),
            "appAttestation": try XCTUnwrap(call.appAttestation),
        ]
        let encoded = try JSONSerialization.data(withJSONObject: body)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let member = try XCTUnwrap(decoded["appAttestation"] as? String, "a JSON string value, not a nested object")
        XCTAssertTrue(String(decoding: encoded, as: UTF8.self).contains(#""appAttestation":"{\"provider\":\"app-attest\""#))
        let token = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(member.utf8)) as? [String: String])
        XCTAssertEqual(token["provider"], "app-attest")
        XCTAssertEqual(Set(token.keys), ["provider", "keyId", "attestation"])
    }

    func testTheHashFallsBackToTheDeviceIdWithoutADeviceUid() async throws {
        let api = AttestedApi()
        api.answer(placeholderChain)
        let appAttest = AppAttest([AppAttest.token(1)])
        let key = self.key!
        _ = try await EnrollmentRequests.send(
            api: api, certStore: store, key: key, certLabel: label, token: nil, deviceId: "ios-id-1",
            deviceAlias: nil, deviceUid: nil, appAttestation: appAttest.source
        ) {
            try key.ensureKeyPair()
            return try Pkcs10Csr.encode(commonName: "device", key: key)
        }
        let csr = try XCTUnwrap(api.calls.first).csr
        XCTAssertEqual(appAttest.hashes.get(), [Hashing.sha256(Data(IntegrityRequestHash.of(deviceId: "ios-id-1", csrDer: csr).utf8))])
    }

    func testWithoutAnAttestationTheFieldIsOmittedAndTheRequestGoesAsBefore() async throws {
        let api = AttestedApi()
        for _ in 0..<3 { api.answer(placeholderChain) }
        // No source (not wired), App Attest gives nothing (simulator, unsupported, a failure), or a blank.
        try await send(api, appAttest: nil)
        try await send(api, appAttest: AppAttest([nil]))
        try await send(api, appAttest: AppAttest(["  "]))
        XCTAssertEqual(api.calls.map(\.arity), [7, 7, 7])
        XCTAssertEqual(api.calls.map(\.appAttestation), [nil, nil, nil])
    }

    func testAnApiThatCannotCarryTheAttestationGetsItsCallWithout() async throws {
        let api = ScriptedEnrollmentApi()
        api.answer(placeholderChain)
        try await send(api, appAttest: AppAttest([AppAttest.token(1)]))
        XCTAssertEqual(api.calls.map(\.arity), [7])
        XCTAssertNil(api.calls[0].appAttestation)
    }

    func testAPendingPickUpCarriesNoAttestation() async throws {
        try key.ensureKeyPair()
        try store.savePendingRequest(label, requestId: "r1", clientId: "field-x")
        let api = AttestedApi()
        api.answer(placeholderChain)
        let appAttest = AppAttest([AppAttest.token(1)])
        try await send(api, appAttest: appAttest, token: nil)
        XCTAssertEqual(api.calls.first?.requestId, "r1")
        XCTAssertNil(api.calls.first?.appAttestation)
        XCTAssertTrue(appAttest.hashes.get().isEmpty, "App Attest is not asked for a request that is already made")
    }

    func testANewRequestAfterALapsedOneIsAttestedAgain() async throws {
        try store.savePendingRequest(label, requestId: "r1", clientId: nil)
        let api = AttestedApi()
        api.answer(throwing: .enrollmentRefused(httpStatus: 410, serverError: "enrollment_request_expired"))
        api.answer(placeholderChain)
        let appAttest = AppAttest([AppAttest.token(1)])
        try await send(api, appAttest: appAttest)
        XCTAssertEqual(api.calls.map(\.requestId), ["r1", nil])
        XCTAssertEqual(api.calls.map(\.appAttestation), [nil, AppAttest.token(1)])
    }

    func testAnAttestationRefusalOfAnUnattestedRequestIsRetriedOnceWithAFreshAttestation() async throws {
        let api = AttestedApi()
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required"))
        api.answer(placeholderChain)
        // App Attest failed for the first request, works for the retry.
        let appAttest = AppAttest([nil, AppAttest.token(2)])

        let answer = try await send(api, appAttest: appAttest)

        XCTAssertEqual(answer, placeholderChain)
        let calls = api.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertNil(calls[0].appAttestation)
        XCTAssertEqual(calls[1].appAttestation, AppAttest.token(2))
        XCTAssertNotEqual(try ParsedCsr(calls[0].csr).spki, try ParsedCsr(calls[1].csr).spki, "a new key")
        // A fresh attestation, bound to the new request.
        XCTAssertEqual(appAttest.hashes.get(), [expectedHash(calls[0]), expectedHash(calls[1])])
        XCTAssertNotEqual(appAttest.hashes.get()[0], appAttest.hashes.get()[1])
    }

    func testADeviceThatStillCannotAttestIsNotAskedTwice() async throws {
        let api = AttestedApi()
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required"))
        let appAttest = AppAttest([nil, nil])
        let refusal = await expectRefusal("attestation_required") { try await self.send(api, appAttest: appAttest) }
        XCTAssertEqual(refusal?.refusal, .attestationFailed)
        XCTAssertEqual(api.calls.count, 1, "one request, no second one without attestation")
        XCTAssertEqual(appAttest.hashes.get().count, 2, "the retry asked App Attest for a fresh one")
    }

    func testARefusedAttestationIsNotRetried() async throws {
        let api = AttestedApi()
        api.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_invalid", serverMessage: "app_attest"))
        let appAttest = AppAttest([AppAttest.token(1), AppAttest.token(2)])
        await expectRefusal("attestation_invalid") { try await self.send(api, appAttest: appAttest) }
        XCTAssertEqual(api.calls.count, 1)
        XCTAssertEqual(appAttest.hashes.get().count, 1)
        XCTAssertTrue(key.exists(), "the key stays: it was attested, the server does not accept it")
    }

    func testTheServiceSendsItsSourcesAttestation() async throws {
        let environment = try testStoreEnvironment(self)
        let prefix = uniqueLabel("svc-attest")
        let appAttest = AppAttest([AppAttest.token(7)])
        let service = EnrollmentService(
            storage: .on(environment, identityKeys: { ClientIdentityKeys.software(label: "\(prefix)-\($0)") }, importedKeys: InMemoryImportedClientKeys()),
            deviceId: { "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b" },
            appAttestation: appAttest.source
        )
        defer { try? ClientIdentityKeys.software(label: "\(prefix)-default").clear() }
        let api = AttestedApi()
        api.answer(throwing: .enrollmentPending(requestId: "r1"))
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://config.test/") { block in
                block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin("A"), pin("B")])])
                block.allowUnsigned()
            }
            .build()
        let target = EnrollmentService.Target(config: config, block: config.defaultConfigApi!, api: { api }, live: nil)
        let result = await service.enroll(token: "CODE", deviceId: nil, label: nil, target: target)
        guard case .pending = result else { return XCTFail("\(result)") }
        XCTAssertEqual(api.calls.first?.appAttestation, AppAttest.token(7))
        XCTAssertEqual(appAttest.hashes.get(), [expectedHash(api.calls[0])])
    }
}
