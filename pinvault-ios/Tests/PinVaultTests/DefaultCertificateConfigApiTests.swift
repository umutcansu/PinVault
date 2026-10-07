import Foundation
import XCTest
@testable import PinVault

/// Port of DefaultCertificateConfigApiTest: every endpoint, header, body,
/// status mapping and size limit of the library's Config API client, over a
/// pinned TLS test server (MockWebServer's counterpart).
final class DefaultCertificateConfigApiTests: XCTestCase {

    private var server: TestServer!
    private let now = Int64(Date().timeIntervalSince1970 * 1000)

    override func setUp() async throws {
        server = try await startConfigApiServer()
    }

    override func tearDown() async throws {
        server.stop()
    }

    private func api(signaturePublicKey: String? = nil, allowServerGeneratedKey: Bool = false) -> DefaultCertificateConfigApi {
        makeConfigApi(server, signaturePublicKey: signaturePublicKey, allowServerGeneratedKey: allowServerGeneratedKey)
    }

    private func freshPayload(version: Int = 7) -> String {
        json(CertificateConfig(
            version: version,
            pins: [HostPin(hostname: "secure.example.com", sha256: ["pin1", "pin2"], version: version)],
            issuedAt: now,
            expiresAt: now + 3_600_000
        ))
    }

    private func enqueueJSON(_ body: String, status: Int = 200, headers: [String: String] = [:]) {
        server.enqueue(.status(status, body, headers: headers))
    }

    // MARK: Health

    func testHealthCheckReturnsTrueWhenStatusIsOk() async throws {
        enqueueJSON(#"{"status":"ok"}"#)
        let healthy = try await api().healthCheck()
        XCTAssertTrue(healthy)
    }

    func testHealthCheckReturnsFalseWhenStatusIsNotOk() async throws {
        enqueueJSON(#"{"status":"degraded"}"#)
        let healthy = try await api().healthCheck()
        XCTAssertFalse(healthy)
    }

    func testHealthCheckReturnsFalseOnNetworkError() async throws {
        let api = api()
        server.stop()
        let healthy = try await api.healthCheck()
        XCTAssertFalse(healthy)
    }

    // MARK: Config

    func testFetchConfigWithoutSignatureParsesConfigDirectly() async throws {
        enqueueJSON(json(CertificateConfig(version: 3, pins: [HostPin(hostname: "api.example.com", sha256: ["hash1", "hash2"], version: 3)])))
        let result = try await api().fetchConfig(currentVersion: 1)
        XCTAssertEqual(result.version, 3)
        XCTAssertEqual(result.pins.count, 1)
        XCTAssertEqual(result.pins[0].hostname, "api.example.com")
    }

    func testFetchConfigWithValidSignatureVerifiesAndParses() async throws {
        let signer = TestSigner()
        let payload = json(CertificateConfig(
            version: 5, pins: [HostPin(hostname: "secure.example.com", sha256: ["pin1", "pin2"], version: 5)],
            issuedAt: now, expiresAt: now + 3_600_000
        ))
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: signer.sign(payload))))
        let result = try await api(signaturePublicKey: signer.pub).fetchConfig(currentVersion: 1)
        XCTAssertEqual(result.version, 5)
        XCTAssertEqual(result.pins[0].hostname, "secure.example.com")
    }

    func testFetchConfigRejectsSignedConfigMissingExpiresAt() async throws {
        let signer = TestSigner()
        let payload = json(CertificateConfig(version: 5, pins: [HostPin(hostname: "a.com", sha256: ["p1", "p2"], version: 5)]))
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: signer.sign(payload))))
        let error = await assertPinVaultError { _ = try await self.api(signaturePublicKey: signer.pub).fetchConfig(currentVersion: 1) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("expiresAt"), message)
    }

    func testFetchConfigRejectsSignedConfigWithExpiredWindow() async throws {
        let signer = TestSigner()
        let payload = json(CertificateConfig(
            version: 5, pins: [HostPin(hostname: "a.com", sha256: ["p1", "p2"], version: 5)],
            issuedAt: now - 86_400_000, expiresAt: now - 60_000
        ))
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: signer.sign(payload))))
        let error = await assertPinVaultError { _ = try await self.api(signaturePublicKey: signer.pub).fetchConfig(currentVersion: 1) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("expired") || message.contains("replay"), message)
    }

    func testFetchConfigWithInvalidSignatureThrowsSecurityException() async throws {
        let signer = TestSigner()
        enqueueJSON(json(SignedConfigResponse(payload: #"{"version":1,"pins":[]}"#, signature: "aW52YWxpZHNpZ25hdHVyZQ==")))
        let error = await assertPinVaultError { _ = try await self.api(signaturePublicKey: signer.pub).fetchConfig(currentVersion: 0) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("tampering"), message)
    }

    func testFetchConfigPassesCurrentVersionAsQueryParameter() async throws {
        enqueueJSON(json(CertificateConfig(version: 1, pins: [HostPin(hostname: "a.com", sha256: ["h1", "h2"])])))
        _ = try await api().fetchConfig(currentVersion: 42)
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.query("currentVersion"), "42")
        XCTAssertTrue(request.path.hasPrefix("/api/v1/certificate-config"), request.path)
    }

    func testAnHTTPErrorIsAnHttpException() async throws {
        server.enqueue(.status(503, #"{"error":"busy"}"#))
        do {
            _ = try await api().fetchConfig(currentVersion: 1)
            XCTFail("expected an HttpException")
        } catch let error as HttpException {
            XCTAssertEqual(error.code, 503)
            XCTAssertEqual(error.message, "HTTP 503 Service Unavailable")
        }
    }

    // MARK: Host client certificates

    func testDownloadHostClientCertReturnsBinaryBytes() async throws {
        let expected = Data([0x50, 0x4B, 0x03, 0x04, 0x10, 0x20])
        server.enqueue(TestServer.Response(status: 200, headers: ["Content-Type": "application/octet-stream"], body: expected))
        let result = try await api().downloadHostClientCert(hostname: "host.com")
        XCTAssertEqual(result, expected)
    }

    func testDownloadHostClientCertConstructsCorrectURLPath() async throws {
        server.enqueue(TestServer.Response(status: 200, headers: ["Content-Type": "application/octet-stream"], body: Data([0x01])))
        _ = try await api().downloadHostClientCert(hostname: "api.example.com")
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertTrue(request.path.contains("api/v1/client-certs/api.example.com/download"), request.path)
    }

    private func opens(_ p12: Data, _ password: String) -> Bool {
        (try? ClientIdentity.fromPKCS12(p12, password: password)) != nil
    }

    func testAHostClientCertificateSentWithAOneOffPasswordComesBackUnderTheBlockPassword() async throws {
        let oneOff = try P12Rewrap.rewrap(TLSFixture.p12("client-a"), from: "changeit", to: "one-off-7Qx")
        server.enqueue(TestServer.Response(
            status: 200, headers: ["Content-Type": "application/octet-stream", "X-P12-Password": "one-off-7Qx"], body: oneOff
        ))
        let api = makeConfigApi(server, clientKeyPassword: "block-pass")
        let bytes = try await api.downloadHostClientCert(hostname: "host.com")

        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).features, ["p12password", "forbidden-as-409"])
        XCTAssertTrue(opens(bytes, "block-pass"))
        XCTAssertFalse(opens(bytes, "one-off-7Qx"))
    }

    // MARK: Enrollment (P12)

    func testEnrollmentAsksForAOneOffPasswordAndReturnsItWithTheBundle() async throws {
        let bundle = try P12Rewrap.rewrap(TLSFixture.p12("client-a"), from: "changeit", to: "one-off-9Kz")
        server.enqueue(TestServer.Response(status: 200, headers: ["X-P12-SHA256": "hash", "X-P12-Password": "one-off-9Kz"], body: bundle))
        let result = try await api().enroll(token: "t", deviceId: nil, deviceAlias: nil, deviceUid: nil)

        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).features, ["p12password", "forbidden-as-409"])
        XCTAssertEqual(result.p12Password, "one-off-9Kz")
        XCTAssertEqual(result.p12Hash, "hash")
        XCTAssertEqual(result.p12Bytes, bundle)
        XCTAssertFalse(result.description.contains("one-off-9Kz"), "the password stays out of logs")
    }

    // MARK: Several signers and signing-key sets on the wire

    func testFetchConfigAcceptsAnEnvelopeCarryingAllSignaturesForA2Of2Block() async throws {
        let k1 = TestSigner(), k2 = TestSigner()
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [k1.pub, k2.pub], builtInThreshold: 2,
                                   recoveryKeys: [], recoveryThreshold: 1, store: nil)
        let payload = freshPayload()
        let first = k1.sign(payload), second = k2.sign(payload)

        // Only the legacy single field → one signer → rejected.
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: first)))
        let error = await assertPinVaultError { _ = try await makeConfigApi(self.server, signatureTrust: trust).fetchConfig(currentVersion: 1) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("1 of 2 required signatures valid"), message)

        enqueueJSON(json(SignedConfigResponse(
            payload: payload, signature: first,
            signatures: [SignatureEntry(signature: first), SignatureEntry(signature: second)]
        )))
        let config = try await makeConfigApi(server, signatureTrust: trust).fetchConfig(currentVersion: 1)
        XCTAssertEqual(config.version, 7)
    }

    func testFetchConfigAppliesAKeySetAndAcceptsAConfigSignedByTheKeyItIntroduces() async throws {
        let oldKey = TestSigner(), newKey = TestSigner(), recovery = TestSigner()
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [oldKey.pub], builtInThreshold: 1,
                                   recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: SigningKeyStore(prefs: InMemoryPreferences()))
        let setPayload = #"{"type":"pinvault-signing-keys","version":1,"keys":["\#(newKey.pub)"]}"#
        let keySet = SignedKeySet(payload: setPayload, signatures: [SignatureEntry(signature: recovery.sign(setPayload))])
        let payload = freshPayload()
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: newKey.sign(payload), signingKeys: keySet)))

        let config = try await makeConfigApi(server, signatureTrust: trust).fetchConfig(currentVersion: 1)
        XCTAssertEqual(config.version, 7)
        XCTAssertEqual(try trust.keySetVersion(), 1)

        // The old key is revoked from now on, even without a set in the response.
        let next = freshPayload(version: 8)
        enqueueJSON(json(SignedConfigResponse(payload: next, signature: oldKey.sign(next))))
        let error = await assertPinVaultError { _ = try await makeConfigApi(self.server, signatureTrust: trust).fetchConfig(currentVersion: 7) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("revoked by signing-key set v1"), message)
    }

    func testFetchConfigRejectsTheWholeResponseWhenItsKeySetIsForged() async throws {
        let signingKey = TestSigner(), recovery = TestSigner(), attacker = TestSigner()
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [signingKey.pub], builtInThreshold: 1,
                                   recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: SigningKeyStore(prefs: InMemoryPreferences()))
        let setPayload = #"{"type":"pinvault-signing-keys","version":5,"keys":["\#(attacker.pub)"]}"#
        let forged = SignedKeySet(payload: setPayload, signatures: [SignatureEntry(signature: signingKey.sign(setPayload))])
        let payload = freshPayload()
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: signingKey.sign(payload), signingKeys: forged)))

        let error = await assertPinVaultError { _ = try await makeConfigApi(self.server, signatureTrust: trust).fetchConfig(currentVersion: 1) }
        guard case .security(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("Signing-key set rejected"), message)
        XCTAssertEqual(try trust.keySetVersion(), 0)
    }

    func testSignedConfigRequestsAdvertiseWhatThisClientUnderstands() async throws {
        let key = TestSigner()
        let payload = freshPayload()
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: key.sign(payload))))
        _ = try await api(signaturePublicKey: key.pub).fetchConfig(currentVersion: 1)
        let features = try XCTUnwrap(server.takeRequest()).features
        XCTAssertEqual(features, ["redelivery", "multisig", "keyset", "forbidden-as-409"])
    }

    // MARK: CSR enrollment and renewal

    private let csr = Data([0x30, 0x03, 0x02, 0x01, 0x00])
    private let chainJSON = #"{"clientId":"dev-1","chain":["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"]}"#

    private func enqueueChain() {
        server.enqueue(.status(200, chainJSON, headers: ["Content-Type": "application/json", "X-PinVault-Cert-Format": "pem-chain"]))
    }

    func testEnrollWithCsrSendsTheCSRAndTheCsrFeatureAndReadsAPEMChain() async throws {
        enqueueChain()
        let enrolled = try await api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: "alias", deviceUid: "uid", csrDer: csr, requestId: nil)
        let result = try XCTUnwrap(enrolled)

        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.path, "/api/v1/client-certs/enroll")
        XCTAssertEqual(request.method, "POST")
        // Only csr: without allowServerGeneratedKey() the device must not invite a server-made key.
        XCTAssertEqual(request.features, ["csr", "forbidden-as-409"])
        let body = request.jsonBody
        XCTAssertEqual(body["token"] as? String, "tok")
        XCTAssertEqual(body["deviceAlias"] as? String, "alias")
        XCTAssertEqual(body["csr"] as? String, csr.base64EncodedString())

        XCTAssertTrue(result.isCertificateChain)
        XCTAssertEqual(result.certificateChainPem?.count, 2)
        XCTAssertEqual(result.p12Bytes.count, 0)
    }

    func testACSREnrollmentOffersP12PasswordOnlyWhenTheBlockAcceptsAServerMadeKey() async throws {
        enqueueChain()
        enqueueChain()
        _ = try await api(allowServerGeneratedKey: true).enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: "alias", deviceUid: "uid", csrDer: csr, requestId: nil)
        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).features, ["p12password", "csr", "forbidden-as-409"])

        _ = try await api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: "alias", deviceUid: "uid", csrDer: csr, requestId: nil)
        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).features, ["csr", "forbidden-as-409"])
        // The P12 path is unchanged.
        XCTAssertEqual(api().enrollmentFeatures(csr: false), "p12password")
    }

    func testEnrollmentGoesToTheEnrollmentURLWhenOneIsSet() async throws {
        let tls = try await startConfigApiServer()
        defer { tls.stop() }
        tls.enqueue(.status(200, chainJSON, headers: ["X-PinVault-Cert-Format": "pem-chain"]))
        let api = makeConfigApi(server, enrollmentUrl: tls.baseURL)
        let result = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil, csrDer: csr, requestId: nil)
        XCTAssertEqual(result?.isCertificateChain, true)
        XCTAssertEqual(tls.takeRequest()?.path, "/api/v1/client-certs/enroll")
        XCTAssertEqual(server.requestCount, 0)
    }

    func testEnrollWithCsrFallsBackToAP12WhenTheServerIgnoresTheCSR() async throws {
        let bundle = TLSFixture.p12("client-a")
        server.enqueue(TestServer.Response(status: 200, headers: ["X-P12-SHA256": "hash"], body: bundle))
        let enrolled = try await api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil, csrDer: csr, requestId: nil)
        let result = try XCTUnwrap(enrolled)
        XCTAssertFalse(result.isCertificateChain)
        XCTAssertEqual(result.p12Bytes, bundle)
        XCTAssertEqual(result.p12Hash, "hash")
        XCTAssertEqual(server.requestCount, 1)
    }

    func testARefusedEnrollmentCarriesTheServersReason() async throws {
        server.enqueue(.status(409, #"{"error":"device_already_enrolled","message":"This device is enrolled under another client id."}"#,
                               headers: ["Content-Type": "application/json"]))
        let error = await assertPinVaultError {
            _ = try await self.api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: self.csr, requestId: nil)
        }
        guard case .enrollmentRefused(let status, let serverError, let serverMessage)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(status, 409)
        XCTAssertEqual(serverError, "device_already_enrolled")
        XCTAssertEqual(serverMessage, "This device is enrolled under another client id.")
        XCTAssertEqual(error?.refusal, .deviceAlreadyEnrolled)
    }

    func testARefusalWithoutAJSONBodyStillSaysItWasRefused() async throws {
        server.enqueue(.status(413, "<html>too large</html>"))
        let error = await assertPinVaultError { _ = try await self.api().enroll(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil) }
        guard case .enrollmentRefused(let status, let serverError, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(status, 413)
        XCTAssertNil(serverError)
        XCTAssertEqual(error?.refusal, .other)
    }

    func testAServerErrorIsAFailureNotARefusal() async throws {
        server.enqueue(.status(503, #"{"error":"busy"}"#))
        do {
            _ = try await api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil, csrDer: csr, requestId: nil)
            XCTFail("expected an exception")
        } catch let error as PinVaultError {
            XCTFail("a 5xx is no refusal: \(error)")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("503"), "\(error)")
        }
    }

    func testA202MeansTheDeviceWaitsForApprovalWithTheRequestId() async throws {
        server.enqueue(.status(202, #"{"status":"pending","requestId":"r-123","clientId":"field-7k2m9x","message":"Waiting for an administrator."}"#,
                               headers: ["Content-Type": "application/json", "Retry-After": "15"]))
        let error = await assertPinVaultError {
            _ = try await self.api().enrollWithCsr(token: "K7QM2-XRT9V-4NWDP-J6E8B-HC3MA", deviceId: nil, deviceAlias: "Pixel", deviceUid: "uid", csrDer: self.csr, requestId: nil)
        }
        guard case .enrollmentPending(let requestId, let clientId, let message, let retryAfter, _)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(requestId, "r-123")
        XCTAssertEqual(clientId, "field-7k2m9x")
        XCTAssertEqual(message, "Waiting for an administrator.")
        XCTAssertEqual(retryAfter, 15)
    }

    func testA202WithoutARequestIdIsAFailure() async throws {
        server.enqueue(.status(202, #"{"status":"pending"}"#))
        do {
            _ = try await api().enrollWithCsr(token: "code", deviceId: nil, deviceAlias: nil, deviceUid: nil, csrDer: csr, requestId: nil)
            XCTFail("expected an exception")
        } catch let error as PinVaultError {
            XCTFail("no request id to ask again with: \(error)")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("requestId"), "\(error)")
        }
    }

    func testAskingAgainSendsTheRequestIdWithTheCSRAndNoToken() async throws {
        enqueueChain()
        let result = try await api().enrollWithCsr(token: nil, deviceId: nil, deviceAlias: "Pixel", deviceUid: "uid", csrDer: csr, requestId: "r-123")
        let body = try XCTUnwrap(server.takeRequest()).jsonBody
        XCTAssertEqual(body["requestId"] as? String, "r-123")
        XCTAssertNil(body["token"])
        XCTAssertEqual(body["csr"] as? String, csr.base64EncodedString())
        XCTAssertEqual(result?.isCertificateChain, true)
    }

    func testEnrollWithCsrRejectsAChainAnswerWithoutAChain() async throws {
        server.enqueue(.status(200, #"{"clientId":"x"}"#, headers: ["X-PinVault-Cert-Format": "pem-chain"]))
        do {
            _ = try await api().enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil, csrDer: csr, requestId: nil)
            XCTFail("expected an exception")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("chain"), "\(error)")
        }
    }

    func testRenewClientCertOverTheBlockReturnsTheIssuedChain() async throws {
        server.enqueue(.status(200, chainJSON))
        let response = try await api().renewClientCert(clientId: "dev-1", csrDer: csr, recoveryUrl: nil)

        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.path, "/api/v1/client-certs/renew")
        XCTAssertEqual(request.features, ["csr", "forbidden-as-409"])
        XCTAssertEqual(request.jsonBody["clientId"] as? String, "dev-1")
        XCTAssertEqual(request.jsonBody["csr"] as? String, csr.base64EncodedString())
        guard case .issued(let chain) = response else { return XCTFail("\(response)") }
        XCTAssertEqual(chain.count, 2)
    }

    func testRenewClientCertUsesTheRecoveryURLVerbatimWhenGiven() async throws {
        let recovery = try await startConfigApiServer()
        defer { recovery.stop() }
        recovery.enqueue(.status(200, chainJSON))
        let response = try await api().renewClientCert(clientId: "dev-1", csrDer: csr, recoveryUrl: recovery.url("/recover/").absoluteString)
        XCTAssertEqual(server.requestCount, 0)
        XCTAssertEqual(recovery.takeRequest()?.path, "/recover/api/v1/client-certs/renew")
        guard case .issued = response else { return XCTFail("\(response)") }
    }

    func testRenewClientCertMapsTheStatuses() async throws {
        let api = api()
        server.enqueue(.status(403, #"{"error":"reenroll_required","message":"revoked"}"#))
        let refused = try await api.renewClientCert(clientId: "dev-1", csrDer: csr)
        XCTAssertEqual(refused, .reenrollRequired(reason: "revoked"))

        server.enqueue(.status(404))
        let unsupported = try await api.renewClientCert(clientId: "dev-1", csrDer: csr)
        XCTAssertEqual(unsupported, .unsupported)

        server.enqueue(.status(429, #"{"error":"rate_limited"}"#))
        do {
            _ = try await api.renewClientCert(clientId: "dev-1", csrDer: csr)
            XCTFail("expected an exception")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("429"), "\(error)")
        }

        server.enqueue(.status(403, #"{"error":"something_else"}"#))
        do {
            _ = try await api.renewClientCert(clientId: "dev-1", csrDer: csr)
            XCTFail("expected an exception")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("403"), "\(error)")
        }
    }

    func testRebuildBootstrapClientBuildsAFreshClientAndRequestsUseIt() async throws {
        let api = api()
        XCTAssertEqual(api.bootstrapBuilds, 1)
        api.rebuildBootstrapClient()
        XCTAssertEqual(api.bootstrapBuilds, 2)
        enqueueJSON(#"{"status":"ok"}"#)
        let healthy = try await api.healthCheck()
        XCTAssertTrue(healthy)
        XCTAssertEqual(server.connectionCount, 1)
    }

    // MARK: Device keys

    func testRegisterDevicePublicKeySendsTheKeyProofHeadersOnlyWhenItHasAProof() async throws {
        enqueueJSON(#"{"registered":"true"}"#)
        enqueueJSON(#"{"registered":"true"}"#)
        let api = api()

        try await api.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM")
        let plain = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(plain.path, "/api/v1/vault/devices/ios-07/public-key")
        XCTAssertNil(plain.header("X-Vault-Key"))
        XCTAssertNil(plain.header("X-Vault-Token"))
        // iOS keys are RSA-OAEP with MGF1-SHA256 (PORTING.md §3).
        XCTAssertEqual(plain.jsonBody["algorithm"] as? String, "RSA-OAEP-SHA256-MGF1-SHA256")
        XCTAssertEqual(plain.jsonBody["publicKeyPem"] as? String, "PEM")
        XCTAssertNil(plain.jsonBody["purpose"])

        try await api.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM", proof: DeviceKeyProof(vaultKey: "secret-model", token: "tok-123"))
        let proven = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(proven.header("X-Vault-Key"), "secret-model")
        XCTAssertEqual(proven.header("X-Vault-Token"), "tok-123")
    }

    func testRegisterDevicePublicKeySendsTheAlgorithmTheKeyProviderNames() async throws {
        enqueueJSON("{}")
        try await api().registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM", proof: nil, algorithm: "RSA-OAEP-SHA256")
        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).jsonBody["algorithm"] as? String, "RSA-OAEP-SHA256")
    }

    func testRegisterDevicePublicKeyReportsARefusedKeyChangeAndAForeignCertificate() async throws {
        server.enqueue(.status(409, #"{"error":"key_change_requires_proof"}"#))
        server.enqueue(.status(403, #"{"error":"device_identity_mismatch"}"#))
        let api = api()
        do {
            try await api.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM")
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("409"), "\(error)")
        }
        do {
            try await api.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM")
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue(ErrorMessage.of(error)!.contains("403"), "\(error)")
        }
    }

    func testUserAuthRegistrationSendsThePurposeAndTheAttestationChainLeafFirst() async throws {
        enqueueJSON(#"{"registered":"true"}"#)
        enqueueJSON(#"{"registered":"true"}"#)
        let api = api()
        try await api.registerUserAuthPublicKey(deviceId: "ios-07", publicKeyPem: "PEM", attestationChain: ["bGVhZg==", "cm9vdA=="])
        let body = try XCTUnwrap(server.takeRequest()).jsonBody
        XCTAssertEqual(body["purpose"] as? String, "user_auth")
        XCTAssertEqual(body["algorithm"] as? String, "RSA-OAEP-SHA256-MGF1-SHA256")
        XCTAssertEqual(body["attestationChain"] as? [String], ["bGVhZg==", "cm9vdA=="])

        try await api.registerUserAuthPublicKey(deviceId: "ios-07", publicKeyPem: "PEM", attestationChain: [])
        XCTAssertNil(try XCTUnwrap(server.takeRequest()).jsonBody["attestationChain"], "no chain, no field")
    }

    func testUserAuthRegistrationRefusalsSayWhatToDo() async throws {
        server.enqueue(.status(409, #"{"error":"user_auth_key_exists"}"#))
        server.enqueue(.status(403, #"{"error":"attestation_required"}"#))
        server.enqueue(.status(403, #"{"error":"attestation_invalid","reason":"challenge mismatch"}"#))
        server.enqueue(.status(409, #"{"error":"key_change_requires_proof"}"#))
        let api = api()

        func refusal(_ chain: [String]) async -> (any Error)? {
            do {
                try await api.registerUserAuthPublicKey(deviceId: "ios-07", publicKeyPem: "PEM", attestationChain: chain)
                return nil
            } catch {
                return error
            }
        }
        let exists = await refusal(["bGVhZg=="])
        XCTAssertTrue(exists is UserAuthKeyRefusedException)
        XCTAssertTrue(ErrorMessage.of(exists!)!.contains("administrator must reset this device's user-auth key"))
        let required = await refusal([])
        XCTAssertTrue(ErrorMessage.of(required!)!.contains("attestation_required"))
        let invalid = await refusal(["bGVhZg=="])
        XCTAssertTrue(ErrorMessage.of(invalid!)!.contains("attestation_invalid") && ErrorMessage.of(invalid!)!.contains("challenge mismatch"))
        let other = await refusal([])
        XCTAssertFalse(other is UserAuthKeyRefusedException)
        XCTAssertTrue(ErrorMessage.of(other!)!.contains("409"))
    }

    func testAKeyProofNeverPrintsItsToken() {
        XCTAssertFalse(DeviceKeyProof(vaultKey: "secret-model", token: "tok-123").description.contains("tok-123"))
    }

    // MARK: Enrollment key attestation

    func testACSREnrollmentCarriesTheKeysAttestationChainLeafFirstOnEveryPath() async throws {
        enqueueChain(); enqueueChain(); enqueueChain()
        let api = api()
        let attestation = ["bGVhZg==", "aW50ZXJtZWRpYXRl", "cm9vdA=="]
        _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: "iPhone", deviceUid: "ios-07", csrDer: csr, requestId: nil, attestationChain: attestation)
        _ = try await api.enrollWithCsr(token: nil, deviceId: "ios-07", deviceAlias: "iPhone", deviceUid: "ios-07", csrDer: csr, requestId: nil, attestationChain: attestation)
        _ = try await api.enrollWithCsr(token: nil, deviceId: nil, deviceAlias: "iPhone", deviceUid: "ios-07", csrDer: csr, requestId: "r-123", attestationChain: attestation)
        for round in 0..<3 {
            let body = try XCTUnwrap(server.takeRequest()).jsonBody
            XCTAssertEqual(body["attestationChain"] as? [String], attestation, "request \(round)")
            XCTAssertEqual(body["deviceUid"] as? String, "ios-07")
            XCTAssertNotNil(body["csr"])
        }
    }

    func testNoAttestationChainNoField() async throws {
        enqueueChain(); enqueueChain()
        let api = api()
        _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: csr, requestId: nil, attestationChain: [])
        _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: csr, requestId: nil)
        for _ in 0..<2 { XCTAssertNil(try XCTUnwrap(server.takeRequest()).jsonBody["attestationChain"]) }
    }

    func testAnIntegrityTokenGoesAlongOnlyWithACSR() async throws {
        enqueueChain()
        server.enqueue(TestServer.Response(status: 200, headers: ["X-P12-SHA256": "hash"], body: Data([1])))
        let api = api()
        _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: csr, requestId: nil,
                                        attestationChain: [], integrityToken: "{\"provider\":\"app-attest\"}")
        XCTAssertEqual(try XCTUnwrap(server.takeRequest()).jsonBody["integrityToken"] as? String, "{\"provider\":\"app-attest\"}")
        _ = try await api.enroll(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid")
        XCTAssertNil(try XCTUnwrap(server.takeRequest()).jsonBody["integrityToken"])
    }

    func testAttestationRefusalsCarryTheServersReason() async throws {
        server.enqueue(.status(403, #"{"error":"attestation_required"}"#))
        server.enqueue(.status(403, #"{"error":"attestation_invalid","reason":"not_hardware_backed"}"#))
        let api = api()
        let required = await assertPinVaultError {
            _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: self.csr, requestId: nil, attestationChain: [])
        }
        XCTAssertEqual(required?.refusal, .attestationFailed)
        guard case .enrollmentRefused(_, "attestation_required", _)? = required else { return XCTFail("\(String(describing: required))") }

        let invalid = await assertPinVaultError {
            _ = try await api.enrollWithCsr(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: "uid", csrDer: self.csr, requestId: nil, attestationChain: ["bGVhZg=="])
        }
        XCTAssertEqual(invalid?.refusal, .attestationFailed)
        guard case .enrollmentRefused(_, "attestation_invalid", let message)? = invalid else { return XCTFail("\(String(describing: invalid))") }
        XCTAssertEqual(message, "not_hardware_backed", "the reason reaches Refused.message")
    }

    // MARK: Vault downloads

    func testAVaultDownloadReadsTheV2SignatureHeadersNextToTheV1Ones() async throws {
        server.enqueue(.status(200, "content", headers: [
            "X-Vault-Version": "4", "X-Vault-Signature": "djE=", "X-Vault-Signatures": "k1:djE=",
            "X-Vault-Signature-V2": "djI=", "X-Vault-Signatures-V2": "k1:djI=, k2:djJi",
        ]))
        let response = try await api().downloadVaultFileWithMeta(endpoint: "api/v1/vault/flags")
        XCTAssertEqual(response.signature, "djE=")
        XCTAssertEqual(response.signatures, [SignatureEntry(keyId: "k1", signature: "djE=")])
        XCTAssertEqual(response.signatureV2, "djI=")
        XCTAssertEqual(response.signaturesV2, [SignatureEntry(keyId: "k1", signature: "djI="), SignatureEntry(keyId: "k2", signature: "djJi")])
        XCTAssertEqual(response.version, 4)
        XCTAssertEqual(response.content, Data("content".utf8))
        XCTAssertEqual(server.takeRequest()?.path, "/api/v1/vault/flags?version=0")
    }

    func testAServerWithoutV2HeadersLeavesThemNil() async throws {
        server.enqueue(.status(200, "content", headers: ["X-Vault-Version": "4", "X-Vault-Signature": "djE="]))
        let response = try await api().downloadVaultFileWithMeta(endpoint: "api/v1/vault/flags")
        XCTAssertNil(response.signatureV2)
        XCTAssertNil(response.signaturesV2)
    }

    func testAVaultDownloadSendsTheDeviceAndTokenHeadersAndReads304() async throws {
        server.enqueue(.status(304, "", headers: ["X-Vault-Version": "6", "X-Vault-Encryption": "end_to_end"]))
        let response = try await api().downloadVaultFileWithMeta(endpoint: "api/v1/vault/flags?x=1", currentVersion: 6, deviceId: "dev", accessToken: "tok")
        XCTAssertTrue(response.notModified)
        XCTAssertEqual(response.version, 6)
        XCTAssertEqual(response.encryption, "end_to_end")
        XCTAssertTrue(response.content.isEmpty)
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.path, "/api/v1/vault/flags?x=1&version=6")
        XCTAssertEqual(request.header("X-Device-Id"), "dev")
        XCTAssertEqual(request.header("X-Vault-Token"), "tok")
    }

    // MARK: Bodies are read with a ceiling (L-13)

    private let oneMiB: Int64 = 1 << 20

    private func assertTooLarge(_ body: () async throws -> Void) async -> ResponseTooLargeException? {
        do {
            try await body()
            XCTFail("expected the body to be refused")
        } catch let error as ResponseTooLargeException {
            return error
        } catch {
            XCTFail("unexpected \(error)")
        }
        return nil
    }

    func testAConfigBodyOver1MiBIsRefusedByItsContentLengthBeforeItIsRead() async throws {
        server.enqueue(TestServer.Response(status: 200, body: Data(repeating: 0x20, count: Int(oneMiB + 1))))
        let error = await assertTooLarge { _ = try await self.api().fetchConfig(currentVersion: 1) }
        XCTAssertEqual(error?.maxBytes, oneMiB)
        XCTAssertEqual(error?.declared, oneMiB + 1)
        XCTAssertEqual(error?.message, "The config response body exceeds 1048576 bytes (Content-Length: 1048577); refused")
    }

    func testAChunkedConfigBodyIsCutOffAtTheLimitWhileItIsRead() async throws {
        server.enqueue(TestServer.Response(status: 200, headers: ["Transfer-Encoding": "chunked"], body: Data(repeating: 0x20, count: Int(oneMiB + 1))))
        let error = await assertTooLarge { _ = try await self.api().fetchConfig(currentVersion: 1) }
        XCTAssertNotNil(error)
        XCTAssertNil(error?.declared, "not from a declared length")
    }

    func testAVaultDownloadOverItsLimitIsRefusedDeclaredOrChunkedAndOneAtTheLimitIsRead() async throws {
        let api = makeConfigApi(server, vaultBodyLimit: 1_000)

        server.enqueue(TestServer.Response(status: 200, headers: ["X-Vault-Version": "4"], body: Data(count: 1_001)))
        let declared = await assertTooLarge { _ = try await api.downloadVaultFileWithMeta(endpoint: "api/v1/vault/model") }
        XCTAssertEqual(declared?.declared, 1_001)

        server.enqueue(TestServer.Response(status: 200, headers: ["X-Vault-Version": "4", "Transfer-Encoding": "chunked"], body: Data(count: 1_001)))
        let chunked = await assertTooLarge { _ = try await api.downloadVaultFileWithMeta(endpoint: "api/v1/vault/model") }
        XCTAssertNil(chunked?.declared)

        server.enqueue(TestServer.Response(status: 200, headers: ["X-Vault-Version": "4"], body: Data(count: 1_000)))
        let atLimit = try await api.downloadVaultFileWithMeta(endpoint: "api/v1/vault/model")
        XCTAssertEqual(atLimit.content.count, 1_000)

        // The one-argument download reads with the same ceiling.
        server.enqueue(TestServer.Response(status: 200, body: Data(count: 1_001)))
        let single = await assertTooLarge { _ = try await api.downloadVaultFile(endpoint: "api/v1/vault/model") }
        XCTAssertEqual(single?.maxBytes, 1_000)
    }

    func testALongErrorBodyIsCutNotRefusedSoTheStatusStillReachesTheRouter() async throws {
        server.enqueue(.status(412, String(repeating: "x", count: 5_000)))
        do {
            _ = try await makeConfigApi(server, vaultBodyLimit: 1_000).downloadVaultFileWithMeta(endpoint: "api/v1/vault/model")
            XCTFail("expected the refusal")
        } catch let error as VaultFetchHttpException {
            XCTAssertEqual(error.code, 412)
            XCTAssertEqual(error.body?.count, 200)
            XCTAssertTrue(error.message.hasPrefix("Vault fetch failed: HTTP 412 — xxx"))
        }
    }

    func testAnOversizedP12OrEnrollmentAnswerIsRefused() async throws {
        let tooBig = Data(count: (256 << 10) + 1)
        server.enqueue(TestServer.Response(status: 200, headers: ["Content-Type": "application/octet-stream"], body: tooBig))
        server.enqueue(TestServer.Response(status: 200, headers: ["X-P12-SHA256": "hash"], body: tooBig))
        let api = api()
        _ = await assertTooLarge { _ = try await api.downloadHostClientCert(hostname: "host.com") }
        _ = await assertTooLarge { _ = try await api.enroll(token: "tok", deviceId: nil, deviceAlias: nil, deviceUid: nil) }
    }

    // MARK: Reports and attestation

    func testAVaultReportPostsItsFieldsAndNeverThrows() async throws {
        enqueueJSON("{}")
        let api = api()
        try await api.reportVaultDownload(VaultDownloadReport(
            key: "flags", version: 3, status: "failed", deviceManufacturer: "Apple", deviceModel: "iPhone17,1",
            enrollmentLabel: "default", deviceId: "dev", deviceAlias: "Phone", failureReason: "signature_invalid", authMethod: "token"
        ))
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.path, "/api/v1/vault/report")
        let body = request.jsonBody
        XCTAssertEqual(body["key"] as? String, "flags")
        XCTAssertEqual(body["version"] as? Int, 3)
        XCTAssertEqual(body["failureReason"] as? String, "signature_invalid")
        XCTAssertEqual(body["authMethod"] as? String, "token")

        server.stop()
        try await api.reportVaultDownload(VaultDownloadReport(
            key: "flags", version: 3, status: "downloaded", deviceManufacturer: "Apple", deviceModel: "x",
            enrollmentLabel: "default", deviceId: "dev", deviceAlias: "Phone"
        ))
    }

    func testAttestEndpointsReturnTheServersJSONAndMapRefusals() async throws {
        enqueueJSON(#"{"nonce":"abc","expiresIn":60,"serverTime":1}"#)
        server.enqueue(.status(403, #"{"error":"device_revoked","message":"gone"}"#))
        let api = api()
        let challenge = try await api.attestChallenge()
        XCTAssertEqual(challenge["nonce"] as? String, "abc")
        XCTAssertEqual(server.takeRequest()?.path, "/api/v1/attest/challenge")
        do {
            _ = try await api.attest(Data(#"{"report":1}"#.utf8))
            XCTFail("expected a refusal")
        } catch let error as AttestationHttpException {
            XCTAssertEqual(error.httpStatus, 403)
            XCTAssertEqual(error.serverError, "device_revoked")
            XCTAssertEqual(error.serverMessage, "gone")
            XCTAssertEqual(error.message, "Attestation refused — HTTP 403 device_revoked: gone")
        }
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(String(decoding: request.body, as: UTF8.self), #"{"report":1}"#)
    }

    // MARK: Scoped fetches

    func testAScopedFetchSendsHostsAndTheDeviceId() async throws {
        let key = TestSigner()
        let payload = freshPayload()
        enqueueJSON(json(SignedConfigResponse(payload: payload, signature: key.sign(payload))))
        _ = try await api(signaturePublicKey: key.pub).fetchScopedConfig(currentVersion: 2, hosts: ["a.example.com", "b.example.com"], deviceId: "dev-1")
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.query("hosts"), "a.example.com,b.example.com")
        XCTAssertEqual(request.query("currentVersion"), "2")
        XCTAssertEqual(request.header("X-Device-Id"), "dev-1")
        XCTAssertEqual(request.features, ["redelivery", "multisig", "keyset", "forbidden-as-409"])
    }
}
