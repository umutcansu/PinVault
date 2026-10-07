import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of VaultFileSignatureRouterTest: ``VaultFileRouter`` enforces vault
/// file signatures fail-closed — a tampered or unsigned file is NEVER written
/// to storage when a verifying key is configured.
final class VaultFileRouterSignatureTests: XCTestCase {

    private let signer = TestSigner()
    private let second = TestSigner()

    /// Records saves; every stored copy reads as version 1 (Kotlin `MemStore`).
    private final class SaveRecorder: VaultStorageProvider, @unchecked Sendable {
        let saved = Locked<[String: Data]>([:])
        func save(key: String, bytes: Data, version: Int) throws { saved.withLock { $0[key] = bytes } }
        func load(key: String) throws -> Data? { saved.get()[key] }
        func getVersion(key: String) throws -> Int { saved.get()[key] == nil ? 0 : 1 }
        func exists(key: String) throws -> Bool { saved.get()[key] != nil }
        func clear(key: String) throws { saved.withLock { $0[key] = nil } }
    }

    private func router(_ storage: any VaultStorageProvider, _ api: any CertificateConfigApi, _ block: ConfigApiBlock,
                        keys: (any DeviceKeyProvider)? = nil) -> VaultFileRouter {
        VaultFileRouter(clients: [vaultClient(api, block)], storageFor: { _ in storage }, deviceKeyProvider: keys,
                        deviceIdProvider: { "test-device" })
    }

    private func answering(_ response: VaultFetchResponse) -> VaultApiStub {
        let api = VaultApiStub()
        api.answer(response)
        return api
    }

    private func fileFor(_ key: String, configApiId: String = "default") -> VaultFileConfig {
        VaultFileConfig(key: key, endpoint: "api/v1/vault/\(key)", configApiId: configApiId)
    }

    func testAValidSignatureIsAcceptedAndStored() async throws {
        let content = Data(utf8: "truststore-bytes")
        let storage = SaveRecorder()
        let response = VaultFetchResponse(content: content, version: 1, encryption: "plain", signature: signer.vaultV1("ts", 1, content))
        guard case .updated = await router(storage, answering(response), vaultBlock(signer: signer)).fetchFile(fileFor("ts")) else {
            return XCTFail("a valid signature must yield updated")
        }
        XCTAssertEqual(try storage.load(key: "ts"), content)
    }

    func testATamperedSignatureIsRejectedAndNotStored() async throws {
        let storage = SaveRecorder()
        let response = VaultFetchResponse(content: Data(utf8: "real"), version: 1, encryption: "plain",
                                          signature: signer.vaultV1("ts", 1, Data(utf8: "ATTACKER")))
        failure(await router(storage, answering(response), vaultBlock(signer: signer)).fetchFile(fileFor("ts")))
        XCTAssertNil(try storage.load(key: "ts"), "a tampered file must NOT be persisted")
    }

    func testAMissingSignatureWithAKeyConfiguredIsRejected() async throws {
        let storage = SaveRecorder()
        let response = VaultFetchResponse(content: Data(utf8: "real"), version: 1, encryption: "plain")
        failure(await router(storage, answering(response), vaultBlock(signer: signer)).fetchFile(fileFor("ts")))
        XCTAssertNil(try storage.load(key: "ts"), "an unsigned file must NOT be persisted when a key is set")
    }

    func testNoVerifyingKeyBypassesVerification() async throws {
        let storage = SaveRecorder()
        let content = Data(utf8: "legacy")
        let response = VaultFetchResponse(content: content, version: 1, encryption: "plain")
        guard case .updated = await router(storage, answering(response), vaultBlock()).fetchFile(fileFor("ts")) else { return XCTFail() }
        XCTAssertEqual(try storage.load(key: "ts"), content)
    }

    func testAFilesOwnKeyOverridesTheBlocksKeys() async throws {
        let storage = SaveRecorder()
        let content = Data(utf8: "model")
        let own = VaultFileConfig(key: "m", endpoint: "api/v1/vault/m", signaturePublicKey: second.pub)
        let signedByBlock = VaultFetchResponse(content: content, version: 1, signature: signer.vaultV1("m", 1, content))
        failure(await router(storage, answering(signedByBlock), vaultBlock(signer: signer)).fetchFile(own))
        let signedByOwn = VaultFetchResponse(content: content, version: 1, signature: second.vaultV1("m", 1, content))
        guard case .updated = await router(storage, answering(signedByOwn), vaultBlock(signer: signer)).fetchFile(own) else { return XCTFail() }
    }

    // MARK: m-of-n and several trusted keys

    private func twoKeyBlock(_ required: Int) -> ConfigApiBlock {
        vaultBlock(signer: signer, signaturePublicKeys: [signer.pub, second.pub], requiredSignatures: required)
    }

    func testEitherTrustedKeyMaySignWhenOneSignatureIsRequired() async throws {
        let content = Data(utf8: "model-v2")
        let response = VaultFetchResponse(content: content, version: 2, encryption: "plain", signature: second.vaultV1("m", 2, content))
        guard case .updated = await router(SaveRecorder(), answering(response), twoKeyBlock(1)).fetchFile(fileFor("m")) else {
            return XCTFail("a backup-key signature must be accepted")
        }
    }

    func testMOfNOneOfTwoRequiredSignaturesIsRejectedBothAreAccepted() async throws {
        let content = Data(utf8: "model-v2")
        let one = [SignatureEntry(signature: signer.vaultV1("m", 2, content))]
        let duplicated = one + one   // the same signature twice still counts as ONE key
        let both = one + [SignatureEntry(signature: second.vaultV1("m", 2, content))]

        for entries in [one, duplicated] {
            let storage = SaveRecorder()
            let failed = failure(await router(storage, answering(VaultFetchResponse(content: content, version: 2, signatures: entries)),
                                              twoKeyBlock(2)).fetchFile(fileFor("m")))
            XCTAssertTrue(failed.reason.contains("1 of 2 required signatures valid"), failed.reason)
            XCTAssertNil(try storage.load(key: "m"))
        }

        let storage = SaveRecorder()
        guard case .updated = await router(storage, answering(VaultFetchResponse(content: content, version: 2, signatures: both)),
                                           twoKeyBlock(2)).fetchFile(fileFor("m")) else { return XCTFail() }
        XCTAssertEqual(try storage.load(key: "m"), content)
    }

    // MARK: end_to_end: one failure code whatever went wrong in the envelope

    private func e2eFile(_ key: String) -> VaultFileConfig {
        VaultFileConfig(key: key, endpoint: "api/v1/vault/\(key)", configApiId: "default", encryption: .endToEnd)
    }

    /// The device's RSA public key, from the PEM the provider registers with the server.
    private func publicKeyOf(_ provider: any DeviceKeyProvider) throws -> SecKey {
        try provider.ensureKeyPair()
        return try SPKI.secKey(fromSPKI: XCTUnwrap(PEM.decode(provider.getPublicKeyPem(), label: "PUBLIC KEY")))
    }

    func testEveryWayAnEndToEndEnvelopeCanFailGivesTheSameCodeAndReasonWithoutTheExceptionText() async throws {
        let content = Data(utf8: "model")
        let device = DeviceKeys.software(alias: "e2e-codes")
        let other = try rsaPrivateKey()
        let good = try SoftwareUserAuthKeys.serverEnvelope(content, publicKeyOf(device))
        var tampered = good
        tampered[tampered.count - 1] ^= 1
        let wrongKey = try SoftwareUserAuthKeys.serverEnvelope(content, publicOf(other))
        let malformed = Data(count: 8)
        let signature = signer.vaultV1("m", 1, content)

        var failures: [(reason: String, exception: (any Error)?, code: String)] = []
        for (what, envelope) in [("tampered", tampered), ("wrong key", wrongKey), ("malformed", malformed)] {
            let storage = SaveRecorder()
            let response = VaultFetchResponse(content: envelope, version: 1, encryption: "end_to_end", signature: signature)
            let result = await router(storage, answering(response), vaultBlock(signer: signer), keys: device).fetchFile(e2eFile("m"))
            XCTAssertNil(try storage.load(key: "m"), "\(what): nothing stored")
            failures.append(failure(result))
        }
        for failed in failures {
            XCTAssertEqual(failed.code, VaultFileResult.FailureCode.decryptFailed)
            XCTAssertEqual(failed.reason, failures[0].reason, "one text whatever the step")
            if let message = failed.exception.map(VaultErrorText.message), !message.isBlank {
                XCTAssertFalse(failed.reason.contains(message), "the exception's text stays out of the reason")
            }
        }

        let storage = SaveRecorder()
        let response = VaultFetchResponse(content: good, version: 1, encryption: "end_to_end", signature: signature)
        guard case .updated = await router(storage, answering(response), vaultBlock(signer: signer), keys: device).fetchFile(e2eFile("m")) else {
            return XCTFail()
        }
        XCTAssertEqual(try storage.load(key: "m"), content)
    }

    func testAnUnsignedEndToEndAnswerIsRefusedBeforeTheDeviceKeyTouchesIt() async throws {
        final class Watched: DeviceKeyProvider, @unchecked Sendable {
            let inner = DeviceKeys.software(alias: "e2e-unsigned")
            let used = Locked(false)
            func ensureKeyPair() throws { try inner.ensureKeyPair() }
            func getPublicKeyPem() throws -> String { try inner.getPublicKeyPem() }
            func getPrivateKey() throws -> SecKey { used.set(true); return try inner.getPrivateKey() }
            func clear() throws { try inner.clear() }
        }
        let watched = Watched()
        let envelope = try SoftwareUserAuthKeys.serverEnvelope(Data(utf8: "model"), publicKeyOf(watched))
        let response = VaultFetchResponse(content: envelope, version: 1, encryption: "end_to_end")

        let failed = failure(await router(SaveRecorder(), answering(response), vaultBlock(signer: signer), keys: watched).fetchFile(e2eFile("m")))
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.signatureMissing)
        XCTAssertFalse(watched.used.get(), "no signature, no decryption")
    }

    func testAnEndToEndFileWithoutADeviceKeyIsNotConfigured() async throws {
        let response = VaultFetchResponse(content: Data(count: 300), version: 1, encryption: "end_to_end")
        let failed = failure(await router(SaveRecorder(), answering(response), vaultBlock()).fetchFile(e2eFile("m")))
        XCTAssertEqual(failed.reason, "encryption=end_to_end requires DeviceKeyProvider; none configured")
        XCTAssertEqual(failed.code, VaultFileResult.FailureCode.notConfigured)
    }

    func testFailureCodesNameTheClassOfAFailureNeverTheServersText() async throws {
        let content = Data(utf8: "real")
        let refused = VaultApiStub()
        refused.onDownload { _ in throw VaultFetchHTTPError(httpStatus: 401, responseBody: #"{"error":"invalid or revoked token"}"#) }
        let http = failure(await router(SaveRecorder(), refused, vaultBlock(signer: signer)).fetchFile(fileFor("ts")))
        XCTAssertEqual(http.code, "http_401")
        XCTAssertTrue(http.reason.contains("HTTP 401"), "the app still gets the detail")
        XCTAssertEqual(http.reason, #"Vault fetch failed: HTTP 401 — {"error":"invalid or revoked token"}"#)

        let forged = VaultFetchResponse(content: content, version: 1, signature: signer.vaultV1("ts", 1, Data(utf8: "ATTACKER")))
        let forgedCode = failure(await router(SaveRecorder(), answering(forged), vaultBlock(signer: signer)).fetchFile(fileFor("ts"))).code
        XCTAssertEqual(forgedCode, VaultFileResult.FailureCode.signatureInvalid)

        let unsigned = VaultFetchResponse(content: content, version: 1)
        let unsignedCode = failure(await router(SaveRecorder(), answering(unsigned), vaultBlock(signer: signer)).fetchFile(fileFor("ts"))).code
        XCTAssertEqual(unsignedCode, VaultFileResult.FailureCode.signatureMissing)

        let offline = VaultApiStub()
        offline.onDownload { _ in throw URLError(.cannotFindHost) }
        let offlineCode = failure(await router(SaveRecorder(), offline, vaultBlock(signer: signer)).fetchFile(fileFor("ts"))).code
        XCTAssertEqual(offlineCode, VaultFileResult.FailureCode.network)

        struct TooLarge: VaultResponseTooLargeFailure {}
        let large = VaultApiStub()
        large.onDownload { _ in throw TooLarge() }
        let largeCode = failure(await router(SaveRecorder(), large, vaultBlock()).fetchFile(fileFor("ts"))).code
        XCTAssertEqual(largeCode, VaultFileResult.FailureCode.responseTooLarge)

        let unknownApi = failure(await router(SaveRecorder(), answering(unsigned), vaultBlock()).fetchFile(fileFor("ts", configApiId: "gone")))
        XCTAssertEqual(unknownApi.code, VaultFileResult.FailureCode.notConfigured)
        XCTAssertEqual(unknownApi.reason, "VaultFile 'ts' bound to unknown configApi 'gone'")
    }
}

/// Port of VaultFileTokenHeaderTest: a blank `accessToken { … }` result must
/// NOT become an empty `X-Vault-Token` header.
final class VaultFileRouterTokenHeaderTests: XCTestCase {

    private func tokenSent(_ provider: (@Sendable () -> String)?, policy: VaultFileAccessPolicy = .token) async -> VaultApiStub.Download? {
        let api = VaultApiStub()
        api.answer(VaultFetchResponse(content: Data(utf8: "payload"), version: 1, encryption: "plain"))
        let router = VaultFileRouter(clients: [vaultClient(api, vaultBlock())], storageFor: { _ in MemVaultStore() },
                                     deviceKeyProvider: nil, deviceIdProvider: { "test-device" })
        _ = await router.fetchFile(VaultFileConfig(key: "secret", endpoint: "api/v1/vault/secret", configApiId: "default",
                                                   accessPolicy: policy, accessTokenProvider: provider))
        return api.downloads.first
    }

    func testAnEmptyTokenIsNotSentAsAHeader() async {
        let sent = await tokenSent { "" }
        XCTAssertNil(sent?.accessToken, "an empty accessToken must be dropped, not sent as `X-Vault-Token: `")
    }

    func testAWhitespaceOnlyTokenIsNotSentAsAHeader() async {
        let sent = await tokenSent { "   " }
        XCTAssertNil(sent?.accessToken, "a whitespace-only accessToken is still 'no token'")
    }

    func testARealTokenIsSentUnchanged() async {
        let sent = await tokenSent { "real-token-value" }
        XCTAssertEqual(sent?.accessToken, "real-token-value")
        XCTAssertEqual(sent?.deviceId, "test-device")
        XCTAssertEqual(sent?.endpoint, "api/v1/vault/secret")
        XCTAssertEqual(sent?.currentVersion, 0)
    }

    func testAPublicFileSendsNoTokenEvenWhenOneIsConfigured() async {
        let sent = await tokenSent({ "tok" }, policy: .public)
        XCTAssertNil(sent?.accessToken)
    }

    func testABlankDeviceIdIsNotSent() async {
        let api = VaultApiStub()
        api.answer(VaultFetchResponse(content: Data(utf8: "payload"), version: 1))
        let router = VaultFileRouter(clients: [vaultClient(api, vaultBlock())], storageFor: { _ in MemVaultStore() },
                                     deviceKeyProvider: nil, deviceIdProvider: { "" })
        _ = await router.fetchFile(VaultFileConfig(key: "f", endpoint: "api/v1/vault/f"))
        XCTAssertNil(api.downloads.first?.deviceId)
    }
}

/// Port of DeviceKeyProofTest: over a TLS Config API the server keeps a
/// device's first E2E key and replaces it only for a request carrying the
/// device's token for an end_to_end file. The router picks that token per Config API.
final class VaultFileRouterKeyProofTests: XCTestCase {

    private func router(_ clients: [VaultFileRouter.Client] = []) -> VaultFileRouter {
        VaultFileRouter(clients: clients, storageFor: { _ in MemVaultStore() }, deviceKeyProvider: nil, deviceIdProvider: { "ios-07" })
    }

    private func file(_ key: String, api: String = "default-tls", policy: VaultFileAccessPolicy = .token,
                      encryption: VaultFileEncryption = .endToEnd, endpoint: String? = nil,
                      token: (@Sendable () -> String)? = nil) -> VaultFileConfig {
        VaultFileConfig(key: key, endpoint: endpoint ?? "api/v1/vault/\(key)", configApiId: api, accessPolicy: policy,
                        accessTokenProvider: token ?? { "tok-\(key)" }, encryption: encryption)
    }

    func testTheTokenOfAnEndToEndFileOfTheSameConfigApiIsTheProof() {
        let files = [
            file("flags", encryption: .plain),
            file("other-api-model", api: "secure-mtls"),
            VaultFileConfig(key: "public-e2e", endpoint: "api/v1/vault/public-e2e", configApiId: "default-tls", encryption: .endToEnd),
            file("model", endpoint: "api/v1/vault/ml-model-v2?channel=beta"),
        ]
        XCTAssertEqual(router().keyProof("default-tls", files), VaultDeviceKeyProof(vaultKey: "ml-model-v2", token: "tok-model"))
    }

    func testATrailingSlashIsIgnored() {
        XCTAssertEqual(router().keyProof("default-tls", [file("m", endpoint: "api/v1/vault/m-key/")]),
                       VaultDeviceKeyProof(vaultKey: "m-key", token: "tok-m"))
    }

    func testNoProofWithoutAUsableToken() {
        let files = [
            file("blank", token: { "  " }),
            VaultFileConfig(key: "none", endpoint: "api/v1/vault/none", configApiId: "default-tls", accessPolicy: .token, encryption: .endToEnd),
        ]
        XCTAssertNil(router().keyProof("default-tls", files))
        XCTAssertNil(router().keyProof("default-tls", []))
    }

    func testRegistrationCarriesTheProofToTheDefaultApiAndStaysPlainForCustomOnes() async {
        let defaultApi = ProofApiStub()
        let customApi = VaultApiStub()
        let r = router([vaultClient(defaultApi, vaultBlock(id: "default-tls")), vaultClient(customApi, vaultBlock(id: "custom"))])

        await r.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM", files: [file("model")])

        XCTAssertEqual(defaultApi.recorded.map(\.kind), ["device"])
        XCTAssertEqual(defaultApi.recorded.first?.deviceId, "ios-07")
        XCTAssertEqual(defaultApi.recorded.first?.pem, "PEM")
        XCTAssertEqual(defaultApi.recorded.first?.proof, VaultDeviceKeyProof(vaultKey: "model", token: "tok-model"))
        XCTAssertEqual(customApi.deviceRegistrations, [VaultApiStub.Registration(deviceId: "ios-07", publicKeyPem: "PEM", attestationChain: [])])
    }

    func testOneConfigApiThatFailsDoesNotStopTheOthers() async {
        let failing = VaultApiStub()
        failing.onRegisterDevice { _ in throw URLError(.timedOut) }
        let working = VaultApiStub()
        let r = router([vaultClient(failing, vaultBlock(id: "a")), vaultClient(working, vaultBlock(id: "b"))])
        await r.registerDevicePublicKey(deviceId: "ios-07", publicKeyPem: "PEM")
        XCTAssertEqual(failing.deviceRegistrations.count, 1)
        XCTAssertEqual(working.deviceRegistrations.count, 1)
    }
}
