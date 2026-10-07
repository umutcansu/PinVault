import Security
import XCTest
@testable import PinVault

/// The façade's enrollment flow (Kotlin `PinVault.enroll*` / `isEnrolled` /
/// `unenroll`, and the instrumented `PinVaultEnrollTest`) through
/// ``EnrollmentService``, with in-memory keys and a scripted backend. Loading
/// the new identity into a live SSL manager needs the Keychain:
/// `IdentityKeychainTests` (hosted simulator suite).
final class EnrollmentServiceTests: XCTestCase {

    private var environment: SecureStoreEnvironment!
    private var service: EnrollmentService!
    private var importedKeys: InMemoryImportedClientKeys!
    private var api: ScriptedEnrollmentApi!
    private var ca: ClientCertTestCA!
    private var labelPrefix = ""
    private let password = "changeit"

    override func setUpWithError() throws {
        environment = try testStoreEnvironment(self)
        importedKeys = InMemoryImportedClientKeys()
        // A key namespace of its own: the in-memory keys live for the process.
        let prefix = uniqueLabel("svc")
        labelPrefix = prefix
        service = EnrollmentService(
            storage: .on(environment, identityKeys: { ClientIdentityKeys.software(label: "\(prefix)-\($0)") }, importedKeys: importedKeys),
            deviceId: { "a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90" },
            deviceModel: "Apple iPhone17,1"
        )
        api = ScriptedEnrollmentApi()
        ca = ClientCertTestCA()
    }

    override func tearDown() {
        for label in ["default", "custom", "host_x", "my_host"] {
            try? ClientIdentityKeys.software(label: "\(labelPrefix)-\(label)").clear()
        }
    }

    private func key(_ label: String = "default") -> any ClientIdentityKeyProvider {
        service.storage.identityKeys(label)
    }

    private func store() throws -> ClientCertSecureStore { try service.storage.openStore() }

    private func config(
        label: String = "default", allowServerGeneratedKey: Bool = false, alias: String? = nil,
        guardAllows: Bool = true, url: String = "https://config.test/"
    ) throws -> PinVaultConfig {
        let builder = PinVaultConfig.Builder()
            .configApi("api", url: url) { block in
                block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin("A"), pin("B")])])
                block.allowUnsigned()
                block.clientCertLabel(label)
                if allowServerGeneratedKey { block.allowServerGeneratedKey() }
            }
            .environmentGuard { _ in guardAllows }
        if let alias { builder.deviceAlias(alias) }
        return try builder.build()
    }

    private func target(_ config: PinVaultConfig) -> EnrollmentService.Target {
        let api = self.api!
        return EnrollmentService.Target(
            config: config, block: config.defaultConfigApi!, api: { api }, live: nil,
            environmentRefusal: { PinVault.shared.environmentRefusal(config, .enroll) }
        )
    }

    /// Answers the next CSR enrollment with a chain the test CA issues over the CSR's key.
    private func issueOverTheCsr() {
        let ca = self.ca!
        api.answer { call in
            let spki = try ParsedCsr(call.csr).spki
            let now = Date()
            let leaf = ca.issue(cn: "PinVault Client: dev-1", spki: spki, notBefore: now.addingTimeInterval(-3600),
                                notAfter: now.addingTimeInterval(90 * ClientCertTestCA.day))
            return EnrollmentResult(p12Bytes: Data(), certificateChainPem: [Pkcs10Csr.toPem(leaf), ca.pem])
        }
    }

    // MARK: isEnrolled / unenroll (PinVaultEnrollTest)

    func testIsEnrolledIsFalseWithoutACertificate() throws {
        XCTAssertFalse(service.isEnrolled(label: "default"))
        XCTAssertFalse(service.isEnrolled(config: try config()))
    }

    func testIsEnrolledIsTrueAfterACredentialIsStored() throws {
        try store().save("default", p12: Data([1, 2, 3, 4, 5]))
        XCTAssertTrue(service.isEnrolled(label: "default"))
        XCTAssertTrue(service.isEnrolled(config: try config()))
    }

    func testIsEnrolledWithACustomLabel() throws {
        XCTAssertFalse(service.isEnrolled(label: "my_host"))
        try store().save("my_host", p12: Data([10, 20]))
        XCTAssertTrue(service.isEnrolled(label: "my_host"))
        XCTAssertFalse(service.isEnrolled(label: "default"), "the default label is still empty")
        XCTAssertTrue(service.isEnrolled(config: try config(label: "my_host")))
    }

    func testUnenrollRemovesTheDefaultCertificateItsKeyAndAnImportedKey() throws {
        try store().saveChain("default", pemChain: [ca.pem])
        try store().savePendingRequest("default", requestId: "r", clientId: nil)
        try key().ensureKeyPair()
        _ = try ImportedIdentities(certStore: try store(), keys: importedKeys).import(label: "default", p12: TLSFixture.p12("client-a"), password: password)
        XCTAssertTrue(service.isEnrolled(label: "default"))

        service.forgetIdentity(label: "default")
        XCTAssertFalse(service.isEnrolled(label: "default"))
        XCTAssertFalse(key().exists(), "a re-enrollment is a new identity")
        XCTAssertNil(importedKeys.privateKey(alias: ImportedKeys.aliasFor("default")))
        XCTAssertNil(try store().loadPendingRequest("default"))
    }

    func testUnenrollWithALabelRemovesOnlyThatLabel() throws {
        try store().save("default", p12: Data([1]))
        try store().save("host_x", p12: Data([2]))
        service.forgetIdentity(label: "host_x")
        XCTAssertTrue(service.isEnrolled(label: "default"))
        XCTAssertFalse(service.isEnrolled(label: "host_x"))
    }

    func testADoubleUnenrollIsSafe() {
        service.forgetIdentity(label: "default")
        service.forgetIdentity(label: "default")
        XCTAssertFalse(service.isEnrolled(label: "default"))
    }

    // MARK: Enrollment

    func testEnrollingBeforeStartStoresTheIssuedChainOverTheDevicesKey() async throws {
        issueOverTheCsr()
        let result = await service.enrollBeforeStart(token: "tok", deviceId: nil, target: target(try config(alias: "Field phone 7")))
        XCTAssertEqual(result, .enrolled(keySecurityLevel: .software))

        let call = try XCTUnwrap(api.calls.first)
        XCTAssertEqual(call.token, "tok")
        XCTAssertNil(call.deviceId)
        XCTAssertEqual(call.deviceUid, "a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90")
        let csr = try ParsedCsr(call.csr)
        XCTAssertEqual(csr.commonName, "a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90", "CN = deviceId, else the vendor id")
        XCTAssertEqual(SPKI.pin(csr.spki), try key().spkiSha256())
        XCTAssertTrue(service.isEnrolled(label: "default"))
        XCTAssertEqual(service.enrolledClientCN(label: "default", p12Password: nil), "PinVault Client: dev-1")
        let notAfter = try XCTUnwrap(service.enrolledClientNotAfter(label: "default", p12Password: nil))
        XCTAssertEqual(Double(notAfter), Date().addingTimeInterval(90 * ClientCertTestCA.day).timeIntervalSince1970 * 1000, accuracy: 60_000)
        XCTAssertEqual(service.identityKeySecurityLevel(label: "default"), .software)

        // Enrolled already: answered without the server.
        let again = await service.enrollBeforeStart(token: "tok", deviceId: nil, target: target(try config()))
        XCTAssertEqual(again, .enrolled(alreadyEnrolled: true))
        XCTAssertEqual(api.calls.count, 1)
    }

    func testAutoEnrollSendsTheDeviceIdAsCommonNameAndTheVendorIdAsDeviceUid() async throws {
        issueOverTheCsr()
        let deviceId = service.autoEnrollDeviceId()
        let result = await service.enroll(token: nil, deviceId: deviceId, label: nil, target: target(try config()))
        XCTAssertTrue(result.isEnrolled)
        let call = try XCTUnwrap(api.calls.first)
        XCTAssertEqual(call.deviceId, "a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90")
        XCTAssertEqual(try ParsedCsr(call.csr).commonName, deviceId)
    }

    func testWithoutAVendorIdAutoEnrollUsesUnknownDevice() {
        let service = EnrollmentService(storage: self.service.storage, deviceId: { nil })
        XCTAssertEqual(service.autoEnrollDeviceId(), "unknown-device")
    }

    func testAWaitIsReportedWithTheCodeOfThisDevicesKeyAndCheckedAgainLater() async throws {
        api.answer(throwing: .enrollmentPending(requestId: "r1", clientId: "field-x", serverMessage: "wait", retryAfterSeconds: 30))
        let target = target(try config())
        let result = await service.enroll(token: "CODE-1", deviceId: nil, label: nil, target: target)
        let code = try XCTUnwrap(service.enrollmentVerificationCode(label: "default"))
        XCTAssertEqual(result, .pending(requestId: "r1", clientId: "field-x", message: "wait", retryAfterSeconds: 30, verificationCode: code))
        XCTAssertTrue(service.isEnrollmentPending(label: "default"))
        XCTAssertFalse(service.isEnrolled(label: "default"))

        // Approved: the next check gets the certificate over the same key.
        issueOverTheCsr()
        let approved = await service.checkPendingEnrollment(target: target)
        XCTAssertTrue(approved.isEnrolled)
        XCTAssertEqual(api.calls[1].requestId, "r1")
        XCTAssertFalse(service.isEnrollmentPending(label: "default"))

        // Enrolled now: answered locally.
        let shortcut = await service.checkPendingEnrollment(target: target)
        XCTAssertEqual(shortcut, .enrolled(alreadyEnrolled: true))
        XCTAssertEqual(api.calls.count, 2)
    }

    func testCheckingWithNothingWaitingAsksNoServer() async throws {
        let result = await service.checkPendingEnrollmentBeforeStart(target: target(try config()))
        XCTAssertEqual(result, .failed(message: "No enrollment is waiting for approval"))
        XCTAssertTrue(api.calls.isEmpty)
    }

    func testAPendingEnrollmentIsPickedUpOnItsOwn() async throws {
        try store().savePendingRequest("default", requestId: "r9", clientId: nil)
        try key().ensureKeyPair()
        issueOverTheCsr()
        await service.pickUpPendingEnrollment(target: target(try config()))
        XCTAssertEqual(api.calls.first?.requestId, "r9")
        XCTAssertTrue(service.isEnrolled(label: "default"))

        // Nothing waiting: nothing sent.
        await service.pickUpPendingEnrollment(target: target(try config()))
        XCTAssertEqual(api.calls.count, 1)
    }

    func testARefusalCarriesTheServersReason() async throws {
        api.answer(throwing: .enrollmentRefused(httpStatus: 409, serverError: "device_already_enrolled", serverMessage: "enrolled as field-1"))
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config()))
        XCTAssertEqual(result, .refused(reason: .deviceAlreadyEnrolled, httpStatus: 409, serverError: "device_already_enrolled", message: "enrolled as field-1"))
    }

    func testTheEnvironmentGuardRefusesBeforeAnythingIsSent() async throws {
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(guardAllows: false)))
        guard case .failed(let message, let cause) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(message, "The app's environment guard refused ENROLL on this device")
        guard case PinVaultError.untrustedEnvironment? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertTrue(api.calls.isEmpty)
        XCTAssertFalse(key().exists())
    }

    func testABlockThatStartWouldRefuseDoesNotEnrollBeforeStart() async throws {
        let result = await service.enrollBeforeStart(token: "tok", deviceId: nil, target: target(try config(url: "http://config.test/")))
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertTrue(api.calls.isEmpty)
    }

    /// Store keys that fail altogether while `broken` (a locked or failing Keychain).
    private final class BrokenKeys: PrefsCipher, @unchecked Sendable {
        private let real = KeyedPrefsCipher(source: InMemoryPrefsKeySource())
        private let state = Locked(false)
        var broken: Bool {
            get { state.get() }
            set { state.set(newValue) }
        }
        private func check() throws { if broken { throw ProviderException(message: "Keychain operation failed") } }
        func seal(_ plaintext: Data, aad: Data) throws -> Data { try check(); return try real.seal(plaintext, aad: aad) }
        func open(_ sealed: Data, aad: Data) throws -> Data { try check(); return try real.open(sealed, aad: aad) }
        func mac(_ input: Data) throws -> Data { try check(); return try real.mac(input) }
    }

    func testACredentialStoreThatCannotBeReadSendsNothing() async throws {
        let cipher = BrokenKeys()
        let environment = try testStoreEnvironment(self, cipher: cipher)
        let prefix = labelPrefix
        let service = EnrollmentService(
            storage: .on(environment, identityKeys: { ClientIdentityKeys.software(label: "\(prefix)-\($0)") }, importedKeys: importedKeys),
            deviceId: { "uid" }
        )
        try ClientCertSecureStore.open(environment: environment).saveChain("default", pemChain: [ca.pem])
        cipher.broken = true
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config()))
        guard case .failed(let message, let cause) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(message.hasPrefix("The stored client credentials cannot be read right now (StoreUnreadableException: "), message)
        XCTAssertTrue(message.hasSuffix("); nothing was sent — try again later"), message)
        guard case PinVaultError.storeUnreadable? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertTrue(api.calls.isEmpty)
    }

    func testAChainThatDoesNotCheckOutIsNotStored() async throws {
        // Over another key than the device's.
        let other = TestKeyPair()
        let ca = self.ca!
        api.answer { _ in
            let leaf = ca.issue(spki: other.spki, notBefore: Date().addingTimeInterval(-60), notAfter: Date().addingTimeInterval(ClientCertTestCA.day))
            return EnrollmentResult(p12Bytes: Data(), certificateChainPem: [Pkcs10Csr.toPem(leaf), ca.pem])
        }
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config()))
        XCTAssertEqual(result, .failed(message: "Issued certificate is not over this device's key", cause: PinVaultError.security(message: "Issued certificate is not over this device's key")))
        XCTAssertFalse(service.isEnrolled(label: "default"))
    }

    // MARK: A key the server made (allowServerGeneratedKey)

    func testAServerMadeKeyIsImportedIntoTheKeychainAndOnlyItsChainStored() async throws {
        let p12 = TLSFixture.p12("client-a")
        api.answer(EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(p12)))
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(allowServerGeneratedKey: true)))
        XCTAssertTrue(result.isEnrolled, "\(result)")
        XCTAssertEqual(try store().mode("default"), .imported)
        XCTAssertNotNil(importedKeys.privateKey(alias: ImportedKeys.aliasFor("default")))
        XCTAssertFalse(key().exists(), "no orphan identity key next to a server-made one")
        XCTAssertEqual(service.enrolledClientCN(label: "default", p12Password: nil), "client-a")
    }

    func testAServerMadeKeyTheKeychainRefusesIsKeptAsAP12() async throws {
        let p12 = TLSFixture.p12("client-b")
        importedKeys.refuse(ImportedKeys.aliasFor("default"))
        api.answer(EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(p12)))
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(allowServerGeneratedKey: true)))
        XCTAssertEqual(result, .enrolled(keySecurityLevel: .software))
        XCTAssertEqual(try store().mode("default"), .p12)
        XCTAssertEqual(service.enrolledClientCN(label: "default", p12Password: password), "client-b")
    }

    func testAServerMadeKeyWithoutItsHashOrWithAnotherHashIsRefused() async throws {
        let p12 = TLSFixture.p12("client-a")
        api.answer(EnrollmentResult(p12Bytes: p12))
        let missing = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(allowServerGeneratedKey: true)))
        guard case .failed(let message, _) = missing else { return XCTFail("\(missing)") }
        XCTAssertTrue(message.hasPrefix("Server did not provide X-P12-SHA256 header"), message)

        api.answer(EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(Data([1]))))
        let wrong = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(allowServerGeneratedKey: true)))
        guard case .failed(let wrongMessage, _) = wrong else { return XCTFail("\(wrong)") }
        XCTAssertEqual(wrongMessage, "P12 integrity check failed — SHA-256 mismatch (transport corruption or tampering)")

        api.answer(EnrollmentResult(p12Bytes: p12, p12Hash: "not base64!"))
        let invalid = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config(allowServerGeneratedKey: true)))
        guard case .failed(let invalidMessage, _) = invalid else { return XCTFail("\(invalid)") }
        XCTAssertEqual(invalidMessage, "Invalid X-P12-SHA256 header — not valid Base64. Refusing to install P12.")
        XCTAssertFalse(service.isEnrolled(label: "default"))
    }

    func testAP12WithAOneOffPasswordOpensWithIt() throws {
        let p12 = TLSFixture.p12("client-a")
        let result = EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(p12), p12Password: "changeit")
        XCTAssertEqual(try service.acceptEnrolledP12(result, localPassword: "other"), "changeit")
        XCTAssertThrowsError(try service.acceptEnrolledP12(EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(p12)), localPassword: "other"))
    }

    func testAP12AnswerWithoutTheOptInIsRefused() async throws {
        let p12 = TLSFixture.p12("client-a")
        api.answer(EnrollmentResult(p12Bytes: p12, p12Hash: Hashing.sha256Base64(p12)))
        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target(try config()))
        guard case .failed(let message, let cause) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(message.contains("allowServerGeneratedKey"), message)
        XCTAssertTrue(cause is ServerGeneratedKeyRefusedError)
        XCTAssertFalse(service.isEnrolled(label: "default"))
    }
}
