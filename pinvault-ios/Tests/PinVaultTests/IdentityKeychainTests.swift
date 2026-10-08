#if os(iOS)
import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// What only a device (or a signed simulator app) can show about the identity
/// keys — the counterpart of the instrumented `KeystoreIdentityDeviceTest`,
/// `ClientCertSecureStoreTest` and `PinVaultEnrollTest`:
///
///  - the identity key is made in the Secure Enclave, signs, cannot be read
///    out, and a CSR over it parses and verifies; the Keychain software
///    fallback says it is software and is refused under `requireHardwareBackedKeys()`;
///  - a certificate issued over the Secure Enclave key becomes a `SecIdentity`
///    through the Keychain and authenticates a TLS client (server requires a
///    client certificate), right after enrollment and after a renewal;
///  - keys that arrive in a PKCS12 (RSA and EC) are imported into the
///    Keychain and authenticate a TLS client from there;
///  - the credential store over the real Keychain store keys.
///
/// A package test bundle on the simulator runs inside `xctest`, which has no
/// Keychain entitlement: these tests skip there. They run hosted in an
/// ad-hoc signed app: `sh pinvault-ios/Tests/IdentityKeychainHost/run-tests.sh <udid>`.
final class IdentityKeychainTests: XCTestCase {

    private let password = "changeit"
    private var labels: [String] = []
    private var server: TestServer?

    override func setUpWithError() throws {
        try XCTSkipUnless(keychainAvailable(), "no Keychain in this process (unsigned xctest): run IdentityKeychainHost/run-tests.sh")
    }

    override func tearDown() {
        server?.stop()
        for label in labels {
            try? ClientIdentityKeys.secureEnclave(label: label).clear()
            KeychainImportedClientKeys().delete(alias: ImportedKeys.aliasFor(label))
        }
    }

    private func label(_ prefix: String) -> String {
        let label = uniqueLabel(prefix)
        labels.append(label)
        return label
    }

    private func startServer() async throws -> TestServer {
        let server = try TestServer(p12: "server", chain: ["intermediate"], clientAuth: .required)
        try await server.start()
        self.server = server
        return server
    }

    /// The CN of the client certificate the server saw, or nil when the connection was refused.
    private func presented(by manager: DynamicSSLManager, to server: TestServer) async -> String? {
        let config = pinConfig("localhost", [TLSFixture.pin("leaf")], mtls: true)
        let session = manager.applyTo(.ephemeral, configProvider: { config })
        let before = server.requestCount
        do {
            let (_, response) = try await session.data(from: server.url())
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        } catch {
            XCTAssertEqual(server.requestCount, before, "a refused connection carries no request")
            return nil
        }
        return server.requests.last?.clientCertificate?.subject.commonName
    }

    private func isExportable(_ key: SecKey) -> Bool {
        SecKeyCopyExternalRepresentation(key, nil) != nil
    }

    // MARK: The identity key

    func testTheIdentityKeyIsMadeInTheSecureEnclaveSignsAndCannotBeReadOut() throws {
        let label = label("se")
        let provider = ClientIdentityKeys.secureEnclave(label: label)
        XCTAssertFalse(provider.exists())
        XCTAssertNil(EnrollmentService().identityKeySecurityLevel(label: label))
        try provider.ensureKeyPair(attestationChallenge: ClientIdentityKeys.attestationChallenge(deviceUid: "device-test-uid"))
        XCTAssertTrue(provider.exists())
        XCTAssertEqual(provider.securityLevel(), SecureEnclave.isAvailable ? .secureEnclave : .software)
        XCTAssertEqual(KeyInspector.securityLevel(try provider.privateKey()), provider.securityLevel())
        XCTAssertTrue(provider.attestationChain().isEmpty, "iOS keys carry no attestation chain")

        let data = Data("handshake transcript".utf8)
        let signature = try provider.sign(data)
        XCTAssertTrue(SecKeyVerifySignature(try provider.publicKey(), .ecdsaSignatureMessageX962SHA256, data as CFData, signature as CFData, nil))
        XCTAssertFalse(isExportable(try provider.privateKey()), "the private key cannot be read out")

        // Another instance for the label finds the same key; an existing key is not replaced.
        let again = ClientIdentityKeys.secureEnclave(label: label)
        let spki = try provider.spkiSha256()
        try again.ensureKeyPair()
        XCTAssertEqual(try again.spkiSha256(), spki)
        XCTAssertEqual(EnrollmentService().identityKeySecurityLevel(label: label), provider.securityLevel())
        XCTAssertNotNil(EnrollmentService().enrollmentVerificationCode(label: label))

        try provider.clear()
        XCTAssertFalse(again.exists())
        XCTAssertNil(EnrollmentService().enrollmentVerificationCode(label: label))
        try again.ensureKeyPair()
        XCTAssertNotEqual(try again.spkiSha256(), spki, "a new identity")
    }

    func testACsrOverTheSecureEnclaveKeyParsesAndVerifies() throws {
        let provider = ClientIdentityKeys.secureEnclave(label: label("csr"))
        try provider.ensureKeyPair()
        let csr = try ParsedCsr(Pkcs10Csr.encode(commonName: "device-test", key: provider))
        XCTAssertTrue(csr.signatureValid)
        XCTAssertEqual(csr.commonName, "device-test")
        XCTAssertEqual(SPKI.pin(csr.spki), try provider.spkiSha256())
    }

    func testTheKeychainSoftwareKeySaysSoIsRefusedUnderRequireHardwareBackedKeysAndTheSecureEnclaveKeyIsNot() throws {
        let label = label("sw")
        let software = ClientIdentityKeys.keychainSoftware(label: label)
        try software.ensureKeyPair()
        XCTAssertEqual(software.securityLevel(), .software)
        let signature = try software.sign(Data("x".utf8))
        XCTAssertTrue(SecKeyVerifySignature(try software.publicKey(), .ecdsaSignatureMessageX962SHA256, Data("x".utf8) as CFData, signature as CFData, nil))
        try software.clear()

        let options = KeystoreOptions()
        options.hardwareBackedRequired = true
        let refused = KeychainClientIdentityKeyProvider(alias: ClientIdentityKeys.aliasFor(label), secureEnclave: false, options: options)
        guard case .hardwareBackedKeyRequired(let kind, let level, _)? = assertThrowsPinVault({ try refused.ensureKeyPair() }) else {
            return XCTFail("a software key must be refused")
        }
        XCTAssertEqual(kind, "Client identity key")
        XCTAssertEqual(level, .software)
        XCTAssertFalse(refused.exists(), "the refused key is deleted")

        try XCTSkipUnless(SecureEnclave.isAvailable, "no Secure Enclave here")
        let hardware = KeychainClientIdentityKeyProvider(alias: ClientIdentityKeys.aliasFor(label), secureEnclave: true, options: options)
        try hardware.ensureKeyPair()
        XCTAssertEqual(hardware.securityLevel(), .secureEnclave)
    }

    func testAnUnlockedDeviceKeyIsMadeWhenTheConfigAsksForIt() throws {
        let options = KeystoreOptions()
        options.unlockedDeviceRequired = true
        let provider = KeychainClientIdentityKeyProvider(alias: ClientIdentityKeys.aliasFor(label("unlocked")), secureEnclave: true, options: options)
        try provider.ensureKeyPair()
        XCTAssertTrue(provider.exists())
        XCTAssertNoThrow(try provider.sign(Data([1])))
    }

    // MARK: The Secure Enclave identity in a handshake

    func testACertificateOverTheSecureEnclaveKeyAuthenticatesATlsClient() async throws {
        let server = try await startServer()
        let label = label("tls")
        let key = ClientIdentityKeys.secureEnclave(label: label)
        try key.ensureKeyPair()
        let ca = ClientCertTestCA()
        let leaf = ca.issue(cn: "PinVault Client: se-device", spki: try SPKI.der(for: key.publicKey()),
                            notBefore: Date().addingTimeInterval(-60), notAfter: Date().addingTimeInterval(30 * ClientCertTestCA.day))

        let identity = try EnrolledIdentity.clientIdentity(key: key, label: label, chain: [leaf, ca.certificate])
        XCTAssertEqual(identity.chain.count, 2)
        XCTAssertEqual(identity.leaf?.der, leaf.der)
        XCTAssertEqual(KeyInspector.securityLevel(identity.identity), key.securityLevel(), "the identity's key is the identity key")

        let manager = testManager()
        manager.loadClientKey(identity)
        let cn = await presented(by: manager, to: server)
        XCTAssertEqual(cn, "PinVault Client: se-device")
        XCTAssertEqual(server.requests.last?.clientCertificate?.der, leaf.der)

        // A certificate over another key never pairs with this one.
        let stranger = ca.issue(spki: TestKeyPair().spki, notBefore: Date(), notAfter: Date().addingTimeInterval(ClientCertTestCA.day))
        XCTAssertThrowsError(try EnrolledIdentity.clientIdentity(key: key, label: label, chain: [stranger, ca.certificate])) { error in
            XCTAssertTrue(error is EnrolledIdentity.NotOverKey, "\(error)")
        }
    }

    func testEnrollmentRenewalAndUnenrollChangeWhatTheSameSessionPresents() async throws {
        let server = try await startServer()
        let label = label("flow")
        let environment = try testStoreEnvironment(self)
        let storage = EnrollmentService.Storage.on(
            environment, identityKeys: { _ in ClientIdentityKeys.secureEnclave(label: label) }, importedKeys: KeychainImportedClientKeys()
        )
        let service = EnrollmentService(storage: storage, deviceId: { "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b" })
        let ca = ClientCertTestCA()
        let api = ScriptedEnrollmentApi()
        api.answer { call in
            let leaf = ca.issue(cn: "PinVault Client: field-1", spki: try ParsedCsr(call.csr).spki,
                                notBefore: Date().addingTimeInterval(-3600), notAfter: Date().addingTimeInterval(90 * ClientCertTestCA.day))
            return EnrollmentResult(p12Bytes: Data(), certificateChainPem: [Pkcs10Csr.toPem(leaf), ca.pem])
        }
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://config.test/") { block in
                block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin("A"), pin("B")])])
                block.allowUnsigned()
                block.clientCertLabel(label)
                block.clientCaPins(ca.pin)
            }
            .build()
        let block = config.defaultConfigApi!
        let manager = testManager()
        let rebuilt = Locked(0)
        let target = EnrollmentService.Target(
            config: config, block: block, api: { api },
            live: .init(sslManager: manager, identityChanged: { rebuilt.withLock { $0 += 1 } })
        )

        let before = await presented(by: manager, to: server)
        XCTAssertNil(before, "not enrolled: no certificate, the server refuses")

        let result = await service.enroll(token: "tok", deviceId: nil, label: nil, target: target)
        XCTAssertEqual(result, .enrolled(keySecurityLevel: SecureEnclave.isAvailable ? .secureEnclave : .software))
        XCTAssertEqual(rebuilt.get(), 1)
        let enrolled = await presented(by: manager, to: server)
        XCTAssertEqual(enrolled, "PinVault Client: field-1")

        // Renewed (forced): the loader presents the new certificate over the same key.
        let certStore = try storage.openStore()
        let loader = ClientIdentityLoader(block: block, certStore: certStore, sslManager: manager, identityKeys: storage.identityKeys, importedKeys: storage.importedKeys)
        api.onRenew = { clientId, csr, _ in
            let leaf = ca.issue(cn: "PinVault Client: \(clientId)-renewed", spki: try ParsedCsr(csr).spki,
                                notBefore: Date().addingTimeInterval(-3600), notAfter: Date().addingTimeInterval(90 * ClientCertTestCA.day))
            return .issued(certificateChainPem: [Pkcs10Csr.toPem(leaf), ca.pem])
        }
        let renewer = ClientCertRenewer(block: block, certStore: certStore, identityKeys: storage.identityKeys, api: { api }, reload: { loader.load() })
        let renewal = await renewer.renewIfNeeded(force: true)
        guard case .renewed(_, .mtls) = renewal else { return XCTFail("\(renewal)") }
        let renewed = await presented(by: manager, to: server)
        XCTAssertEqual(renewed, "PinVault Client: field-1-renewed")

        // A new process: the loader finds the chain and pairs it with the key again.
        let fresh = testManager()
        ClientIdentityLoader(block: block, certStore: try storage.openStore(), sslManager: fresh, identityKeys: storage.identityKeys, importedKeys: storage.importedKeys).load()
        XCTAssertEqual(fresh.defaultClientCertificate()?.subject.commonName, "PinVault Client: field-1-renewed")

        // Unenroll: storage and key gone, the live identity dropped.
        service.forgetIdentity(label: label)
        manager.clearClientKeystore()
        XCTAssertFalse(service.isEnrolled(label: label))
        XCTAssertFalse(ClientIdentityKeys.secureEnclave(label: label).exists())
        let after = await presented(by: manager, to: server)
        XCTAssertNil(after)
    }

    func testTheLoaderDropsAChainWhoseKeyIsGone() throws {
        let label = label("gone")
        let key = ClientIdentityKeys.secureEnclave(label: label)
        try key.ensureKeyPair()
        let ca = ClientCertTestCA()
        let leaf = ca.issue(spki: try SPKI.der(for: key.publicKey()), notBefore: Date(), notAfter: Date().addingTimeInterval(ClientCertTestCA.day))
        let store = try testCertStore(self)
        try store.saveChain(label, pemChain: [Pkcs10Csr.toPem(leaf), ca.pem])
        let block = ConfigApiBlock(id: "blk", configUrl: "https://config.test/", bootstrapPins: [], clientCertLabel: label)
        let manager = testManager()
        let loader = ClientIdentityLoader(block: block, certStore: store, sslManager: manager, identityKeys: { ClientIdentityKeys.secureEnclave(label: $0) }, importedKeys: KeychainImportedClientKeys())

        loader.load()
        XCTAssertEqual(manager.defaultClientCertificate()?.der, leaf.der)

        try key.clear()   // a restored backup on another device, a reset Keychain
        loader.load()
        XCTAssertNil(manager.defaultClientCertificate())
        XCTAssertEqual(try store.mode(label), .none, "dropped: re-enrollment needed")
    }

    // MARK: Keys that arrive in a PKCS12

    func testImportedRsaAndEcKeysStayInTheKeychainAndAuthenticateATlsClient() async throws {
        let server = try await startServer()
        let keys = KeychainImportedClientKeys()
        for (name, p12) in [("rsa", rsaTestP12), ("ec", TLSFixture.p12("client-a"))] {
            let label = label("imported-\(name)")
            let alias = ImportedKeys.aliasFor(label)
            let parsed = try ImportedIdentities.readP12(p12, password: password)
            try keys.importIdentity(alias: alias, identity: parsed.identity, chain: parsed.chain)
            let identity = try XCTUnwrap(try keys.identity(alias: alias, leaf: parsed.chain[0]), name)
            XCTAssertEqual(KeyInspector.securityLevel(identity), .software, "a Keychain key: software")
            var importedKey: SecKey?
            SecIdentityCopyPrivateKey(identity, &importedKey)
            XCTAssertNotNil(try KeychainIdentities.privateKey(alias: alias), "stored under its alias")

            let manager = testManager()
            manager.loadClientKey(try ClientIdentity(identity: identity, chain: parsed.chain))
            let cn = await presented(by: manager, to: server)
            XCTAssertEqual(cn, name == "rsa" ? "pinvault-device-test-rsa" : "client-a", name)

            keys.delete(alias: alias)
            XCTAssertNil(try keys.identity(alias: alias, leaf: parsed.chain[0]))
            _ = importedKey
        }
    }

    func testAnImportedIdentityIsLoadedAgainFromTheKeychainAndDroppedWhenItsKeyIsGone() throws {
        let label = label("imported")
        let store = try testCertStore(self)
        let identities = ImportedIdentities(certStore: store, keys: KeychainImportedClientKeys())
        XCTAssertNotNil(try identities.import(label: label, p12: TLSFixture.p12("client-b"), password: password))
        XCTAssertEqual(try store.mode(label), .imported)
        XCTAssertFalse(try store.hasP12(label))

        let loaded = try XCTUnwrap(ImportedIdentities(certStore: store, keys: KeychainImportedClientKeys()).load(label: label))
        XCTAssertEqual(loaded.leaf?.subject.commonName, "client-b")

        KeychainImportedClientKeys().delete(alias: ImportedKeys.aliasFor(label))
        XCTAssertNil(identities.load(label: label))
        XCTAssertEqual(try store.mode(label), .none)
    }

    func testAnImportedKeyIsRefusedUnderRequireHardwareBackedKeys() throws {
        let options = KeystoreOptions()
        options.hardwareBackedRequired = true
        let alias = ImportedKeys.aliasFor(label("hw"))
        let parsed = try ImportedIdentities.readP12(TLSFixture.p12("client-a"), password: password)
        let keys = KeychainImportedClientKeys(options: options)
        guard case .hardwareBackedKeyRequired? = assertThrowsPinVault({
            try keys.importIdentity(alias: alias, identity: parsed.identity, chain: parsed.chain)
        }) else { return XCTFail("a Keychain key is not hardware") }
        XCTAssertNil(try KeychainIdentities.privateKey(alias: alias), "the refused key is deleted")
    }

    // MARK: The credential store over the Keychain store keys

    func testTheCredentialStoreKeepsEveryFormPerLabelWithTheKeychainKeys() throws {
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(
            directory: directory, cipher: KeyedPrefsCipher(source: KeychainPrefsKeySource(requireUnlockedDevice: { false }))
        )
        let store = try ClientCertSecureStore.open(environment: environment)
        try store.save("default", p12: Data([1, 2, 3, 4, 5]))
        try store.save("host_api.example.com", p12: Data([10, 20, 30]))
        try store.saveChain("chain", pemChain: [ClientCertTestCA().pem])
        try store.savePendingRequest("pending", requestId: "r-1", clientId: "c-1")

        // Another store on the file, as after a restart.
        let reopened = try ClientCertSecureStore.openStrict(environment: SecureStoreEnvironment(
            directory: directory, cipher: KeyedPrefsCipher(source: KeychainPrefsKeySource(requireUnlockedDevice: { false }))
        ))
        XCTAssertEqual(try reopened.load("default"), Data([1, 2, 3, 4, 5]))
        XCTAssertEqual(try reopened.load("host_api.example.com"), Data([10, 20, 30]))
        XCTAssertEqual(try reopened.mode("chain"), .chain)
        XCTAssertEqual(try reopened.loadPendingRequest("pending"), .init(requestId: "r-1", clientId: "c-1"))
        try reopened.clear("default")
        XCTAssertFalse(try reopened.exists("default"))
        try reopened.clearAll()
        XCTAssertNil(try reopened.load("host_api.example.com"))
    }

    func testIsEnrolledAndUnenrollOnTheAppsStores() throws {
        // `PinVaultEnrollTest` on the app's own stores (Application Support + Keychain).
        let service = EnrollmentService(storage: .shared)
        let store = try ClientCertSecureStore.open()
        let label = label("app")
        XCTAssertFalse(service.isEnrolled(label: label))
        try store.save(label, p12: Data([1, 2, 3]))
        try store.save("host_x_\(label)", p12: Data([2]))
        XCTAssertTrue(service.isEnrolled(label: label))
        service.forgetIdentity(label: "host_x_\(label)")
        XCTAssertTrue(service.isEnrolled(label: label), "another label untouched")
        XCTAssertFalse(service.isEnrolled(label: "host_x_\(label)"))
        service.forgetIdentity(label: label)
        service.forgetIdentity(label: label)
        XCTAssertFalse(service.isEnrolled(label: label))
    }

    // MARK: The CSR the demo server's interop test parses

    /// Writes `Fixtures/enrollment/ios-device.csr` (+ `.json`) from a Secure
    /// Enclave key. Runs only with `TEST_RUNNER_PINVAULT_WRITE_CSR_FIXTURE=1`.
    func testWriteTheCsrFixture() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["PINVAULT_WRITE_CSR_FIXTURE"] == "1", "fixture writer: opt-in")
        let key = ClientIdentityKeys.secureEnclave(label: label("fixture"))
        try key.ensureKeyPair()
        let commonName = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
        let csr = try Pkcs10Csr.encode(commonName: commonName, key: key)
        let spki = try SPKI.der(for: key.publicKey())
        let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/enrollment", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try csr.write(to: directory.appendingPathComponent("ios-device.csr"))
        let expected: [String: String] = [
            "commonName": commonName,
            "spkiSha256": SPKI.pin(spki),
            "verificationCode": try VerificationCode.of(spki: spki),
            "keySecurityLevel": key.securityLevel().wireName,
            // The request hash with deviceUid = the CN, and what App Attest binds (PORTING.md §6).
            "integrityRequestHash": IntegrityRequestHash.of(deviceId: commonName, csrDer: csr),
            "appAttestClientDataHash": EnrollmentAppAttestation.clientDataHash(
                requestHash: IntegrityRequestHash.of(deviceId: commonName, csrDer: csr)
            ).base64EncodedString(),
            "made": "IdentityKeychainTests.testWriteTheCsrFixture (Pkcs10Csr over a Secure Enclave key, iOS simulator)",
        ]
        let json = try JSONSerialization.data(withJSONObject: expected, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try (json + Data("\n".utf8)).write(to: directory.appendingPathComponent("ios-device.json"))
    }
}
#endif
