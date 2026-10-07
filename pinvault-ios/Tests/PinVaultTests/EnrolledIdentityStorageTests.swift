import Security
import XCTest
@testable import PinVault

/// A Keychain that fails right now says nothing about an enrolled identity:
/// loading it presents nothing but keeps everything (A2), and the enroll
/// paths read the credential store strictly, so "cannot read" never looks
/// like "not enrolled" and never costs the key behind a stored chain (A8)
/// (Kotlin `EnrolledIdentityStorageTest`).
final class EnrolledIdentityStorageTests: XCTestCase {

    private var cipher: FlakyCipher!
    private var environment: SecureStoreEnvironment!
    private var label = ""
    private var key: (any ClientIdentityKeyProvider)!
    private var chain: [String] = []
    private var presented = 0

    override func setUpWithError() throws {
        cipher = FlakyCipher()
        environment = try testStoreEnvironment(self, cipher: cipher)
        label = uniqueLabel("identity")
        key = ClientIdentityKeys.software(label: label)
        try key.ensureKeyPair()
        let ca = ClientCertTestCA()
        let leaf = ca.issue(spki: try SPKI.der(for: key.publicKey()), notBefore: Date(), notAfter: Date().addingTimeInterval(90 * ClientCertTestCA.day))
        chain = [Pkcs10Csr.toPem(leaf), ca.pem]
        try store(strict: false).saveChain(label, pemChain: chain)
    }

    override func tearDown() {
        try? key.clear()
    }

    private func store(strict: Bool) throws -> ClientCertSecureStore {
        strict ? try ClientCertSecureStore.openStrict(environment: environment) : try ClientCertSecureStore.open(environment: environment)
    }

    /// What the loader does with a chain: the identity must be over the key, then it is presented.
    private func present(_ key: any ClientIdentityKeyProvider, _ chain: [X509Certificate]) throws {
        _ = try key.privateKey()
        guard try SPKI.der(for: key.publicKey()) == chain[0].subjectPublicKeyInfo else { throw EnrolledIdentity.NotOverKey() }
        presented += 1
    }

    private func load(_ store: ClientCertSecureStore, _ key: any ClientIdentityKeyProvider) -> ClientIdentityLoader.EnrolledChain {
        ClientIdentityLoader.loadEnrolledChain(certStore: store, label: label, key: key, present: present)
    }

    /// `key` with one operation made to fail.
    private struct Failing: ClientIdentityKeyProvider {
        let base: any ClientIdentityKeyProvider
        var existsOverride: (@Sendable () -> Bool)?
        var privateKeyOverride: (@Sendable () throws -> SecKey)?

        func ensureKeyPair() throws { try base.ensureKeyPair() }
        func exists() -> Bool { existsOverride?() ?? base.exists() }
        func publicKey() throws -> SecKey {
            if let privateKeyOverride { _ = try privateKeyOverride() }
            return try base.publicKey()
        }
        func privateKey() throws -> SecKey { try privateKeyOverride?() ?? base.privateKey() }
        func sign(_ data: Data) throws -> Data { try base.sign(data) }
        func clear() throws { try base.clear() }
    }

    // MARK: A2: loading the enrolled chain

    func testAReadableChainOverAnExistingKeyIsPresented() throws {
        XCTAssertEqual(load(try store(strict: false), key), .loaded)
        XCTAssertEqual(presented, 1)
    }

    func testAChainTheStoreCannotDecryptRightNowIsKeptNotDropped() throws {
        cipher.broken = true
        let s = try store(strict: false)
        XCTAssertEqual(try s.mode(label), .chain)
        XCTAssertNil(try s.loadChain(label), "the non-strict store reads it as absent")

        XCTAssertEqual(load(s, key), .unavailable)
        XCTAssertEqual(presented, 0)
        cipher.broken = false
        XCTAssertEqual(try store(strict: false).loadChain(label), chain)
        XCTAssertTrue(key.exists())
    }

    func testAKeychainErrorReadingTheKeyKeepsTheChainAndTheKey() throws {
        let busy = Failing(base: key, privateKeyOverride: { throw ProviderException(message: "Keychain operation failed") })
        XCTAssertEqual(load(try store(strict: false), busy), .unavailable)
        // The Keychain cannot say whether the key exists: it reads as existing, and its use fails.
        let unreachable = Failing(base: key, existsOverride: { true }, privateKeyOverride: { throw ProviderException(message: "Keychain unavailable") })
        XCTAssertEqual(load(try store(strict: false), unreachable), .unavailable)
        XCTAssertEqual(try store(strict: false).loadChain(label), chain)
        XCTAssertTrue(key.exists())
    }

    func testAMissingOrDifferentKeyOrAChainThatDoesNotParseEndsTheEnrollment() throws {
        // A key that is not the one the certificate names (a new key under the label).
        let other = ClientIdentityKeys.software(label: uniqueLabel("other"))
        try other.ensureKeyPair()
        XCTAssertEqual(load(try store(strict: false), other), .dropped)
        XCTAssertFalse(try store(strict: false).exists(label))
        try other.clear()

        try store(strict: false).saveChain(label, pemChain: chain)
        try key.clear()
        XCTAssertEqual(load(try store(strict: false), key), .dropped)
        XCTAssertFalse(try store(strict: false).exists(label))

        try key.ensureKeyPair()
        try store(strict: false).saveChain(label, pemChain: ["not a certificate"])
        XCTAssertEqual(load(try store(strict: false), key), .dropped)
        XCTAssertEqual(presented, 0)
    }

    // MARK: A8: the enroll paths' checks

    func testAStrictStoreSaysCannotTellWhereThePlainOneSaysNothingStored() throws {
        cipher.broken = true
        XCTAssertNil(try store(strict: false).loadChain(label))
        assertStoreUnreadable("a strict read") { _ = try self.store(strict: true).loadChain(self.label) }
    }

    func testAKeyUnderAStoredChainIsNeverDeletedByAnEnrollmentAnswer() throws {
        XCTAssertFalse(EnrollmentRequests.mayDeleteKey(certStore: try store(strict: true), certLabel: label), "a chain is stored over this key")

        XCTAssertFalse(EnrollmentRequests.mayDeleteKey(certStore: try throwingStore(), certLabel: label), "cannot tell: keep it")

        try store(strict: false).clear(label)
        XCTAssertTrue(EnrollmentRequests.mayDeleteKey(certStore: try store(strict: true), certLabel: label))
    }

    /// A cipher whose name lookups fail after the first (the namespace tag is computed when the store is made).
    private final class FailingMac: PrefsCipher, @unchecked Sendable {
        let base: any PrefsCipher
        let calls = Locked(0)
        init(_ base: any PrefsCipher) { self.base = base }
        func seal(_ plaintext: Data, aad: Data) throws -> Data { try base.seal(plaintext, aad: aad) }
        func open(_ sealed: Data, aad: Data) throws -> Data { try base.open(sealed, aad: aad) }
        func mac(_ input: Data) throws -> Data {
            let n = calls.withLock { count -> Int in defer { count += 1 }; return count }
            if n > 0 { throw ProviderException(message: "Keychain operation failed") }
            return try base.mac(input)
        }
    }

    /// A strict store whose name lookups fail too (the name key is in the Keychain as well).
    private func throwingStore() throws -> ClientCertSecureStore {
        let failing = SecureStoreEnvironment(directory: environment.directory, cipher: FailingMac(cipher))
        return try ClientCertSecureStore.openStrict(environment: failing)
    }

    func testAnAttestationRefusalDoesNotTakeTheKeyFromUnderAStoredChain() async throws {
        let refusing = ScriptedEnrollmentApi(takesIntegrityToken: false)
        refusing.answer(throwing: .enrollmentRefused(httpStatus: 403, serverError: "attestation_required", serverMessage: "no chain"))
        let (store, key, label) = (try store(strict: true), self.key!, self.label)
        await expectRefusal("attestation_required") {
            try await EnrollmentRequests.send(
                api: refusing, certStore: store, key: key, certLabel: label, token: "tok", deviceId: nil,
                deviceAlias: nil, deviceUid: "uid"
            ) { Data([1]) }
        }
        XCTAssertTrue(key.exists(), "the key behind the stored chain stays")
        XCTAssertNotNil(try self.store(strict: false).loadChain(label))
    }
}
