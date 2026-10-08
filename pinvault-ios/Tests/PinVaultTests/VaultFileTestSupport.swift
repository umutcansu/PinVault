import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// A software stand-in for the Keychain's user-auth key (Kotlin test helper
/// `SoftwareUserAuthKeys`). The platform's part (refusing the key, losing it,
/// failing for a moment) is played by the flags. Grants are single-use by
/// default, like an Android per-use cipher; `reusableGrants` plays the iOS
/// `LAContext`, which serves every use until it is invalidated.
final class SoftwareUserAuthKeys: UserAuthKeys, @unchecked Sendable {
    private struct State {
        var screenLock = true
        var kind = UserAuthKeyKind.perUse
        var key: SecKey?
        var retired = false
        var stateError: (any Error)?
        var unwrapError: (any Error)?
        var generated = 0
        var chain: [Data] = []
        var reusableGrants = false
        var unwraps = 0
    }

    private let store = Locked(State())

    var screenLock: Bool { get { store.get().screenLock } set { store.withLock { $0.screenLock = newValue } } }
    var kindValue: UserAuthKeyKind { get { store.get().kind } set { store.withLock { $0.kind = newValue } } }
    var key: SecKey? { get { store.get().key } set { store.withLock { $0.key = newValue } } }
    var retired: Bool { get { store.get().retired } set { store.withLock { $0.retired = newValue } } }
    /// Thrown by state() while set: a Keychain hiccup, not a missing key.
    var stateError: (any Error)? { get { store.get().stateError } set { store.withLock { $0.stateError = newValue } } }
    /// Thrown by unwrap() while set.
    var unwrapError: (any Error)? { get { store.get().unwrapError } set { store.withLock { $0.unwrapError = newValue } } }
    var generated: Int { store.get().generated }
    var unwraps: Int { store.get().unwraps }
    var chain: [Data] { get { store.get().chain } set { store.withLock { $0.chain = newValue } } }
    var reusableGrants: Bool { get { store.get().reusableGrants } set { store.withLock { $0.reusableGrants = newValue } } }

    func isScreenLockSet() -> Bool { screenLock }

    func state() throws -> UserAuthKeyState {
        let current = store.get()
        if let error = current.stateError { throw error }
        if current.key == nil { return .missing }
        return current.retired ? .invalidated : .usable
    }

    @discardableResult
    func ensureKey() throws -> Bool {
        if try state() == .usable { return false }
        let fresh = try rsaPrivateKey()
        store.withLock {
            $0.key = fresh
            $0.retired = false
            $0.generated += 1
        }
        return true
    }

    func publicKey() throws -> SecKey {
        guard let key else { throw UserAuthKeyError.retired("no key") }
        return SecKeyCopyPublicKey(key)!
    }

    func kind() throws -> UserAuthKeyKind { kindValue }

    func grantForPrompt() throws -> UserAuthGrant? {
        let current = store.get()
        if current.key == nil || current.retired { throw UserAuthKeyError.retired("retired") }
        if current.kind == .timeBound { return nil }
        return UserAuthGrant(context: nil, singleUse: !current.reusableGrants)
    }

    func unwrap(_ grant: UserAuthGrant?, _ wrapped: Data) throws -> Data {
        let current = store.withLock { state -> State in
            state.unwraps += 1
            return state
        }
        if let error = current.unwrapError { throw error }
        guard let key = current.key else { throw UserAuthKeyError.retired("no key") }
        return try UserAuthKeyConstants.unwrap(wrapped, with: key)
    }

    func attestationChain() throws -> [Data] { chain }

    func delete() {
        store.withLock {
            $0.key = nil
            $0.retired = false
        }
    }

    /// What the server sends for a `user_auth` (and `end_to_end`) file: the
    /// envelope over `publicKey`, RSA-OAEP SHA-256 with MGF1-SHA256.
    static func serverEnvelope(_ content: Data, _ publicKey: SecKey) throws -> Data {
        let sessionKey = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(content, using: sessionKey, nonce: AES.GCM.Nonce())
        let wrapped = try UserAuthKeyConstants.wrap(sessionKey.withUnsafeBytes { Data($0) }, for: publicKey)
        var envelope = Data()
        withUnsafeBytes(of: UInt32(wrapped.count).bigEndian) { envelope.append(contentsOf: $0) }
        envelope.append(wrapped)
        envelope.append(contentsOf: sealed.nonce)
        envelope.append(sealed.ciphertext)
        envelope.append(sealed.tag)
        return envelope
    }
}

/// An RSA-2048 private key in memory.
func rsaPrivateKey() throws -> SecKey {
    try DeviceKeyKeychain.ephemeralRSA()
}

/// The public half of `key`.
func publicOf(_ key: SecKey) -> SecKey {
    SecKeyCopyPublicKey(key)!
}

/// In-memory ``VaultStorageProvider`` (Kotlin `MemVaultStore`).
final class MemVaultStore: VaultStorageProvider, @unchecked Sendable {
    private struct State {
        var blobs: [String: Data] = [:]
        var versions: [String: Int] = [:]
    }

    private let state = Locked(State())

    var blobs: [String: Data] {
        get { state.get().blobs }
    }

    func setBlob(_ key: String, _ blob: Data) { state.withLock { $0.blobs[key] = blob } }
    func setVersion(_ key: String, _ version: Int) { state.withLock { $0.versions[key] = version } }

    func save(key: String, bytes: Data, version: Int) throws {
        state.withLock {
            $0.blobs[key] = bytes
            $0.versions[key] = version
        }
    }

    func load(key: String) throws -> Data? { state.get().blobs[key] }
    func getVersion(key: String) throws -> Int { state.get().versions[key] ?? 0 }
    func exists(key: String) throws -> Bool { state.get().blobs[key] != nil }

    func clear(key: String) throws {
        state.withLock {
            $0.blobs[key] = nil
            $0.versions[key] = nil
        }
    }
}

/// A prompt that records what it was shown and answers with `outcome`.
final class RecordingPrompt: @unchecked Sendable {
    private struct State {
        var shown = 0
        var kind: UserAuthKeyKind?
        var grant: UserAuthGrant?
        var hadGrant = false
    }

    private let state = Locked(State())
    private let outcome: @Sendable (UserAuthGrant?) -> AuthOutcome

    init(_ outcome: @escaping @Sendable (UserAuthGrant?) -> AuthOutcome) {
        self.outcome = outcome
    }

    static func passes() -> RecordingPrompt { RecordingPrompt { .succeeded($0) } }

    var shown: Int { state.get().shown }
    var kind: UserAuthKeyKind? { state.get().kind }
    var hadGrant: Bool { state.get().hadGrant }

    var fn: UserAuthAuthenticate {
        { kind, grant in
            self.state.withLock {
                $0.shown += 1
                $0.kind = kind
                $0.grant = grant
                $0.hadGrant = grant != nil
            }
            return self.outcome(grant)
        }
    }
}

/// A ``CertificateConfigApi`` whose vault calls are closures and are recorded.
final class VaultApiStub: CertificateConfigApi, @unchecked Sendable {
    struct Download: Equatable {
        let endpoint: String
        let currentVersion: Int
        let deviceId: String?
        let accessToken: String?
    }

    struct Registration: Equatable {
        let deviceId: String
        let publicKeyPem: String
        let attestationChain: [String]
    }

    private struct State {
        var downloads: [Download] = []
        var userAuthRegistrations: [Registration] = []
        var deviceRegistrations: [Registration] = []
        var reports: [VaultDownloadReport] = []
    }

    private let state = Locked(State())
    private let handlers = Locked(Handlers())

    struct Handlers {
        var download: (@Sendable (Download) throws -> VaultFetchResponse)?
        var registerUserAuth: (@Sendable (Registration) async throws -> Void)?
        var registerDevice: (@Sendable (Registration) async throws -> Void)?
        var report: (@Sendable (VaultDownloadReport) async throws -> Void)?
    }

    var downloads: [Download] { state.get().downloads }
    var askedVersions: [Int] { downloads.map(\.currentVersion) }
    var userAuthRegistrations: [Registration] { state.get().userAuthRegistrations }
    var deviceRegistrations: [Registration] { state.get().deviceRegistrations }
    var reports: [VaultDownloadReport] { state.get().reports }

    func onDownload(_ handler: @escaping @Sendable (Download) throws -> VaultFetchResponse) {
        handlers.withLock { $0.download = handler }
    }

    func answer(_ response: VaultFetchResponse) { onDownload { _ in response } }

    func onRegisterUserAuth(_ handler: @escaping @Sendable (Registration) async throws -> Void) {
        handlers.withLock { $0.registerUserAuth = handler }
    }

    func onRegisterDevice(_ handler: @escaping @Sendable (Registration) async throws -> Void) {
        handlers.withLock { $0.registerDevice = handler }
    }

    func onReport(_ handler: @escaping @Sendable (VaultDownloadReport) async throws -> Void) {
        handlers.withLock { $0.report = handler }
    }

    func healthCheck() async throws -> Bool { true }
    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { CertificateConfig(version: currentVersion, pins: []) }
    func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        EnrollmentResult(p12Bytes: Data())
    }

    func downloadVaultFileWithMeta(endpoint: String, currentVersion: Int, deviceId: String?, accessToken: String?) async throws -> VaultFetchResponse {
        let download = Download(endpoint: endpoint, currentVersion: currentVersion, deviceId: deviceId, accessToken: accessToken)
        state.withLock { $0.downloads.append(download) }
        guard let handler = handlers.get().download else { throw URLError(.notConnectedToInternet) }
        return try handler(download)
    }

    func registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: [String]) async throws {
        let registration = Registration(deviceId: deviceId, publicKeyPem: publicKeyPem, attestationChain: attestationChain)
        state.withLock { $0.userAuthRegistrations.append(registration) }
        try await handlers.get().registerUserAuth?(registration)
    }

    func registerDevicePublicKey(deviceId: String, publicKeyPem: String) async throws {
        let registration = Registration(deviceId: deviceId, publicKeyPem: publicKeyPem, attestationChain: [])
        state.withLock { $0.deviceRegistrations.append(registration) }
        try await handlers.get().registerDevice?(registration)
    }

    func reportVaultDownload(_ report: VaultDownloadReport) async throws {
        state.withLock { $0.reports.append(report) }
        try await handlers.get().report?(report)
    }
}

/// ``VaultApiStub`` that also takes a key proof, like PinVault's own API client.
final class ProofApiStub: VaultKeyProofRegistering, CertificateConfigApi, @unchecked Sendable {
    let base = VaultApiStub()
    private let proofs = Locked<[(kind: String, deviceId: String, pem: String, proof: VaultDeviceKeyProof?)]>([])

    var recorded: [(kind: String, deviceId: String, pem: String, proof: VaultDeviceKeyProof?)] { proofs.get() }

    func healthCheck() async throws -> Bool { true }
    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { CertificateConfig(version: currentVersion, pins: []) }
    func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        EnrollmentResult(p12Bytes: Data())
    }

    func downloadVaultFileWithMeta(endpoint: String, currentVersion: Int, deviceId: String?, accessToken: String?) async throws -> VaultFetchResponse {
        try await base.downloadVaultFileWithMeta(endpoint: endpoint, currentVersion: currentVersion, deviceId: deviceId, accessToken: accessToken)
    }

    func registerDevicePublicKey(deviceId: String, publicKeyPem: String) async throws {
        proofs.withLock { $0.append(("device-plain", deviceId, publicKeyPem, nil)) }
    }

    func registerDevicePublicKey(deviceId: String, publicKeyPem: String, proof: VaultDeviceKeyProof?) async throws {
        proofs.withLock { $0.append(("device", deviceId, publicKeyPem, proof)) }
    }

    func registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: [String], proof: VaultDeviceKeyProof?,
                                   appAttestation: String?) async throws {
        proofs.withLock { $0.append(("user_auth", deviceId, publicKeyPem, proof)) }
        attestations.withLock { $0.append(appAttestation) }
        body.withLock {
            $0 = try? VaultKeyRegistrationBody.json(publicKeyPem: publicKeyPem, purpose: VaultKeyRegistrationBody.userAuthPurpose,
                                                    attestationChain: attestationChain, appAttestation: appAttestation)
        }
    }

    /// The `appAttestation` of each user-auth registration.
    let attestations = Locked<[String?]>([])
    /// The JSON body the last user-auth registration would send.
    let body = Locked<Data?>(nil)
}

/// Signs vault files the way the server does (`pinvault-vault-file:v1|v2:…`).
extension TestSigner {
    func vaultV1(_ key: String, _ version: Int, _ content: Data) -> String {
        sign("pinvault-vault-file:v1:\(key):\(version):\(Hashing.sha256Hex(content))")
    }

    func vaultV2(_ scope: String, _ key: String, _ version: Int, _ content: Data) -> String {
        sign("pinvault-vault-file:v2:\(scope):\(key):\(version):\(Hashing.sha256Hex(content))")
    }
}

/// A block of the test Config API.
func vaultBlock(id: String = "default", signer: TestSigner? = nil, serverScope: String? = nil,
                signaturePublicKeys: [String] = [], requiredSignatures: Int = 1) -> ConfigApiBlock {
    ConfigApiBlock(
        id: id, configUrl: "https://example.test/", bootstrapPins: [],
        signaturePublicKey: signer?.pub, signaturePublicKeys: signaturePublicKeys,
        requiredSignatures: requiredSignatures, serverScope: serverScope
    )
}

/// The router's view of a block: `api` + the block's trust.
func vaultClient(_ api: any CertificateConfigApi, _ block: ConfigApiBlock) -> VaultFileRouter.Client {
    VaultFileRouter.Client(api: api, block: block, signatureTrust: SignatureTrust.forBlock(block, store: nil))
}

extension Data {
    /// UTF-8 bytes of `text`.
    init(utf8 text: String) { self = Data(text.utf8) }
}

/// Asserts that `result` is `.failed` and returns its parts.
@discardableResult
func failure(_ result: VaultFileResult, file: StaticString = #filePath, line: UInt = #line) -> (reason: String, exception: (any Error)?, code: String) {
    guard case .failed(_, let reason, let exception, let code) = result else {
        XCTFail("expected .failed, was \(result)", file: file, line: line)
        return ("", nil, "")
    }
    return (reason, exception, code)
}

/// Asserts that `result` is `.failed` and returns its reason.
@discardableResult
func unlockFailure(_ result: VaultFileUnlockResult, file: StaticString = #filePath, line: UInt = #line) -> (reason: String, exception: (any Error)?) {
    guard case .failed(_, let reason, let exception) = result else {
        XCTFail("expected .failed, was \(result)", file: file, line: line)
        return ("", nil)
    }
    return (reason, exception)
}
