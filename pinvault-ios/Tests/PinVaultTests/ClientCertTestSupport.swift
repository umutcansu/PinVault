import Foundation
import Security
import XCTest
@testable import PinVault

// Shared by the enrollment, renewal and identity tests (L3).

/// A P-256 key pair held in memory (the BouncyCastle key pairs of the Kotlin tests).
struct TestKeyPair: @unchecked Sendable {
    let privateKey: SecKey
    let publicKey: SecKey

    init() {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrIsPermanent: false,
        ]
        privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil)!
        publicKey = SecKeyCopyPublicKey(privateKey)!
    }

    var spki: Data { try! SPKI.der(for: publicKey) }
    var pin: String { SPKI.pin(spki) }

    func sign(_ data: Data) -> Data {
        SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, nil)! as Data
    }
}

/// A certificate authority made in-test (the Kotlin tests' BouncyCastle "server CA").
struct ClientCertTestCA: @unchecked Sendable {
    let keys: TestKeyPair
    let name: Data
    let certificate: X509Certificate

    static let day: TimeInterval = 86_400

    /// A self-signed CA `CN=<cn>`, valid from a day ago for ten years.
    init(cn: String = "PinVault Client CA", now: Date = Date()) {
        keys = TestKeyPair()
        name = Self.name(cn)
        certificate = Self.make(
            issuer: name, subject: name, spki: keys.spki,
            notBefore: now.addingTimeInterval(-Self.day), notAfter: now.addingTimeInterval(3650 * Self.day),
            ca: true, signer: keys
        )
    }

    var pin: String { certificate.spkiPin }
    var pem: String { Pkcs10Csr.toPem(certificate) }

    /// A leaf `CN=<cn>` over `spki`, signed by this CA (or by `signer` under this CA's name).
    func issue(
        cn: String = "PinVault Client: dev-1", spki: Data, notBefore: Date, notAfter: Date,
        issuerName: Data? = nil, signer: TestKeyPair? = nil
    ) -> X509Certificate {
        Self.make(
            issuer: issuerName ?? name, subject: Self.name(cn), spki: spki,
            notBefore: notBefore, notAfter: notAfter, ca: false, signer: signer ?? keys
        )
    }

    /// `SEQUENCE { SET { SEQUENCE { commonName, UTF8String } } }`.
    static func name(_ cn: String) -> Data {
        DER.sequence([DER.set([DER.sequence([try! DER.objectIdentifier(X509OID.commonName), DER.utf8String(cn)])])])
    }

    /// A v3 certificate, ecdsa-with-SHA256.
    static func make(issuer: Data, subject: Data, spki: Data, notBefore: Date, notAfter: Date, ca: Bool, signer: TestKeyPair) -> X509Certificate {
        let algorithm = DER.sequence([try! DER.objectIdentifier(X509OID.ecdsaWithSHA256)])
        var serial = Data(count: 8)
        _ = serial.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 8, $0.baseAddress!) }
        serial[0] &= 0x7F
        var fields = [
            DER.explicit(0, DER.integer(2)),
            DER.integer(unsigned: serial),
            algorithm,
            issuer,
            DER.sequence([DER.time(notBefore), DER.time(notAfter)]),
            subject,
            spki,
        ]
        if ca {
            let basicConstraints = DER.sequence([
                try! DER.objectIdentifier(X509OID.basicConstraints),
                DER.boolean(true),
                DER.octetString(DER.sequence([DER.boolean(true)])),
            ])
            fields.append(DER.explicit(3, DER.sequence([basicConstraints])))
        }
        let tbs = DER.sequence(fields)
        let der = DER.sequence([tbs, algorithm, DER.bitString(signer.sign(tbs))])
        return try! X509Certificate(der: der)
    }
}

/// A store over a fresh directory with in-memory store keys (or `cipher`).
func testCertStore(_ testCase: XCTestCase, cipher: (any PrefsCipher)? = nil, strict: Bool = false) throws -> ClientCertSecureStore {
    let environment = try testStoreEnvironment(testCase, cipher: cipher)
    return strict ? try ClientCertSecureStore.openStrict(environment: environment) : try ClientCertSecureStore.open(environment: environment)
}

/// A store environment over a fresh directory with in-memory store keys (or `cipher`).
func testStoreEnvironment(_ testCase: XCTestCase, cipher: (any PrefsCipher)? = nil) throws -> SecureStoreEnvironment {
    let directory = try temporaryStoreDirectory(testCase)
    if let cipher { return SecureStoreEnvironment(directory: directory, cipher: cipher) }
    return SecureStoreEnvironment(directory: directory)
}

/// A label no other test uses (the in-memory keys live for the process).
func uniqueLabel(_ prefix: String) -> String {
    "\(prefix)-\(UUID().uuidString.prefix(8))"
}

/// A placeholder chain (what the Kotlin tests send where the content does not matter).
let placeholderChain = EnrollmentResult(p12Bytes: Data(), certificateChainPem: ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"])

/// A backend whose enrollment and renewal answers the test scripts (the
/// Kotlin tests' anonymous `CertificateConfigApi`s).
class ScriptedEnrollmentApi: CertificateConfigApi, @unchecked Sendable {

    struct Call: Equatable {
        let token: String?
        let deviceId: String?
        let deviceUid: String?
        let requestId: String?
        let csr: Data
        let attestation: [String]
        let integrityToken: String?
        let arity: Int
        var appAttestation: String? = nil
    }

    private let state = Locked(State())

    private struct State {
        var calls: [Call] = []
        var p12Calls = 0
        var renewCalls: [String?] = []
        var csrAnswers: [(Call) throws -> EnrollmentResult?] = []
    }

    /// The P12 enrollment's answer (`allowServerGeneratedKey`).
    var onEnroll: (@Sendable () throws -> EnrollmentResult)?
    /// The renewal's answer; the default is "unsupported".
    var onRenew: (@Sendable (_ clientId: String, _ csr: Data, _ recoveryUrl: String?) throws -> ClientCertRenewalResponse)?
    /// Whether the eight-argument `enrollWithCsr` (with the integrity token) is implemented.
    let takesIntegrityToken: Bool

    init(takesIntegrityToken: Bool = true) {
        self.takesIntegrityToken = takesIntegrityToken
    }

    var calls: [Call] { state.withLock { $0.calls } }
    var p12Calls: Int { state.withLock { $0.p12Calls } }
    var renewCalls: [String?] { state.withLock { $0.renewCalls } }

    /// Queues the answer of the next CSR enrollment.
    func answer(_ answer: @escaping (Call) throws -> EnrollmentResult?) {
        state.withLock { $0.csrAnswers.append(answer) }
    }

    func answer(_ result: EnrollmentResult?) { answer { _ in result } }

    func answer(throwing error: PinVaultError) { answer { _ in throw error } }

    func healthCheck() async throws -> Bool { true }
    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig { CertificateConfig(version: 0, pins: []) }
    func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }

    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        state.withLock { $0.p12Calls += 1 }
        guard let onEnroll else { throw PinVaultError.illegalState("P12 enrollment was not expected") }
        return try onEnroll()
    }

    func enrollWithCsr(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
        csrDer: Data, requestId: String?, attestationChain: [String]
    ) async throws -> EnrollmentResult? {
        try record(Call(
            token: token, deviceId: deviceId, deviceUid: deviceUid, requestId: requestId, csr: csrDer,
            attestation: attestationChain, integrityToken: nil, arity: 7
        ))
    }

    func enrollWithCsr(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?,
        csrDer: Data, requestId: String?, attestationChain: [String], integrityToken: String?
    ) async throws -> EnrollmentResult? {
        guard takesIntegrityToken else {
            return try await enrollWithCsr(
                token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid,
                csrDer: csrDer, requestId: requestId, attestationChain: attestationChain
            )
        }
        return try record(Call(
            token: token, deviceId: deviceId, deviceUid: deviceUid, requestId: requestId, csr: csrDer,
            attestation: attestationChain, integrityToken: integrityToken, arity: 8
        ))
    }

    func renewClientCert(clientId: String, csrDer: Data, recoveryUrl: String?) async throws -> ClientCertRenewalResponse {
        state.withLock { $0.renewCalls.append(recoveryUrl) }
        guard let onRenew else { return .unsupported }
        return try onRenew(clientId, csrDer, recoveryUrl)
    }

    func record(_ call: Call) throws -> EnrollmentResult? {
        let answer = state.withLock { state -> ((Call) throws -> EnrollmentResult?)? in
            state.calls.append(call)
            return state.csrAnswers.isEmpty ? nil : state.csrAnswers.removeFirst()
        }
        guard let answer else { throw PinVaultError.illegalState("no answer queued for enrollment call \(calls.count)") }
        return try answer(call)
    }
}

/// The SubjectPublicKeyInfo and CN inside a CSR (DER), and whether its signature verifies.
struct ParsedCsr {
    let commonName: String?
    let spki: Data
    let signatureAlgorithm: String
    let attributesEmpty: Bool
    let signatureValid: Bool

    init(_ der: Data) throws {
        let parts = try DER.parse(der).expect(ASN1Tag.sequence).children()
        guard parts.count == 3 else { throw DERError.invalidValue("CertificationRequest must have three parts") }
        let info = try parts[0].expect(ASN1Tag.sequence)
        let fields = try info.children()
        guard fields.count == 4, try fields[0].intValue() == 0 else { throw DERError.invalidValue("bad CertificationRequestInfo") }
        commonName = try X509Certificate.Name(der: fields[1].encoded).commonName
        spki = fields[2].encoded
        attributesEmpty = fields[3].tag == ASN1Tag.contextSpecific(0, constructed: true) && fields[3].content.isEmpty
        signatureAlgorithm = try parts[1].expect(ASN1Tag.sequence).children()[0].objectIdentifier()
        let signature = try parts[2].bitStringBytes()
        let key = try SPKI.secKey(fromSPKI: spki)
        signatureValid = SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, info.encoded as CFData, signature as CFData, nil)
    }
}

/// Runs `body`, expecting a ``PinVaultError/enrollmentRefused(httpStatus:serverError:serverMessage:)``; returns it.
@discardableResult
func expectRefusal(
    _ serverError: String,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> EnrollmentResult
) async -> PinVaultError? {
    do {
        _ = try await body()
        XCTFail("expected a refusal (\(serverError))", file: file, line: line)
    } catch let error as PinVaultError {
        guard case .enrollmentRefused(_, let actual, _) = error else {
            XCTFail("unexpected error \(error)", file: file, line: line)
            return nil
        }
        XCTAssertEqual(actual, serverError, file: file, line: line)
        return error
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
    return nil
}

/// Runs `body`, expecting ``PinVaultError/enrollmentPending(requestId:clientId:serverMessage:retryAfterSeconds:verificationCode:)``;
/// returns (requestId, verificationCode).
@discardableResult
func expectPending(
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> EnrollmentResult
) async -> (requestId: String, code: String?)? {
    do {
        _ = try await body()
        XCTFail("expected to wait", file: file, line: line)
    } catch let PinVaultError.enrollmentPending(requestId, _, _, _, code) {
        return (requestId, code)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
    return nil
}

/// TEST FIXTURE ONLY: a throwaway self-signed RSA-2048 identity
/// (`CN=pinvault-device-test-rsa`, LibreSSL, valid until 2046, password
/// `changeit`, 3DES). It protects nothing. The TLS fixtures are EC only.
let rsaTestP12 = Data(base64Encoded: [
    "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",
].joined())!

/// True when this process can use the Keychain (a signed app; not `swift test`
/// nor a package test bundle in the simulator's `xctest`).
func keychainAvailable() -> Bool {
    let probe: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "io.github.umutcansu.pinvault.tests.probe",
        kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemCopyMatching(probe as CFDictionary, nil)
    return status != errSecMissingEntitlement && status != errSecNotAvailable
}
