import CryptoKit
import Foundation
import Security
import XCTest
@testable import PinVault

/// A device key in memory (CryptoKit P-256): the test stand-in for the
/// block's Secure Enclave / Keychain identity key. Its reported level and
/// attestation chain are set by the test; the challenge it was made with is recorded.
final class TestIdentityKey: ClientIdentityKeyProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var key: P256.Signing.PrivateKey?
    private var _challenge: Data?
    private var _level: KeySecurityLevel
    private var _chain: [Data]

    init(level: KeySecurityLevel = .software, chain: [Data] = []) {
        _level = level
        _chain = chain
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

    var level: KeySecurityLevel { get { locked { _level } } set { locked { _level = newValue } } }
    var chain: [Data] { get { locked { _chain } } set { locked { _chain = newValue } } }
    /// The attestation challenge the key was made with.
    var challenge: Data? { locked { _challenge } }

    func ensureKeyPair() throws { try ensureKeyPair(attestationChallenge: nil) }

    func ensureKeyPair(attestationChallenge: Data?) throws {
        locked {
            if key == nil {
                key = P256.Signing.PrivateKey()
                _challenge = attestationChallenge
            }
        }
    }

    func attestationChain() -> [Data] { chain }

    func exists() -> Bool { locked { key != nil } }

    var signingKey: P256.Signing.PrivateKey {
        get throws {
            guard let key = locked({ key }) else { throw PinVaultError.illegalState("no key") }
            return key
        }
    }

    /// The SPKI DER of the public key.
    var spki: Data { get throws { try signingKey.publicKey.derRepresentation } }

    func publicKey() throws -> SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(try signingKey.publicKey.x963Representation as CFData, attributes as CFDictionary, &error) else {
            throw PinVaultError.illegalState("public key: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }

    func privateKey() throws -> SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(try signingKey.x963Representation as CFData, attributes as CFDictionary, &error) else {
            throw PinVaultError.illegalState("private key: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }

    func sign(_ data: Data) throws -> Data {
        try signingKey.signature(for: data).derRepresentation
    }

    func securityLevel() -> KeySecurityLevel { level }

    func clear() throws { locked { key = nil } }
}

/// The attest endpoints of a Config API as a queue of canned answers (the
/// Kotlin tests' MockWebServer). Records every call.
final class FakeAttestationApi: AttestationApi, @unchecked Sendable {

    enum Answer {
        case json(String)
        case http(Int, String)
        case failure(any Error)
    }

    struct Call {
        let endpoint: String
        let body: Data?
        var json: [String: Any] { body.flatMap { LenientJSON.object($0) } ?? [:] }
    }

    private let lock = NSLock()
    private var answers: [Answer] = []
    private var _calls: [Call] = []
    /// Every call fails like an unreachable server.
    var down = false

    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

    func enqueue(_ answer: Answer) { locked { answers.append(answer) } }

    var calls: [Call] { locked { _calls } }
    var requestCount: Int { calls.count }
    /// The attest POST bodies, in order.
    var attestBodies: [[String: Any]] { calls.filter { $0.endpoint == AttestationEndpoints.attest }.map(\.json) }

    func attestChallenge() async throws -> Data {
        try answer(Call(endpoint: AttestationEndpoints.challenge, body: nil))
    }

    func attest(body: Data) async throws -> Data {
        try answer(Call(endpoint: AttestationEndpoints.attest, body: body))
    }

    private func answer(_ call: Call) throws -> Data {
        let next: Answer? = try locked {
            if down { throw URLError(.cannotConnectToHost) }
            _calls.append(call)
            return answers.isEmpty ? nil : answers.removeFirst()
        }
        switch next {
        case .json(let text): return Data(text.utf8)
        case .http(let status, let text): throw AttestationHttpError.of(httpStatus: status, body: Data(text.utf8))
        case .failure(let error): throw error
        case nil: throw URLError(.badServerResponse)
        }
    }
}

/// `DCAppAttestService` in memory: real P-256 keys whose key ids are
/// SHA-256 of the uncompressed point (as Apple's), stand-in attestation
/// objects, and real assertions (CBOR `{signature, authenticatorData}`, the
/// signature over SHA-256(authenticatorData ‖ clientDataHash)) that the
/// PinVault server's verifier checks.
final class FakeAppAttestService: AppAttestService, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private var counters: [String: UInt32] = [:]
    private var _generated: [String] = []
    private var _attested: [(keyId: String, clientDataHash: Data)] = []
    private var _asserted: [(keyId: String, clientDataHash: Data)] = []
    private var _supported: Bool
    /// Errors the next calls throw, in order.
    private var generateErrors: [AppAttestServiceError] = []
    private var attestErrors: [AppAttestServiceError] = []
    private var assertErrors: [AppAttestServiceError] = []
    let appId: String

    init(supported: Bool = true, appId: String = "ABCDE12345.com.example.sampleclient") {
        _supported = supported
        self.appId = appId
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

    var supported: Bool { get { locked { _supported } } set { locked { _supported = newValue } } }
    var generated: [String] { locked { _generated } }
    var attested: [(keyId: String, clientDataHash: Data)] { locked { _attested } }
    var asserted: [(keyId: String, clientDataHash: Data)] { locked { _asserted } }

    func failNextGenerate(_ error: AppAttestServiceError) { locked { generateErrors.append(error) } }
    func failNextAttest(_ error: AppAttestServiceError) { locked { attestErrors.append(error) } }
    func failNextAssertion(_ error: AppAttestServiceError) { locked { assertErrors.append(error) } }
    /// Forgets a key, as a restore to another device does.
    func lose(_ keyId: String) { _ = locked { keys.removeValue(forKey: keyId) } }

    /// The SPKI DER (Base64) of a key, what the server stores after a verified attestation.
    func publicKeySpki(_ keyId: String) -> String? {
        locked { keys[keyId]?.publicKey.derRepresentation.base64EncodedString() }
    }

    var isSupported: Bool { supported }

    func generateKey() async throws -> String {
        try locked {
            if !generateErrors.isEmpty { throw generateErrors.removeFirst() }
            let key = P256.Signing.PrivateKey()
            let keyId = Data(SHA256.hash(data: key.publicKey.x963Representation)).base64EncodedString()
            keys[keyId] = key
            _generated.append(keyId)
            return keyId
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try locked {
            if !attestErrors.isEmpty { throw attestErrors.removeFirst() }
            guard keys[keyId] != nil else { throw AppAttestServiceError.invalidKey }
            _attested.append((keyId, clientDataHash))
            // A stand-in attestation object: CBOR {fmt, attStmt: {}, authData}.
            return MiniCbor.map([
                ("fmt", .text("apple-appattest")),
                ("attStmt", .map([])),
                ("authData", .bytes(Data(SHA256.hash(data: Data(appId.utf8))) + Data([0x40, 0, 0, 0, 0]))),
            ])
        }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try locked {
            if !assertErrors.isEmpty { throw assertErrors.removeFirst() }
            guard let key = keys[keyId] else { throw AppAttestServiceError.invalidKey }
            let counter = (counters[keyId] ?? 0) + 1
            counters[keyId] = counter
            _asserted.append((keyId, clientDataHash))
            var authenticatorData = Data(SHA256.hash(data: Data(appId.utf8)))
            authenticatorData.append(0x01)
            authenticatorData.append(contentsOf: withUnsafeBytes(of: counter.bigEndian, Array.init))
            let nonce = Data(SHA256.hash(data: authenticatorData + clientDataHash))
            let signature = try key.signature(for: nonce).derRepresentation
            return MiniCbor.map([("signature", .bytes(signature)), ("authenticatorData", .bytes(authenticatorData))])
        }
    }
}

/// Just enough CBOR (RFC 8949) for App Attest objects: maps with text keys,
/// byte and text strings.
enum MiniCbor {
    indirect enum Item {
        case bytes(Data)
        case text(String)
        case map([(String, Item)])
    }

    static func map(_ entries: [(String, Item)]) -> Data { encode(.map(entries)) }

    static func encode(_ item: Item) -> Data {
        switch item {
        case .bytes(let data): return head(2, data.count) + data
        case .text(let text): return head(3, text.utf8.count) + Data(text.utf8)
        case .map(let entries):
            var out = head(5, entries.count)
            for (key, value) in entries {
                out += encode(.text(key))
                out += encode(value)
            }
            return out
        }
    }

    private static func head(_ major: UInt8, _ length: Int) -> Data {
        let type = major << 5
        switch length {
        case 0..<24: return Data([type | UInt8(length)])
        case 24..<256: return Data([type | 24, UInt8(length)])
        default: return Data([type | 25, UInt8(length >> 8), UInt8(length & 0xFF)])
        }
    }
}

/// Nonces in the PinVault server's format (`ATTESTATION.md` §2.1):
/// `base64url(ts(8) ‖ rand(16) ‖ HMAC-SHA256(key, ts ‖ rand)[0..16))`, so a
/// fixture made here passes the server's nonce check with the same key and clock.
enum ServerNonce {
    static func make(key: Data, timestampMs: Int64, random: Data = Data((0..<16).map { _ in UInt8.random(in: 0...255) })) -> String {
        var body = withUnsafeBytes(of: timestampMs.bigEndian, { Data($0) })
        body.append(random.prefix(16))
        let mac = Data(HMAC<SHA256>.authenticationCode(for: body, using: SymmetricKey(data: key))).prefix(16)
        return Base64.encodeURL(body + mac)
    }
}

/// A `ConfigApiBlock` for attestation tests.
func attestingBlock(
    _ id: String = "api",
    url: String = "https://config.example.com:8091/",
    tokenHosts: [String] = [],
    wantPinsFor: [String] = [],
    attestation: Bool = true,
    proof: Bool = false
) throws -> ConfigApiBlock {
    let builder = ConfigApiBlock.Builder(id, url: url).allowUnpinnedConfigApi().allowUnsigned()
    if attestation { builder.attestation() }
    if proof { builder.proofOfPossession() }
    if !tokenHosts.isEmpty { builder.tokenHosts(tokenHosts) }
    if !wantPinsFor.isEmpty { builder.wantPinsFor(wantPinsFor) }
    return try builder.build()
}

/// Collects values from `@Sendable` callbacks.
final class AttestCollector<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _values: [Value] = []

    func append(_ value: Value) { lock.lock(); _values.append(value); lock.unlock() }
    var values: [Value] { lock.lock(); defer { lock.unlock() }; return _values }
    var count: Int { values.count }
}

/// A clock tests move by hand.
final class AttestTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var _now: Int64

    init(_ now: Int64) { _now = now }

    var now: Int64 { get { lock.lock(); defer { lock.unlock() }; return _now } set { lock.lock(); _now = newValue; lock.unlock() } }
    func advance(_ ms: Int64) { now += ms }
    var function: @Sendable () -> Int64 { { self.now } }
}
