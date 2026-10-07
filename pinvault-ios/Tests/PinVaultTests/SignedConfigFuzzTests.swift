import Foundation
import XCTest
@testable import PinVault

/// Port of SignedConfigFuzzTest: the signed config response is untrusted
/// input. Whatever a broken proxy or an attacker does to it, the client must
/// either reject it with an error (the updater keeps the previous config) or,
/// when the signed payload survived untouched, return exactly the original
/// config — never a different config, and never a crash.
///
/// The Kotlin test serves the body through MockWebServer and
/// `DefaultCertificateConfigApi.fetchConfig`; here the body goes through the
/// same steps without HTTP (decode the envelope, apply the key set riding
/// along, verify). `SignedConfigFetchFuzzTests` serves damaged envelopes over
/// TLS through the Config API client and the updater.
final class SignedConfigFuzzTests: XCTestCase {

    private let signer = TestSigner()
    private let now = Int64(Date().timeIntervalSince1970 * 1000)

    private lazy var original = CertificateConfig(
        version: 7,
        pins: [
            HostPin(hostname: "api.example.com", sha256: ["pinA", "pinB"], version: 7),
            HostPin(hostname: "*.cdn.example.com", sha256: ["pinC", "pinD"], version: 3),
        ],
        issuedAt: now,
        expiresAt: now + 3_600_000
    )
    private lazy var payload = String(decoding: try! JSONEncoder().encode(original), as: UTF8.self)
    private lazy var signature = signer.sign(payload)
    private lazy var envelope = JSONText.object([("payload", JSONText.string(payload)), ("signature", JSONText.string(signature))])

    /// What `DefaultCertificateConfigApi.fetchConfig` does with a body, minus the HTTP.
    private func fetchConfig(_ body: String, _ verifier: SignedConfigVerifier) throws -> CertificateConfig {
        let signed = try JSONDecoder().decode(SignedConfigResponse.self, from: Data(body.utf8))
        try verifier.applyKeySet(signed)
        return try verifier.verifyFetched(signed).config
    }

    private lazy var verifier = SignedConfigVerifier(trust: SignatureTrust.single(configApiId: "default", key: signer.pub))

    /// Serves `body` once; returns the config or the error, failing when a different config gets through.
    @discardableResult
    private func serve(_ body: String, _ label: String, verifier: SignedConfigVerifier? = nil) -> Result<CertificateConfig, any Error> {
        let result = Result { try fetchConfig(body, verifier ?? self.verifier) }
        if case .success(let config) = result {
            XCTAssertEqual(config, original, "\(label): accepted a config other than the signed one\n\(body)")
        }
        return result
    }

    private func edit(_ change: (inout [String: Any]) -> Void) -> String {
        var object = try! JSONSerialization.jsonObject(with: Data(envelope.utf8)) as! [String: Any]
        change(&object)
        return String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    func testTheUntouchedEnvelopeIsAccepted() {
        XCTAssertNoThrow(try serve(envelope, "untouched").get())
    }

    func testTargetedEnvelopeEditsAreRejectedUnlessTheSignedPayloadIsIntact() throws {
        var evil = original
        evil.pins.append(HostPin(hostname: "evil.example.com", sha256: ["x", "y"]))
        let other = String(decoding: try JSONEncoder().encode(evil), as: UTF8.self)
        let payloadObject = try JSONSerialization.jsonObject(with: Data(payload.utf8))

        let mustReject: [(String, String)] = [
            ("empty body", ""),
            ("JSON null", "null"),
            ("array", "[]"),
            ("number", "42"),
            ("string", "\"payload\""),
            ("no payload", edit { $0.removeValue(forKey: "payload") }),
            ("payload null", edit { $0["payload"] = NSNull() }),
            ("payload is an object", edit { $0["payload"] = payloadObject }),
            ("payload replaced", edit { $0["payload"] = other }),
            ("payload with trailing space", edit { $0["payload"] = self.payload + " " }),
            ("no signature", edit { $0.removeValue(forKey: "signature") }),
            ("empty signature", edit { $0["signature"] = "" }),
            ("signature not base64", edit { $0["signature"] = "%%%" }),
            ("signature of the other payload", edit {
                $0["payload"] = other
                $0["signature"] = self.signature
            }),
            ("signatures list names only a bad one", edit { $0["signatures"] = [["signature": "AAAA"]] }),
            ("signatures list is a string", edit { $0["signatures"] = "x" }),
        ]
        for (label, body) in mustReject {
            if case .success = serve(body, label) { XCTFail("\(label) must be rejected") }
        }

        let mustAccept: [(String, String)] = [
            ("unknown fields", edit {
                $0["extra"] = 1
                $0["more"] = [Any]()
            }),
            ("empty signatures list falls back to signature", edit { $0["signatures"] = [Any]() }),
            ("keyId hint is wrong", edit { $0["keyId"] = "not-the-key" }),
        ]
        for (label, body) in mustAccept {
            if case .failure(let error) = serve(body, label) { XCTFail("\(label) must be accepted: \(error)") }
        }

        // Either outcome is fine here; serve() still checks nothing else gets through.
        // JSONDecoder keeps the FIRST of two equal keys (Gson the last), so the two
        // duplicate-key bodies swap outcomes compared with Android: still only
        // ever the signed payload, verified with its own signature.
        let quotedPayload = JSONText.string(payload)
        let quotedOther = JSONText.string(other)
        let either: [(String, String)] = [
            ("duplicate payload key, the last one altered", envelope.replacingFirst("{", with: "{\"payload\":\(quotedPayload),")
                .replacingOccurrences(of: ",\"signature\"", with: ",\"payload\":\(quotedOther),\"signature\"")),
            ("duplicate payload key, the last one intact", envelope.replacingFirst("{", with: "{\"payload\":\(quotedOther),")),
            ("deeply nested unknown field",
             envelope.replacingFirst("{", with: "{\"x\":" + String(repeating: "[", count: 5000) + String(repeating: "]", count: 5000) + ",")),
        ]
        for (label, body) in either { serve(body, label) }
        if case .success = serve(either[1].1, either[1].0) { XCTFail("the first payload key is the altered one here") }
    }

    // Random damage: byte flips, cuts, insertions, truncations, swapped
    // characters. Seeded, so a failure reproduces.
    func testRandomlyDamagedEnvelopesNeverYieldADifferentConfig() {
        let (accepted, rejected) = fuzz(envelope, rounds: 600, seed: 20_260_925) { body, label in serve(body, label) }
        print("SignedConfigFuzzTests: 600 damaged envelopes → \(accepted) accepted unchanged, rejected: \(rejected)")
        XCTAssertGreaterThan(rejected.values.reduce(0, +), 500, "most damage must be caught")
    }

    /// With rotation on and a key set riding along: no damaged envelope moves
    /// the stored key set or the stored config, and nothing but the signed
    /// config gets through.
    func testRandomlyDamagedEnvelopesNeverChangeStoredState() throws {
        let recovery = TestSigner()
        let directory = try temporaryStoreDirectory(self)
        let environment = SecureStoreEnvironment(directory: directory)
        let keyStore = try SigningKeyStore.open(environment: environment)
        let configStore = try CertificateConfigStore.forOrigin(prefsName: "ssl_cert_config_default", origin: "scope:default", environment: environment)
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [signer.pub], builtInThreshold: 1,
                                   recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: keyStore)
        let verifier = SignedConfigVerifier(
            trust: trust,
            trustedNow: { try configStore.highestSeenTime() },
            issuedAtWatermark: { try configStore.getCurrentIssuedAt() }
        )
        let setPayload = keySetPayload(version: 1, keys: [signer.pub])
        let keySet = SignedKeySet(payload: setPayload, signatures: [recovery.entry(setPayload)])
        var stored = original
        stored.issuedAt = now - 60_000
        try configStore.save(stored)
        try configStore.setHighestSeenTime(now - 1)

        let body = String(decoding: try JSONEncoder().encode(SignedConfigResponse(payload: payload, signature: signature, signingKeys: keySet)), as: UTF8.self)
        XCTAssertNoThrow(try serve(body, "untouched", verifier: verifier).get())
        XCTAssertEqual(try trust.keySetVersion(), 1)

        let keyFile = environment.file(SigningKeyStore.fileName)
        let configFile = environment.file(CertificateConfigStore.fileName)
        let keysBefore = try keyFile.entries()
        let configBefore = try configFile.entries()
        let keysOnDisk = try Data(contentsOf: keyFile.url)
        let configOnDisk = try Data(contentsOf: configFile.url)

        let (_, rejected) = fuzz(body, rounds: 600, seed: 7) { damaged, label in serve(damaged, label, verifier: verifier) }
        XCTAssertGreaterThan(rejected.values.reduce(0, +), 400, "most damage must be caught")

        XCTAssertEqual(try trust.keySetVersion(), 1)
        XCTAssertEqual(try keyFile.entries(), keysBefore)
        XCTAssertEqual(try configFile.entries(), configBefore)
        XCTAssertEqual(try Data(contentsOf: keyFile.url), keysOnDisk)
        XCTAssertEqual(try Data(contentsOf: configFile.url), configOnDisk)
        XCTAssertEqual(try configStore.load(), stored)
    }

    /// Applies 1–3 random edits per round (UTF-16 units, as the Kotlin StringBuilder) and serves the result.
    private func fuzz(
        _ text: String,
        rounds: Int,
        seed: UInt64,
        serve: (String, String) -> Result<CertificateConfig, any Error>
    ) -> (accepted: Int, rejected: [String: Int]) {
        var random = SplitMix64(seed: seed)
        let junk = ["\"", "\\", "{", "}", "[", "]", ",", ":", "null", "0", "-1", "1e999", "\\u0000", "é", "\u{FFFD}", " ", "true"]
            .map { Array($0.utf16) } + [[0xD83D]]
        var accepted = 0
        var rejected: [String: Int] = [:]
        for round in 0..<rounds {
            var chars = Array(text.utf16)
            for _ in 0..<(1 + random.next(3)) {
                let at = random.next(chars.count)
                switch random.next(5) {
                case 0: chars[at] ^= UInt16(1 << random.next(7))
                case 1: chars.removeSubrange(at..<min(chars.count, at + 1 + random.next(8)))
                case 2: chars.insert(contentsOf: junk[random.next(junk.count)], at: at)
                case 3: chars.removeSubrange(max(1, at)...)
                default: if at + 1 < chars.count { chars.swapAt(at, at + 1) }
                }
                if chars.isEmpty { chars = Array("{".utf16) }
            }
            switch serve(String(decoding: chars, as: UTF16.self), "round \(round)") {
            case .success: accepted += 1
            case .failure(let error): rejected[Self.kind(error), default: 0] += 1
            }
        }
        return (accepted, rejected)
    }

    private static func kind(_ error: any Error) -> String {
        if let error = error as? PinVaultError { return error.exceptionName }
        return String(describing: type(of: error))
    }
}

/// A small seeded generator, so a failing round reproduces.
private struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    /// Uniform in `0..<bound` (bound > 0).
    mutating func next(_ bound: Int) -> Int {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        z ^= z >> 31
        return Int(z % UInt64(bound))
    }
}

private extension String {
    func replacingFirst(_ target: String, with replacement: String) -> String {
        guard let range = range(of: target) else { return self }
        return replacingCharacters(in: range, with: replacement)
    }
}
