import Foundation
import XCTest
@testable import PinVault

/// The HTTP layer of SignedConfigFuzzTest: damaged signed config responses
/// served over TLS by a test server, fetched through the library's own Config
/// API client and the updater. None may be applied, and the stored state —
/// the encrypted store file, byte for byte — must stay as the last good
/// config left it. (`SignedConfigFuzzTests` covers the verifier on its own.)
final class SignedConfigFetchFuzzTests: XCTestCase {

    private let signer = TestSigner()
    private let now = Int64(Date().timeIntervalSince1970 * 1000)

    func testDamagedEnvelopesFetchedOverHTTPAreNeverAppliedAndLeaveTheStoreUntouched() async throws {
        let server = try await startConfigApiServer()
        defer { server.stop() }
        let body = Locked("")
        server.setHandler { _ in .ok(body.get()) }

        let original = CertificateConfig(
            version: 7,
            pins: [
                HostPin(hostname: "api.example.com", sha256: [pin("A"), pin("B")], version: 7),
                HostPin(hostname: "*.cdn.example.com", sha256: [pin("C"), pin("D")], version: 3),
            ],
            issuedAt: now,
            expiresAt: now + 3_600_000
        )
        let payload = json(original)
        let envelope = json(SignedConfigResponse(payload: payload, signature: signer.sign(payload)))

        let environment = SecureStoreEnvironment(directory: try temporaryStoreDirectory(self))
        let store = try CertificateConfigStore.forOrigin(prefsName: "ssl_cert_config_default", origin: "scope:default", environment: environment)
        let manager = testManager()
        let provider = HttpClientProvider(sslManager: manager)
        let trust = SignatureTrust.single(configApiId: "default", key: signer.pub)
        let updater = SSLCertificateUpdater(
            configApi: makeConfigApi(server, manager: manager, signaturePublicKey: signer.pub),
            configStore: store,
            httpClientProvider: provider,
            maxRetryCount: 1,
            verifier: SignedConfigVerifier(trust: trust, trustedNow: nil, issuedAtWatermark: { try store.getCurrentIssuedAt() }),
            sleep: { _ in }
        )

        body.set(envelope)
        let first = await updater.updateNow()
        XCTAssertEqual(first, .updated(newVersion: 7))
        let applied = try XCTUnwrap(provider.currentConfig)

        let file = environment.file(CertificateConfigStore.fileName)
        let entriesBefore = try file.entries()
        let bytesBefore = try Data(contentsOf: file.url)

        var random = FuzzRandom(seed: 20_260_925)
        let junk = ["\"", "\\", "{", "}", "[", "]", ",", ":", "null", "0", "-1", "1e999", "\\u0000", "é", "\u{FFFD}", " ", "true"]
            .map { Array($0.utf16) } + [[0xD83D]]
        var current = 0
        var refused: [String: Int] = [:]
        for round in 0..<600 {
            var chars = Array(envelope.utf16)
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
            body.set(String(decoding: chars, as: UTF16.self))
            let result = await updater.updateNow()
            switch result {
            case .updated:
                XCTFail("round \(round): a damaged envelope was applied\n\(body.get())")
            case .alreadyCurrent:
                current += 1
            case .failed(_, let exception):
                let kind = (exception as? PinVaultError)?.exceptionName ?? exception.map { String(describing: type(of: $0)) } ?? "nil"
                refused[kind, default: 0] += 1
            }
            XCTAssertEqual(provider.currentConfig, applied, "round \(round): the live config moved")
        }
        print("SignedConfigFetchFuzzTests: 600 damaged envelopes over HTTP → \(current) current (payload intact), refused: \(refused)")

        XCTAssertGreaterThan(refused.values.reduce(0, +), 500, "most damage must be caught")
        XCTAssertEqual(try file.entries(), entriesBefore)
        XCTAssertEqual(try Data(contentsOf: file.url), bytesBefore, "the stored state is byte-identical")
        XCTAssertEqual(try store.load(), original)
        XCTAssertEqual(server.requestCount, 601)
    }
}

/// A small seeded generator (SplitMix64), so a failing round reproduces.
struct FuzzRandom {
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
