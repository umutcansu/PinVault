import CryptoKit
import Security
import XCTest
@testable import PinVault

/// `PinVault-Proof` (ATTESTATION.md §5.1), the DPoP proof the token
/// interceptor adds (Kotlin `TokenProofTest`), and the fixture the server's
/// `ClientProofInteropTest` verifies (`demo-server/src/test/resources/interop/ios-proof.json`).
///
/// Regenerate the fixture after a change to the proof:
///
///     PINVAULT_PROOF_FIXTURE_DIR=$PWD/demo-server/src/test/resources/interop \
///       swift test --filter TokenProofTests
final class TokenProofTests: XCTestCase {

    private let key = TestIdentityKey()

    override func setUp() {
        try? key.ensureKeyPair()
    }

    private func make(_ method: String = "GET", _ url: String, token: String = "the.token.value", iat: Int64 = 1_759_660_800) throws -> String? {
        try TokenProof.make(method: method, url: URL(string: url)!, token: token, publicKey: try key.publicKey(), nowSeconds: iat, sign: { try self.key.sign($0) })
    }

    private func json(_ segment: Substring) -> [String: Any] {
        try! JSONSerialization.jsonObject(with: Base64.decodeURL(String(segment))!) as! [String: Any]
    }

    func testTheProofIsADPoPJWSSignedByTheKeyItNames() throws {
        let proof = try XCTUnwrap(make("GET", "https://API.example.com:8444/v1/me?x=1#f"))
        let parts = proof.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        let header = json(parts[0])
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header["alg"] as? String, "ES256")
        let jwk = try XCTUnwrap(header["jwk"] as? [String: String])
        XCTAssertEqual(jwk["kty"], "EC")
        XCTAssertEqual(jwk["crv"], "P-256")
        let point = try key.signingKey.publicKey.x963Representation
        XCTAssertEqual(Base64.decodeURL(jwk["x"]!), point.subdata(in: 1..<33))
        XCTAssertEqual(Base64.decodeURL(jwk["y"]!), point.subdata(in: 33..<65))

        let payload = json(parts[1])
        XCTAssertEqual(payload["htm"] as? String, "GET")
        XCTAssertEqual(payload["htu"] as? String, "https://api.example.com:8444/v1/me")
        XCTAssertEqual((payload["iat"] as? NSNumber)?.int64Value, 1_759_660_800)
        XCTAssertEqual((payload["jti"] as? String)?.count, 22)
        XCTAssertEqual(payload["ath"] as? String, Base64.encodeURL(Data(SHA256.hash(data: Data("the.token.value".utf8)))))

        let signature = try XCTUnwrap(Base64.decodeURL(String(parts[2])))
        XCTAssertEqual(signature.count, 64)
        let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        XCTAssertTrue(try key.signingKey.publicKey.isValidSignature(ecdsa, for: Data((parts[0] + "." + parts[1]).utf8)))
    }

    func testEveryProofHasItsOwnJti() throws {
        let a = json(try XCTUnwrap(make("GET", "https://a.example/x")).split(separator: ".")[1])
        let b = json(try XCTUnwrap(make("GET", "https://a.example/x")).split(separator: ".")[1])
        XCTAssertNotEqual(a["jti"] as? String, b["jti"] as? String)
    }

    func testHtuDropsQueryFragmentAndTheDefaultPort() {
        XCTAssertEqual(TokenProof.htu(URL(string: "https://A.example")!), "https://a.example/")
        XCTAssertEqual(TokenProof.htu(URL(string: "https://a.example:443/p%20q?x=1")!), "https://a.example/p%20q")
        XCTAssertEqual(TokenProof.htu(URL(string: "http://10.0.0.1:8080/x")!), "http://10.0.0.1:8080/x")
        XCTAssertEqual(TokenProof.htu(URL(string: "http://a.example:80/x")!), "http://a.example/x")
        XCTAssertEqual(TokenProof.htu(URL(string: "https://[::1]:8443/x")!), "https://[::1]:8443/x")
        XCTAssertNil(TokenProof.htu(URL(string: "ftp://a.example/x")!))
        XCTAssertNil(TokenProof.htu(URL(string: "/relative")!))
    }

    func testAnOddMethodMakesNoProof() throws {
        XCTAssertNil(try make("get", "https://a.example/"))
        XCTAssertNil(try make("GE\"T", "https://a.example/"))
    }

    func testDerToRaw() throws {
        for _ in 0..<200 {
            let data = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
            let raw = try XCTUnwrap(TokenProof.derToRaw(try key.sign(data)))
            XCTAssertEqual(raw.count, 64)
            XCTAssertTrue(try key.signingKey.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: data))
        }
        let small = Data([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual(TokenProof.derToRaw(small), Data(repeating: 0, count: 31) + [1] + Data(repeating: 0, count: 31) + [0x80])
        XCTAssertNil(TokenProof.derToRaw(Data()))
        XCTAssertNil(TokenProof.derToRaw(small + [0]), "trailing bytes")
        XCTAssertNil(TokenProof.derToRaw(Data([0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01])), "negative r")
        XCTAssertNil(TokenProof.derToRaw(Data([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])), "zero r")
        XCTAssertNil(TokenProof.derToRaw(Data([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])), "not a SEQUENCE")
        XCTAssertNil(TokenProof.derToRaw(Data([0x30, 0x25, 0x02, 0x21, 0x01] + [UInt8](repeating: 0, count: 32) + [0x02, 0x01, 0x01])), "r over 32 bytes")
    }

    /// The fixture the server verifies; written with the variable, checked against itself without.
    func testInteropFixture() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZXYtMSJ9.ios-fixture"
        let url = "https://api.example.com:8444/v1/me?page=2"
        if let dir = ProcessInfo.processInfo.environment["PINVAULT_PROOF_FIXTURE_DIR"], !dir.isEmpty {
            let proof = try XCTUnwrap(make("POST", url, token: token))
            let spki = Base64.encode(try key.spki)
            let text = #"{"platform":"ios","method":"POST","url":"\#(url)","token":"\#(token)","iat":1759660800,"publicKey":"\#(spki)","proof":"\#(proof)"}"# + "\n"
            try text.write(to: URL(fileURLWithPath: dir).appendingPathComponent("ios-proof.json"), atomically: true, encoding: .utf8)
        }
        let committed = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("demo-server/src/test/resources/interop/ios-proof.json")
        guard let data = try? Data(contentsOf: committed) else { return }
        let fixture = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let proof = try XCTUnwrap(fixture["proof"] as? String)
        let parts = proof.split(separator: ".")
        let publicKey = try P256.Signing.PublicKey(derRepresentation: try XCTUnwrap(Base64.decode(fixture["publicKey"] as! String)))
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: Base64.decodeURL(String(parts[2]))!),
                                                 for: Data((parts[0] + "." + parts[1]).utf8)))
        XCTAssertEqual(json(parts[1])["htu"] as? String, "https://api.example.com:8444/v1/me")
    }
}
