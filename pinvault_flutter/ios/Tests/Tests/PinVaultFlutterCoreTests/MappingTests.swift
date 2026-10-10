import XCTest
import PinVault
@testable import PinVaultFlutterCore

final class MappingTests: XCTestCase {
    let tokens = VaultTokenStore()
    lazy var mapper = ResultMapper(tokens: tokens)

    func testResultsKeepTheNativeNames() {
        XCTAssertEqual(mapper.initResult(.ready(version: 4))["type"] as? String, "ready")
        XCTAssertEqual(mapper.initResult(.ready(version: 4))["version"] as? Int, 4)
        let failed = mapper.initResult(.failed(reason: "pin", exception: PinVaultError.sslPinning(message: "Certificate pinning failure")))
        let exception = failed["exception"] as? [String: Any]
        XCTAssertEqual(exception?["name"] as? String, "SSLPinningException")
        XCTAssertEqual(mapper.update(.alreadyCurrent)["type"] as? String, "alreadyCurrent")
        let refused = mapper.enrollment(.refused(reason: .invalidToken, httpStatus: 401))
        XCTAssertEqual(refused["reason"] as? String, "INVALID_TOKEN")
        XCTAssertTrue(refused["serverError"] is NSNull)
        let enrolled = mapper.enrollment(.enrolled(alreadyEnrolled: false, keySecurityLevel: .secureEnclave))
        XCTAssertEqual(enrolled["keySecurityLevel"] as? String, "SECURE_ENCLAVE")
    }

    func testDownloadResultsCarryNoContent() {
        let m = mapper.vaultFile(.updated(key: "k", version: 3, bytes: Data("secret content".utf8)))
        XCTAssertEqual(Set(m.keys), ["type", "key", "version"])
        let f = mapper.vaultFile(.failed(key: "k", reason: "HTTP 401", code: "http_401"))
        XCTAssertEqual(f["code"] as? String, "http_401")
    }

    func testUnlockedContentEncoding() {
        let bytes = Data([0, 1, 2, 0x61])
        XCTAssertEqual(mapper.unlock(.unlocked(key: "k", version: 1, bytes: bytes), encoding: "base64")["content"] as? String, "AAECYQ==")
        XCTAssertEqual(mapper.unlock(.cancelled(key: "k"), encoding: "utf8")["type"] as? String, "cancelled")
    }

    func testTokensNeverReachDartThroughAMessage() async {
        tokens.put("file", "vault-token-abcdef")
        let m = mapper.enrollment(.failed(message: "server said vault-token-abcdef is bad"))
        XCTAssertEqual(m["message"] as? String, "server said *** is bad")
        let redacted = await tokens.withTransientSecret("enroll-token-123456") { tokens.redact("refused enroll-token-123456") }
        XCTAssertEqual(redacted, "refused ***")
        XCTAssertEqual(tokens.redact("refused enroll-token-123456"), "refused enroll-token-123456")
    }

    func testEventsAndTokenResult() {
        let e = mapper.event(.configUpdate(status: .updated, newVersion: 5, deviceManufacturer: "Apple", deviceModel: "x"))
        XCTAssertEqual(e["type"] as? String, "configUpdate")
        XCTAssertEqual(e["status"] as? String, "UPDATED")
        XCTAssertEqual(mapper.attestationToken(.unsupported)["type"] as? String, "unsupported")
    }

    func testFetchRequestsAreStrict() throws {
        XCTAssertThrowsError(try PinnedFetch.parse(#"{"url":"http://a/"}"#))
        XCTAssertThrowsError(try PinnedFetch.parse(#"{"url":"https://a/","metod":"GET"}"#))
        XCTAssertThrowsError(try PinnedFetch.parse(#"{"url":"https://a/","headers":{"X-A":"a\r\nB: 1"}}"#))
        XCTAssertThrowsError(try PinnedFetch.parse(#"{"url":"https://a/","method":"GET","body":"x"}"#))
        let r = try PinnedFetch.parse(#"{"url":"https://a/p","method":"post","headers":{"X-A":"1"},"body":"AP8=","bodyEncoding":"base64","timeoutMs":1500}"#)
        XCTAssertEqual(r.method, "POST")
        XCTAssertEqual(r.body, Data([0, 0xff]))
        let request = PinnedFetch.urlRequest(r)
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-A"), "1")
        XCTAssertEqual(request.timeoutInterval, 1.5)
    }

    func testResponseSizeIsBounded() throws {
        let r = try PinnedFetch.parse(#"{"url":"https://a/","maxResponseBytes":4}"#)
        let http = HTTPURLResponse(url: URL(string: "https://a/")!, statusCode: 200, httpVersion: nil, headerFields: ["X-R": "1"])!
        XCTAssertThrowsError(try PinnedFetch.map(http, Data(repeating: 1, count: 5), r))
        let ok = try PinnedFetch.map(http, Data("ok".utf8), r)
        XCTAssertEqual(ok["body"] as? String, "ok")
        XCTAssertEqual((ok["headers"] as? [String: String])?["x-r"], "1")
    }
}

final class GuardTests: XCTestCase {
    func testAllowsOnlyOnATrueAnswer() throws {
        var g: DartEnvironmentGuard!
        g = DartEnvironmentGuard(timeoutMs: 2000) { id, op in
            DispatchQueue.global().async { g.answer(id, allowed: op == "INIT") }
        }
        XCTAssertTrue(try g.allows(.start))
        XCTAssertFalse(try g.allows(.enroll))
        XCTAssertEqual(g.pendingCount, 0)
    }

    func testNoAnswerInTimeIsARefusal() throws {
        let g = DartEnvironmentGuard(timeoutMs: 150) { _, _ in }
        let start = Date()
        XCTAssertFalse(try g.allows(.fetchFile))
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.14)
        XCTAssertEqual(g.pendingCount, 0)
    }

    func testLateAnswersChangeNothing() throws {
        var last = ""
        let g = DartEnvironmentGuard(timeoutMs: 100) { id, _ in last = id }
        XCTAssertFalse(try g.allows(.unlockFile))
        g.answer(last, allowed: true)
        g.answer("unknown", allowed: true)
        XCTAssertEqual(g.pendingCount, 0)
    }
}
