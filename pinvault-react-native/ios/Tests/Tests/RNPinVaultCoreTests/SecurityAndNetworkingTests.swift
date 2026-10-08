import XCTest
import PinVault
@testable import RNPinVaultCore

/// The native security file, deep-nesting refusal, the guard's asynchronous
/// wait and React Native's https through the pinned session.
final class SecurityAndNetworkingTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let key2 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2B2nCnNnOqLbd9HnN0Bzh1n0yA0V1Z2tKm8bq6H1Z0lFv8yP0n0n8y0Ue7c3Hn2c9mQ3M6nYk0fJm5X3Qh9g=="
    let key3 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp9Vq4Xn1m3Lk2h8Gf5Jd6Sa0Qw7Er1Ty2Ui3Op4As5Df6Gh7Jk8Lz9Xc0Vb1Nm2Qa3Ws4Ed5Rf6Tg7Yh8Uj9Ik0Ol=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    let evil = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    let tokens = VaultTokenStore()

    lazy var file: NativeSecurity = try! NativeSecurity.parse("""
        {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],
          "signaturePublicKeys":["\(key)","\(key2)"],"requiredSignatures":2,"recoveryPublicKeys":["\(key3)"],
          "serverScope":"default-tls","clientCaPins":["\(pinA)"]}]}
        """, source: "pinvault_security.json")

    func parse(_ json: String, native: NativeSecurity?, release: Bool = true) throws -> ParsedConfig {
        try ConfigParser.parse(json, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } },
                               listener: nil, native: native, release: release)
    }

    func assertRefused(_ json: String, native: NativeSecurity?, release: Bool = true, _ fragments: String...,
                       file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try parse(json, native: native, release: release)
            XCTFail("accepted: \(json.prefix(200))", file: file, line: line)
        } catch {
            let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
            for f in fragments { XCTAssertTrue(message.contains(f), "'\(message)' lacks '\(f)'", file: file, line: line) }
        }
    }

    let base = #""id":"default","url":"https://h.example:8081/""#

    // MARK: native security file

    func testTheNativeValuesApplyAndMayBeRepeated() throws {
        let p = try parse(#"{"configApis":[{\#(base)}]}"#, native: file)
        XCTAssertTrue(p.nativeSecurityApplied)
        let block = try XCTUnwrap(p.config.configApis["default"])
        XCTAssertEqual(block.bootstrapPins.first?.sha256, [pinA, pinB])
        XCTAssertEqual(block.serverScope, "default-tls")
        XCTAssertEqual(block.requiredSignatures, 2)
        _ = try parse("""
            {"configApis":[{\(base),"bootstrapPins":[{"hostname":"H.example","sha256":["\(pinB)","\(pinA)"]}],
              "signaturePublicKeys":["\(key2)","\(key)"],"serverScope":"default-tls"}]}
            """, native: file)
    }

    func testADifferingTrustAnchorIsRefused() {
        assertRefused(#"{"configApis":[{\#(base),"bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(evil)"]}]}]}"#,
                      native: file, "config.configApis[0].bootstrapPins", "fixed")
        assertRefused(#"{"configApis":[{\#(base),"signaturePublicKey":"\#(key)"}]}"#, native: file, "signaturePublicKey")
        assertRefused(#"{"configApis":[{\#(base),"requiredSignatures":1}]}"#, native: file, "requiredSignatures")
        assertRefused(#"{"configApis":[{\#(base),"serverScope":"x"}]}"#, native: file, "serverScope")
        assertRefused(#"{"configApis":[{\#(base),"clientCaPins":["\#(evil)"]}]}"#, native: file, "clientCaPins")
        assertRefused(#"{"configApis":[{\#(base),"recoveryPublicKeys":["\#(key)"]}]}"#, native: file, "recoveryPublicKeys")
    }

    func testUndeclaredBlocksStaticPinsAndRelaxationsAreRefused() {
        assertRefused(#"{"configApis":[{"id":"evil","url":"https://e/","signaturePublicKey":"\#(key)","bootstrapPins":[{"hostname":"e","sha256":["\#(pinA)","\#(pinB)"]}]}]}"#,
                      native: file, "'evil' is not declared")
        assertRefused(#"{"staticPins":{"pins":[{"hostname":"x","sha256":["\#(pinA)","\#(pinB)"]}]}}"#, native: file, "config.staticPins")
        assertRefused(#"{"configApis":[{\#(base),"allowUnsigned":true}]}"#, native: file, release: false, "does not allow")
        assertRefused(#"{"configApis":[{\#(base),"allowUnpinnedConfigApi":true}]}"#, native: file, "allowUnpinnedConfigApi")
        assertRefused(#"{"configApis":[{\#(base),"allowServerGeneratedKey":true}]}"#, native: file, "allowServerGeneratedKey")
    }

    func testWithoutAFileReleaseRefusesTheRelaxationsDebugTakesThem() throws {
        let api = #""id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)""#
        assertRefused(#"{"configApis":[{\#(api),"allowServerGeneratedKey":true}]}"#, native: nil, "refused from JS", "native security file")
        assertRefused(#"{"configApis":[{"id":"a","url":"https://h/","allowUnsigned":true}]}"#, native: nil, "allowUnsigned")
        let debug = try parse(#"{"configApis":[{\#(api),"allowServerGeneratedKey":true}]}"#, native: nil, release: false)
        XCTAssertEqual(debug.config.configApis["a"]?.allowServerGeneratedKey, true)
    }

    func testAFileAllowingARelaxationAppliesIt() throws {
        let allowing = try NativeSecurity.parse(#"{"configApis":[{"id":"default","allowServerGeneratedKey":true}]}"#, source: "f")
        let p = try parse(#"{"configApis":[{\#(base),"bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)"}]}"#,
                          native: allowing)
        XCTAssertEqual(p.config.configApis["default"]?.allowServerGeneratedKey, true)
    }

    func testTheFileIsParsedStrictly() {
        for (text, fragment) in [
            (#"{"configApis":[{"id":"a","serverScop":"x"}]}"#, "'serverScop'"),
            (#"{"configApis":[{"id":"a"},{"id":"a"}]}"#, "declared twice"),
            ("{}", "declares neither"),
            (#"{"configApis":"#, "not valid JSON"),
            (#"{"configApis":[{"id":"a","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)"]}]}]}"#, "2 pins"),
        ] {
            XCTAssertThrowsError(try NativeSecurity.parse(text, source: "pinvault_security.json")) { error in
                let message = (error as? BridgeInputError)?.message ?? "\(error)"
                XCTAssertTrue(message.hasPrefix("native security file"), message)
                XCTAssertTrue(message.contains(fragment), "'\(message)' lacks '\(fragment)'")
            }
        }
    }

    func testNetworkingOptions() throws {
        let api = #"{"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)"}"#
        let p = try parse(#"{"configApis":[\#(api)],"requirePinnedReactNativeNetworking":true,"ios":{"reactNativeMaxResponseBytes":1024}}"#, native: nil)
        XCTAssertTrue(p.requirePinnedReactNativeNetworking)
        XCTAssertEqual(p.reactNativeMaxResponseBytes, 1024)
        XCTAssertEqual(try parse(#"{"configApis":[\#(api)]}"#, native: nil).reactNativeMaxResponseBytes, ReactNetworking.defaultMaxResponseBytes)
        assertRefused(#"{"configApis":[\#(api)],"ios":{"reactNativeMaxResponseBytes":0}}"#, native: nil, "reactNativeMaxResponseBytes")
    }

    // MARK: deep nesting

    func testDeepNestingIsRefusedBeforeTheParser() {
        let deep = String(repeating: "[", count: 100_000) + String(repeating: "]", count: 100_000)
        XCTAssertThrowsError(try StrictJSON.parseObject(#"{"a":\#(deep)}"#, path: "config", maxChars: 1 << 20)) { error in
            XCTAssertEqual((error as? BridgeInputError)?.message, "config: nested too deeply")
        }
        XCTAssertEqual(StrictJSON.nestingDepth(#"{"a":"[[[[[[[[[[{{{{"}"#), 1)
        XCTAssertEqual(StrictJSON.nestingDepth(#"{"a":[{"b":"\"]"}]}"#), 3)
    }

    // MARK: guard

    func testAVerdictAskedBeforehandIsAnsweredWithoutWaiting() async throws {
        var g: JSEnvironmentGuard!
        g = JSEnvironmentGuard(timeoutMs: 5000) { id, op in
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(20)) { g.answer(id, allowed: op == "INIT") }
        }
        let both = try await g.withVerdicts([.start, .enroll]) { [try g.allows(.start), try g.allows(.enroll)] }
        XCTAssertEqual(both, [true, false])
        let timed = try await g.withVerdicts([.start]) { () async throws -> TimeInterval in
            let t = Date()
            _ = try g.allows(.start)
            return Date().timeIntervalSince(t)
        }
        XCTAssertLessThan(timed, 0.01, "the library's check reads the verdict, nothing waits")
        let refused = try await g.withVerdicts([.enroll]) { try g.allows(.enroll) }
        XCTAssertFalse(refused)
        XCTAssertEqual(g.pendingCount, 0)
    }

    func testTheAsyncWaitTimesOutAsARefusal() async {
        let g = JSEnvironmentGuard(timeoutMs: 100) { _, _ in }
        let allowed = await g.verdict(.fetchFile)
        XCTAssertFalse(allowed)
        XCTAssertEqual(g.pendingCount, 0)
    }

    // MARK: React Native networking

    final class Recorder: @unchecked Sendable {
        let lock = NSLock()
        var events: [String] = []
        var data = Data()
        var error: NSError?
        let done = XCTestExpectation(description: "complete")

        func add(_ e: String) { lock.lock(); events.append(e); lock.unlock() }

        var callbacks: ReactNetworking.Callbacks {
            ReactNetworking.Callbacks(
                didSendData: { self.add("sent \($0)") },
                didReceiveResponse: { self.add("response \(($0 as? HTTPURLResponse)?.statusCode ?? 0)") },
                didReceiveData: { d in self.lock.lock(); self.data.append(d); self.lock.unlock(); self.add("data") },
                didComplete: { e in self.error = e as NSError?; self.add("complete"); self.done.fulfill() }
            )
        }
    }

    let describe: @Sendable (any Error) -> (String, String) = { e in ("X", "\(e)") }

    func testBeforeStartEveryHttpsRequestFails() async {
        let r = Recorder()
        let request = URLRequest(url: URL(string: "https://h.example/")!)
        XCTAssertTrue(ReactNetworking.handles(request))
        XCTAssertFalse(ReactNetworking.handles(URLRequest(url: URL(string: "http://localhost:8081/status")!)))
        _ = ReactNetworking.start(request, send: nil, maxResponseBytes: 10, describe: describe, callbacks: r.callbacks)
        await fulfillment(of: [r.done], timeout: 2)
        XCTAssertEqual(r.events, ["complete"])
        XCTAssertTrue(r.error?.localizedDescription.contains("PinVault has not started") == true)
    }

    func testTheAnswerGoesToRNInChunksAfterTheResponse() async {
        let r = Recorder()
        let body = Data(repeating: 7, count: ReactNetworking.chunkSize * 2 + 10)
        var request = URLRequest(url: URL(string: "https://h.example/x")!)
        request.httpMethod = "POST"
        request.httpBody = Data("abc".utf8)
        let seenLimit = LockedBox<Int64>(0)
        _ = ReactNetworking.start(request, send: { req, limit in
            seenLimit.value = limit
            XCTAssertEqual(req.httpBody, Data("abc".utf8))
            return (body, HTTPURLResponse(url: req.url!, statusCode: 201, httpVersion: nil, headerFields: nil)!)
        }, maxResponseBytes: 4096 * 1024, describe: describe, callbacks: r.callbacks)
        await fulfillment(of: [r.done], timeout: 2)
        XCTAssertEqual(r.events, ["sent 3", "response 201", "data", "data", "data", "complete"])
        XCTAssertEqual(r.data, body)
        XCTAssertNil(r.error)
        XCTAssertEqual(seenLimit.value, 4096 * 1024)
    }

    func testAFailureIsNamedForJS() async {
        let r = Recorder()
        _ = ReactNetworking.start(URLRequest(url: URL(string: "https://h.example/")!), send: { _, _ in
            throw PinVaultError.sslPeerUnverified(message: "pin mismatch")
        }, maxResponseBytes: 10, describe: { e in ((e as? PinVaultError)?.exceptionName ?? "?", "pin mismatch") }, callbacks: r.callbacks)
        await fulfillment(of: [r.done], timeout: 2)
        XCTAssertEqual(r.events, ["complete"])
        XCTAssertEqual(r.error?.domain, "PinVault")
        XCTAssertEqual(r.error?.localizedDescription, "SSLPeerUnverifiedException: pin mismatch")
    }

    func testACancelledRequestTellsRNNothingMore() async throws {
        let r = Recorder()
        r.done.isInverted = true
        let task = ReactNetworking.start(URLRequest(url: URL(string: "https://h.example/")!), send: { req, _ in
            try await Task.sleep(nanoseconds: 300_000_000)
            return (Data("late".utf8), HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }, maxResponseBytes: 10, describe: describe, callbacks: r.callbacks)
        task.cancel()
        await fulfillment(of: [r.done], timeout: 0.6)
        XCTAssertEqual(r.events, [])
        XCTAssertTrue(task.isCancelled)
    }
}

final class LockedBox<V>: @unchecked Sendable {
    private let lock = NSLock()
    private var v: V
    init(_ v: V) { self.v = v }
    var value: V {
        get { lock.lock(); defer { lock.unlock() }; return v }
        set { lock.lock(); v = newValue; lock.unlock() }
    }
}
