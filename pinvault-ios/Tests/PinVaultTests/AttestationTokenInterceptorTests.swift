import XCTest
@testable import PinVault

/// The `PinVault-Token` header, and the one retry after a 401 that names the
/// token (Kotlin `AttestationTokenInterceptorTest`), through a pinned session.
final class AttestationTokenInterceptorTests: XCTestCase {

    /// A source whose token is `t1` until a forced refresh makes it `t2`.
    final class FakeSource: AttestationTokenSource, @unchecked Sendable {
        private let lock = NSLock()
        private var _handles: Bool
        private var _nextOnForce: String?
        private var _token: String? = "t1"
        private var _forced = 0
        private var _asked = 0

        init(handles: Bool = true, nextOnForce: String? = "t2") {
            _handles = handles
            _nextOnForce = nextOnForce
        }

        private func locked<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }

        var handles: Bool { get { locked { _handles } } set { locked { _handles = newValue } } }
        var nextOnForce: String? { get { locked { _nextOnForce } } set { locked { _nextOnForce = newValue } } }
        var token: String? { get { locked { _token } } set { locked { _token = newValue } } }
        var forced: Int { locked { _forced } }
        var asked: Int { locked { _asked } }

        func handlesHost(_ host: String, port: Int) -> Bool { handles }

        private var _proofs = false
        private var _proofFor: [String] = []
        var proofs: Bool { get { locked { _proofs } } set { locked { _proofs = newValue } } }
        var proofFor: [String] { locked { _proofFor } }

        func proof(method: String, url: URL, token: String) -> String? {
            locked {
                guard _proofs else { return nil }
                _proofFor.append("\(method) \(url.path) \(token)")
                return "proof-\(_proofFor.count)-\(token)"
            }
        }

        func token(host: String, port: Int, forceRefresh: Bool) async -> String? {
            locked {
                _asked += 1
                if forceRefresh {
                    _forced += 1
                    _token = _nextOnForce
                }
                return _token
            }
        }
    }

    private var server: TestServer!
    private var source = FakeSource()
    private var client: PinnedSession!

    override func setUp() async throws {
        server = try TestServer(p12: "server", chain: ["intermediate"])
        try await server.start()
        source = FakeSource()
        client = session([source])
    }

    override func tearDown() {
        server.stop()
    }

    private func session(_ sources: [any AttestationTokenSource]) -> PinnedSession {
        testManager().buildDynamicClient(
            configProvider: { pinConfig("localhost", [TLSFixture.pin("leaf")]) },
            extraInterceptors: [AttestationTokenInterceptor { sources }]
        )
    }

    private func get(_ session: PinnedSession? = nil, path: String = "/api/data") async throws -> (Int, String) {
        let (data, response) = try await (session ?? client).data(from: server.url(path))
        return ((response as! HTTPURLResponse).statusCode, String(decoding: data, as: UTF8.self))
    }

    func testRequestsToATokenHostCarryTheHeader() async throws {
        let (status, _) = try await get()
        XCTAssertEqual(status, 200)
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "t1")
        XCTAssertEqual(source.forced, 0)
    }

    func testRequestsToOtherHostsCarryNothingAndAskForNoToken() async throws {
        source.handles = false
        _ = try await get()
        XCTAssertNil(server.takeRequest()?.header("PinVault-Token"))
        XCTAssertEqual(source.asked, 0)
    }

    func testTheTokenNeverGoesOutOverCleartext() async throws {
        let seen = Locked<[String?]>([])
        let session = PinnedSession(
            interceptors: [AttestationTokenInterceptor { [source] in [source] }],
            transport: FakeTransport { exchange in
                seen.withLock { $0.append(exchange.request.value(forHTTPHeaderField: "PinVault-Token")) }
                return fakeResponse(url: exchange.request.url)
            }
        )
        _ = try await session.data(from: URL(string: "http://example.com/plain")!)
        _ = try await session.data(from: URL(string: "https://example.com/tls")!)
        XCTAssertEqual(seen.withLock { $0 }, [nil, "t1"], "a bearer token is attached to https requests only")
    }

    func testWithoutATokenTheRequestGoesOutBare() async throws {
        source.token = nil
        source.nextOnForce = nil
        _ = try await get()
        XCTAssertNil(server.takeRequest()?.header("PinVault-Token"))
    }

    func testA401WhoseChallengeNamesTheTokenForcesOneReAttestationAndOneRetry() async throws {
        server.enqueue(.status(401, headers: ["WWW-Authenticate": #"Bearer realm="api", error="invalid_token", header="PinVault-Token""#]))
        server.enqueue(.ok())
        let (status, _) = try await get()
        XCTAssertEqual(status, 200)
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "t1")
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "t2")
        XCTAssertEqual(source.forced, 1)
        XCTAssertEqual(server.requestCount, 2)
    }

    func testA401WhoseBodySaysInvalidTokenIsRetriedOnceAndTheRetryIsNeverRetried() async throws {
        server.enqueue(.status(401, #"{"error":"invalid_token","message":"expired"}"#))
        server.enqueue(.status(401, #"{"error":"invalid_token"}"#))
        let (status, _) = try await get()
        XCTAssertEqual(status, 401)
        XCTAssertEqual(server.requestCount, 2)
        XCTAssertEqual(source.forced, 1)
    }

    func testA401ThatIsNotAboutTheTokenIsReturnedAsItIs() async throws {
        server.enqueue(.status(401, #"{"error":"login_required"}"#, headers: ["WWW-Authenticate": #"Session realm="x""#]))
        let (status, _) = try await get()
        XCTAssertEqual(status, 401)
        XCTAssertEqual(server.requestCount, 1)
        XCTAssertEqual(source.forced, 0)
    }

    func testTheServersOwnChallengeFormIsRecognised() async throws {
        server.enqueue(.status(401, "", headers: ["WWW-Authenticate": #"PinVault-Token error="invalid_token", error_description="expired""#]))
        server.enqueue(.ok())
        let (status, _) = try await get()
        XCTAssertEqual(status, 200)
        XCTAssertEqual(server.requestCount, 2, "URLSession does not answer this scheme itself")
        XCTAssertEqual(source.forced, 1)
    }

    /// PLATFORM DIFFERENCE: for a Basic (Digest, NTLM, Negotiate) challenge
    /// URLSession asks the delegate, which answers "no credential" like OkHttp's
    /// default authenticator — and URLSession then sends the request once more
    /// before returning the 401 (cancelling instead would lose the response).
    func testABasicChallengeIsAnsweredWithoutCredentialsAndTheFinal401Returned() async throws {
        server.setHandler { _ in .status(401, #"{"error":"login_required"}"#, headers: ["WWW-Authenticate": #"Basic realm="x""#]) }
        let (status, _) = try await get()
        XCTAssertEqual(status, 401)
        XCTAssertEqual(source.forced, 0, "not about the token")
        XCTAssertNil(server.requests.last?.header("Authorization"), "no credential was sent")
        XCTAssertLessThanOrEqual(server.requestCount, 2)
    }

    func testNoRetryWhenTheReAttestationBringsNoNewToken() async throws {
        source.nextOnForce = nil
        server.enqueue(.status(401, #"{"error":"invalid_token"}"#))
        let (status, body) = try await get()
        XCTAssertEqual(status, 401)
        XCTAssertEqual(body, #"{"error":"invalid_token"}"#, "the original answer, body intact")
        XCTAssertEqual(server.requestCount, 1)
        XCTAssertEqual(source.forced, 1)

        // The same token again is no reason to retry either.
        source.token = "t1"
        source.nextOnForce = "t1"
        server.enqueue(.status(401, #"{"error":"invalid_token"}"#))
        let (again, _) = try await get()
        XCTAssertEqual(again, 401)
        XCTAssertEqual(server.requestCount, 2)
    }

    func testARequestWhoseBodyCanBeSentOnceOnlyIsNotRetried() async throws {
        server.enqueue(.status(401, #"{"error":"invalid_token"}"#))
        var request = URLRequest(url: server.url("/upload"))
        request.httpMethod = "POST"
        request.httpBodyStream = InputStream(data: Data("stream".utf8))
        let (_, response) = try await client.data(for: request)
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 401)
        XCTAssertEqual(server.requestCount, 1)
        XCTAssertEqual(source.forced, 0)
        XCTAssertEqual(server.takeRequest()?.body, Data("stream".utf8))
    }

    func testAReplayablePOSTBodyIsRetriedWithTheNewToken() async throws {
        server.enqueue(.status(401, #"{"error":"invalid_token"}"#))
        server.enqueue(.ok())
        var request = URLRequest(url: server.url("/upload"))
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (_, response) = try await client.data(for: request)
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)
        _ = server.takeRequest()
        let retry = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(retry.header("PinVault-Token"), "t2")
        XCTAssertEqual(retry.body, Data("{}".utf8))
    }

    func testTheFirstSourceThatHandlesTheHostWins() async throws {
        let other = FakeSource()
        other.token = "other"
        let two = session([FakeSource(handles: false), other])
        _ = try await get(two)
        XCTAssertEqual(server.takeRequest()?.header("PinVault-Token"), "other")
    }

    func testTheTokenGoesOutsideTheRecoveryRetry() async throws {
        // The token interceptor wraps recovery, so a request recovery retries still carries it.
        let calls = Counter()
        let recovery = PinRecoveryInterceptor(updater: { true })
        let headers = Locked<[String?]>([])
        let source = self.source
        let session = PinnedSession(
            interceptors: [AttestationTokenInterceptor { [source] }, recovery],
            transport: FakeTransport { exchange in
                headers.withLock { $0.append(exchange.request.value(forHTTPHeaderField: "PinVault-Token")) }
                if calls.increment() == 1 { throw mismatch() }
                return fakeResponse(200)
            }
        )
        _ = try await session.data(from: URL(string: "https://example.com/x")!)
        XCTAssertEqual(headers.get(), ["t1", "t1"])
    }

    func testWithProofsEachRequestCarriesOneForItsTokenAndTheRetryANewOne() async throws {
        source.proofs = true
        server.enqueue(.status(401, headers: ["WWW-Authenticate": #"PinVault-Token error="invalid_token""#]))
        server.enqueue(.ok())
        let (status, _) = try await get(path: "/api/data?q=1")
        XCTAssertEqual(status, 200)
        let first = server.takeRequest()
        XCTAssertEqual(first?.header("PinVault-Token"), "t1")
        XCTAssertEqual(first?.header("PinVault-Proof"), "proof-1-t1")
        let retry = server.takeRequest()
        XCTAssertEqual(retry?.header("PinVault-Token"), "t2")
        XCTAssertEqual(retry?.header("PinVault-Proof"), "proof-2-t2")
        XCTAssertEqual(source.proofFor, ["GET /api/data t1", "GET /api/data t2"])
    }

    func testWithoutProofsNoProofHeaderIsSent() async throws {
        _ = try await get()
        XCTAssertNil(server.takeRequest()?.header("PinVault-Proof"))
    }
}
