import XCTest
@testable import PinVault

/// A revoked identity is answered `403 {"error":"reenroll_required"}` on every
/// mTLS request; every request of a Config API's bootstrap session reports it
/// (Kotlin `ReenrollRequiredDetectionTest`; the per-endpoint cases go through
/// `DefaultCertificateConfigApi`, L2 — here the interceptor on the bootstrap session).
final class ReenrollRequiredDetectionTests: XCTestCase {

    private final class Reports: @unchecked Sendable {
        let entries = Locked<[(String, X509Certificate?)]>([])
        var reasons: [String] { entries.get().map(\.0) }
        var presented: [X509Certificate?] { entries.get().map(\.1) }
    }

    private var server: TestServer!
    private var reports = Reports()
    private let revoked = TestServer.Response.status(403, #"{"error":"reenroll_required","message":"This identity was revoked."}"#)

    override func setUp() async throws {
        reports = Reports()
    }

    override func tearDown() {
        server?.stop()
    }

    private func start(clientAuth: TestServer.ClientAuth = .none) async throws {
        server = try TestServer(p12: "server", chain: ["intermediate"], clientAuth: clientAuth)
        try await server.start()
    }

    private func bootstrap(_ manager: DynamicSSLManager = testManager()) -> PinnedSession {
        let reports = self.reports
        return manager.buildBootstrapClient(
            [HostPin(hostname: "localhost", sha256: [TLSFixture.pin("leaf"), TLSFixture.backupPin])],
            interceptor: ReenrollRequiredInterceptor { reason, presented in
                reports.entries.withLock { $0.append((reason, presented)) }
            }
        )
    }

    func testARefusalIsReportedAndTheResponseGoesOnUntouched() async throws {
        try await start()
        server.enqueue(revoked)
        let (data, response) = try await bootstrap().data(from: server.url("/api/v1/certificate-config"))
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 403)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), #"{"error":"reenroll_required","message":"This identity was revoked."}"#)
        XCTAssertEqual(reports.reasons, ["This identity was revoked."])
        // No client certificate on this connection: the listener is told so.
        XCTAssertEqual(reports.presented.count, 1)
        XCTAssertNil(reports.presented[0])
    }

    func testAMissingMessageFallsBackToTheErrorCode() async throws {
        try await start()
        server.enqueue(.status(403, #"{"error":"reenroll_required"}"#))
        _ = try await bootstrap().data(from: server.url())
        XCTAssertEqual(reports.reasons, ["reenroll_required"])
    }

    func testOtherRefusalsAreNotReported() async throws {
        try await start()
        server.enqueue(.status(403, #"{"error":"device_identity_mismatch"}"#))
        server.enqueue(.status(403, "<html>forbidden</html>"))
        server.enqueue(.status(401, #"{"error":"reenroll_required"}"#))
        server.enqueue(.status(200, #"{"error":"reenroll_required"}"#))
        let session = bootstrap()
        for _ in 0..<4 { _ = try await session.data(from: server.url()) }
        XCTAssertTrue(reports.reasons.isEmpty)
    }

    func testTheIdentityThePresentedConnectionCarriedIsReported() async throws {
        // The transport hands the presented leaf up with every response …
        try await start(clientAuth: .required)
        let manager = testManager()
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts([server.url().absoluteString])
        let seen = Locked<X509Certificate?>(nil)
        let session = manager.buildBootstrapClient(
            [HostPin(hostname: "localhost", sha256: [TLSFixture.pin("leaf"), TLSFixture.backupPin])],
            interceptor: Capture { seen.set($0.presentedClientCertificate) }
        )
        _ = try await session.data(from: server.url())
        XCTAssertEqual(seen.get()?.subject.commonName, "client-a")

        // … and the interceptor passes it on with the reason.
        let reports = self.reports
        let interceptor = ReenrollRequiredInterceptor { reason, presented in reports.entries.withLock { $0.append((reason, presented)) } }
        let leaf = TLSFixture.identity("client-a").leaf
        let fake = PinnedSession(interceptors: [interceptor], transport: FakeTransport { _ in
            PinnedResponse(
                data: Data(#"{"error":"reenroll_required","message":"revoked"}"#.utf8),
                response: HTTPURLResponse(url: URL(string: "https://config.test/")!, statusCode: 403, httpVersion: nil, headerFields: nil)!,
                presentedClientCertificate: leaf
            )
        })
        _ = try await fake.data(from: URL(string: "https://config.test/")!)
        XCTAssertEqual(reports.reasons, ["revoked"])
        XCTAssertEqual(reports.presented.first??.subject.commonName, "client-a")
    }

    /// PLATFORM LIMIT: on a connection where the server asked for a client
    /// certificate, CFNetwork turns ANY HTTP 403 into `URLError.clientCertificateRequired`
    /// (-1206) and drops the response — neither the completion handler nor the
    /// data delegate sees it (409 / 410 pass through). An mTLS listener that
    /// answers `403 reenroll_required` is therefore seen as a TLS failure on iOS.
    func test403OverMTLSIsSwallowedByURLSession() async throws {
        try await start(clientAuth: .required)
        let manager = testManager()
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts([server.url().absoluteString])
        server.enqueue(revoked)
        let error = await assertPinVaultError { _ = try await self.bootstrap(manager).data(from: self.server.url()) }
        guard case .sslHandshake(_, let cause)? = error, (cause as? URLError)?.code == .clientCertificateRequired else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(error!), "not a pin mismatch")
        XCTAssertTrue(reports.reasons.isEmpty)
        XCTAssertEqual(server.requestCount, 1, "the request did reach the server")
        XCTAssertEqual(server.takeRequest()?.clientCertificate?.subject.commonName, "client-a")
    }

    func testTheReasonParser() {
        XCTAssertEqual(ReenrollRequiredInterceptor.reenrollReason(Data(#"{"error":"reenroll_required","message":"  "}"#.utf8)), "reenroll_required")
        XCTAssertNil(ReenrollRequiredInterceptor.reenrollReason(Data("not json".utf8)))
        XCTAssertNil(ReenrollRequiredInterceptor.reenrollReason(Data(#"["reenroll_required"]"#.utf8)))
        // A body larger than the peek window is not read past it (OkHttp peekBody).
        let padded = #"{"error":"reenroll_required","pad":""# + String(repeating: "x", count: 9_000) + #""}"#
        XCTAssertNil(ReenrollRequiredInterceptor.reenrollReason(Data(padded.utf8)))
    }
}

/// Hands every response to a closure.
private struct Capture: PinnedInterceptor {
    let body: @Sendable (PinnedResponse) -> Void

    func intercept(_ exchange: PinnedExchange, proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse) async throws -> PinnedResponse {
        let response = try await proceed(exchange)
        body(response)
        return response
    }
}
