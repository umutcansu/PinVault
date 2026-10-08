import XCTest
@testable import PinVault

/// Real TLS handshakes (Kotlin `CaTrustAndExpiryHandshakeTest`):
///  - Y1: a config past its expiresAt (plus grace) pins nothing.
///  - Y3: `requireCaTrust` hosts need the platform CAs as well as a pin.
final class CaTrustAndExpiryHandshakeTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000
    private var manager = testManager()
    private var server: TestServer!

    override func setUp() async throws {
        manager = testManager()
        let now = self.now
        manager.clock = { now }
        server = try TestServer(p12: "server", chain: ["intermediate"])
        try await server.start()
    }

    override func tearDown() {
        server.stop()
    }

    private func config(expiresAt: Int64 = 0) -> CertificateConfig {
        pinConfig("localhost", [TLSFixture.pin("leaf")], expiresAt: expiresAt)
    }

    private func call(_ config: CertificateConfig) async throws -> Int {
        let session = manager.applyTo(.ephemeral, configProvider: { config })
        let (_, response) = try await session.data(from: server.url("/"))
        return (response as! HTTPURLResponse).statusCode
    }

    /// Asserts the call fails with an error of `kind` somewhere in its cause chain.
    private func assertRefused(_ kind: String, file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> Void) async {
        let error = await assertPinVaultError(file: file, line: line, body)
        let names = error?.causeChain.compactMap { ($0 as? PinVaultError)?.exceptionName } ?? []
        XCTAssertTrue(names.contains(kind), "expected \(kind) in \(names)", file: file, line: line)
    }

    /// A check over anchors holding only the test root: a "CA" that knows the server.
    private var trustingTheServer: SecTrustCaCheck {
        SecTrustCaCheck(anchors: [TLSFixture.cert("root").der])
    }

    // MARK: Y1

    func testAnUnexpiredConfigPinsAsBefore() async throws {
        let status = try await call(config(expiresAt: now + 60_000))
        XCTAssertEqual(status, 200)
    }

    func testAnExpiredConfigRefusesTheHandshake() async {
        await assertRefused("ConfigExpiredException") { _ = try await self.call(self.config(expiresAt: self.now - 1)) }
        XCTAssertEqual(server.requestCount, 0)
    }

    func testTheExpiryIsCheckedAtTheHandshakeToo() {
        // The handshake check alone (no per-request check before it).
        let error = assertThrowsPinVault {
            try manager.checkServerTrusted([TLSFixture.cert("leaf")], hostname: "localhost", port: 443, config: config(expiresAt: now - 1))
        }
        XCTAssertEqual(
            error?.message,
            "Pin config expired at \(now - 1) (Unix ms) — refusing connection to 'localhost' until a fresh config is fetched"
        )
        guard case .configExpired? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
    }

    func testGraceKeepsAnExpiredConfigWorkingThatMuchLonger() async throws {
        manager.expiredConfigGraceMs = 60_000
        let status = try await call(config(expiresAt: now - 30_000))
        XCTAssertEqual(status, 200)
        await assertRefused("ConfigExpiredException") { _ = try await self.call(self.config(expiresAt: self.now - 90_000)) }
    }

    func testAFreshnessWriteBackReachesTheProvidersSession() async throws {
        // swap(expired) → write-back of a fresh envelope with the same pins → the session get() hands out connects.
        let provider = HttpClientProvider(sslManager: manager)
        provider.swap(config(expiresAt: now - 1))
        await assertRefused("ConfigExpiredException") { _ = try await provider.get().data(from: self.server.url()) }

        provider.replaceConfigInPlace(config(expiresAt: now + 60_000))

        let (_, response) = try await provider.get().data(from: server.url())
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)
    }

    func testAConfigWithoutExpiresAtIsNeverRefusedForAge() async throws {
        let status = try await call(config(expiresAt: 0))
        XCTAssertEqual(status, 200)
    }

    // MARK: Y3

    func testAPinnedButNotCATrustedHostIsRefusedWhenRequireCaTrustNamesIt() async {
        manager.requireCaTrust(["localhost"])
        // The platform trust store does not know the test root.
        await assertRefused("CaTrustException") { _ = try await self.call(self.config()) }
        XCTAssertEqual(server.requestCount, 0)
    }

    func testPinAndCABothPassingIsAccepted() async throws {
        manager.requireCaTrust(["localhost"])
        manager.caCheck = trustingTheServer
        let status = try await call(config())
        XCTAssertEqual(status, 200)
    }

    func testCATrustDoesNotReplaceThePin() async {
        manager.requireCaTrust(["localhost"])
        manager.caCheck = trustingTheServer
        await assertRefused("CertificateException") { _ = try await self.call(pinConfig("localhost", [pin("A"), pin("B")])) }
    }

    func testHostsNotNamedKeepPinOnlyTrust() async throws {
        manager.requireCaTrust(["api.example.com", "*.example.org"])
        let status = try await call(config())
        XCTAssertEqual(status, 200)
    }

    func testAPortSpecificPatternAppliesToThatPortOnly() async throws {
        manager.requireCaTrust(["localhost:\(server.port)"])
        await assertRefused("CaTrustException") { _ = try await self.call(self.config()) }

        manager.requireCaTrust(["localhost:1"])
        let status = try await call(config())
        XCTAssertEqual(status, 200)
    }

    func testTheCACheckJudgesTheLogicalHostName() throws {
        // The platform check uses the SSL policy for the host the app named.
        let chain = [TLSFixture.cert("leaf"), TLSFixture.cert("intermediate")]
        try trustingTheServer.check(chain, host: "mock-tls.sample", at: TLSFixture.validNow)
        XCTAssertThrowsError(try trustingTheServer.check(chain, host: "elsewhere.test", at: TLSFixture.validNow))
        XCTAssertThrowsError(try trustingTheServer.check(chain, host: "localhost", at: TLSFixture.cert("leaf").notAfter.addingTimeInterval(86_400)))
    }
}
