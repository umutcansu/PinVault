import XCTest
@testable import PinVault

/// Expired certificates (Kotlin `RetryAndExpiredCertTest`, D26 / E34). The
/// updater's retry cases (E31, E29) belong to `SSLCertificateUpdater` (L2).
final class RetryAndExpiredCertTests: XCTestCase {

    private let password = "changeit"

    func testE34AnExpiredHostClientCertLoadsAndTheValidOneKeepsWorking() {
        // Validity of a client certificate is the server's business; the library loads it.
        let manager = testManager()
        manager.loadHostClientCerts(["valid.host": TLSFixture.p12("client-a")], password: password)
        manager.loadHostClientCerts(["valid.host": TLSFixture.p12("client-a"), "expired.host": TLSFixture.p12("expired")], password: password)
        let selector = manager.buildCompositeKeyManagers()
        XCTAssertEqual(selector?.select(host: "valid.host", port: 443)?.identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(selector?.select(host: "expired.host", port: 443)?.identity.leaf?.spkiPin, TLSFixture.pin("expired"))
    }

    func testD26AnExpiredServerCertIsRefusedAtTheHandshakeAndNotRecovered() async throws {
        let server = try TestServer(p12: "expired", chain: ["intermediate"])
        try await server.start()
        defer { server.stop() }
        let refetches = Counter()
        let recovery = PinRecoveryInterceptor(updater: { refetches.increment(); return true })
        let session = testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("expired")]), recovery: recovery)

        let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
        guard case .sslHandshake? = error, case .certificateValidity? = error?.pinVaultCause else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(refetches.count, 0, "refetching pins cannot make an expired certificate valid")
        XCTAssertEqual(server.requestCount, 0)
    }

    func testAPinMismatchOverTheWireIsRecoveredOnceTheConfigIsRepaired() async throws {
        let server = try TestServer(p12: "server", chain: ["intermediate"])
        try await server.start()
        defer { server.stop() }
        let manager = testManager()
        let provider = HttpClientProvider(sslManager: manager)
        provider.swap(pinConfig("localhost", [pin("Z")]))
        let refetches = Counter()
        provider.recoveryUpdater = { [weak provider] in
            refetches.increment()
            provider?.swap(pinConfig("localhost", [TLSFixture.pin("leaf")], version: 2))
            return true
        }
        let (_, response) = try await provider.get().data(from: server.url())
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)
        XCTAssertEqual(refetches.count, 1)
        XCTAssertEqual(server.requestCount, 1)
    }
}
