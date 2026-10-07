import Foundation
import XCTest
@testable import PinVault

/// Port of ReporterPinnedClientTest: reports can go to a pinned HTTPS endpoint
/// without an unpinned session — and do (`pinnedClient` over the bootstrap
/// client, 5 s timeouts).
final class ReporterPinnedClientTests: XCTestCase {

    private var servers: [TestServer] = []

    override func tearDown() async throws {
        servers.forEach { $0.stop() }
    }

    private func server(_ p12: String = "server", chain: [String] = ["intermediate"]) async throws -> TestServer {
        let server = try TestServer(p12: p12, chain: chain)
        try await server.start()
        servers.append(server)
        return server
    }

    private func client(host: String = "localhost") -> PinnedSession {
        PinVaultBackendReporter.pinnedClient(hostname: host, pins: [TLSFixture.pin("leaf"), TLSFixture.backupPin], manager: testManager())
    }

    func testAcceptsThePinnedCertificateAndRefusesAnyOther() async throws {
        let pinned = try await server()
        let (_, response) = try await client().data(from: pinned.url("/report"))
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)

        let other = try await server("selfsigned", chain: [])
        let error = await assertPinVaultError { _ = try await self.client().data(from: other.url("/report")) }
        guard case .sslHandshake(_, let cause)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue((cause as? PinVaultError)?.message.contains("pinning failure") == true, "\(String(describing: cause))")
    }

    func testPinsOnlyTheNamedHostAndKeepsShortTimeouts() async throws {
        let pinned = try await server()
        let error = await assertPinVaultError { _ = try await self.client().data(from: pinned.url("/report", host: "127.0.0.1")) }
        guard case .sslHandshake(_, let cause)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue((cause as? PinVaultError)?.message.contains("No pin entry") == true, "\(String(describing: cause))")

        let session = PinVaultBackendReporter.pinnedClient(hostname: "reports.test", pins: [TLSFixture.pin("leaf"), TLSFixture.backupPin])
        let transport = try XCTUnwrap(((session.transport as? InterceptedTransport)?.base ?? session.transport) as? URLSessionTransport)
        XCTAssertEqual(transport.configuration.timeoutIntervalForRequest, 5)
        XCTAssertEqual(PinVaultBackendReporter.pinnedClientTimeout, 5)
    }

    func testAReporterPostsThroughThePinnedClient() async throws {
        let pinned = try await server()
        let reporter = PinVaultBackendReporter(managementUrl: pinned.baseURL, pinnedSession: client())
        await reporter.handle(.connection(
            hostname: "api.example.com", success: true, pinVersion: 2, deviceManufacturer: "Apple",
            deviceModel: "iPhone17,1", actualPin: "abc", expectedPins: ["abc"]
        ))
        let request = try XCTUnwrap(pinned.takeRequest())
        XCTAssertEqual(request.path, "/api/v1/connection-history/client-report")
        XCTAssertEqual(request.jsonBody["deviceModel"] as? String, "iPhone17,1")
        XCTAssertNil(request.header("X-PinVault-Features"), "telemetry is no Config API request")
    }
}
