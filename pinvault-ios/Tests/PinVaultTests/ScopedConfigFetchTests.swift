import Foundation
import XCTest
@testable import PinVault

/// Port of ScopedConfigFetchTest (L-1 regression): `wantPinsFor(...)` must
/// actually reach the server — `?hosts=` and `X-Device-Id` on the wire, through
/// the real ``DefaultCertificateConfigApi``.
final class ScopedConfigFetchTests: XCTestCase {

    private var server: TestServer!
    private let deviceId = "ios-deadbeef01234567"

    override func setUp() async throws {
        server = try await startConfigApiServer()
    }

    override func tearDown() async throws {
        server.stop()
    }

    private func updater(wantPinsFor: [String], deviceId: String?) -> SSLCertificateUpdater {
        let manager = testManager()
        return SSLCertificateUpdater(
            // Unsigned config API — the block under test opts out via allowUnsigned().
            configApi: makeConfigApi(server, manager: manager),
            configStore: SpyConfigStore(),
            httpClientProvider: HttpClientProvider(sslManager: manager),
            sslManager: manager,
            clientKeyPassword: "changeit",
            maxRetryCount: 1,
            wantPinsFor: wantPinsFor,
            deviceIdProvider: { deviceId },
            sleep: { _ in }
        )
    }

    private func enqueueConfig() {
        server.enqueue(.ok(json(CertificateConfig(
            version: 1, pins: [HostPin(hostname: "a.example.com", sha256: [pin("A"), pin("B")], version: 1)]
        ))))
    }

    func testWantPinsForSendsTheHostsQueryAndTheDeviceIdHeader() async throws {
        enqueueConfig()
        let result = await updater(wantPinsFor: ["a.example.com", "b.example.com"], deviceId: deviceId).updateNow()
        guard case .updated = result else { return XCTFail("update should succeed, got \(result)") }

        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.query("hosts"), "a.example.com,b.example.com")
        XCTAssertEqual(request.header("X-Device-Id"), deviceId)
        // currentVersion is still forwarded alongside the scoping params.
        XCTAssertEqual(request.query("currentVersion"), "0")
    }

    func testWithoutWantPinsForTheLegacyRequestCarriesNeitherHostsNorTheDeviceId() async throws {
        enqueueConfig()
        let result = await updater(wantPinsFor: [], deviceId: deviceId).updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }

        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertNil(request.query("hosts"))
        XCTAssertNil(request.header("X-Device-Id"))
    }

    func testWithoutADeviceIdTheHostsAreStillSentAndTheHeaderIsLeftOut() async throws {
        enqueueConfig()
        let result = await updater(wantPinsFor: ["a.example.com"], deviceId: nil).updateNow()
        guard case .updated = result else { return XCTFail("\(result)") }

        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.query("hosts"), "a.example.com")
        XCTAssertNil(request.header("X-Device-Id"))
    }
}
