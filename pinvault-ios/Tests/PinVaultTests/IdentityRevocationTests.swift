import Foundation
import XCTest
@testable import PinVault

/// `403 reenroll_required` is not signed. It may delete a device's vault files
/// (`wipeVaultFilesOnRevocation()`) only when the server gave it while looking
/// at this device's client certificate: on a connection that presented the
/// identity loaded now. Over real TLS, with the real interceptor (Kotlin
/// `IdentityRevocationTest`).
///
/// iOS: on a connection where the server asked for a client certificate,
/// URLSession turns a 403 into an error, so the server answers iOS `409` +
/// `X-PinVault-Status: 403` (PORTING.md §4) and the transport hands it on as
/// the 403. Here a small interceptor stands in for that step of the transport (L2).
final class IdentityRevocationTests: XCTestCase {

    /// The transport's `409` + `X-PinVault-Status: 403` → `403` step.
    private struct ForbiddenAsConflict: PinnedInterceptor {
        func intercept(_ exchange: PinnedExchange, proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse) async throws -> PinnedResponse {
            let response = try await proceed(exchange)
            guard response.statusCode == 409, response.http?.value(forHTTPHeaderField: "X-PinVault-Status") == "403",
                  let http = response.http, let url = http.url,
                  let forbidden = HTTPURLResponse(url: url, statusCode: 403, httpVersion: "HTTP/1.1", headerFields: nil) else {
                return response
            }
            return PinnedResponse(data: response.data, response: forbidden, presentedClientCertificate: response.presentedClientCertificate)
        }
    }

    private final class Recorder: @unchecked Sendable {
        let presented = Locked<[String?]>([])
        let wipes = Locked(0)
    }

    private var server: TestServer!
    private let manager = testManager()
    private let recorder = Recorder()
    private lazy var revocation: IdentityRevocation = { [manager] in
        IdentityRevocation { manager.defaultClientCertificate() }
    }()

    private let revokedBody = #"{"error":"reenroll_required","message":"revoked"}"#

    override func tearDown() {
        server?.stop()
    }

    private func start(_ clientAuth: TestServer.ClientAuth) async throws {
        server = try TestServer(p12: "server", chain: ["intermediate"], clientAuth: clientAuth)
        try await server.start()
    }

    /// A pinned session with the interceptor wired the way `ConfigApiClient` wires it.
    private func session(mtlsHost: Bool) -> PinnedSession {
        let config = pinConfig("localhost", [TLSFixture.pin("leaf")], mtls: mtlsHost)
        let revocation = self.revocation
        let recorder = self.recorder
        let interceptor = ReenrollRequiredInterceptor { _, certificate in
            recorder.presented.withLock { $0.append(certificate?.subject.commonName) }
            if revocation.refusedOnConnection(certificate) { recorder.wipes.withLock { $0 += 1 } }
        }
        return manager.applyTo(.ephemeral, configProvider: { config }, interceptors: [interceptor, ForbiddenAsConflict()])
    }

    private func revoked(viaConflict: Bool) -> TestServer.Response {
        viaConflict ? .status(409, revokedBody, headers: ["X-PinVault-Status": "403"]) : .status(403, revokedBody)
    }

    func testARefusalOnAConnectionThatPresentedTheIdentityWipesOnce() async throws {
        try await start(.required)
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let client = session(mtlsHost: true)
        for _ in 0..<3 { server.enqueue(revoked(viaConflict: true)) }

        for _ in 0..<3 { _ = try await client.data(from: server.url("/api/v1/vault/x")) }

        XCTAssertEqual(recorder.presented.get(), ["client-a", "client-a", "client-a"])
        XCTAssertEqual(recorder.wipes.get(), 1, "a revoked device hears it on every request; its files go once")
    }

    func testARefusalOnABlockWithoutAnIdentityWipesNothing() async throws {
        // A TLS-only block: nothing enrolled, nothing presented.
        try await start(.none)
        let client = session(mtlsHost: true)
        server.enqueue(revoked(viaConflict: false))

        _ = try await client.data(from: server.url("/api/v1/vault/x"))

        XCTAssertEqual(recorder.presented.get(), [nil])
        XCTAssertEqual(recorder.wipes.get(), 0)
    }

    func testARefusalOnAConnectionThatDidNotPresentTheLoadedIdentityWipesNothing() async throws {
        // An identity is loaded, but this host is not one it is shown to
        // (not the block's own listener, not an mtls host).
        try await start(.none)
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let client = session(mtlsHost: false)
        server.enqueue(revoked(viaConflict: false))

        _ = try await client.data(from: server.url("/api/v1/vault/x"))

        XCTAssertEqual(recorder.presented.get(), [nil])
        XCTAssertEqual(recorder.wipes.get(), 0)
    }

    func testOnlyTheIdentityLoadedNowCountsAndANewIdentityCanBeRefusedAgain() {
        let device = TLSFixture.identity("client-a")
        let other = TLSFixture.identity("client-b")
        manager.loadClientKey(device)
        XCTAssertFalse(revocation.presentedCurrent(other.leaf), "another certificate is not this device's")
        XCTAssertFalse(revocation.presentedCurrent(nil))
        XCTAssertTrue(revocation.presentedCurrent(device.leaf))

        XCTAssertTrue(revocation.refusedOnConnection(device.leaf))
        XCTAssertFalse(revocation.refusedOnConnection(device.leaf))

        // Re-enrolled: a new certificate, a new notice.
        manager.loadClientKey(other)
        XCTAssertFalse(revocation.refusedOnConnection(device.leaf), "the old certificate no longer speaks for the device")
        XCTAssertTrue(revocation.refusedOnConnection(other.leaf))
    }

    func testTheAnswerToTheIdentitysOwnRenewalCountsOnceAndNeverWithoutAnIdentity() {
        XCTAssertFalse(revocation.claim(), "nothing loaded: nothing to revoke")
        let device = TLSFixture.identity("client-a")
        manager.loadClientKey(device)
        XCTAssertTrue(revocation.claim())
        XCTAssertFalse(revocation.claim())
        // The request path and the renewal path share the one notice.
        XCTAssertFalse(revocation.refusedOnConnection(device.leaf))
    }
}
