import Foundation
import XCTest
@testable import PinVault

/// `forbidden-as-409` (PORTING.md §4): every request of the Config API client
/// asks for it, an app request only when the library presents a client
/// identity to its host, and the transport hands a `409` +
/// `X-PinVault-Status: 403` to the interceptors as the 403 it is.
final class ForbiddenAsConflictTests: XCTestCase {

    private let reenroll = #"{"error":"reenroll_required","message":"This identity was revoked. Enroll again."}"#
    private var servers: [TestServer] = []

    override func tearDown() async throws {
        servers.forEach { $0.stop() }
    }

    private func server(clientAuth: TestServer.ClientAuth = .none) async throws -> TestServer {
        let server = try await startConfigApiServer(clientAuth: clientAuth)
        servers.append(server)
        return server
    }

    private var asConflict: TestServer.Response {
        .status(409, reenroll, headers: ["Content-Type": "application/json", "X-PinVault-Status": "403", "X-Trace": "t-1"])
    }

    // MARK: Header values

    func testTheTokenIsAppendedOnceAndRecognisedCaseInsensitively() {
        XCTAssertEqual(ForbiddenAsConflict.adding(to: nil), "forbidden-as-409")
        XCTAssertEqual(ForbiddenAsConflict.adding(to: " "), "forbidden-as-409")
        XCTAssertEqual(ForbiddenAsConflict.adding(to: "redelivery,multisig,keyset"), "redelivery,multisig,keyset,forbidden-as-409")
        XCTAssertEqual(ForbiddenAsConflict.adding(to: "csr, FORBIDDEN-AS-409"), "csr, FORBIDDEN-AS-409")
        XCTAssertTrue(ForbiddenAsConflict.requested("redelivery, forbidden-as-409"))
        XCTAssertFalse(ForbiddenAsConflict.requested("forbidden-as-4090"))
        XCTAssertFalse(ForbiddenAsConflict.requested(nil))
    }

    // MARK: The Config API client

    func testEveryConfigAPIRequestAsksForItEvenWithoutAFeaturesHeaderOfItsOwn() async throws {
        let server = try await server()
        server.setHandler { _ in .ok(#"{"status":"ok"}"#) }
        let api = makeConfigApi(server)
        _ = try await api.healthCheck()
        try await api.reportVaultDownload(VaultDownloadReport(
            key: "k", version: 1, status: "downloaded", deviceManufacturer: "Apple", deviceModel: "m",
            enrollmentLabel: "default", deviceId: "d", deviceAlias: "a"
        ))
        _ = try? await api.downloadVaultFileWithMeta(endpoint: "api/v1/vault/flags")
        for request in server.requests {
            XCTAssertEqual(request.features, ["forbidden-as-409"], request.path)
        }
        XCTAssertEqual(server.requestCount, 3)
    }

    func testAConflictStandingForA403ReachesTheReenrollSniffAndTheRenewalMappingAsA403() async throws {
        let server = try await server()
        server.setHandler { [asConflict] _ in asConflict }
        let heard = Locked<[String]>([])
        let api = makeConfigApi(server, onReenrollRequired: { reason, _ in heard.withLock { $0.append(reason) } })

        let renewal = try await api.renewClientCert(clientId: "dev-1", csrDer: Data([0x30, 0x00]))

        XCTAssertEqual(renewal, .reenrollRequired(reason: "This identity was revoked. Enroll again."))
        XCTAssertEqual(heard.get(), ["This identity was revoked. Enroll again."])
    }

    func testANormalisedResponseKeepsItsBodyAndHeaders() async throws {
        let server = try await server()
        server.setHandler { [asConflict] _ in asConflict }
        let session = makeConfigApi(server).bootstrapClient
        var request = URLRequest(url: server.url("/api/v1/anything"))
        request.setValue("forbidden-as-409", forHTTPHeaderField: "X-PinVault-Features")
        let (data, response) = try await session.data(for: request)
        let http = try XCTUnwrap(response as? HTTPURLResponse)
        XCTAssertEqual(http.statusCode, 403)
        XCTAssertEqual(http.value(forHTTPHeaderField: "X-Trace"), "t-1")
        XCTAssertEqual(http.url, server.url("/api/v1/anything"))
        XCTAssertEqual(String(decoding: data, as: UTF8.self), reenroll)
    }

    func testAConflictOnARequestThatDidNotAskStaysAConflict() async throws {
        let server = try await server()
        server.setHandler { [asConflict] _ in asConflict }
        let manager = testManager()
        let session = manager.buildDynamicClient(configProvider: { CertificateConfig(version: 1, pins: configApiServerPins) })
        let (_, response) = try await session.data(from: server.url("/x"))
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 409)
        XCTAssertNil(server.takeRequest()?.header("X-PinVault-Features"))
    }

    // MARK: mTLS: why the feature exists

    func testOnAListenerThatAsksForACertificateA403IsLostButTheConflictArrives() async throws {
        let server = try await server(clientAuth: .required)
        let manager = testManager()
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: "changeit")
        manager.setIdentityHosts([server.baseURL])
        let heard = Locked<[(String, X509Certificate?)]>([])
        let api = makeConfigApi(server, manager: manager, onReenrollRequired: { reason, presented in
            heard.withLock { $0.append((reason, presented)) }
        })

        // A plain 403 on this connection: URLSession turns it into a client-certificate error.
        server.enqueue(.status(403, reenroll, headers: ["Content-Type": "application/json"]))
        do {
            _ = try await api.bootstrapClient.data(from: server.url("/api/v1/certificate-config"))
            XCTFail("URLSession hands no 403 over on a connection that presented a client certificate")
        } catch let error as PinVaultError {
            guard case .sslHandshake(_, let cause) = error else { return XCTFail("\(error)") }
            XCTAssertEqual((cause as? URLError)?.code, .clientCertificateRequired)
        }
        XCTAssertTrue(heard.get().isEmpty)

        // The same answer as 409 + X-PinVault-Status: 403 (what the server sends when asked).
        server.enqueue(asConflict)
        let renewal = try await api.renewClientCert(clientId: "dev-1", csrDer: Data([0x30, 0x00]))
        XCTAssertEqual(renewal, .reenrollRequired(reason: "This identity was revoked. Enroll again."))
        XCTAssertEqual(heard.get().count, 1)
        XCTAssertEqual(heard.get().first?.1?.subject.commonName, "client-a", "the identity the connection presented")
        XCTAssertTrue(server.requests.allSatisfy { $0.features.contains("forbidden-as-409") })
    }

    // MARK: App sessions

    func testAppSessionsAskOnlyWhereTheLibraryPresentsAClientIdentity() async throws {
        let withIdentity = try await server(clientAuth: .required)
        let without = try await server()
        let manager = testManager()
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: "changeit")
        manager.setIdentityHosts([withIdentity.baseURL])
        let provider = HttpClientProvider(sslManager: manager)
        provider.swap(CertificateConfig(version: 1, pins: configApiServerPins))
        withIdentity.setHandler { [asConflict] _ in asConflict }
        without.setHandler { _ in .ok() }

        let sessions = [
            provider.get(),
            manager.buildDynamicClient(configProvider: { provider.currentConfig }, settings: HttpConnectionSettings()),
            manager.applyTo(.ephemeral, configProvider: { provider.currentConfig }),
        ]
        for session in sessions {
            let (_, toIdentityHost) = try await session.data(from: withIdentity.url("/api"))
            XCTAssertEqual((toIdentityHost as? HTTPURLResponse)?.statusCode, 403, "normalised for the app too")
            _ = try await session.data(from: without.url("/api"))
        }
        XCTAssertTrue(withIdentity.requests.allSatisfy { $0.features == ["forbidden-as-409"] })
        XCTAssertEqual(withIdentity.requestCount, 3)
        XCTAssertTrue(without.requests.allSatisfy { $0.header("X-PinVault-Features") == nil }, "a host without the identity never hears of it")
        XCTAssertEqual(without.requestCount, 3)
    }

    func testAnAppsOwnFeaturesHeaderKeepsItsTokens() async throws {
        let server = try await server(clientAuth: .required)
        let manager = testManager()
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: "changeit")
        manager.setIdentityHosts([server.baseURL])
        let session = manager.buildDynamicClient(configProvider: { CertificateConfig(version: 1, pins: configApiServerPins) })
        var request = URLRequest(url: server.url("/x"))
        request.setValue("custom", forHTTPHeaderField: "X-PinVault-Features")
        _ = try await session.data(for: request)
        XCTAssertEqual(server.takeRequest()?.features, ["custom", "forbidden-as-409"])
    }
}
