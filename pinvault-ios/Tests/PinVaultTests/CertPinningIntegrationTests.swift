import XCTest
@testable import PinVault

/// Real TLS handshakes against an in-process server (Kotlin
/// `CertPinningIntegrationTest`, plus every refusal path of the handshake
/// check over the wire).
final class CertPinningIntegrationTests: XCTestCase {

    private var servers: [TestServer] = []
    private let leafPin = TLSFixture.pin("leaf")
    private let password = "changeit"

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func server(_ p12: String = "server", chain: [String] = ["intermediate"]) async throws -> TestServer {
        let server = try TestServer(p12: p12, chain: chain)
        try await server.start()
        servers.append(server)
        return server
    }

    private func get(_ session: PinnedSession, _ url: URL) async throws -> (Int, String) {
        let (data, response) = try await session.data(from: url)
        return ((response as! HTTPURLResponse).statusCode, String(decoding: data, as: UTF8.self))
    }

    /// The trust check's error behind a refused request.
    private func refusal(_ session: PinnedSession, _ url: URL, file: StaticString = #filePath, line: UInt = #line) async -> PinVaultError? {
        let error = await assertPinVaultError(file: file, line: line) { _ = try await session.data(from: url) }
        guard case .sslHandshake(_, let cause)? = error else {
            XCTFail("expected an SSLHandshakeException, got \(String(describing: error))", file: file, line: line)
            return nil
        }
        return cause as? PinVaultError
    }

    func testCorrectPinConnects() async throws {
        let server = try await server()
        let config = pinConfig("localhost", [leafPin])
        let session = testManager().applyTo(.ephemeral, configProvider: { config })
        let (status, body) = try await get(session, server.url("/test"))
        XCTAssertEqual(status, 200)
        XCTAssertEqual(body, "ok")
        XCTAssertEqual(server.takeRequest()?.path, "/test")
    }

    func testWrongPinIsRefusedAndNothingReachesTheServer() async throws {
        let server = try await server()
        let session = testManager().buildClient(pinConfig("localhost", [pin("Z")]))
        let cause = await refusal(session, server.url("/test"))
        guard case .certificate(let message, _)? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertTrue(message.contains("Certificate pinning failure for localhost"), message)
        XCTAssertEqual(server.requestCount, 0)
    }

    func testWrongP12PasswordThrows() {
        XCTAssertThrowsError(try testManager().loadClientKeystore(TLSFixture.p12("client-a"), password: "wrongpassword"))
        XCTAssertThrowsError(try testManager().loadClientKeystore(Data([1, 2, 3]), password: password))
    }

    func testTwoHostCertsAreParsedAndKeptApart() {
        let manager = testManager()
        manager.loadHostClientCerts(["alpha.host": TLSFixture.p12("client-a"), "beta.host": TLSFixture.p12("client-b")], password: password)
        let selector = manager.buildCompositeKeyManagers()!
        XCTAssertEqual(selector.select(host: "alpha.host", port: 443)?.identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(selector.select(host: "beta.host", port: 443)?.identity.leaf?.subject.commonName, "client-b")
        XCTAssertNotEqual(TLSFixture.pin("client-a"), TLSFixture.pin("client-b"))
    }

    func testASecondCertForTheSameHostReplacesTheFirst() {
        let manager = testManager()
        manager.loadHostClientCerts(["same.host": TLSFixture.p12("client-a")], password: password)
        manager.loadHostClientCerts(["same.host": TLSFixture.p12("client-b")], password: password)
        XCTAssertEqual(manager.buildCompositeKeyManagers()?.select(host: "same.host", port: 443)?.identity.leaf?.subject.commonName, "client-b")
    }

    func testNoConfigRefusesTheConnectionInsteadOfFallingBackToSystemTrust() async throws {
        let server = try await server()
        let cause = await refusal(testManager().buildClient(nil), server.url("/test"))
        XCTAssertTrue(cause?.message.contains("No pins configured") == true, "\(String(describing: cause))")
        XCTAssertEqual(server.requestCount, 0)
    }

    func testTheSameDynamicSessionConnectsOnceAConfigArrives() async throws {
        let server = try await server()
        let live = Locked<CertificateConfig?>(nil)
        let session = testManager().buildDynamicClient(configProvider: { live.get() })
        _ = await refusal(session, server.url("/test"))

        live.set(pinConfig("localhost", [leafPin]))
        let (status, _) = try await get(session, server.url("/test"))
        XCTAssertEqual(status, 200)
    }

    func testTheProviderIsReReadOnEachHandshake() async throws {
        let server = try await server()
        let events = EventRecorder()
        let manager = testManager()
        manager.setConnectionListener(events.listener)
        let reads = Locked(0)
        let config = pinConfig("localhost", [leafPin])
        let session = manager.applyTo(.ephemeral, configProvider: { reads.withLock { $0 += 1 }; return config })
        _ = try await get(session, server.url("/first"))
        manager.onPinsChanged()
        _ = try await get(session, server.url("/second"))

        XCTAssertGreaterThanOrEqual(reads.get(), 2)
        let twoHandshakes = await eventually { events.connections.count == 2 }
        XCTAssertTrue(twoHandshakes, "\(events.connections)")
        XCTAssertEqual(server.connectionCount, 2)
    }

    // MARK: Refusals over the wire

    func testIssuerPinsOverTheWire() async throws {
        let full = try await server("server-full", chain: ["intermediate", "root"])
        for pinned in ["intermediate", "root"] {
            let session = testManager().buildClient(pinConfig("localhost", [TLSFixture.pin(pinned)]))
            let (status, _) = try await get(session, full.url())
            XCTAssertEqual(status, 200, pinned)
        }
    }

    func testAnIssuerPinMatchedForACertificateIssuedForAnotherHostIsRefused() async throws {
        let server = try await server("wrongsan", chain: ["intermediate"])
        let cause = await refusal(testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("intermediate")])), server.url())
        guard case .hostnameMismatch? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertEqual(server.requestCount, 0)
    }

    func testALeafPinForACertificateThatDoesNotNameTheHostFailsHostnameVerification() async throws {
        let server = try await server("wrongsan", chain: ["intermediate"])
        let session = testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("wrongsan")]))
        let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
        guard case .sslPeerUnverified(let message)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.hasPrefix("Hostname localhost not verified:"), message)
        XCTAssertTrue(message.contains("subjectAltNames: [other.chain.test]"), message)
        XCTAssertEqual(server.requestCount, 0)
    }

    func testASelfSignedCertificateWithoutSubjectAltNameIsRefusedByTheHostnameCheck() async throws {
        let server = try await server("nosan", chain: [])
        let session = testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("nosan")]))
        let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
        guard case .sslPeerUnverified? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testASelfSignedLeafPinnedByItsOwnKeyConnects() async throws {
        let server = try await server("selfsigned", chain: [])
        let session = testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("selfsigned")]))
        let (status, _) = try await get(session, server.url())
        XCTAssertEqual(status, 200)
        // By IP address too (the SAN lists 127.0.0.1).
        let byIP = testManager().buildClient(pinConfig("127.0.0.1", [TLSFixture.pin("selfsigned")]))
        let (ipStatus, _) = try await get(byIP, server.url(host: "127.0.0.1"))
        XCTAssertEqual(ipStatus, 200)
    }

    func testAnExpiredLeafIsRefusedAsAValidityFailureNotAMismatch() async throws {
        let server = try await server("expired", chain: ["intermediate"])
        let cause = await refusal(testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("expired")])), server.url())
        guard case .certificateValidity(let message, _)? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertTrue(message.hasPrefix("Server certificate is expired or not yet valid: NotAfter:"), message)
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(PinVaultError.sslHandshake(message: message, cause: cause)))
    }

    func testANotYetValidLeafIsRefused() async throws {
        let server = try await server("notyetvalid", chain: ["intermediate"])
        let cause = await refusal(testManager().buildClient(pinConfig("localhost", [TLSFixture.pin("notyetvalid")])), server.url())
        guard case .certificateValidity(let message, _)? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertTrue(message.contains("NotBefore:"), message)
    }

    func testTheValidityIsJudgedAtTheLibraryClock() async throws {
        let server = try await server()
        let manager = testManager()
        manager.wallClock = { TLSFixture.cert("leaf").notAfter.addingTimeInterval(60) }
        let cause = await refusal(manager.buildClient(pinConfig("localhost", [leafPin])), server.url())
        guard case .certificateValidity? = cause else { return XCTFail("\(String(describing: cause))") }
    }

    func testAHostWithoutAPinEntryIsRefused() async throws {
        let server = try await server()
        let cause = await refusal(testManager().buildClient(pinConfig("elsewhere.test", [leafPin])), server.url())
        guard case .unpinnedHost(let message, _)? = cause else { return XCTFail("\(String(describing: cause))") }
        XCTAssertEqual(message, "No pin entry for hostname 'localhost'. Configured hosts: elsewhere.test")
    }

    func testAPinForTheHostIsNotAPinForAnotherNameOfTheSameServer() async throws {
        // 127.0.0.1 and localhost are the same server and the same certificate,
        // but only localhost is pinned.
        let server = try await server()
        let cause = await refusal(testManager().buildClient(pinConfig("localhost", [leafPin])), server.url(host: "127.0.0.1"))
        guard case .unpinnedHost? = cause else { return XCTFail("\(String(describing: cause))") }
    }

    func testConnectionEventsReportSuccessAndMismatch() async throws {
        let server = try await server()
        let events = EventRecorder()
        let manager = testManager()
        manager.setConnectionListener(events.listener)
        _ = try await get(manager.buildClient(pinConfig("localhost", [leafPin], version: 7)), server.url())
        _ = await refusal(manager.buildClient(pinConfig("localhost", [pin("Q")], version: 8)), server.url())
        let both = await eventually { events.connections.count == 2 }
        XCTAssertTrue(both)
        let all = events.all
        guard case .connection("localhost", true, 7, "Apple", _, let actual, let expected) = all[0],
              case .connection("localhost", false, 8, _, _, let actual2, let expected2) = all[1] else {
            return XCTFail("\(all)")
        }
        XCTAssertEqual(actual, leafPin)
        XCTAssertEqual(expected, [leafPin, TLSFixture.backupPin])
        XCTAssertEqual(actual2, leafPin)
        XCTAssertEqual(expected2, [pin("Q"), TLSFixture.backupPin])
    }

    func testTLS12OrNewerIsNegotiated() async throws {
        let server = try await server()
        _ = try await get(testManager().buildClient(pinConfig("localhost", [leafPin])), server.url())
        let version = try XCTUnwrap(server.takeRequest()?.tlsVersion)
        XCTAssertTrue(version == .TLSv12 || version == .TLSv13, "\(version)")
        // And no configuration can lower the floor.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.tlsMinimumSupportedProtocolVersion = tls_protocol_version_t(rawValue: 0x0301)!  // TLS 1.0
        configuration.tlsMaximumSupportedProtocolVersion = tls_protocol_version_t(rawValue: 0x0302)!  // TLS 1.1
        DynamicSSLManager.harden(configuration, libraryOwned: false)
        XCTAssertEqual(configuration.tlsMinimumSupportedProtocolVersion, .TLSv12)
        XCTAssertEqual(configuration.tlsMaximumSupportedProtocolVersion, .TLSv13)
        XCTAssertNil(configuration.urlCache)
        XCTAssertNil(configuration.urlCredentialStorage)
    }

    func testLibrarySessionsKeepNoCacheCookiesOrCredentials() {
        let configuration = DynamicSSLManager.sessionConfiguration(HttpConnectionSettings(connectTimeout: 5, readTimeout: 12, writeTimeout: 7, callTimeout: 40, maxIdleConnections: 3))
        XCTAssertNil(configuration.urlCache)
        XCTAssertNil(configuration.httpCookieStorage)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertNil(configuration.urlCredentialStorage)
        XCTAssertEqual(configuration.timeoutIntervalForRequest, 12)
        XCTAssertEqual(configuration.timeoutIntervalForResource, 40)
        XCTAssertEqual(configuration.httpMaximumConnectionsPerHost, 3)
        XCTAssertEqual(configuration.tlsMinimumSupportedProtocolVersion, .TLSv12)
        let unlimited = DynamicSSLManager.sessionConfiguration(HttpConnectionSettings(connectTimeout: 0, readTimeout: 0, writeTimeout: 0))
        XCTAssertEqual(unlimited.timeoutIntervalForRequest, DynamicSSLManager.noTimeout)
    }

    func testAnInvalidatedSessionRefusesFurtherRequests() async throws {
        let server = try await server()
        let session = testManager().buildClient(pinConfig("localhost", [leafPin]))
        _ = try await get(session, server.url())
        session.invalidateAndCancel()
        let error = await assertPinVaultError { _ = try await session.data(from: server.url()) }
        guard case .illegalState? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAnUnsupportedURLIsRefused() async {
        let session = testManager().buildClient(pinConfig("localhost", [leafPin]))
        let error = await assertPinVaultError { _ = try await session.data(from: URL(string: "ftp://localhost/x")!) }
        guard case .illegalArgument? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testCancellingTheCallerCancelsTheRequest() async throws {
        let server = try await server()
        server.setHandler { _ in
            Thread.sleep(forTimeInterval: 2)
            return .ok()
        }
        let session = testManager().buildClient(pinConfig("localhost", [leafPin]))
        let url = server.url()
        let task = Task { try await session.data(from: url) }
        try await Task.sleep(nanoseconds: 300_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }
    }
}
