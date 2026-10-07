import XCTest
@testable import PinVault

/// `resolve(host:to:)` and the E2E redirects: the request goes to the mapped
/// address, the `Host` header keeps the logical `host:port`, and every trust
/// and identity decision uses the logical name. Plus redirect following.
final class RequestRoutingTests: XCTestCase {

    private var servers: [TestServer] = []
    private let leafPin = TLSFixture.pin("leaf")

    override func tearDown() {
        servers.forEach { $0.stop() }
        servers = []
    }

    private func server(_ p12: String? = "server", chain: [String] = ["intermediate"], clientAuth: TestServer.ClientAuth = .none) async throws -> TestServer {
        let server = try TestServer(p12: p12, chain: p12 == nil ? [] : chain, clientAuth: clientAuth)
        try await server.start()
        servers.append(server)
        return server
    }

    private func logicalURL(_ host: String, _ server: TestServer, _ path: String = "/") -> URL {
        URL(string: "https://\(host):\(server.port)\(path)")!
    }

    private func status(_ session: PinnedSession, _ url: URL) async throws -> HTTPURLResponse {
        let (_, response) = try await session.data(from: url)
        return response as! HTTPURLResponse
    }

    private func mapped(_ manager: DynamicSSLManager = testManager(), pins host: String = "mock-tls.sample", _ extra: [String: String] = [:]) -> PinnedSession {
        var settings = HttpConnectionSettings().resolve(host: "mock-tls.sample", to: "127.0.0.1")
        for (name, address) in extra { settings = settings.resolve(host: name, to: address) }
        return manager.buildDynamicClient(configProvider: { pinConfig(host, [TLSFixture.pin("leaf")]) }, settings: settings)
    }

    // MARK: resolve

    func testTheRequestGoesToTheResolvedAddressWithTheLogicalHostHeader() async throws {
        let server = try await server()
        let url = logicalURL("mock-tls.sample", server, "/health?x=1")
        let response = try await status(mapped(), url)
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.url, url, "the app sees the URL it asked for")
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.header("Host"), "mock-tls.sample:\(server.port)")
        XCTAssertEqual(request.path, "/health?x=1")
    }

    func testPinsAreLookedUpForTheLogicalHostNotTheAddress() async throws {
        let server = try await server()
        let error = await assertPinVaultError { _ = try await self.status(self.mapped(pins: "127.0.0.1"), self.logicalURL("mock-tls.sample", server)) }
        guard case .unpinnedHost(let message, _)? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("'mock-tls.sample'"), message)
        XCTAssertEqual(server.requestCount, 0)
    }

    func testTheHostnameIsVerifiedAgainstTheLogicalHost() async throws {
        // The server's leaf does not name other.chain.test.
        let server = try await server()
        let settings = HttpConnectionSettings().resolve(host: "other.chain.test", to: "127.0.0.1")
        let session = testManager().buildDynamicClient(configProvider: { pinConfig("other.chain.test", [TLSFixture.pin("leaf")]) }, settings: settings)
        let error = await assertPinVaultError { _ = try await self.status(session, self.logicalURL("other.chain.test", server)) }
        guard case .sslPeerUnverified(let message)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.hasPrefix("Hostname other.chain.test not verified"), message)
    }

    func testTheConfigsResolveEntriesApplyAndSettingsOverrideThem() async throws {
        let server = try await server()
        let manager = testManager()
        manager.resolvedHosts = ["MOCK-TLS.sample": "127.0.0.1"]
        let bootstrap = manager.buildBootstrapClient([HostPin(hostname: "mock-tls.sample", sha256: [leafPin, TLSFixture.backupPin])])
        let response = try await status(bootstrap, logicalURL("mock-tls.sample", server))
        XCTAssertEqual(response.statusCode, 200)

        // A session's own entry wins: here it sends the host nowhere useful.
        let settings = HttpConnectionSettings().resolve(host: "mock-tls.sample", to: "127.0.0.2")
        XCTAssertEqual(manager.connectAddress(host: "mock-tls.sample", port: 443, overrides: settings.resolvedHosts).host, "127.0.0.2")
        XCTAssertEqual(manager.connectAddress(host: "mock-tls.sample", port: 443, overrides: [:]).host, "127.0.0.1")
        XCTAssertEqual(manager.connectAddress(host: "plain.test", port: 8443, overrides: [:]).host, "plain.test")
    }

    func testTheClientCertificateIsChosenForTheLogicalHost() async throws {
        let server = try await server(clientAuth: .required)
        let manager = testManager()
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts(["https://mock-tls.sample:\(server.port)/"])
        let response = try await status(mapped(manager), logicalURL("mock-tls.sample", server))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(server.takeRequest()?.clientCertificate?.subject.commonName, "client-a")

        // The same server under its address is not the listener the identity is for.
        let direct = manager.buildDynamicClient(configProvider: { pinConfig("127.0.0.1", [TLSFixture.pin("leaf")]) })
        _ = await assertPinVaultError { _ = try await self.status(direct, server.url(host: "127.0.0.1")) }
        XCTAssertEqual(server.requestCount, 1)
    }

    func testTwoNamesResolvedToTheSameAddressNeverShareAConnection() async throws {
        // Both names are on the server's certificate and pinned alike; a pooled
        // connection judged for one must not carry the other's requests.
        let server = try await server()
        let settings = HttpConnectionSettings()
            .resolve(host: "mock-tls.sample", to: "127.0.0.1")
            .resolve(host: "api.chain.test", to: "127.0.0.1")
        let config = CertificateConfig(version: 1, pins: [
            HostPin(hostname: "mock-tls.sample", sha256: [leafPin, TLSFixture.backupPin]),
            HostPin(hostname: "api.chain.test", sha256: [leafPin, TLSFixture.backupPin]),
        ])
        let session = testManager().buildDynamicClient(configProvider: { config }, settings: settings)
        _ = try await status(session, logicalURL("mock-tls.sample", server))
        _ = try await status(session, logicalURL("api.chain.test", server))
        _ = try await status(session, logicalURL("mock-tls.sample", server))
        let requests = server.requests
        XCTAssertEqual(requests.map { $0.header("Host") }, ["mock-tls.sample:\(server.port)", "api.chain.test:\(server.port)", "mock-tls.sample:\(server.port)"])
        XCTAssertNotEqual(requests[0].connection, requests[1].connection)
        XCTAssertEqual(requests[0].connection, requests[2].connection, "each name keeps its own pooled connection")
    }

    // MARK: E2E redirects

    func testAnE2ERedirectSendsTheConnectionElsewhereAndKeepsTheLogicalPort() async throws {
        let server = try await server()
        let manager = testManager()
        let port = server.port
        manager.connectionRedirect = { $0 == "127.0.0.1:6651" ? "127.0.0.1:\(port)" : nil }
        let session = manager.buildDynamicClient(configProvider: { pinConfig("127.0.0.1:6651", [TLSFixture.pin("leaf")]) })
        let response = try await status(session, URL(string: "https://127.0.0.1:6651/api")!)
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.url?.absoluteString, "https://127.0.0.1:6651/api")
        XCTAssertEqual(server.takeRequest()?.header("Host"), "127.0.0.1:6651", "pins and Host follow the logical host:port")
    }

    func testAnE2ERedirectAppliesOnTopOfAResolveEntry() async throws {
        let server = try await server()
        let manager = testManager()
        let port = server.port
        manager.connectionRedirect = { $0 == "127.0.0.1:443" ? "127.0.0.1:\(port)" : nil }
        let session = mapped(manager)
        let response = try await status(session, URL(string: "https://mock-tls.sample/x")!)
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(server.takeRequest()?.header("Host"), "mock-tls.sample", "the default port is not named")
    }

    func testAChangedE2EGenerationRebuildsTheSessions() async throws {
        let first = try await server()
        let second = try await server()
        let manager = testManager()
        let target = Locked(first.port)
        let generation = Locked(0)
        manager.connectionRedirect = { _ in "127.0.0.1:\(target.get())" }
        manager.externalGeneration = { generation.get() }
        let session = manager.buildDynamicClient(configProvider: { pinConfig("localhost", [TLSFixture.pin("leaf")]) })
        let url = URL(string: "https://localhost:7000/")!
        _ = try await status(session, url)
        XCTAssertEqual(first.requestCount, 1)

        target.set(second.port)
        _ = try await status(session, url)
        XCTAssertEqual(first.requestCount, 2, "same generation: the pooled session keeps its address")

        generation.set(1)
        _ = try await status(session, url)
        XCTAssertEqual(second.requestCount, 1, "new connections follow the new redirect")
    }

    func testRedirectTargetsAreParsed() {
        XCTAssertEqual(DynamicSSLManager.parseHostPort("127.0.0.1:6661")?.port, 6661)
        XCTAssertEqual(DynamicSSLManager.parseHostPort("[::1]:6661")?.host, "::1")
        XCTAssertNil(DynamicSSLManager.parseHostPort("127.0.0.1"))
        XCTAssertNil(DynamicSSLManager.parseHostPort("host:0"))
        XCTAssertNil(DynamicSSLManager.parseHostPort("host:99999"))
        XCTAssertEqual(URLSessionTransport.hostHeader("::1", 8443, scheme: "https"), "[::1]:8443")
        XCTAssertEqual(URLSessionTransport.hostHeader("a.test", 80, scheme: "http"), "a.test")
    }

    // MARK: HTTP redirects

    func testASameSchemeRedirectIsFollowedThroughTheRouting() async throws {
        let server = try await server()
        let port = server.port
        server.setHandler { request in
            request.path == "/a" ? .status(302, headers: ["Location": "https://mock-tls.sample:\(port)/b"]) : .ok("b")
        }
        let (data, response) = try await mapped().data(from: logicalURL("mock-tls.sample", server, "/a"))
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "b")
        XCTAssertEqual(response.url?.absoluteString, "https://mock-tls.sample:\(port)/b")
        XCTAssertEqual(server.requests.map(\.path), ["/a", "/b"])
        XCTAssertEqual(server.requests.last?.header("Host"), "mock-tls.sample:\(port)")
    }

    func testARedirectToAnotherPinnedNameIsPinnedForThatName() async throws {
        let server = try await server()
        let port = server.port
        server.setHandler { request in
            request.path == "/a" ? .status(302, headers: ["Location": "https://api.chain.test:\(port)/b"]) : .ok()
        }
        // api.chain.test is routed but not pinned: the hop is refused.
        let session = mapped(testManager(), ["api.chain.test": "127.0.0.1"])
        let error = await assertPinVaultError { _ = try await session.data(from: self.logicalURL("mock-tls.sample", server, "/a")) }
        guard case .unpinnedHost? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(server.requestCount, 1)
    }

    func testAuthorizationIsDroppedWhenARedirectChangesTheHost() async throws {
        let server = try await server()
        let port = server.port
        server.setHandler { request in
            switch request.path {
            case "/same": return .status(301, headers: ["Location": "/same2"])
            case "/other": return .status(302, headers: ["Location": "https://api.chain.test:\(port)/x"])
            default: return .ok()
            }
        }
        let settings = HttpConnectionSettings().resolve(host: "mock-tls.sample", to: "127.0.0.1").resolve(host: "api.chain.test", to: "127.0.0.1")
        let config = CertificateConfig(version: 1, pins: [
            HostPin(hostname: "mock-tls.sample", sha256: [leafPin, TLSFixture.backupPin]),
            HostPin(hostname: "api.chain.test", sha256: [leafPin, TLSFixture.backupPin]),
        ])
        let session = testManager().buildDynamicClient(configProvider: { config }, settings: settings)
        for path in ["/same", "/other"] {
            var request = URLRequest(url: logicalURL("mock-tls.sample", server, path))
            request.setValue("Bearer secret", forHTTPHeaderField: "Authorization")
            _ = try await session.data(for: request)
        }
        let requests = server.requests
        XCTAssertEqual(requests.map(\.path), ["/same", "/same2", "/other", "/x"])
        XCTAssertEqual(requests[1].header("Authorization"), "Bearer secret", "same host keeps it")
        XCTAssertNil(requests[3].header("Authorization"), "another host gets no credentials")
    }

    func testA302TurnsAPOSTIntoAGETWhileA307KeepsMethodAndBody() async throws {
        let server = try await server()
        server.setHandler { request in
            switch request.path {
            case "/302": return .status(302, headers: ["Location": "/target"])
            case "/307": return .status(307, headers: ["Location": "/target"])
            default: return .ok()
            }
        }
        let session = testManager().buildClient(pinConfig("localhost", [leafPin]))
        for path in ["/302", "/307"] {
            var request = URLRequest(url: server.url(path))
            request.httpMethod = "POST"
            request.httpBody = Data("payload".utf8)
            request.setValue("text/plain", forHTTPHeaderField: "Content-Type")
            _ = try await session.data(for: request)
        }
        let requests = server.requests
        XCTAssertEqual(requests.map(\.method), ["POST", "GET", "POST", "POST"])
        XCTAssertEqual(requests[1].body, Data())
        XCTAssertNil(requests[1].header("Content-Type"))
        XCTAssertEqual(requests[3].body, Data("payload".utf8))
    }

    func testA307WithAStreamBodyIsNotFollowed() async throws {
        let server = try await server()
        server.setHandler { request in
            request.path == "/307" ? .status(307, headers: ["Location": "/target"]) : .ok()
        }
        var request = URLRequest(url: server.url("/307"))
        request.httpMethod = "POST"
        request.httpBodyStream = InputStream(data: Data("once".utf8))
        let (_, response) = try await testManager().buildClient(pinConfig("localhost", [leafPin])).data(for: request)
        XCTAssertEqual((response as! HTTPURLResponse).statusCode, 307, "a one-shot body is not sent again: the 3xx is the answer")
        XCTAssertEqual(server.requests.map(\.path), ["/307"])
    }

    func testALibrarySessionDoesNotFollowARedirectIntoTheClearButAnAppliedOneDoes() async throws {
        let tls = try await server()
        let plain = try await server(nil)
        tls.setHandler { _ in .status(302, headers: ["Location": plain.url("/clear").absoluteString]) }
        let config = pinConfig("localhost", [leafPin])
        let library = testManager().buildDynamicClient(configProvider: { config })
        let refused = try await status(library, tls.url("/start"))
        XCTAssertEqual(refused.statusCode, 302, "followSslRedirects(false): the 3xx is the answer")
        XCTAssertEqual(plain.requestCount, 0)

        let applied = testManager().applyTo(.ephemeral, configProvider: { config })
        let followed = try await status(applied, tls.url("/start"))
        XCTAssertEqual(followed.statusCode, 200, "the app's own configuration keeps OkHttp's default")
        XCTAssertEqual(plain.requests.map(\.path), ["/clear"])
    }

    func testTooManyFollowUpsFail() async throws {
        let server = try await server()
        let counter = Counter()
        server.setHandler { _ in .status(302, headers: ["Location": "/loop\(counter.increment())"]) }
        let session = testManager().buildClient(pinConfig("localhost", [leafPin]))
        let error = await assertPinVaultError { _ = try await session.data(from: server.url("/loop")) }
        XCTAssertEqual(error?.message, "Too many follow-up requests: 21")
        XCTAssertEqual(server.requestCount, 21)
    }
}
