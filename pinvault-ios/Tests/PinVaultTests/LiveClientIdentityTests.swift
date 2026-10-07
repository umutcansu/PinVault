import XCTest
@testable import PinVault

/// A session the app keeps lives on while the client identity changes
/// underneath it: each new connection presents the identity loaded at that
/// moment — after a renewal the new one, after unenroll none (Kotlin
/// `LiveClientIdentityTest`). The server requires a client certificate, so
/// "presents none" shows as a refused connection.
final class LiveClientIdentityTests: XCTestCase {

    private var manager = testManager()
    private var server: TestServer!
    private let password = "changeit"
    /// mtls = true: the default identity goes to hosts the config marks as mTLS
    /// (and to the block's own listeners), not to every pinned host.
    private let config = pinConfig("localhost", [TLSFixture.pin("leaf")], mtls: true)

    override func setUp() async throws {
        manager = testManager()
        server = try TestServer(p12: "server", chain: ["intermediate"], clientAuth: .required)
        try await server.start()
    }

    override func tearDown() {
        server.stop()
    }

    private func client() -> PinnedSession {
        let config = self.config
        return manager.applyTo(.ephemeral, configProvider: { config })
    }

    /// The CN of the client certificate the server saw for one request, or nil when the connection was refused.
    private func presentedBy(_ session: PinnedSession) async -> String? {
        let before = server.requestCount
        do {
            let (_, response) = try await session.data(from: server.url())
            XCTAssertEqual((response as! HTTPURLResponse).statusCode, 200)
        } catch {
            XCTAssertEqual(server.requestCount, before, "a refused connection carries no request")
            return nil
        }
        return server.requests.last?.clientCertificate?.subject.commonName
    }

    func testAfterARenewalTheSameSessionPresentsTheNewCertificate() async {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let client = client()
        let first = await presentedBy(client)
        XCTAssertEqual(first, "client-a")

        manager.loadClientKey(TLSFixture.identity("client-b"))
        let second = await presentedBy(client)
        XCTAssertEqual(second, "client-b")
    }

    func testASessionBuiltBeforeEnrollmentPresentsTheCertificateOnceEnrolled() async throws {
        let client = client()
        let before = await presentedBy(client)
        XCTAssertNil(before)

        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        let after = await presentedBy(client)
        XCTAssertEqual(after, "client-a")
    }

    func testAfterUnenrollTheSameSessionPresentsNoCertificate() async throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        let client = client()
        let before = await presentedBy(client)
        XCTAssertEqual(before, "client-a")

        manager.clearClientKeystore()
        let after = await presentedBy(client)
        XCTAssertNil(after)
    }

    func testWithoutAnIdentityChangeThePooledConnectionIsReused() async throws {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let client = client()
        _ = try await client.data(from: server.url())
        _ = try await client.data(from: server.url())
        XCTAssertEqual(server.takeRequest()?.sequenceNumber, 0)
        XCTAssertEqual(server.takeRequest()?.sequenceNumber, 1, "the second request rode the same connection")
    }

    func testAPinnedHostThatIsNotAnMtlsHostSeesNoCertificate() async {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let plain = pinConfig("localhost", [TLSFixture.pin("leaf")])
        let session = manager.applyTo(.ephemeral, configProvider: { plain })
        let none = await presentedBy(session)
        XCTAssertNil(none, "the device identity is not handed to a host the device merely talks to")

        // The block's own listener gets it.
        manager.setIdentityHosts([server.url().absoluteString])
        let own = await presentedBy(session)
        XCTAssertEqual(own, "client-a")
    }

    func testAHostSpecificCertificateIsPresentedToItsHost() async {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.loadHostClientCerts(["localhost:\(server.port)": TLSFixture.p12("client-b")], password: password)
        let presented = await presentedBy(client())
        XCTAssertEqual(presented, "client-b")
    }

    func testTheIntermediatesTravelWithTheCertificate() async throws {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        _ = try await client().data(from: server.url())
        let request = try XCTUnwrap(server.takeRequest())
        XCTAssertEqual(request.clientCertificate?.spkiPin, TLSFixture.pin("client-a"))
    }
}
