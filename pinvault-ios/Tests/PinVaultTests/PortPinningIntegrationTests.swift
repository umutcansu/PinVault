import XCTest
@testable import PinVault

/// A listener whose leaf is signed by the backend's own CA and served with
/// that CA in the chain — the certificate-renewal door. Pinned through a
/// `host:port` entry holding the CA's pin, it is accepted however often the
/// leaf changes; the same CA pin does not open the host's other ports
/// (Kotlin `PortPinningIntegrationTest`).
final class PortPinningIntegrationTests: XCTestCase {

    private var server: TestServer!
    private let caPin = TLSFixture.pin("door-ca")

    override func setUp() async throws {
        server = try TestServer(p12: "door", chain: ["door-ca"])
        try await server.start()
    }

    override func tearDown() {
        server.stop()
    }

    private func get(_ pins: [HostPin]) async throws -> Int {
        let config = CertificateConfig(version: 1, pins: pins)
        let session = testManager().applyTo(.ephemeral, configProvider: { config })
        let (_, response) = try await session.data(from: server.url("/renew"))
        return (response as! HTTPURLResponse).statusCode
    }

    func testTheCAPinOnAHostPortEntryAcceptsAnyLeafTheCASigns() async throws {
        let status = try await get([
            HostPin(hostname: "localhost", sha256: [pin("A"), pin("B")]),
            HostPin(hostname: "localhost:\(server.port)", sha256: [caPin, pin("C")]),
        ])
        XCTAssertEqual(status, 200)
        XCTAssertNotEqual(TLSFixture.pin("door"), caPin, "the leaf itself is not among the pins")
    }

    func testTheSameCAPinUnderTheBareHostDoesNotCoverTheHostsOtherPorts() async {
        // CA pin only on a DIFFERENT port; this port falls back to the host entry, whose pins do not match.
        let error = await assertPinVaultError {
            _ = try await self.get([
                HostPin(hostname: "localhost", sha256: [pin("A"), pin("B")]),
                HostPin(hostname: "localhost:\(self.server.port + 1)", sha256: [self.caPin, pin("C")]),
            ])
        }
        guard case .certificate(let message, _)? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("pinning failure"), message)
    }

    func testAHostPortEntryAloneLeavesTheHostsOtherPortsUnpinned() async {
        let error = await assertPinVaultError {
            _ = try await self.get([HostPin(hostname: "localhost:\(self.server.port + 1)", sha256: [self.caPin, pin("C")])])
        }
        guard case .unpinnedHost? = error?.pinVaultCause else { return XCTFail("\(String(describing: error))") }
    }
}
