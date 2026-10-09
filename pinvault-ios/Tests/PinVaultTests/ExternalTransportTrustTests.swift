import Security
import XCTest
@_spi(PinVaultE2E) @testable import PinVault

/// `PinVault.evaluateServerTrust(_:host:port:)`: the pin decision of the
/// library's sessions for a TLS connection it does not open (React Native's
/// WebSocket on SocketRocket). Fail-closed before start, same refusals after.
final class ExternalTransportTrustTests: XCTestCase {

    private let host = "api.chain.test"
    private let leaf = TLSFixture.cert("leaf")
    private let intermediate = TLSFixture.cert("intermediate")

    private func started(_ pins: [String], host: String? = nil) async throws -> PinVault {
        let vault = try isolatedPinVault(self)
        let result = await vault.start(config: PinVaultConfig.static(
            HostPin(hostname: host ?? self.host, sha256: pins + [TLSFixture.backupPin], version: 1)
        ))
        XCTAssertEqual(result, .ready(version: 1))
        return vault
    }

    private func serverTrust(_ chain: [X509Certificate]) throws -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(chain.compactMap { $0.secCertificate() } as CFArray, SecPolicyCreateBasicX509(), &trust)
        XCTAssertEqual(status, errSecSuccess)
        return try XCTUnwrap(trust)
    }

    func testBeforeStartEveryChainIsRefused() throws {
        let trust = try serverTrust([leaf, intermediate])
        XCTAssertThrowsError(try PinVault().evaluateServerTrust(trust, host: host, port: 443)) { error in
            guard case .illegalState(let message)? = error as? PinVaultError else { return XCTFail("\(error)") }
            XCTAssertEqual(message, PinVault.notInitializedMessage)
        }
    }

    func testThePinnedChainIsAcceptedForItsHost() async throws {
        let vault = try await started([leaf.spkiPin])
        try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 443)
        // The host is compared as the sessions compare it: case-insensitive.
        try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: "API.Chain.Test", port: 443)
        // An issuer pin the leaf really chains to counts too.
        let byIssuer = try await started([intermediate.spkiPin])
        try byIssuer.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 443)
    }

    func testAChainOutsideThePinsIsAHandshakeFailure() async throws {
        let vault = try await started([TLSFixture.pin("selfsigned")])
        XCTAssertThrowsError(try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 443)) { error in
            guard case .sslHandshake? = error as? PinVaultError else { return XCTFail("\(error)") }
        }
    }

    func testAHostWithoutAnEntryIsRefusedEvenWithAKnownChain() async throws {
        // The cross-host pin reuse H-01 closes: the leaf is pinned, but for another name.
        let vault = try await started([leaf.spkiPin])
        XCTAssertThrowsError(try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: "localhost", port: 443)) { error in
            guard case .sslHandshake? = error as? PinVaultError else { return XCTFail("\(error)") }
        }
    }

    func testAPortEntryOnlyCoversItsPort() async throws {
        let vault = try await started([leaf.spkiPin], host: "\(host):8443")
        try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 8443)
        XCTAssertThrowsError(try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 443))
    }

    func testAPinnedLeafThatDoesNotNameTheHostIsPeerUnverified() async throws {
        let noName = TLSFixture.cert("nosan-leaf")
        let vault = try await started([noName.spkiPin])
        XCTAssertThrowsError(try vault.evaluateServerTrust(try serverTrust([noName, intermediate]), host: host, port: 443)) { error in
            guard case .sslPeerUnverified(let message)? = error as? PinVaultError else { return XCTFail("\(error)") }
            XCTAssertTrue(message.hasPrefix("Hostname \(host) not verified:"), message)
        }
    }

    func testAfterResetTheDecisionIsFailClosedAgain() async throws {
        let vault = try await started([leaf.spkiPin])
        vault.reset()
        XCTAssertThrowsError(try vault.evaluateServerTrust(try serverTrust([leaf, intermediate]), host: host, port: 443)) { error in
            guard case .illegalState? = error as? PinVaultError else { return XCTFail("\(error)") }
        }
    }
}
