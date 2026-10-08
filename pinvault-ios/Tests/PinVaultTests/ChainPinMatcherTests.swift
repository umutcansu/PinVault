import Security
import XCTest
@testable import PinVault

/// Pins may name the leaf or an issuer the leaf really chains to. The issuer
/// case must not open a hole in a library that does no CA validation: a forged
/// leaf with the genuine intermediate appended has to be refused (Kotlin `ChainPinMatcherTest`).
final class ChainPinMatcherTests: XCTestCase {

    private let host = "api.chain.test"
    private let root = TLSFixture.cert("root")
    private let intermediate = TLSFixture.cert("intermediate")
    private let leaf = TLSFixture.cert("leaf")
    private let now = TLSFixture.validNow

    private func config(_ pins: [String], host: String? = nil) -> CertificateConfig {
        pinConfig(host ?? self.host, pins)
    }

    private func check(_ pins: [String], _ chain: [X509Certificate], manager: DynamicSSLManager = testManager()) throws {
        try manager.checkServerTrusted(chain, hostname: host, port: 443, config: config(pins))
    }

    private func assertRefused(_ pins: [String], _ chain: [X509Certificate], file: StaticString = #filePath, line: UInt = #line) {
        let error = assertThrowsPinVault(file: file, line: line) { try check(pins, chain) }
        guard case .certificate(let message, _)? = error else {
            return XCTFail("expected a pinning failure, got \(String(describing: error))", file: file, line: line)
        }
        XCTAssertTrue(message.contains("pinning failure"), message, file: file, line: line)
    }

    func testLeafPinIsAcceptedAsBefore() throws {
        try check([leaf.spkiPin], [leaf, intermediate])
    }

    func testIntermediatePinIsAcceptedWhenTheLeafIsIssuedByIt() throws {
        try check([intermediate.spkiPin], [leaf, intermediate])
    }

    func testRootPinIsAcceptedThroughAValidIntermediate() throws {
        try check([root.spkiPin], [leaf, intermediate, root])
    }

    func testForgedLeafWithTheGenuineIntermediateAppendedIsRefused() {
        // Same issuer name, signed by the attacker's own key.
        assertRefused([intermediate.spkiPin], [TLSFixture.cert("forged"), intermediate])
    }

    func testACertificateWithoutCARightsCannotVouchForTheLeaf() {
        assertRefused([root.spkiPin], [TLSFixture.cert("leaf-under-notca"), TLSFixture.cert("notca"), root])
    }

    func testExpiredPinnedIntermediateIsRefused() {
        let expired = TLSFixture.cert("expired-intermediate")
        assertRefused([expired.spkiPin], [TLSFixture.cert("leaf-under-expired-intermediate"), expired])
    }

    func testAnUnrelatedCertificateInTheMiddleBreaksThePathToAPinnedRoot() {
        assertRefused([root.spkiPin], [leaf, TLSFixture.cert("stranger"), root])
    }

    func testIssuerPinOfAnotherHostDoesNotApply() {
        let manager = testManager()
        let error = assertThrowsPinVault {
            try manager.checkServerTrusted([leaf, intermediate], hostname: host, port: 443, config: config([intermediate.spkiPin], host: "other.chain.test"))
        }
        guard case .unpinnedHost(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("No pin entry"))
    }

    func testAnIssuerPinDoesNotAcceptACertificateTheCAIssuedForAnotherHost() throws {
        // Pinning a public intermediate would otherwise accept any site's certificate.
        let forOtherHost = TLSFixture.cert("other-host-leaf")
        var error = assertThrowsPinVault { try check([intermediate.spkiPin], [forOtherHost, intermediate]) }
        guard case .hostnameMismatch(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("not issued for \(host)"), message)

        // A leaf without any subjectAltName is refused on an issuer pin too …
        let noName = TLSFixture.cert("nosan-leaf")
        error = assertThrowsPinVault { try check([intermediate.spkiPin], [noName, intermediate]) }
        guard case .hostnameMismatch? = error else { return XCTFail("\(String(describing: error))") }

        // … but its own key pin needs no name in the trust check: the pin is the identity.
        try check([noName.spkiPin], [noName, intermediate])
        XCTAssertFalse(ChainPinMatcher.leafNamesHost(leaf, ""))
        XCTAssertTrue(ChainPinMatcher.leafNamesHost(leaf, host))
    }

    func testAfterTheTrustCheckTheHandshakeStillVerifiesTheHostname() throws {
        // OkHttp's hostname verifier runs after every handshake of a library
        // client: a SAN-less leaf passes on its own pin in the trust check, and
        // is then refused as SSLPeerUnverifiedException.
        let noName = TLSFixture.cert("nosan-leaf")
        let trust = try serverTrust([noName, intermediate])
        let manager = testManager()
        let configValue = config([noName.spkiPin])
        do {
            try manager.evaluateServerTrust(trust, hostname: host, port: 443, mode: .pinned({ configValue }))
            XCTFail("the hostname must be verified")
        } catch DynamicSSLManager.PinCheckError.peerUnverified(let message) {
            XCTAssertTrue(message.hasPrefix("Hostname \(host) not verified:"), message)
            XCTAssertTrue(message.contains("certificate: sha256/\(noName.spkiPin)"), message)
        }
        // With a named leaf the whole decision passes.
        let named = try serverTrust([leaf, intermediate])
        let leafConfig = config([leaf.spkiPin])
        try manager.evaluateServerTrust(named, hostname: host, port: 443, mode: .pinned({ leafConfig }))
    }

    func testMatcherReportsWhichPinMatched() {
        let accepted: Set<String> = [intermediate.spkiPin, root.spkiPin]
        XCTAssertEqual(ChainPinMatcher.match([leaf, intermediate, root], accepted: accepted, now: now), intermediate.spkiPin)
        XCTAssertNil(ChainPinMatcher.match([leaf], accepted: accepted, now: now))
        XCTAssertNil(ChainPinMatcher.match([], accepted: accepted, now: now))
        XCTAssertTrue(ChainPinMatcher.chainsTo([leaf, intermediate], 1, now: now))
        XCTAssertTrue(ChainPinMatcher.chainsTo([leaf, intermediate, root], 2, now: now))
        XCTAssertFalse(ChainPinMatcher.chainsTo([leaf, root], 1, now: now))
        XCTAssertFalse(ChainPinMatcher.chainsTo([leaf, intermediate], 0, now: now))
        XCTAssertFalse(ChainPinMatcher.chainsTo([leaf, intermediate], 2, now: now))
    }

    func testThePathIsJudgedAtTheLibraryClock() {
        // After the leaf expired, its issuer pin no longer vouches for it.
        let later = leaf.notAfter.addingTimeInterval(86_400)
        XCTAssertFalse(ChainPinMatcher.chainsTo([leaf, intermediate], 1, now: later))
        // Before the anchor became valid either.
        let earlier = intermediate.notBefore.addingTimeInterval(-86_400)
        XCTAssertFalse(ChainPinMatcher.chainsTo([leaf, intermediate], 1, now: earlier))
    }

    /// A `SecTrust` over `chain`, as a handshake would hand it over.
    private func serverTrust(_ chain: [X509Certificate]) throws -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(chain.compactMap { $0.secCertificate() } as CFArray, SecPolicyCreateBasicX509(), &trust)
        XCTAssertEqual(status, errSecSuccess)
        return try XCTUnwrap(trust)
    }
}
