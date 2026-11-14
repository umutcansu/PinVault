import Foundation
import Security
import XCTest
@testable import PinVault

/// Who gets the client certificate: the origin the session connects to, once
/// its own certificate has passed this session's trust check. A TLS proxy that
/// asks gets none, and neither does a peer the trust check never saw.
final class ProxyClientCertificateTests: XCTestCase {

    private final class Sender: NSObject, URLAuthenticationChallengeSender {
        func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
        func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
        func cancel(_ challenge: URLAuthenticationChallenge) {}
    }

    /// A server-trust protection space carrying `trust` (the public initializer has no way to give one).
    private final class TrustSpace: URLProtectionSpace, @unchecked Sendable {
        private var trust: SecTrust?

        convenience init(host: String, port: Int, trust: SecTrust) {
            self.init(host: host, port: port, protocol: NSURLProtectionSpaceHTTPS, realm: nil,
                      authenticationMethod: NSURLAuthenticationMethodServerTrust)
            self.trust = trust
        }

        override var serverTrust: SecTrust? { trust }
    }

    private let host = "api.chain.test"

    /// A delegate for `https://api.chain.test/` with a client identity for that
    /// host, pinned to `pin` (the fixture leaf's by default).
    private func delegate(pin: String? = nil, log: UnverifiedConnectionLog? = nil) throws -> PinnedSessionDelegate {
        let manager = testManager()
        if let log { manager.unverifiedConnections = log }
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: "changeit")
        manager.setIdentityHosts(["https://\(host)/"])
        let config = pinConfig(host, [pin ?? TLSFixture.pin("leaf")])
        let context = PinnedSessionDelegate.Context(
            logicalHost: host, logicalPort: 443, connectHost: host, connectPort: 443,
            trust: .pinned({ config })
        )
        return PinnedSessionDelegate(manager: manager, context: context)
    }

    private struct Answer {
        let disposition: URLSession.AuthChallengeDisposition
        /// What the request would throw for it, if the delegate recorded a refusal.
        let failure: PinVaultError?
    }

    private func answer(_ delegate: PinnedSessionDelegate, _ space: URLProtectionSpace) -> Answer {
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URL(string: "https://\(host)/")!)
        let challenge = URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil, previousFailureCount: 0,
            failureResponse: nil, error: nil, sender: Sender()
        )
        let disposition = Locked<URLSession.AuthChallengeDisposition?>(nil)
        delegate.urlSession(session, task: task, didReceive: challenge) { answer, _ in
            disposition.withLock { $0 = answer }
        }
        return Answer(
            disposition: disposition.withLock { $0 } ?? .cancelAuthenticationChallenge,
            failure: delegate.takeFailure(task.taskIdentifier)?.thrown
        )
    }

    /// The server-trust challenge of a handshake with the fixture chain, from `peer`.
    private func serverTrust(from peer: String? = nil) throws -> URLProtectionSpace {
        var trust: SecTrust?
        let chain = [TLSFixture.secCert("leaf"), TLSFixture.secCert("intermediate")]
        XCTAssertEqual(SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust), errSecSuccess)
        return TrustSpace(host: peer ?? host, port: 443, trust: try XCTUnwrap(trust))
    }

    private func clientCertificate(from peer: String? = nil, port: Int = 443) -> URLProtectionSpace {
        URLProtectionSpace(
            host: peer ?? host, port: port, protocol: NSURLProtectionSpaceHTTPS, realm: nil,
            authenticationMethod: NSURLAuthenticationMethodClientCertificate
        )
    }

    func testTheOriginGetsTheIdentityOnceItsCertificatePassedTheTrustCheck() throws {
        let delegate = try delegate()
        XCTAssertEqual(answer(delegate, try serverTrust()).disposition, .useCredential)
        let asked = answer(delegate, clientCertificate())
        XCTAssertEqual(asked.disposition, .useCredential)
        XCTAssertNil(asked.failure)
        XCTAssertNotNil(delegate.presentedClientCertificate)
        // A later connection of the session that resumes its TLS session, or
        // renegotiates, is asked for no server certificate again: still served.
        XCTAssertEqual(answer(delegate, clientCertificate()).disposition, .useCredential)
    }

    // In a handshake the server-trust challenge comes first. A client-certificate
    // challenge in a session that never saw one means something answered it
    // before the delegate (security review 2026-11-14, R-04).
    func testTheIdentityIsWithheldWhileTheSessionsTrustCheckNeverRan() throws {
        let log = UnverifiedConnectionLog()
        let delegate = try delegate(log: log)
        let asked = answer(delegate, clientCertificate())
        XCTAssertEqual(asked.disposition, .cancelAuthenticationChallenge)
        XCTAssertNil(delegate.presentedClientCertificate)
        guard case .sslHandshake(let message, let cause)? = asked.failure else { return XCTFail("\(String(describing: asked.failure))") }
        XCTAssertTrue(message.contains("without PinVault's trust check"), message)
        XCTAssertTrue(message.hasSuffix("the client certificate was not presented"), message)
        guard case .security? = cause as? PinVaultError else { return XCTFail("\(String(describing: cause))") }
        XCTAssertFalse(PinRecoveryInterceptor.isPinMismatch(asked.failure!), "no config repairs this")
        XCTAssertEqual(log.evidence(), ["tls-unverified:\(host)"])
    }

    func testATrustCheckThatRefusedThePeerDoesNotUnlockTheIdentity() throws {
        // Pinned to another key: the challenge was asked and answered "no".
        let delegate = try delegate(pin: TLSFixture.pin("root"))
        XCTAssertEqual(answer(delegate, try serverTrust()).disposition, .cancelAuthenticationChallenge)
        XCTAssertEqual(delegate.serverTrustChallengeCount, 1)
        XCTAssertEqual(answer(delegate, clientCertificate()).disposition, .cancelAuthenticationChallenge)
        XCTAssertNil(delegate.presentedClientCertificate)

        // Nor does a challenge from an address the session does not connect to.
        let other = try self.delegate()
        XCTAssertEqual(answer(other, try serverTrust(from: "elsewhere.test")).disposition, .cancelAuthenticationChallenge)
        XCTAssertEqual(answer(other, clientCertificate()).disposition, .cancelAuthenticationChallenge)
    }

    func testAnotherAddressAskingForTheCertificateGetsNone() throws {
        let delegate = try delegate()
        XCTAssertEqual(answer(delegate, try serverTrust()).disposition, .useCredential)
        for space in [clientCertificate(from: "elsewhere.test"), clientCertificate(port: 8443)] {
            let asked = answer(delegate, space)
            XCTAssertEqual(asked.disposition, .cancelAuthenticationChallenge)
            guard case .sslHandshake(let message, _)? = asked.failure else { return XCTFail("\(String(describing: asked.failure))") }
            XCTAssertTrue(message.contains("is not the address this session connects to (\(host):443)"), message)
            XCTAssertNil(delegate.presentedClientCertificate)
        }
        XCTAssertEqual(answer(delegate, clientCertificate()).disposition, .useCredential, "the origin still gets it")
    }

    func testAHostWithoutAnIdentityIsAnsweredAsBeforeWhateverTheTrustCheckSaw() throws {
        // Nothing to withhold: the handshake goes on without a certificate, as it always did.
        let manager = testManager()
        let config = pinConfig(host, [TLSFixture.pin("leaf")])
        let bare = PinnedSessionDelegate(manager: manager, context: .init(
            logicalHost: host, logicalPort: 443, connectHost: host, connectPort: 443, trust: .pinned({ config })
        ))
        let asked = answer(bare, clientCertificate())
        XCTAssertEqual(asked.disposition, .rejectProtectionSpace)
        XCTAssertNil(asked.failure)
    }

    func testAProxyGetsNoIdentity() throws {
        let delegate = try delegate()
        XCTAssertEqual(answer(delegate, try serverTrust()).disposition, .useCredential)
        let proxy = URLProtectionSpace(
            proxyHost: "proxy.corp", port: 8443, type: NSURLProtectionSpaceHTTPSProxy, realm: nil,
            authenticationMethod: NSURLAuthenticationMethodClientCertificate
        )
        XCTAssertTrue(proxy.isProxy())
        XCTAssertEqual(answer(delegate, proxy).disposition, .rejectProtectionSpace)
        XCTAssertNil(delegate.presentedClientCertificate)
    }

    func testTheCertificateIsStoredForThisDeviceAfterFirstUnlock() {
        let query = KeychainIdentities.certificateAddQuery(TLSFixture.secCert("leaf"), alias: "alias")
        XCTAssertEqual(query[kSecAttrAccessible] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertEqual(query[kSecAttrLabel] as? String, "alias")
    }
}
