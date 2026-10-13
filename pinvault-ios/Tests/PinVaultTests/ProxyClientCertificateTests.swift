import Foundation
import XCTest
@testable import PinVault

/// A TLS proxy that asks for a client certificate gets none: the identity is
/// for the origin the session connects to.
final class ProxyClientCertificateTests: XCTestCase {

    private final class Sender: NSObject, URLAuthenticationChallengeSender {
        func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
        func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
        func cancel(_ challenge: URLAuthenticationChallenge) {}
    }

    private func delegate() throws -> PinnedSessionDelegate {
        let manager = testManager()
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: "changeit")
        manager.setIdentityHosts(["https://api.test/"])
        let context = PinnedSessionDelegate.Context(
            logicalHost: "api.test", logicalPort: 443, connectHost: "api.test", connectPort: 443,
            trust: .pinned({ nil })
        )
        return PinnedSessionDelegate(manager: manager, context: context)
    }

    private func answer(_ delegate: PinnedSessionDelegate, _ space: URLProtectionSpace) -> URLSession.AuthChallengeDisposition {
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: URL(string: "https://api.test/")!)
        let challenge = URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil, previousFailureCount: 0,
            failureResponse: nil, error: nil, sender: Sender()
        )
        let disposition = Locked<URLSession.AuthChallengeDisposition?>(nil)
        delegate.urlSession(session, task: task, didReceive: challenge) { answer, _ in
            disposition.withLock { $0 = answer }
        }
        return disposition.withLock { $0 } ?? .cancelAuthenticationChallenge
    }

    func testTheOriginGetsTheIdentity() throws {
        let delegate = try delegate()
        let origin = URLProtectionSpace(
            host: "api.test", port: 443, protocol: NSURLProtectionSpaceHTTPS, realm: nil,
            authenticationMethod: NSURLAuthenticationMethodClientCertificate
        )
        XCTAssertEqual(answer(delegate, origin), .useCredential)
        XCTAssertNotNil(delegate.presentedClientCertificate)
    }

    func testAProxyGetsNoIdentity() throws {
        let delegate = try delegate()
        let proxy = URLProtectionSpace(
            proxyHost: "proxy.corp", port: 8443, type: NSURLProtectionSpaceHTTPSProxy, realm: nil,
            authenticationMethod: NSURLAuthenticationMethodClientCertificate
        )
        XCTAssertTrue(proxy.isProxy())
        XCTAssertEqual(answer(delegate, proxy), .rejectProtectionSpace)
        XCTAssertNil(delegate.presentedClientCertificate)
    }

    func testTheCertificateIsStoredForThisDeviceAfterFirstUnlock() {
        let query = KeychainIdentities.certificateAddQuery(TLSFixture.secCert("leaf"), alias: "alias")
        XCTAssertEqual(query[kSecAttrAccessible] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertEqual(query[kSecAttrLabel] as? String, "alias")
    }
}
