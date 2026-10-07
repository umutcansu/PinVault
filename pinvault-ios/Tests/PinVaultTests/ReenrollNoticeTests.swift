import XCTest
@testable import PinVault

/// Kotlin `ReenrollNoticeTest`.
final class ReenrollNoticeTests: XCTestCase {

    func testOneNoticePerIdentity() {
        let notice = ReenrollNotice()
        XCTAssertTrue(notice.claim("CN=PinVault Client CA#1"))
        // Every later request of the revoked identity, and the refused renewal, stay quiet.
        XCTAssertFalse(notice.claim("CN=PinVault Client CA#1"))
        XCTAssertFalse(notice.claim("CN=PinVault Client CA#1"))
    }

    func testANewIdentityIsReportedAgain() {
        let notice = ReenrollNotice()
        XCTAssertTrue(notice.claim("CN=PinVault Client CA#1"))
        // Re-enrolled, then revoked again.
        XCTAssertTrue(notice.claim("CN=PinVault Client CA#2"))
        XCTAssertFalse(notice.claim("CN=PinVault Client CA#2"))
    }

    func testAnIdentityIsNamedByItsIssuerAndSerial() {
        let ca = ClientCertTestCA()
        let keys = TestKeyPair()
        let now = Date()
        let a = ca.issue(spki: keys.spki, notBefore: now, notAfter: now.addingTimeInterval(ClientCertTestCA.day))
        let b = ca.issue(spki: keys.spki, notBefore: now, notAfter: now.addingTimeInterval(ClientCertTestCA.day))
        XCTAssertTrue(ReenrollNotice.identityName(a).hasPrefix("CN=PinVault Client CA#"))
        XCTAssertNotEqual(ReenrollNotice.identityName(a), ReenrollNotice.identityName(b), "another serial, another identity")
    }
}
