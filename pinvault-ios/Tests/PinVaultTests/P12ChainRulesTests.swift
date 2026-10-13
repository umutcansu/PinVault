import Foundation
import XCTest
@testable import PinVault

/// A PKCS12 answer (`allowServerGeneratedKey()`) is held to the chain rules of
/// a CSR answer: the issuer sent along, the lifetime cap, `clientCaPins`.
final class P12ChainRulesTests: XCTestCase {

    private let now = ClientCertRenewer.millis(TLSFixture.validNow)

    private func refusal(_ body: () throws -> Void) -> String {
        do {
            try body()
            return "accepted"
        } catch {
            return ClientCertRenewer.message(error)
        }
    }

    func testAChainWithItsIssuerIsAccepted() throws {
        let certs = try ClientCertRenewer.acceptIssuedP12(TLSFixture.identity("client-a"), nowMs: now)
        XCTAssertEqual(certs.count, 2)
        XCTAssertEqual(certs[1].spkiPin, TLSFixture.pin("client-ca"))
    }

    func testALeafAloneIsRefused() {
        let message = refusal { _ = try ClientCertRenewer.acceptIssuedP12(TLSFixture.identity("selfsigned"), nowMs: now) }
        XCTAssertTrue(message.contains("CA certificate that signed it"), message)
    }

    func testTheBlocksLifetimeCapApplies() {
        let message = refusal {
            _ = try ClientCertRenewer.acceptIssuedP12(TLSFixture.identity("client-a"), maxLifetimeDays: 30, nowMs: now)
        }
        XCTAssertTrue(message.contains("30 days"), message)
    }

    func testClientCaPinsApply() throws {
        XCTAssertEqual(
            try ClientCertRenewer.acceptIssuedP12(TLSFixture.identity("client-a"), caPins: [TLSFixture.pin("client-ca")], nowMs: now).count, 2
        )
        let message = refusal {
            _ = try ClientCertRenewer.acceptIssuedP12(TLSFixture.identity("client-a"), caPins: [TLSFixture.pin("root")], nowMs: now)
        }
        XCTAssertTrue(message.contains("pinned client CA"), message)
    }
}
