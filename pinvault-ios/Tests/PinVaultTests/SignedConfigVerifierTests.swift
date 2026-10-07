import Foundation
import XCTest
@_spi(PinVaultE2E) @testable import PinVault

/// SignedConfigVerifier on its own: the checks the updater (L2) relies on —
/// scope, freshness, the expiry clock, stored envelopes. The Kotlin suite
/// covers them through SSLCertificateUpdater (SignedConfigUpdateTest).
final class SignedConfigVerifierTests: XCTestCase {

    private let key = TestSigner()
    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000

    private func payload(issuedAt: Int64? = nil, expiresAt: Int64? = nil, scope: String? = nil, version: Int = 3) -> String {
        var fields: [(String, String)] = [
            ("version", String(version)),
            ("pins", JSONText.array([JSONText.object([
                ("hostname", JSONText.string("api.test")),
                ("sha256", JSONText.array([JSONText.string(pin("A")), JSONText.string(pin("B"))])),
                ("version", String(version)),
            ])])),
            ("issuedAt", String(issuedAt ?? now - 1_000)),
            ("expiresAt", String(expiresAt ?? now + hour)),
        ]
        if let scope { fields.append(("configApiId", scope)) }
        return JSONText.object(fields)
    }

    private func signed(_ payload: String, by signer: TestSigner? = nil) -> SignedConfigResponse {
        SignedConfigResponse(payload: payload, signature: (signer ?? key).sign(payload))
    }

    private func verifier(scope: String? = nil, trust: SignatureTrust? = nil) -> SignedConfigVerifier {
        SignedConfigVerifier(trust: trust ?? .single(configApiId: "default", key: key.pub), serverScope: scope, clock: { [now] in now })
    }

    func testAFreshSignedConfigVerifiesAndKeepsItsEnvelope() throws {
        let body = payload()
        let verified = try verifier().verifyFetched(signed(body))
        XCTAssertEqual(verified.config.computedVersion(), 3)
        XCTAssertEqual(verified.envelope.payload, body)
        XCTAssertEqual(verified.envelope.signatures.count, 1)
    }

    func testASignatureFailureIsWordedByTheCaller() throws {
        let message = assertSecurityRefusal { _ = try self.verifier().verifyFetched(self.signed(self.payload(), by: TestSigner())) }
        XCTAssertEqual(message, "Config signature verification failed — possible tampering detected. Keeping previous safe config.")
        assertSecurityRefusal("(scoped fetch). The envelope has no payload.") {
            _ = try self.verifier().verifyFetched(SignedConfigResponse(payload: "", signature: "x")) { "Config signature verification failed (scoped fetch).\($0)" }
        }
    }

    /// The default clock is the library's: the E2E clock offset (Android's
    /// `date -s`) makes a config expired here too, not only in the updater.
    func testTheDefaultClockIsTheLibraryClock() {
        let wall = LibraryClock.wallMillis()
        let body = payload(issuedAt: wall - 1_000, expiresAt: wall + hour)
        let plain = SignedConfigVerifier(trust: .single(configApiId: "default", key: key.pub))
        XCTAssertNoThrow(try plain.verifyFetched(signed(body)))
        PinVault.shared.e2eSetClockOffset(seconds: 2 * 3_600)
        defer { PinVault.shared.e2eSetClockOffset(seconds: 0) }
        assertSecurityRefusal("Signed config expired") { _ = try plain.verifyFetched(self.signed(body)) }
    }

    func testFreshnessFieldsAreRequiredAndExpiryEnforced() {
        let missingExpiry = assertSecurityRefusal { _ = try self.verifier().verifyFetched(self.signed(self.payload(expiresAt: 0))) }
        XCTAssertEqual(missingExpiry, "Signed config missing expiresAt — refusing to apply. " +
            "Server must populate expiresAt (Unix epoch ms) to enable replay protection.")
        let missingIssued = assertSecurityRefusal { _ = try self.verifier().verifyFetched(self.signed(self.payload(issuedAt: 0))) }
        XCTAssertEqual(missingIssued, "Signed config missing issuedAt — refusing to apply. " +
            "Server must populate issuedAt (Unix epoch ms) to enable replay protection.")
        let expired = assertSecurityRefusal { _ = try self.verifier().verifyFetched(self.signed(self.payload(expiresAt: self.now - 5))) }
        XCTAssertEqual(expired, "Signed config expired: expiresAt=\(now - 5), now=\(now) (stale by 5ms). Possible replay attack.")
    }

    func testServerScopeMustMatchThePayloadsConfigApiId() throws {
        let missing = assertSecurityRefusal { _ = try self.verifier(scope: "prod").verifyFetched(self.signed(self.payload())) }
        XCTAssertEqual(missing, "Signed config rejected: its payload names no 'configApiId', and this block accepts only configs " +
            "signed for Config API 'prod' (serverScope). The server must write the field into every signed config.")
        let other = assertSecurityRefusal {
            _ = try self.verifier(scope: "prod").verifyFetched(self.signed(self.payload(scope: JSONText.string("staging"))))
        }
        XCTAssertEqual(other, "Signed config rejected: it was signed for Config API 'staging', this block accepts only 'prod' (serverScope).")
        let long = String(repeating: "x", count: 100)
        assertSecurityRefusal("'\(String(repeating: "x", count: 64))', this block") {
            _ = try self.verifier(scope: "prod").verifyFetched(self.signed(self.payload(scope: JSONText.string(long))))
        }
        assertSecurityRefusal("names no 'configApiId'") {
            _ = try self.verifier(scope: "prod").verifyFetched(self.signed(self.payload(scope: "null")))
        }

        XCTAssertNoThrow(try verifier(scope: "prod").verifyFetched(signed(payload(scope: JSONText.string("prod")))))
        XCTAssertNoThrow(try verifier(scope: "7").verifyFetched(signed(payload(scope: "7"))), "Gson reads a number as its text")
        XCTAssertNoThrow(try verifier().verifyFetched(signed(payload(scope: JSONText.string("anything")))), "no serverScope: not checked")
    }

    func testAPayloadThatIsNotAConfigIsRefused() {
        XCTAssertThrowsError(try verifier().verifyFetched(signed("null"))) { error in
            guard case PinVaultError.security(let message, _) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(message, "Signed config payload is empty.")
        }
        XCTAssertThrowsError(try verifier().verifyFetched(signed("[1,2]"))) { error in
            guard case PinVaultError.illegalArgument(let message) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(message.hasPrefix("Signed config payload is not a valid config"), message)
        }
    }

    func testSignaturesWinOverTheSingleFieldBlankOnesAreDroppedAndAtMost16Kept() throws {
        let body = payload()
        let many = (0..<20).map { _ in TestSigner().entry(body) } + [SignatureEntry(keyId: nil, signature: " ")]
        let envelope = try XCTUnwrap(SignedConfigVerifier.envelopeOf(
            SignedConfigResponse(payload: body, signature: key.sign(body), signatures: [SignatureEntry(keyId: nil, signature: "")] + many)
        ))
        XCTAssertEqual(envelope.signatures.count, 16)
        XCTAssertFalse(envelope.signatures.contains { $0.signature.isBlank })
        // The single field's signature is not among them: the config does not verify.
        assertSecurityRefusal { _ = try self.verifier().verifyFetched(SignedConfigResponse(payload: body, signature: self.key.sign(body), signatures: many)) }
    }

    func testTheExpiryClockIsTheTrustedOneExceptForAConfigNewerThanEveryOther() throws {
        let config = CertificateConfig(version: 1, pins: [], issuedAt: 5_000, expiresAt: 9_000)
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: config, wall: { 1_000 }, trustedNow: nil, issuedAtWatermark: { 9_999 }), 1_000)
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: config, wall: { 1_000 }, trustedNow: { 8_000 }, issuedAtWatermark: { 5_000 }), 8_000)
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: config, wall: { 1_000 }, trustedNow: { 8_000 }, issuedAtWatermark: { 4_999 }), 1_000,
                       "a config newer than every config accepted is judged by the wall clock")

        // A trusted clock that ran ahead refuses a replayed config that the wall clock would let in.
        let ahead = SignedConfigVerifier(
            trust: .single(configApiId: "default", key: key.pub),
            trustedNow: { [now, hour] in now + 2 * hour },
            issuedAtWatermark: { [now] in now },
            clock: { [now] in now }
        )
        assertSecurityRefusal("Signed config expired") { _ = try ahead.verifyFetched(self.signed(self.payload(issuedAt: self.now - 1_000))) }
        XCTAssertNoThrow(try ahead.verifyFetched(signed(payload(issuedAt: now + 1))))
    }

    func testAStoredEnvelopeIsReCheckedAgainstTheKeysTrustedNow() throws {
        let recovery = TestSigner()
        let replacement = TestSigner()
        let trust = SignatureTrust(configApiId: "default", builtInKeys: [key.pub], builtInThreshold: 1,
                                   recoveryKeys: [recovery.pub], recoveryThreshold: 1, store: SigningKeyStore(prefs: InMemoryPreferences()))
        let verifier = SignedConfigVerifier(trust: trust, serverScope: "prod")
        let body = payload(expiresAt: now - hour, scope: JSONText.string("prod"))
        let stored = StoredEnvelope(payload: body, signatures: [key.entry(body)])

        XCTAssertEqual(try verifier.verifyStored(stored)?.computedVersion(), 3, "expiry is the caller's business")
        XCTAssertNil(try verifier.verifyStored(StoredEnvelope(payload: payload(scope: JSONText.string("staging")), signatures: [key.entry(body)])))
        let badPins = #"{"version":1,"pins":[{"hostname":"api.test","sha256":["x","y"]}],"configApiId":"prod"}"#
        XCTAssertNil(try verifier.verifyStored(StoredEnvelope(payload: badPins, signatures: [key.entry(badPins)])), "content is validated")

        // A key set revoking the key that signed it: the stored config no longer counts.
        let setPayload = keySetPayload(version: 1, keys: [replacement.pub])
        XCTAssertTrue(try verifier.applyKeySet(SignedConfigResponse(
            payload: "", signature: "", signingKeys: SignedKeySet(payload: setPayload, signatures: [recovery.entry(setPayload)])
        )))
        XCTAssertEqual(try verifier.keySetVersion(), 1)
        XCTAssertNil(try verifier.verifyStored(stored))
        XCTAssertEqual(verifier.anchorsFingerprint(), trust.anchorsFingerprint())
    }
}
