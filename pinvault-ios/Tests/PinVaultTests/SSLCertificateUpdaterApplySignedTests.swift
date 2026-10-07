import Foundation
import XCTest
@testable import PinVault

/// Port of SSLCertificateUpdaterApplySignedTest: the config inside an
/// attestation answer takes the fetched config's road — verification, replay,
/// storage — without a fetch, and an unsigned block ignores it.
final class SSLCertificateUpdaterApplySignedTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private let pin1 = pin("A"), pin2 = pin("B"), pin3 = pin("C")
    private let keyA = TestSigner(), keyB = TestSigner(), recovery = TestSigner()

    private var store: CertificateConfigStore!
    private var keyStore: SigningKeyStore!
    private var provider: HttpClientProvider!
    /// Never asked: the config comes from the attestation answer.
    private var api: FakeConfigApi!

    override func setUp() {
        store = CertificateConfigStore(prefs: InMemoryPreferences())
        let now = self.now
        store.clock = { now }
        keyStore = SigningKeyStore(prefs: InMemoryPreferences())
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
        api = FakeConfigApi()
    }

    private func trust(keys: [TestSigner]? = nil, withRecovery: Bool = false) -> SignatureTrust {
        SignatureTrust(configApiId: "default", builtInKeys: (keys ?? [keyA]).map(\.pub), builtInThreshold: 1,
                       recoveryKeys: withRecovery ? [recovery.pub] : [], recoveryThreshold: 1, store: withRecovery ? keyStore : nil)
    }

    private func updater(trust: SignatureTrust?? = .none, scope: String? = nil, configApi: (any CertificateConfigApi)? = nil) -> SSLCertificateUpdater {
        let now = self.now
        let resolved: SignatureTrust? = trust ?? self.trust()
        return SSLCertificateUpdater(
            configApi: configApi ?? api, configStore: store, httpClientProvider: provider, maxRetryCount: 1, clock: { now },
            verifier: resolved.map { SignedConfigVerifier(trust: $0, serverScope: scope, clock: { now }) }, sleep: { _ in }
        )
    }

    private func payload(_ version: Int, issuedAt: Int64, expiresAt: Int64? = nil, pins: [String]? = nil, scope: String? = nil) -> String {
        signedPayload(version: version, issuedAt: issuedAt, expiresAt: expiresAt ?? issuedAt + hour,
                      pins: pins ?? [pin1, pin2], hosts: [("api.test", version)], scope: scope)
    }

    private func signed(_ payload: String, signer: TestSigner? = nil, keySet: SignedKeySet? = nil) -> SignedConfigResponse {
        let signer = signer ?? keyA
        return SignedConfigResponse(payload: payload, signature: signer.sign(payload), keyId: signer.id, signingKeys: keySet)
    }

    private func keySet(_ version: Int, _ keys: [TestSigner]) -> SignedKeySet {
        let payload = keySetPayload(version: version, keys: keys.map(\.pub))
        return SignedKeySet(payload: payload, signatures: [SignatureEntry(keyId: recovery.id, signature: recovery.sign(payload))])
    }

    func testAValidEnvelopeIsAppliedStoredWithItsEnvelopeAndPinsTheSessionWithoutAFetch() async throws {
        let response = signed(payload(4, issuedAt: now))
        let result = await updater().applySigned(response)
        XCTAssertEqual(result, .updated(newVersion: 4))
        XCTAssertEqual(try store.loadEnvelope()?.payload, response.payload)
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2])
        XCTAssertEqual(try store.getCurrentIssuedAt(), now)
        XCTAssertEqual(api.fetches, 0)
        XCTAssertEqual(api.scopedFetches, 0)
    }

    func testTheSameEnvelopeAgainIsCurrentAnOlderOneWithOtherPinsIsAReplay() async throws {
        let u = updater()
        let current = signed(payload(4, issuedAt: now))
        let first = await u.applySigned(current)
        XCTAssertEqual(first, .updated(newVersion: 4))
        let again = await u.applySigned(current)
        XCTAssertEqual(again, .alreadyCurrent)

        let replay = await u.applySigned(signed(payload(3, issuedAt: now - hour, expiresAt: now + hour, pins: [pin1, pin3])))
        guard case .failed(let reason, _) = replay else { return XCTFail("\(replay)") }
        XCTAssertTrue(reason.lowercased().contains("replay"), reason)
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2], "the live config is untouched")

        let newer = await u.applySigned(signed(payload(5, issuedAt: now + 1, pins: [pin1, pin3])))
        XCTAssertEqual(newer, .updated(newVersion: 5))
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin3])
    }

    func testAnUnsignedBlockIgnoresTheConfig() async throws {
        let result = await updater(trust: .some(nil)).applySigned(signed(payload(4, issuedAt: now)))
        XCTAssertEqual(result, .failed(reason: "unsigned block: config inside an attestation response is ignored"))
        XCTAssertNil(try store.load())
        XCTAssertNil(provider.currentConfig)
    }

    func testAForgedTamperedExpiredOrOutOfScopeEnvelopeIsRefused() async throws {
        let forged = await updater().applySigned(signed(payload(4, issuedAt: now), signer: keyB))
        guard case .failed(let reason1, _) = forged else { return XCTFail("\(forged)") }
        XCTAssertTrue(reason1.contains("signature verification"), reason1)
        XCTAssertTrue(reason1.contains("attestation answer"), reason1)

        var tampered = signed(payload(4, issuedAt: now))
        tampered.payload = tampered.payload.replacingOccurrences(of: pin2, with: pin3)
        let tamperedResult = await updater().applySigned(tampered)
        guard case .failed = tamperedResult else { return XCTFail("\(tamperedResult)") }

        let expired = await updater().applySigned(signed(payload(4, issuedAt: now - 2 * hour, expiresAt: now - hour)))
        guard case .failed(let reason3, _) = expired else { return XCTFail("\(expired)") }
        XCTAssertTrue(reason3.contains("expired"), reason3)

        let otherScope = await updater(scope: "default-tls").applySigned(signed(payload(4, issuedAt: now, scope: "default-mtls")))
        guard case .failed(let reason4, _) = otherScope else { return XCTFail("\(otherScope)") }
        XCTAssertTrue(reason4.contains("default-mtls"), reason4)

        XCTAssertNil(try store.load())
        XCTAssertNil(provider.currentConfig)
    }

    func testASigningKeySetRidingAlongIsAppliedFirst() async throws {
        let trust = trust(keys: [keyA], withRecovery: true)
        let u = updater(trust: trust)
        let result = await u.applySigned(signed(payload(4, issuedAt: now), signer: keyB, keySet: keySet(1, [keyB])))
        XCTAssertEqual(result, .updated(newVersion: 4))
        XCTAssertEqual(try trust.keySetVersion(), 1)
        XCTAssertNotNil(try store.loadEnvelope())
        // Key A is revoked from now on.
        let revoked = await u.applySigned(signed(payload(5, issuedAt: now + 1), signer: keyA))
        guard case .failed = revoked else { return XCTFail("\(revoked)") }
    }

    func testApplySignedAndUpdateNowSerialiseOnTheSameLock() async throws {
        // A fetch that answers the same config: whichever runs second finds it current.
        let response = signed(payload(4, issuedAt: now))
        let fetching = SignedFakeApi()
        fetching.next = response
        let u = updater(configApi: fetching)
        let first = await u.applySigned(response)
        XCTAssertEqual(first, .updated(newVersion: 4))
        let fetched = await u.updateNow()
        XCTAssertEqual(fetched, .alreadyCurrent)
        let again = await u.applySigned(response)
        XCTAssertEqual(again, .alreadyCurrent)
    }
}
