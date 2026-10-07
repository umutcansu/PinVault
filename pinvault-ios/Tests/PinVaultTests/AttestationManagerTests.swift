import CryptoKit
import XCTest
@testable import PinVault

/// The attestation round trip against a fake server (Kotlin
/// `AttestationManagerTest`): what the request carries (`ATTESTATION.md`
/// §2.2), what a pass, a reject and a refusal do to the status, the token and
/// the events, the config that rides along, the attestation chain, and the
/// refresh arithmetic.
final class AttestationManagerTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000
    private var api = FakeAttestationApi()
    private var key = TestIdentityKey()
    private var events = AttestCollector<PinVaultConnectionEvent>()
    private var applied = AttestCollector<SignedConfigResponse>()
    private var applyResults = AttestCollector<UpdateResult>()
    private var verdicts = AttestCollector<([String], [String])>()
    private let report = #"{"sdkVersion":"2.3.0","signals":{}}"#

    override func setUp() {
        api = FakeAttestationApi()
        key = TestIdentityKey()
        events = AttestCollector()
        applied = AttestCollector()
        applyResults = AttestCollector()
        verdicts = AttestCollector()
    }

    private func manager(
        block: ConfigApiBlock? = nil,
        api: FakeAttestationApi?? = .none,
        liveConfig: @escaping @Sendable () -> CertificateConfig? = { nil },
        deviceId: String? = "device-07",
        sleep: @escaping @Sendable (Int64) async throws -> Void = { _ in try await Task.sleep(nanoseconds: 60_000_000_000) }
    ) throws -> AttestationManager {
        let block = try block ?? attestingBlock(tokenHosts: ["api.example.com", "*.cdn.example.com"])
        let chosenApi: FakeAttestationApi? = api ?? self.api
        let key = self.key
        let report = self.report
        let applied = self.applied
        let applyResults = self.applyResults
        let events = self.events
        let verdicts = self.verdicts
        let now = self.now
        return AttestationManager(
            block: block,
            api: chosenApi,
            identityKey: { key },
            deviceId: { deviceId },
            currentConfigVersion: { 7 },
            currentIssuedAt: { 1_000 },
            liveConfig: liveConfig,
            buildReport: { _, _, _ in report },
            applyConfig: { signed in applied.append(signed); return .updated(newVersion: 9) },
            onConfigApplied: { applyResults.append($0) },
            onEvent: { events.append($0) },
            onVerdict: { verdicts.append(($0, $1)) },
            clock: { now },
            jitter: { 0.5 },
            sleep: sleep
        )
    }

    private func challenge(_ nonce: String = "nonce-1", serverTime: Int64? = nil) -> FakeAttestationApi.Answer {
        .json(#"{"nonce":"\#(nonce)","expiresIn":120,"serverTime":\#(serverTime ?? now + 5_000)}"#)
    }

    private func pass(token: String = "eyJ.token.1", ttl: Int = 300, nextAttestIn: Int = 300, extra: String = "") -> FakeAttestationApi.Answer {
        .json("""
        {"result":"pass","arc":"7f3a9c1e","warnings":["software_key"],"token":"\(token)","tokenExpiresAt":\(now + 5_000 + Int64(ttl) * 1000),
         "tokenTtlSeconds":\(ttl),"nextAttestIn":\(nextAttestIn),"configChanged":false,
         "device":{"registered":true,"firstSeen":true},"policyVersion":3\(extra)}
        """)
    }

    private func reject() -> FakeAttestationApi.Answer {
        .json(#"{"result":"reject","arc":"0badbeef","rejectionReasons":["rooted"],"warnings":[],"nextAttestIn":300,"policyVersion":3}"#)
    }

    private func attestation(_ event: PinVaultConnectionEvent) -> (id: String, status: AttestationEventStatus, arc: String?, reasons: [String], warnings: [String], expiresAt: Int64?, failure: String?)? {
        guard case let .attestation(id, status, arc, reasons, warnings, expiresAt, manufacturer, model, failure) = event else { return nil }
        XCTAssertEqual(manufacturer, "Apple")
        XCTAssertFalse(model.isEmpty)
        return (id, status, arc, reasons, warnings, expiresAt, failure)
    }

    // MARK: The request

    func testAnAttestationGetsAChallengeThenPostsTheSignedReportWithEveryFieldOfTheDesign() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        let m = try manager(block: attestingBlock(tokenHosts: ["api.example.com"], wantPinsFor: ["api.example.com", "cdn.example.com"]))

        let status = await m.attestNow()

        let calls = api.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].endpoint, "api/v1/attest/challenge")
        XCTAssertNil(calls[0].body)
        XCTAssertEqual(calls[1].endpoint, "api/v1/attest")
        let json = calls[1].json
        XCTAssertEqual(json["v"] as? Int, 1)
        XCTAssertEqual(json["nonce"] as? String, "nonce-1")
        XCTAssertEqual(json["deviceId"] as? String, "device-07")
        XCTAssertEqual(json["publicKey"] as? String, try key.spki.base64EncodedString())
        XCTAssertEqual(json["report"] as? String, report, "the report travels as a string")
        XCTAssertEqual(json["currentConfigVersion"] as? Int, 7)
        XCTAssertEqual((json["currentIssuedAt"] as? NSNumber)?.int64Value, 1_000)
        XCTAssertEqual(json["hosts"] as? [String], ["api.example.com", "cdn.example.com"])
        XCTAssertNil(json["attestationChain"], "a key without a chain sends none")

        // SHA256withECDSA over pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>, verified with the device key.
        let reportHash = Data(SHA256.hash(data: Data(report.utf8))).map { String(format: "%02x", $0) }.joined()
        let canonical = "pinvault-attest:v1:nonce-1:device-07:\(reportHash)"
        XCTAssertEqual(AttestationManager.canonicalString(nonce: "nonce-1", deviceId: "device-07", report: report), canonical)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Data(base64Encoded: XCTUnwrap(json["signature"] as? String))))
        XCTAssertTrue(try key.signingKey.publicKey.isValidSignature(signature, for: Data(canonical.utf8)))

        XCTAssertEqual(status.result, .pass)
    }

    func testHostsAreSentOnlyWhenTheBlockScopesItsPinsAndAnUnusableDeviceIdBecomesUnknownDevice() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        _ = try await manager(deviceId: "bad id with spaces").attestNow()
        let json = try XCTUnwrap(api.attestBodies.first)
        XCTAssertNil(json["hosts"])
        XCTAssertEqual(json["deviceId"] as? String, "unknown-device")
        XCTAssertEqual(AttestationManager.resolveDeviceId(nil), "unknown-device")
        XCTAssertEqual(AttestationManager.resolveDeviceId(String(repeating: "a", count: 65)), "unknown-device")
        XCTAssertEqual(AttestationManager.resolveDeviceId(" 6f1c2b6a-0e2f-4c1a-9a7e-3d1f0c6b9e21 "), "6f1c2b6a-0e2f-4c1a-9a7e-3d1f0c6b9e21")
    }

    func testTheBodyCarriesTheReportExactlyAsBuiltSoTheSignedHashMatchesWhatWasSent() async throws {
        // A report with characters JSON must escape: the string inside the body is the hashed one.
        let tricky = #"{"a":"line\nbreak \"quoted\" \\ / é 🎉  "}"#
        api.enqueue(challenge())
        api.enqueue(pass())
        let key = self.key
        let m = AttestationManager(
            block: try attestingBlock(), api: api, identityKey: { key }, deviceId: { "device-07" },
            currentConfigVersion: { 0 }, currentIssuedAt: { 0 }, liveConfig: { nil },
            buildReport: { _, _, _ in tricky }, applyConfig: { _ in .alreadyCurrent }, clock: { 1 }, jitter: { 0.5 }
        )
        _ = await m.attestNow()
        let json = try XCTUnwrap(api.attestBodies.first)
        let sent = try XCTUnwrap(json["report"] as? String)
        XCTAssertEqual(sent, tricky)
        let canonical = AttestationManager.canonicalString(nonce: "nonce-1", deviceId: "device-07", report: sent)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Data(base64Encoded: XCTUnwrap(json["signature"] as? String))))
        XCTAssertTrue(try key.signingKey.publicKey.isValidSignature(signature, for: Data(canonical.utf8)))
    }

    // MARK: Pass

    func testAPassHoldsTheTokenSchedulesTheRefreshAndRaisesAPassEvent() async throws {
        api.enqueue(challenge())
        api.enqueue(pass(ttl: 300, nextAttestIn: 300))
        let m = try manager()

        let status = await m.attestNow()

        XCTAssertEqual(status.result, .pass)
        XCTAssertEqual(status.arc, "7f3a9c1e")
        XCTAssertEqual(status.warnings, ["software_key"])
        XCTAssertTrue(status.rejectionReasons.isEmpty)
        XCTAssertEqual(status.tokenExpiresAt, now + 300_000, "device-clock expiry from the TTL")
        XCTAssertEqual(status.lastAttestedAt, now)
        // min(nextAttestIn 300 s, block 300 s, expiry − 60 s = 240 s), no jitter at 0.5.
        XCTAssertEqual(status.nextAttestAt, now + 240_000)
        XCTAssertEqual(status.clockSkewMs, 5_000)
        XCTAssertEqual(status.policyVersion, 3)
        XCTAssertNil(status.lastError)
        XCTAssertTrue(status.hasValidToken(now: now))
        XCTAssertEqual(m.status, status)

        let token1 = await m.token(host: "api.example.com", port: 443, forceRefresh: false)
        XCTAssertEqual(token1, "eyJ.token.1")
        let token2 = await m.token(host: "img.cdn.example.com", port: 443, forceRefresh: false)
        XCTAssertEqual(token2, "eyJ.token.1", "a wildcard token host")
        XCTAssertTrue(m.handlesHost("api.example.com", port: 443))
        XCTAssertFalse(m.handlesHost("other.example.com", port: 443))
        XCTAssertFalse(m.handlesHost("a.b.cdn.example.com", port: 443))
        XCTAssertEqual(api.requestCount, 2, "no request for a held token")

        let fetched = await m.fetchToken()
        XCTAssertEqual(fetched, .token(value: "eyJ.token.1", expiresAt: now + 300_000))
        XCTAssertFalse("\(fetched)".contains("eyJ.token.1"), "the token stays out of descriptions")

        XCTAssertEqual(events.count, 1)
        let event = try XCTUnwrap(attestation(events.values[0]))
        XCTAssertEqual(event.status, .pass)
        XCTAssertEqual(event.id, "api")
        XCTAssertEqual(event.arc, "7f3a9c1e")
        XCTAssertEqual(event.warnings, ["software_key"])
        XCTAssertEqual(event.expiresAt, now + 300_000)
        XCTAssertNil(event.failure)
        XCTAssertTrue(applied.values.isEmpty)
        XCTAssertEqual(verdicts.values.map(\.0), [["software_key"]], "the verdict's warnings reach the verdict observer")
    }

    func testWithoutTokenHostsTheLiveConfigsPinnedHostsAndTheConfigApiListenerCarryTheToken() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        let live = CertificateConfig(pins: [
            HostPin(hostname: "api.live.test", sha256: [pin("a"), pin("b")]),
            HostPin(hostname: "*.cdn.live.test", sha256: [pin("a"), pin("b")]),
        ])
        let m = try manager(block: attestingBlock(), liveConfig: { live })
        _ = await m.attestNow()

        XCTAssertTrue(m.handlesHost("api.live.test", port: 443))
        XCTAssertTrue(m.handlesHost("x.cdn.live.test", port: 443))
        XCTAssertTrue(m.handlesHost("config.example.com", port: 8091), "the block's own Config API listener")
        XCTAssertFalse(m.handlesHost("config.example.com", port: 443), "another port of it")
        XCTAssertFalse(m.handlesHost("api.example.com", port: 443))
        XCTAssertEqual(AttestationManager.listener(of: "https://Config.Example.com/"), "config.example.com:443")
        XCTAssertEqual(AttestationManager.listener(of: "http://10.0.2.2:8090/"), "10.0.2.2:8090")
    }

    func testAConfigInAPassAnswerGoesThroughTheUpdaterAndIsReportedLikeARecoveryUpdate() async throws {
        api.enqueue(challenge())
        api.enqueue(pass(extra: #","configChanged":true,"config":{"payload":"{\"version\":1}","signature":"c2ln","signatures":[{"keyId":"k1","signature":"c2ln"}]}"#))
        _ = try await manager().attestNow()

        XCTAssertEqual(applied.count, 1)
        XCTAssertEqual(applied.values[0].payload, #"{"version":1}"#)
        XCTAssertEqual(applied.values[0].signature, "c2ln")
        XCTAssertEqual(applied.values[0].signatures?.first?.keyId, "k1")
        XCTAssertEqual(applyResults.values, [.updated(newVersion: 9)])
    }

    func testAnEmbeddedConfigThatIsNotAnEnvelopeIsIgnored() async throws {
        api.enqueue(challenge())
        api.enqueue(pass(extra: #","config":{"payload":5,"signature":[1]}"#))
        let status = try await manager().attestNow()
        XCTAssertEqual(status.result, .pass)
        XCTAssertTrue(applied.values.isEmpty)
        XCTAssertTrue(applyResults.values.isEmpty)
    }

    // MARK: Reject

    func testARejectHoldsNoTokenIgnoresAnyConfigRaisesARejectEventAndDoesNotReAttestOnDemand() async throws {
        api.enqueue(challenge())
        api.enqueue(.json(#"{"result":"reject","arc":"0badbeef","rejectionReasons":["rooted","hooking_framework"],"warnings":["adb_enabled"],"nextAttestIn":300,"policyVersion":3,"config":{"payload":"{}","signature":"x"}}"#))
        let m = try manager()

        let status = await m.attestNow()

        XCTAssertEqual(status.result, .reject)
        XCTAssertEqual(status.arc, "0badbeef")
        XCTAssertEqual(status.rejectionReasons, ["rooted", "hooking_framework"])
        XCTAssertEqual(status.warnings, ["adb_enabled"])
        XCTAssertNil(status.tokenExpiresAt)
        XCTAssertEqual(status.lastAttestedAt, now)
        XCTAssertEqual(status.nextAttestAt, now + 300_000)
        XCTAssertFalse(status.hasValidToken(now: now))
        XCTAssertTrue(applied.values.isEmpty, "a rejected device gets no config")

        let plain = await m.token(host: "api.example.com", port: 443, forceRefresh: false)
        let forced = await m.token(host: "api.example.com", port: 443, forceRefresh: true)
        XCTAssertNil(plain)
        XCTAssertNil(forced)
        XCTAssertEqual(api.requestCount, 2, "requests do not turn a reject into a storm")

        let event = try XCTUnwrap(attestation(try XCTUnwrap(events.values.first)))
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(event.status, .reject)
        XCTAssertEqual(event.reasons, ["rooted", "hooking_framework"])
        XCTAssertEqual(verdicts.values.map(\.1), [["rooted", "hooking_framework"]])

        // The explicit token API attests again and reports the reject.
        api.enqueue(challenge())
        api.enqueue(reject())
        let fetched = await m.fetchToken()
        guard case .rejected(let rejected) = fetched else { return XCTFail("\(fetched)") }
        XCTAssertEqual(rejected.arc, "0badbeef")
        XCTAssertEqual(api.requestCount, 4)
    }

    // MARK: Refusals and failures

    func testARefusalIsFailedWithTheServersReasonBacksOffAndRaisesAFailedEvent() async throws {
        api.enqueue(challenge())
        api.enqueue(.http(403, #"{"error":"key_mismatch","message":"another key is registered for this device"}"#))
        let m = try manager()

        let status = await m.attestNow()

        XCTAssertEqual(status.result, .failed)
        let lastError = try XCTUnwrap(status.lastError)
        XCTAssertTrue(lastError.contains("key_mismatch"), lastError)
        XCTAssertTrue(lastError.contains("another key is registered"), lastError)
        XCTAssertEqual(lastError, "Attestation refused — HTTP 403 key_mismatch: another key is registered for this device")
        XCTAssertEqual(status.nextAttestAt, now + 30_000)
        XCTAssertNil(status.lastAttestedAt)
        let event = try XCTUnwrap(attestation(try XCTUnwrap(events.values.first)))
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(event.status, .failed)
        XCTAssertEqual(event.failure, status.lastError)

        api.enqueue(challenge())
        api.enqueue(.http(401, #"{"error":"signature_invalid"}"#))
        // The backoff holds the on-demand path, not the explicit API.
        let fetched = await m.fetchToken()
        guard case .failed(let message) = fetched else { return XCTFail("\(fetched)") }
        XCTAssertTrue(message.contains("signature_invalid"), message)
    }

    func testARevokedDeviceIsFailedWithTheServersReason() async throws {
        api.enqueue(challenge())
        api.enqueue(.http(403, #"{"error":"device_revoked","message":"This device's identity was revoked."}"#))
        let status = try await manager().attestNow()
        XCTAssertEqual(status.result, .failed)
        XCTAssertEqual(status.lastError, "Attestation refused — HTTP 403 device_revoked: This device's identity was revoked.")
        XCTAssertNil(status.tokenExpiresAt)
    }

    func testAnUnreachableServerIsFailedTooAndTheBackoffGrows() async throws {
        let m = try manager()
        api.down = true

        let first = await m.attestNow()
        XCTAssertEqual(first.result, .failed)
        XCTAssertNotNil(first.lastError)
        XCTAssertTrue(first.lastError?.hasPrefix("URLError: ") == true, first.lastError ?? "")
        XCTAssertEqual(first.nextAttestAt, now + 30_000)

        // The on-demand path honours the backoff: no attempt until nextAttestAt.
        let forced = await m.token(host: "api.example.com", port: 443, forceRefresh: true)
        XCTAssertNil(forced)

        let second = await m.attestNow()
        XCTAssertEqual(second.nextAttestAt, now + 60_000)
        XCTAssertEqual(events.count, 2)
    }

    func testAChallengeWithoutANonceOrAnAnswerThatIsNotJsonFails() async throws {
        let m = try manager()
        api.enqueue(.json(#"{"expiresIn":120}"#))
        let noNonce = await m.attestNow()
        XCTAssertEqual(noNonce.lastError, "IllegalStateException: The attestation challenge carries no nonce")

        api.enqueue(challenge())
        api.enqueue(.json("<html>busy</html>"))
        let notJson = await m.attestNow()
        XCTAssertEqual(notJson.lastError, "Exception: The attestation attest answer is not JSON (<html>busy</html>)")

        api.enqueue(challenge())
        api.enqueue(.json(#"{"result":"maybe"}"#))
        let unknown = await m.attestNow()
        XCTAssertEqual(unknown.result, .failed)
        XCTAssertEqual(unknown.lastError, "The attestation answer has an unknown result 'maybe'")
    }

    func testAFailureKeepsTheLastTokenUntilItExpires() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        let m = try manager()
        _ = await m.attestNow()
        api.enqueue(challenge())
        api.enqueue(.http(503, "busy"))

        let status = await m.attestNow()

        XCTAssertEqual(status.result, .failed)
        XCTAssertEqual(status.tokenExpiresAt, now + 300_000, "the token is still held")
        XCTAssertEqual(status.lastError, "Attestation refused — HTTP 503")
        let held = await m.token(host: "api.example.com", port: 443, forceRefresh: false)
        XCTAssertEqual(held, "eyJ.token.1")
        XCTAssertEqual(status.arc, "7f3a9c1e", "the pass's arc stays")
    }

    func testACustomConfigApiCannotAttest() async throws {
        let m = try manager(api: .some(nil))
        XCTAssertEqual(m.status.result, .unsupported)
        XCTAssertEqual(m.status.lastError, AttestationManager.unsupportedReason)
        let status = await m.attestNow()
        XCTAssertEqual(status.result, .unsupported)
        let fetched = await m.fetchToken()
        XCTAssertEqual(fetched, .unsupported)
        XCTAssertFalse(m.handlesHost("api.example.com", port: 443))
        let token = await m.token(host: "api.example.com", port: 443, forceRefresh: true)
        XCTAssertNil(token)
        XCTAssertFalse(m.supported)
        m.start()
        XCTAssertFalse(m.isRunning)
        XCTAssertTrue(events.values.isEmpty)
    }

    // MARK: Single flight

    func testConcurrentCallersShareOneAttestation() async throws {
        let slow = SlowAttestationApi()
        let key = self.key
        let m = AttestationManager(
            block: try attestingBlock(tokenHosts: ["api.example.com"]), api: slow, identityKey: { key }, deviceId: { "d" },
            currentConfigVersion: { 0 }, currentIssuedAt: { 0 }, liveConfig: { nil },
            buildReport: { _, _, _ in "{}" }, applyConfig: { _ in .alreadyCurrent }, clock: { 1_000 }, jitter: { 0.5 }
        )
        async let a = m.attestNow()
        async let b = m.attestNow()
        async let c = m.token(host: "api.example.com", port: 443, forceRefresh: false)
        let (first, second, token) = await (a, b, c)
        XCTAssertEqual(first, second)
        XCTAssertEqual(token, "eyJ.slow")
        XCTAssertEqual(slow.rounds, 1, "one challenge for three callers")
    }

    // MARK: The attestation chain

    func testTheKeysChainGoesWithTheFirstRequestNotWithTheNextAndAgainWhenTheServerAsksForIt() async throws {
        key.chain = [Data([1, 2, 3]), Data([4])]
        let m = try manager()

        api.enqueue(challenge())
        api.enqueue(pass())
        _ = await m.attestNow()
        XCTAssertEqual(api.attestBodies.last?["attestationChain"] as? [String], ["AQID", "BA=="])

        api.enqueue(challenge())
        api.enqueue(pass())
        _ = await m.attestNow()
        XCTAssertNil(api.attestBodies.last?["attestationChain"], "registered: a key cannot be re-attested")

        api.enqueue(challenge())
        api.enqueue(.http(403, #"{"error":"attestation_required"}"#))
        _ = await m.attestNow()

        api.enqueue(challenge())
        api.enqueue(pass())
        _ = await m.attestNow()
        XCTAssertNotNil(api.attestBodies.last?["attestationChain"], "asked for again")
    }

    func testTheDeviceKeyIsMadeWithTheIdentityAttestationChallengeOfTheDeviceId() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        _ = try await manager().attestNow()
        XCTAssertTrue(key.exists())
        XCTAssertEqual(key.challenge, ClientIdentityKeys.attestationChallenge(deviceUid: "device-07"))
    }

    func testAKeyThatCannotBeMadeFailsTheRound() async throws {
        struct NoKeychain: Error {}
        let m = AttestationManager(
            block: try attestingBlock(), api: api, identityKey: { throw PinVaultError.illegalState("Keychain unavailable") },
            deviceId: { "d" }, currentConfigVersion: { 0 }, currentIssuedAt: { 0 }, liveConfig: { nil },
            buildReport: { _, _, _ in "{}" }, applyConfig: { _ in .alreadyCurrent }, clock: { 1 }, jitter: { 0.5 }
        )
        let status = await m.attestNow()
        XCTAssertEqual(status.result, .failed)
        XCTAssertEqual(status.lastError, "IllegalStateException: Keychain unavailable")
        XCTAssertEqual(api.requestCount, 0)
    }

    // MARK: The refresh arithmetic

    func testTheNextAttestationIsTheEarliestOfNextAttestInTheBlockIntervalAndTheTokensExpiryMinusAMinute() {
        let interval: Int64 = 5 * 60_000
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 300_000, blockIntervalMs: interval, tokenExpiresAt: now + 300_000, now: now, jitter: 0.5), 240_000)
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 120_000, blockIntervalMs: interval, tokenExpiresAt: now + 300_000, now: now, jitter: 0.5), 120_000, "the server asks for sooner")
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 600_000, blockIntervalMs: 60_000, tokenExpiresAt: nil, now: now, jitter: 0.5), 60_000, "the block interval caps it")
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: nil, blockIntervalMs: interval, tokenExpiresAt: nil, now: now, jitter: 0.5), interval, "no server value: the block interval")
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 300_000, blockIntervalMs: interval, tokenExpiresAt: now + 10_000, now: now, jitter: 0.5), 30_000, "never below the floor")
        // ±10 % jitter.
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 300_000, blockIntervalMs: interval, tokenExpiresAt: now + 300_000, now: now, jitter: 0.0), 216_000)
        XCTAssertEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 300_000, blockIntervalMs: interval, tokenExpiresAt: now + 300_000, now: now, jitter: 1.0), 264_000)
        XCTAssertGreaterThanOrEqual(AttestationManager.refreshDelayMs(nextAttestInMs: 300_000, blockIntervalMs: interval, tokenExpiresAt: now + 300_000, now: now, jitter: 0.0), AttestationManager.minDelayMs)
    }

    func testFailuresBackOffFrom30SecondsTo5Minutes() {
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 1), 30_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 2), 60_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 3), 120_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 4), 240_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 5), 300_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 50), 300_000)
        XCTAssertEqual(AttestationManager.backoffMs(consecutiveFailures: 0), 30_000)
    }

    func testResetForgetsTheTokenAndTheStatusAndTheLoopCanBeStartedAndStopped() async throws {
        api.enqueue(challenge())
        api.enqueue(pass())
        let m = try manager()
        _ = await m.attestNow()
        m.start()
        m.start()
        XCTAssertTrue(m.isRunning)
        m.stop()
        XCTAssertFalse(m.isRunning)
        m.reset()
        XCTAssertEqual(m.status.result, .notAttested)
        XCTAssertNil(m.status.tokenExpiresAt)
        // No token, nothing attempted yet: the next request to a token host attests again.
        api.enqueue(challenge())
        api.enqueue(pass(token: "eyJ.token.2"))
        let token = await m.token(host: "api.example.com", port: 443, forceRefresh: false)
        XCTAssertEqual(token, "eyJ.token.2")
    }

    func testTheLoopReAttestsWhenTheScheduleSaysSo() async throws {
        let waits = AttestCollector<Int64>()
        let ticks = AsyncStream<Void>.makeStream()
        api.enqueue(challenge())
        api.enqueue(pass())
        api.enqueue(challenge())
        api.enqueue(pass(token: "eyJ.token.2"))
        let m = try manager(sleep: { ms in
            waits.append(ms)
            ticks.continuation.yield()
            if waits.count > 2 { try await Task.sleep(nanoseconds: 60_000_000_000) }
        })
        _ = await m.attestNow()
        m.start()
        // Wait until the loop has slept twice: one round in between.
        var iterator = ticks.stream.makeAsyncIterator()
        _ = await iterator.next()
        _ = await iterator.next()
        _ = await iterator.next()
        m.stop()
        XCTAssertEqual(waits.values.first, 240_000, "the first wait is nextAttestAt − now")
        XCTAssertEqual(api.attestBodies.count, 2, "the loop attested once")
        let token = await m.token(host: "api.example.com", port: 443, forceRefresh: false)
        XCTAssertEqual(token, "eyJ.token.2")
    }
}

/// An attest API whose challenge takes a moment, counting rounds.
private final class SlowAttestationApi: AttestationApi, @unchecked Sendable {
    private let lock = NSLock()
    private var _rounds = 0
    var rounds: Int { lock.lock(); defer { lock.unlock() }; return _rounds }

    func attestChallenge() async throws -> Data {
        lock.withLock { _rounds += 1 }
        try await Task.sleep(nanoseconds: 200_000_000)
        return Data(#"{"nonce":"n"}"#.utf8)
    }

    func attest(body: Data) async throws -> Data {
        Data(#"{"result":"pass","token":"eyJ.slow","tokenTtlSeconds":300}"#.utf8)
    }
}
