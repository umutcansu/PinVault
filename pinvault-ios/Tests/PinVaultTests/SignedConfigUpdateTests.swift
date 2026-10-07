import Foundation
import XCTest
@testable import PinVault

/// Port of SignedConfigUpdateTest: the updater over signed envelopes and a
/// real ``CertificateConfigStore`` — what is stored, what is verified again
/// when it is read back, what a holder of a stolen signing key cannot leave
/// behind, and how a custom API that hands over envelopes is treated like the library's own.
final class SignedConfigUpdateTests: XCTestCase {

    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private var day: Int64 { 24 * hour }

    private let pin1 = pin("A"), pin2 = pin("B"), pin3 = pin("C")
    private let keyA = TestSigner(), keyB = TestSigner(), recovery = TestSigner()

    private var prefs: InMemoryPreferences!
    private var store: CertificateConfigStore!
    private var keyStore: SigningKeyStore!
    private var api: SignedFakeApi!
    private var provider: HttpClientProvider!

    override func setUp() {
        reset()
    }

    private func reset() {
        prefs = InMemoryPreferences()
        store = CertificateConfigStore(prefs: prefs)
        let now = self.now
        store.clock = { now }
        keyStore = SigningKeyStore(prefs: InMemoryPreferences())
        api = SignedFakeApi()
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    private func trust(keys: [TestSigner]? = nil, withRecovery: Bool = false) -> SignatureTrust {
        SignatureTrust(
            configApiId: "default", builtInKeys: (keys ?? [keyA]).map(\.pub), builtInThreshold: 1,
            recoveryKeys: withRecovery ? [recovery.pub] : [], recoveryThreshold: 1, store: withRecovery ? keyStore : nil
        )
    }

    private func updater(
        trust: SignatureTrust?? = .none,
        scope: String? = nil,
        configApi: (any CertificateConfigApi)? = nil,
        trustedClock: TrustedClock? = nil
    ) -> SSLCertificateUpdater {
        let now = self.now
        let resolved: SignatureTrust? = trust ?? self.trust()
        return SSLCertificateUpdater(
            configApi: configApi ?? api,
            configStore: store,
            httpClientProvider: provider,
            maxRetryCount: 1,
            clock: { now },
            verifier: resolved.map { SignedConfigVerifier(trust: $0, serverScope: scope, clock: { now }) },
            trustedClock: trustedClock,
            sleep: { _ in }
        )
    }

    private func unsignedUpdater(_ configApi: any CertificateConfigApi) -> SSLCertificateUpdater {
        updater(trust: .some(nil), configApi: configApi)
    }

    private func payload(
        _ version: Int,
        issuedAt: Int64,
        expiresAt: Int64? = nil,
        pins: [String]? = nil,
        hosts: [(String, Int)]? = nil,
        scope: String? = nil
    ) -> String {
        signedPayload(
            version: version, issuedAt: issuedAt, expiresAt: expiresAt ?? issuedAt + hour,
            pins: pins ?? [pin1, pin2], hosts: hosts ?? [("api.test", version)], scope: scope
        )
    }

    private func signed(_ payload: String, signer: TestSigner? = nil, keySet: SignedKeySet? = nil) -> SignedConfigResponse {
        let signer = signer ?? keyA
        return SignedConfigResponse(payload: payload, signature: signer.sign(payload), keyId: signer.id, signingKeys: keySet)
    }

    private func keySet(_ version: Int, _ keys: [TestSigner]) -> SignedKeySet {
        let payload = keySetPayload(version: version, keys: keys.map(\.pub))
        return SignedKeySet(payload: payload, signatures: [SignatureEntry(keyId: recovery.id, signature: recovery.sign(payload))])
    }

    @discardableResult
    private func apply(_ response: SignedConfigResponse, with updater: SSLCertificateUpdater? = nil) async -> UpdateResult {
        api.next = response
        api.failure = nil
        return await (updater ?? self.updater()).updateNow()
    }

    private func offline() {
        api.failure = PinVaultError.io(message: "offline")
    }

    private func newProcess() {
        provider = HttpClientProvider(sslManager: DynamicSSLManager())
    }

    // MARK: The envelope is stored, and checked again on every read

    func testASignedConfigIsStoredWithItsEnvelopeAndStartsOfflineFromIt() async throws {
        let response = signed(payload(4, issuedAt: now))
        let result = await apply(response)
        XCTAssertEqual(result, .updated(newVersion: 4))

        let envelope = try XCTUnwrap(try store.loadEnvelope())
        XCTAssertEqual(envelope.payload, response.payload)
        XCTAssertEqual(envelope.signatures, [SignatureEntry(keyId: keyA.id, signature: response.signature)])

        newProcess()
        offline()
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 4))
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2])
    }

    func testStoredPinsRewrittenOnDiskAreNotUsedTheConfigComesFromTheEnvelope() async throws {
        await apply(signed(payload(4, issuedAt: now)))
        // Code that ran once as the app swaps the stored pins for its own.
        try prefs.edit().putString(
            CertificateConfigStore.keyPinsJson,
            #"[{"hostname":"api.test","version":4,"sha256":["\#(pin3)","\#(pin3)"],"forceUpdate":false,"mtls":false}]"#
        ).commit()
        XCTAssertEqual(try store.load()?.pins.first?.sha256, [pin3, pin3])

        newProcess()
        offline()
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 4))
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2], "the signed pins, not the planted ones")
    }

    func testAStoredConfigWithoutAValidEnvelopeIsDiscardedAndStartFailsClosed() async throws {
        let tampers: [(InMemoryPreferences, CertificateConfigStore) throws -> Void] = [
            { prefs, _ in try prefs.edit().remove(CertificateConfigStore.keyEnvelope).commit() },
            { [pin1, pin3] prefs, store in
                // The envelope of another config, re-labelled: payload and signature no longer match.
                let envelope = try XCTUnwrap(try store.loadEnvelope())
                let forged = envelope.payload.replacingOccurrences(of: pin1, with: pin3)
                let signatures = JSONText.array(envelope.signatures.map { entry in
                    JSONText.object([("keyId", entry.keyId.map(JSONText.string) ?? "null"), ("signature", JSONText.string(entry.signature))])
                })
                try prefs.edit().putString(
                    CertificateConfigStore.keyEnvelope,
                    JSONText.object([("payload", JSONText.string(forged)), ("signatures", signatures)])
                ).commit()
            },
        ]
        for tamper in tampers {
            reset()
            await apply(signed(payload(4, issuedAt: now)))
            try tamper(prefs, store)

            newProcess()
            offline()
            let result = try await updater().initializeAndUpdate()
            guard case .failed(let reason, let exception) = result else { return XCTFail("\(result)") }
            XCTAssertTrue(reason.contains("discarded"), reason)
            guard case .noConfigAvailable? = exception as? PinVaultError else { return XCTFail("\(String(describing: exception))") }
            XCTAssertNil(provider.currentConfig, "no config: pinned sessions refuse")
            XCTAssertNil(try store.load())
            XCTAssertEqual(try store.getCurrentIssuedAt(), now, "the replay watermark stays")
        }
    }

    func testADiscardedStoredConfigIsReplacedByTheNextFetchEvenAtTheWatermark() async throws {
        let response = signed(payload(4, issuedAt: now))
        await apply(response)
        try prefs.edit().remove(CertificateConfigStore.keyEnvelope).commit()

        newProcess()
        api.next = response
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 4))
        XCTAssertNotNil(try store.loadEnvelope())
    }

    func testAfterAResetTheNewestConfigIsAcceptedAgainAnOlderOneIsNot() async throws {
        let older = signed(payload(3, issuedAt: now - hour, expiresAt: now + hour))
        let newest = signed(payload(4, issuedAt: now))
        await apply(older)
        await apply(newest)

        // What PinVault.reset() does to the store and the session.
        try store.clearActive()
        provider.reset()

        let replay = await apply(older)
        guard case .failed(let reason, _) = replay else { return XCTFail("\(replay)") }
        XCTAssertTrue(reason.lowercased().contains("replay"), reason)
        XCTAssertNil(provider.currentConfig)

        let again = await apply(newest)
        XCTAssertEqual(again, .updated(newVersion: 4))
    }

    func testAnUnsignedBlockKeepsWorkingWithoutAnEnvelope() async throws {
        let plain = FakeConfigApi()
        plain.returns(CertificateConfig(version: 2, pins: [HostPin(hostname: "api.test", sha256: [pin1, pin2], version: 2)]))

        let first = try await unsignedUpdater(plain).initializeAndUpdate()
        XCTAssertEqual(first, .ready(version: 2))
        XCTAssertNil(try store.loadEnvelope())

        newProcess()
        plain.fails()
        let offlineStart = try await unsignedUpdater(plain).initializeAndUpdate()
        XCTAssertEqual(offlineStart, .ready(version: 2))
    }

    // MARK: Change detection over the whole shape

    func testAPinRemovedWithoutAVersionBumpReachesTheDevice() async throws {
        await apply(signed(payload(4, issuedAt: now - hour, expiresAt: now + hour)))
        let result = await apply(signed(payload(4, issuedAt: now, pins: [pin1, pin3])))
        XCTAssertEqual(result, .updated(newVersion: 4))
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin3])
        XCTAssertEqual(try store.load()?.pins.first?.sha256, [pin1, pin3])
    }

    func testDifferentPinsAtTheSameIssuedAtAreStillAReplay() async throws {
        await apply(signed(payload(4, issuedAt: now)))
        let result = await apply(signed(payload(4, issuedAt: now, pins: [pin1, pin3])))
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.lowercased().contains("replay"), reason)
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2])
    }

    func testAnUnsignedBlockAppliesAChangedPinSetAtTheSameVersionToo() async throws {
        let plain = FakeConfigApi()
        func config(_ pins: [String]) -> CertificateConfig {
            CertificateConfig(version: 2, pins: [HostPin(hostname: "api.test", sha256: pins, version: 2)])
        }
        plain.returns(config([pin1, pin2]))
        let unsigned = unsignedUpdater(plain)
        let first = await unsigned.updateNow()
        XCTAssertEqual(first, .updated(newVersion: 2))
        let second = await unsigned.updateNow()
        XCTAssertEqual(second, .alreadyCurrent)

        plain.returns(config([pin1, pin3]))
        let third = await unsigned.updateNow()
        XCTAssertEqual(third, .updated(newVersion: 2))
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin3])
    }

    func testANewerEnvelopeWithTheSamePinsIsWrittenBackWithItsEnvelope() async throws {
        await apply(signed(payload(4, issuedAt: now - hour, expiresAt: now + hour)))
        let fresher = signed(payload(4, issuedAt: now, expiresAt: now + 2 * hour))

        let result = await apply(fresher)
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertEqual(try store.loadEnvelope()?.payload, fresher.payload)
        XCTAssertEqual(provider.currentConfig?.expiresAt, now + 2 * hour)

        // And it still verifies when read back.
        newProcess()
        offline()
        let started = try await updater().initializeAndUpdate()
        XCTAssertEqual(started, .ready(version: 4))
        XCTAssertEqual(provider.currentConfig?.expiresAt, now + 2 * hour)
    }

    // MARK: Intake: host names, freshness fields, version caps

    func testAConfigWithAHostNameThatIsNotOneIsRefusedAsAWhole() async throws {
        let result = await apply(signed(payload(4, issuedAt: now, hosts: [("api.test", 4), ("api.bank.com|9|x", 4)])))
        guard case .failed(_, let exception) = result, case .invalidPinFormat? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
        XCTAssertNil(try store.load())
        XCTAssertNil(provider.currentConfig)
    }

    func testASignedConfigMustCarryIssuedAtAndExpiresAt() async throws {
        let noIssuedAt = await apply(signed(payload(4, issuedAt: 0, expiresAt: now + hour)))
        guard case .failed(let reason1, _) = noIssuedAt else { return XCTFail("\(noIssuedAt)") }
        XCTAssertTrue(reason1.contains("issuedAt"), reason1)

        let noExpiresAt = await apply(signed(payload(4, issuedAt: now, expiresAt: 0)))
        guard case .failed(let reason2, _) = noExpiresAt else { return XCTFail("\(noExpiresAt)") }
        XCTAssertTrue(reason2.contains("expiresAt"), reason2)
        XCTAssertNil(try store.load())
    }

    func testExpiresAtMoreThanThirtyDaysOutIsRefusedWithOrWithoutIssuedAt() async throws {
        let signedLong = await apply(signed(payload(4, issuedAt: now, expiresAt: now + 31 * day)))
        guard case .failed(let reason1, _) = signedLong else { return XCTFail("\(signedLong)") }
        XCTAssertTrue(reason1.contains("30 days"), reason1)

        // Unsigned, no issuedAt: there used to be nothing to measure the window from.
        let plain = FakeConfigApi()
        plain.returns(CertificateConfig(version: 2, pins: [HostPin(hostname: "api.test", sha256: [pin1, pin2], version: 2)], expiresAt: now + 400 * day))
        let unsignedLong = await unsignedUpdater(plain).updateNow()
        guard case .failed(let reason2, _) = unsignedLong else { return XCTFail("\(unsignedLong)") }
        XCTAssertTrue(reason2.contains("30 days"), reason2)
    }

    func testAHostThatWasDroppedKeepsItsWatermarkAndCannotComeBackLowerOrFarHigher() async throws {
        await apply(signed(payload(5, issuedAt: now - 3 * hour, expiresAt: now + hour, hosts: [("a.test", 5), ("b.test", 5)])))
        await apply(signed(payload(6, issuedAt: now - 2 * hour, expiresAt: now + hour, hosts: [("a.test", 6)])))

        let lower = await apply(signed(payload(6, issuedAt: now - hour, expiresAt: now + hour, hosts: [("a.test", 6), ("b.test", 3)])))
        guard case .failed(let reason1, _) = lower else { return XCTFail("\(lower)") }
        XCTAssertTrue(reason1.contains("downgrade rejected for b.test"), reason1)

        let leap = await apply(signed(payload(6, issuedAt: now - hour, expiresAt: now + hour, hosts: [("a.test", 6), ("b.test", Int(Int32.max))])))
        guard case .failed(let reason2, _) = leap else { return XCTFail("\(leap)") }
        XCTAssertTrue(reason2.contains("version jump rejected for b.test"), reason2)

        let fine = await apply(signed(payload(6, issuedAt: now, hosts: [("a.test", 6), ("b.test", 5)])))
        XCTAssertEqual(fine, .updated(newVersion: 6))
    }

    // MARK: A newer signing-key set ends what a revoked key left behind

    func testRevokingASigningKeyClearsTheWatermarksItPushedUpAndDropsItsConfig() async throws {
        let updater = updater(trust: trust(keys: [keyA, keyB], withRecovery: true))
        // The holder of stolen key A plants a config at the edge of what is accepted.
        let planted = await apply(signed(payload(1_000_000, issuedAt: now + 50 * 60_000, expiresAt: now + 20 * day, pins: [pin3, pin1])), with: updater)
        XCTAssertEqual(planted, .updated(newVersion: 1_000_000))
        // Every honest config now looks like a replay and a downgrade.
        let honest = payload(3, issuedAt: now)
        let refused = await apply(signed(honest, signer: keyB), with: updater)
        guard case .failed = refused else { return XCTFail("\(refused)") }

        // Recovery keys publish set v2 without key A; the honest config rides along.
        let result = await apply(signed(honest, signer: keyB, keySet: keySet(2, [keyB])), with: updater)

        XCTAssertEqual(result, .updated(newVersion: 3))
        XCTAssertEqual(try store.getCurrentIssuedAt(), now)
        XCTAssertEqual(try store.getVersionWatermarks(), ["api.test": 3])
        XCTAssertEqual(provider.currentConfig?.pins.first?.sha256, [pin1, pin2])
        XCTAssertEqual(try store.keySetVersionSeen(), 2)
    }

    func testAConfigPlantedWithARevokedKeyGoesEvenWhenTheConfigNextToTheNewSetFails() async throws {
        let updater = updater(trust: trust(keys: [keyA, keyB], withRecovery: true))
        await apply(signed(payload(7, issuedAt: now, pins: [pin3, pin1])), with: updater)
        XCTAssertNotNil(provider.currentConfig)

        // Set v2 revokes key A, but the config in the same response is still signed with A.
        let result = await apply(signed(payload(8, issuedAt: now + 1), signer: keyA, keySet: keySet(2, [keyB])), with: updater)

        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertNil(provider.currentConfig, "the planted config is no longer pinned")
        XCTAssertNil(try store.load())
        XCTAssertEqual(try store.getCurrentIssuedAt(), 0)
    }

    func testAStoredConfigSignedByAKeyThatIsStillTrustedSurvivesTheNewSet() async throws {
        let updater = updater(trust: trust(keys: [keyA, keyB], withRecovery: true))
        let current = signed(payload(7, issuedAt: now), signer: keyB)
        await apply(current, with: updater)

        // Same envelope again, now with set v2 (key A revoked): nothing to drop.
        var withSet = current
        withSet.signingKeys = keySet(2, [keyB])
        let result = await apply(withSet, with: updater)
        XCTAssertEqual(result, .alreadyCurrent)
        XCTAssertEqual(provider.currentConfig?.computedVersion(), 7)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now)
    }

    // MARK: serverScope

    func testWithAServerScopeOnlyConfigsSignedForThatConfigAPIAreAccepted() async throws {
        let scoped = updater(scope: "default-tls")

        let missing = await apply(signed(payload(4, issuedAt: now)), with: scoped)
        guard case .failed(let reason1, _) = missing else { return XCTFail("\(missing)") }
        XCTAssertTrue(reason1.contains("names no 'configApiId'"), reason1)

        let other = await apply(signed(payload(4, issuedAt: now, scope: "default-mtls")), with: scoped)
        guard case .failed(let reason2, _) = other else { return XCTFail("\(other)") }
        XCTAssertTrue(reason2.contains("signed for Config API 'default-mtls'"), reason2)
        XCTAssertNil(try store.load())

        let right = await apply(signed(payload(4, issuedAt: now, scope: "default-tls")), with: scoped)
        XCTAssertEqual(right, .updated(newVersion: 4))
    }

    func testWithoutAServerScopeTheFieldIsIgnored() async throws {
        let result = await apply(signed(payload(4, issuedAt: now, scope: "whatever")))
        XCTAssertEqual(result, .updated(newVersion: 4))
    }

    func testAStoredEnvelopeSignedForAnotherScopeDoesNotVerifyEither() async throws {
        await apply(signed(payload(4, issuedAt: now, scope: "default-mtls")))
        newProcess()
        offline()
        let result = try await updater(scope: "default-tls").initializeAndUpdate()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("discarded"), reason)
    }

    // MARK: A custom API

    func testACustomAPIsEnvelopeIsVerifiedLikeTheLibrarysOwn() async throws {
        let forged = await apply(signed(payload(4, issuedAt: now), signer: keyB)) // not a trusted key
        guard case .failed(let reason1, _) = forged else { return XCTFail("\(forged)") }
        XCTAssertTrue(reason1.contains("signature verification failed"), reason1)
        XCTAssertNil(try store.load())

        var tampered = signed(payload(4, issuedAt: now))
        tampered.payload = tampered.payload.replacingOccurrences(of: pin2, with: pin3)
        let tamperedResult = await apply(tampered)
        guard case .failed = tamperedResult else { return XCTFail("\(tamperedResult)") }

        let expired = await apply(signed(payload(4, issuedAt: now - 2 * hour, expiresAt: now - hour)))
        guard case .failed(let reason3, _) = expired else { return XCTFail("\(expired)") }
        XCTAssertTrue(reason3.contains("expired"), reason3)
    }

    func testASignedBlockRefusesACustomAPIThatCannotHandOverEnvelopes() async throws {
        let plain = FakeConfigApi()
        plain.returns(CertificateConfig(version: 2, pins: [HostPin(hostname: "api.test", sha256: [pin1, pin2], version: 2)]))
        let result = await updater(configApi: plain).updateNow()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("SignedConfigSource"), reason)
        XCTAssertEqual(plain.fetches, 0)
        XCTAssertNil(try store.load())
    }

    // MARK: One fetch at a time

    func testConcurrentUpdatesShareOneFetch() async throws {
        let updater = updater()
        api.next = signed(payload(4, issuedAt: now))
        let gate = AsyncGate()
        await gate.lock()
        api.gate = gate

        async let first = updater.updateNow()
        async let second = updater.updateNow()
        async let third = updater.updateNow()
        _ = await eventually { self.api.fetches == 1 }
        try await Task.sleep(nanoseconds: 50_000_000)
        gate.unlock()

        let results = await [first, second, third]
        XCTAssertEqual(results, [.updated(newVersion: 4), .updated(newVersion: 4), .updated(newVersion: 4)])
        XCTAssertEqual(api.fetches, 1, "one fetch for all three callers")

        // The next call, with nothing running, fetches again.
        api.gate = nil
        let next = await updater.updateNow()
        XCTAssertEqual(next, .alreadyCurrent)
        XCTAssertEqual(api.fetches, 2)
    }

    // MARK: Expiry does not follow a clock that is set back

    func testSettingTheDeviceClockBackDoesNotReviveAnExpiredConfig() async throws {
        let wall = Locked(now), elapsed = Locked<Int64>(0)
        let store = self.store!
        let clock = TrustedClock(wall: { wall.get() }, elapsed: { elapsed.get() },
                                 load: { try store.highestSeenTime() }, persist: { try store.setHighestSeenTime($0) })
        await apply(signed(payload(4, issuedAt: now, expiresAt: now + hour)), with: updater(trustedClock: clock))

        // Two hours pass (the clock sees it), then the wall clock is set back.
        wall.set(now + 2 * hour)
        elapsed.set(2 * hour)
        clock.checkpoint()
        wall.set(now + 10 * 60_000)

        // A new process over the same store.
        newProcess()
        offline()
        let restarted = TrustedClock(wall: { wall.get() }, elapsed: { 0 },
                                     load: { try store.highestSeenTime() }, persist: { try store.setHighestSeenTime($0) })
        let result = try await updater(trustedClock: restarted).initializeAndUpdate()
        guard case .failed(_, let exception) = result, case .configExpired? = exception as? PinVaultError else {
            return XCTFail("\(result)")
        }
    }

    func testAClockReferenceLeftAheadIsCorrectedByANewerSignedConfigNotByAReplayedOne() async throws {
        let wall = Locked(now)
        let store = self.store!
        let clock = TrustedClock(wall: { wall.get() }, elapsed: { 0 },
                                 load: { try store.highestSeenTime() }, persist: { try store.setHighestSeenTime($0) })
        let updater = updater(trustedClock: clock)
        let first = signed(payload(4, issuedAt: now, expiresAt: now + hour))
        await apply(first, with: updater)

        // The clock was once set a year ahead by mistake, then corrected.
        wall.set(now + 365 * day)
        clock.checkpoint()
        wall.set(now + 10 * 60_000)
        XCTAssertGreaterThan(clock.now(), now + 364 * day)

        // The same config served again proves nothing about the time — and by
        // the trusted clock it has expired, so it is refused as such (C7).
        let again = await apply(first, with: updater)
        guard case .failed(let reason, _) = again else { return XCTFail("\(again)") }
        XCTAssertTrue(reason.contains("already expired"), reason)
        XCTAssertGreaterThan(clock.now(), now + 364 * day)

        // A config newer than every one before does: the reference follows it.
        let newer = await apply(signed(payload(4, issuedAt: now + 5 * 60_000, expiresAt: now + 2 * hour)), with: updater)
        XCTAssertEqual(newer, .alreadyCurrent)
        XCTAssertEqual(clock.now(), wall.get())
        XCTAssertEqual(try store.highestSeenTime(), wall.get())
    }

    // MARK: An app update with new compiled-in keys resets the watermarks (C4)

    func testNewCompiledInSigningKeysEndWhatTheOldKeyPushedUp() async throws {
        // A stolen keyA pushes the host version and issuedAt as far as the checks allow.
        let pushed = await apply(signed(payload(900_000, issuedAt: now + 50 * 60_000)))
        guard case .updated = pushed else { return XCTFail("\(pushed)") }
        let honest = signed(payload(5, issuedAt: now + 60_000), signer: keyB)

        // Still on keyA's anchors the honest config is a replay / downgrade.
        let stillRefused = await apply(signed(payload(5, issuedAt: now + 60_000)))
        guard case .failed = stillRefused else { return XCTFail("\(stillRefused)") }

        // The app update ships keyB instead: the watermarks set under keyA go,
        // and keyA's stored config with them.
        let afterUpdate = updater(trust: trust(keys: [keyB]))
        let accepted = await apply(honest, with: afterUpdate)
        XCTAssertEqual(accepted, .updated(newVersion: 5))
        XCTAssertEqual(try store.getVersionWatermarks()["api.test"], 5)
        XCTAssertEqual(try store.getCurrentIssuedAt(), now + 60_000)

        // Same anchors from now on: no further reset, replays are refused again.
        let replay = await apply(signed(payload(4, issuedAt: now + 30_000), signer: keyB), with: updater(trust: trust(keys: [keyB])))
        guard case .failed = replay else { return XCTFail("\(replay)") }
    }

    func testTheFirstTimeAStoreMeetsTheAnchorsCheckOnlyTheFingerprintIsRecorded() async throws {
        await apply(signed(payload(7, issuedAt: now)))
        try prefs.edit().remove(CertificateConfigStore.keyTrustAnchors).commit() // a store from before the check
        let refused = await apply(signed(payload(6, issuedAt: now + 1)))
        guard case .failed = refused else { return XCTFail("\(refused)") }
        XCTAssertNotNil(try store.trustAnchorsSeen())
        XCTAssertEqual(try store.getVersionWatermarks()["api.test"], 7)
    }

    // MARK: A rollback only undoes what the health check judged (C6)

    func testAFailedHealthCheckDoesNotRollBackANewerConfigAppliedMeanwhile() async throws {
        let u = updater()
        api.next = signed(payload(4, issuedAt: now))
        api.healthy = false
        let api = self.api!
        let newer = signed(payload(5, issuedAt: now + 1))
        let appliedMeanwhile = Locked<UpdateResult?>(nil)
        api.duringHealthCheck = {
            api.duringHealthCheck = nil
            // The worker (or the pin recovery) applies a newer config while the check runs.
            api.next = newer
            appliedMeanwhile.set(await u.updateNow())
        }

        let result = try await u.initializeAndUpdate()
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertEqual(appliedMeanwhile.get(), .updated(newVersion: 5))
        XCTAssertEqual(provider.currentConfig?.pins.first?.version, 5, "the newer config stays live")
        XCTAssertEqual(try store.load()?.pins.first?.version, 5)
    }

    // MARK: "Already expired" by the trusted clock (C7)

    func testAConfigAtTheWatermarkThatExpiredByTheTrustedClockIsNotTakenBackAfterReset() async throws {
        let first = signed(payload(4, issuedAt: now, expiresAt: now + hour))
        let applied = await apply(first)
        XCTAssertEqual(applied, .updated(newVersion: 4))
        try store.clearActive() // PinVault.reset()

        // The device has seen time two hours on; its wall clock now says otherwise.
        let now = self.now, hour = self.hour
        let ahead = TrustedClock(wall: { now }, elapsed: { 0 }, load: { now + 2 * hour })
        let u = updater(trustedClock: ahead)
        let replay = await apply(first, with: u)
        guard case .failed(let reason, _) = replay else { return XCTFail("\(replay)") }
        XCTAssertTrue(reason.contains("already expired"), reason)

        // A config newer than every config before is judged by the wall clock.
        let newer = await apply(signed(payload(5, issuedAt: now + 60_000, expiresAt: now + hour)), with: u)
        XCTAssertEqual(newer, .updated(newVersion: 5))
    }

    func testExpiryNowTakesTheTrustedClockExceptForAConfigNewerThanAllBefore() throws {
        func cfg(_ issuedAt: Int64) -> CertificateConfig { CertificateConfig(pins: [], issuedAt: issuedAt, expiresAt: issuedAt + hour) }
        let now = self.now, hour = self.hour
        let trusted: () throws -> Int64 = { now + 2 * hour }
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: cfg(now), wall: { now }, trustedNow: trusted, issuedAtWatermark: { now }), now + 2 * hour)
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: cfg(now + 1), wall: { now }, trustedNow: trusted, issuedAtWatermark: { now }), now)
        XCTAssertEqual(try SignedConfigVerifier.expiryNow(config: cfg(now), wall: { now }, trustedNow: nil, issuedAtWatermark: { now }), now,
                       "no trusted clock: the wall clock")
    }
}
