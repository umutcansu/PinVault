import Foundation
import XCTest
@testable import PinVault

/// The renewal decision and the renewal round trip, with an in-test CA
/// standing in for the demo server (Kotlin `ClientCertRenewerTest`).
final class ClientCertRenewerTests: XCTestCase {

    private let day: Int64 = 24 * 3600 * 1000
    private var label = ""
    private var key: (any ClientIdentityKeyProvider)!
    private var store: ClientCertSecureStore!
    private var ca: ClientCertTestCA!
    private let now = Int64(Date().timeIntervalSince1970 * 1000)

    private final class Counter: @unchecked Sendable {
        let reloads = Locked(0)
        let refusedOverMtls = Locked<[X509Certificate]>([])
    }

    private let counter = Counter()

    override func setUpWithError() throws {
        label = uniqueLabel("renew")
        key = ClientIdentityKeys.software(label: label)
        try key.ensureKeyPair()
        store = try testCertStore(self)
        ca = ClientCertTestCA(now: date(now))
    }

    override func tearDown() {
        try? key.clear()
    }

    private func date(_ ms: Int64) -> Date { Date(timeIntervalSince1970: Double(ms) / 1000) }

    private func block(
        threshold: Double = 1.0 / 3, renewalUrl: String? = nil, enabled: Bool = true,
        caPins: [String] = [], maxLifetimeDays: Int = ConfigApiBlock.defaultMaxClientCertLifetimeDays
    ) -> ConfigApiBlock {
        ConfigApiBlock(
            id: "blk", configUrl: "https://config.test/", bootstrapPins: [], clientCertLabel: label,
            renewalUrl: renewalUrl, clientCertRenewalThreshold: threshold, clientCertRenewalEnabled: enabled,
            clientCaPins: caPins, maxClientCertLifetimeDays: maxLifetimeDays
        )
    }

    private func leaf(_ spki: Data, _ notBefore: Int64, _ notAfter: Int64, clientId: String = "dev-1", by issuer: ClientCertTestCA? = nil) -> X509Certificate {
        (issuer ?? ca).issue(cn: "PinVault Client: \(clientId)", spki: spki, notBefore: date(notBefore), notAfter: date(notAfter))
    }

    private var keySpki: Data { try! SPKI.der(for: key.publicKey()) }

    private func storeLeaf(_ notBefore: Int64, _ notAfter: Int64) throws {
        try store.saveChain(label, pemChain: [Pkcs10Csr.toPem(leaf(keySpki, notBefore, notAfter)), ca.pem])
    }

    /// A backend that issues over whatever key the CSR carries.
    private func issuing(ttlDays: Int64 = 90) -> ScriptedEnrollmentApi {
        let api = ScriptedEnrollmentApi()
        let (ca, now, day) = (self.ca!, self.now, self.day)
        api.onRenew = { _, csr, _ in
            let spki = try ParsedCsr(csr).spki
            let leaf = ca.issue(spki: spki, notBefore: Date(timeIntervalSince1970: Double(now - 3_600_000) / 1000),
                                notAfter: Date(timeIntervalSince1970: Double(now + ttlDays * day) / 1000))
            return .issued(certificateChainPem: [Pkcs10Csr.toPem(leaf), ca.pem])
        }
        return api
    }

    private func answering(_ answer: @escaping @Sendable (_ csr: Data, _ recoveryUrl: String?) throws -> ClientCertRenewalResponse) -> ScriptedEnrollmentApi {
        let api = ScriptedEnrollmentApi()
        api.onRenew = { _, csr, url in try answer(csr, url) }
        return api
    }

    private func renewer(_ api: ScriptedEnrollmentApi, _ block: ConfigApiBlock? = nil) -> ClientCertRenewer {
        let (key, counter, now) = (self.key!, self.counter, self.now)
        return ClientCertRenewer(
            block: block ?? self.block(), certStore: store, identityKeys: { _ in key }, api: { api },
            reload: { counter.reloads.withLock { $0 += 1 } }, clock: { now },
            onRefusedOverMtls: { leaf in counter.refusedOverMtls.withLock { $0.append(leaf) } }
        )
    }

    private func pemsStored() throws -> [String]? { try store.loadChain(label) }

    // MARK: decide

    func testDecideFreshPastThresholdExpired() {
        let r = renewer(issuing())
        let fresh = leaf(keySpki, now - day, now + 89 * day)
        XCTAssertEqual(r.decide(fresh, nowMs: now, threshold: 1.0 / 3), .none)

        let near = leaf(keySpki, now - 61 * day, now + 29 * day)    // 29/90 < 1/3
        XCTAssertEqual(r.decide(near, nowMs: now, threshold: 1.0 / 3), .renew)
        XCTAssertEqual(r.decide(near, nowMs: now, threshold: 0.25), .none)   // 0.32 > 0.25

        let expired = leaf(keySpki, now - 100 * day, now - 1000)
        XCTAssertEqual(r.decide(expired, nowMs: now, threshold: 1.0 / 3), .recover)
    }

    // MARK: renewIfNeeded

    func testNothingStoredP12StoredOrRenewalDisabledIsNotApplicable() async throws {
        let result = await renewer(issuing()).renewIfNeeded()
        XCTAssertEqual(result, .notApplicable)

        try store.save(label, p12: Data([1, 2, 3]))
        let p12Result = await renewer(issuing()).renewIfNeeded()
        XCTAssertEqual(p12Result, .notApplicable)

        try storeLeaf(now - 80 * day, now + 10 * day)
        let api = issuing()
        let disabled = await renewer(api, block(enabled: false)).renewIfNeeded()
        XCTAssertEqual(disabled, .notApplicable)
        XCTAssertTrue(api.renewCalls.isEmpty)
        // force still works with renewal disabled
        let forced = await renewer(api, block(enabled: false)).renewIfNeeded(force: true)
        guard case .renewed = forced else { return XCTFail("\(forced)") }
    }

    func testAFreshCertificateIsNotNeededWithoutARequest() async throws {
        try storeLeaf(now - day, now + 89 * day)
        let api = issuing()
        let result = await renewer(api).renewIfNeeded()
        guard case .notNeeded(let notAfter) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(Double(notAfter), Double(now + 89 * day), accuracy: 1000)
        XCTAssertTrue(api.renewCalls.isEmpty)
        XCTAssertEqual(counter.reloads.get(), 0)
    }

    func testNearExpiryIsRenewedOverMtlsTheChainReplacedAndTheClientsReloaded() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let api = issuing()
        let result = await renewer(api).renewIfNeeded()
        guard case .renewed(let notAfter, let via) = result else { return XCTFail("\(result)") }

        XCTAssertEqual(via, .mtls)
        XCTAssertEqual(api.renewCalls, [nil])
        XCTAssertEqual(counter.reloads.get(), 1)
        let stored = try Pkcs10Csr.parsePemChain(try XCTUnwrap(pemsStored()))
        XCTAssertEqual(notAfter, ClientCertRenewer.millis(stored[0].notAfter))
        XCTAssertEqual(Double(ClientCertRenewer.millis(stored[0].notAfter)), Double(now + 90 * day), accuracy: 1000)
        XCTAssertEqual(ClientCertRenewer.clientIdOf(stored[0]), "dev-1")
    }

    func testExpiredGoesStraightToTheRecoveryUrl() async throws {
        try storeLeaf(now - 100 * day, now - 1000)
        let api = issuing()
        let result = await renewer(api, block(renewalUrl: "https://recover.test/")).renewIfNeeded()
        guard case .renewed(_, let via) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(via, .recovery)
        XCTAssertEqual(api.renewCalls, ["https://recover.test/"])
    }

    func testTheRecoveryUrlDefaultsToTheBlockUrl() async throws {
        try storeLeaf(now - 100 * day, now - 1000)
        let api = issuing()
        _ = await renewer(api).renewIfNeeded()
        XCTAssertEqual(api.renewCalls, ["https://config.test/"])
    }

    func testAHandshakeRefusedOnMtlsIsRetriedOverRecoveryOnce() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let good = issuing()
        let api = answering { csr, url in
            if url == nil { throw PinVaultError.sslHandshake(message: "Handshake failed", cause: URLError(.clientCertificateRejected)) }
            return try good.onRenew!("dev-1", csr, url)
        }
        let result = await renewer(api).renewIfNeeded()
        guard case .renewed(_, let via) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(via, .recovery)
        XCTAssertEqual(api.renewCalls, [nil, "https://config.test/"])
    }

    func testAPinFailureIsNotAClientCertRefusal() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let api = answering { _, _ in
            throw PinVaultError.sslHandshake(message: "pin", cause: PinVaultError.certificate(message: "Pin mismatch"))
        }
        let result = await renewer(api).renewIfNeeded()
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertEqual(api.renewCalls, [nil])
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(PinVaultError.io(message: "x")))
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslHandshake(message: "refused")))
        // TLS 1.3: the server's alert arrives after the handshake.
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslHandshake(
            message: "SSLV3_ALERT_BAD_CERTIFICATE", cause: URLError(.secureConnectionFailed)
        )))
    }

    func testReenrollRequiredIsSurfacedAndTheStoredChainIsKept() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let api = answering { _, _ in .reenrollRequired(reason: "revoked") }
        let result = await renewer(api).renewIfNeeded()
        XCTAssertEqual(result, .reenrollRequired(reason: "revoked"))
        XCTAssertEqual(try pemsStored(), before)
        XCTAssertEqual(counter.reloads.get(), 0)
    }

    func testOnlyARefusalOverMtlsSpeaksAboutTheIdentityNeverOneFromTheRecoveryDoor() async throws {
        // Over the block's own mTLS connection: the identity was presented.
        try storeLeaf(now - 61 * day, now + 29 * day)
        let refuse = answering { _, _ in .reenrollRequired(reason: "revoked") }
        let overMtls = await renewer(refuse).renewIfNeeded()
        XCTAssertEqual(overMtls, .reenrollRequired(reason: "revoked"))
        XCTAssertEqual(counter.refusedOverMtls.get().count, 1)
        XCTAssertEqual(ClientCertRenewer.clientIdOf(counter.refusedOverMtls.get()[0]), "dev-1", "the leaf that was to be presented")

        // Expired: straight to the recovery door (TLS, no client certificate).
        counter.refusedOverMtls.set([])
        try storeLeaf(now - 100 * day, now - 1000)
        let viaRecovery = await renewer(refuse, block(renewalUrl: "https://recover.test/")).renewIfNeeded()
        XCTAssertEqual(viaRecovery, .reenrollRequired(reason: "revoked"))
        XCTAssertTrue(counter.refusedOverMtls.get().isEmpty, "reported, but nothing about this identity was refused")

        // The mTLS handshake refused, the recovery door answers reenroll_required.
        try storeLeaf(now - 61 * day, now + 29 * day)
        let viaDoor = answering { _, url in
            if url == nil { throw PinVaultError.sslHandshake(message: "Handshake failed") }
            return .reenrollRequired(reason: "revoked")
        }
        let doorResult = await renewer(viaDoor).renewIfNeeded()
        XCTAssertEqual(doorResult, .reenrollRequired(reason: "revoked"))
        XCTAssertTrue(counter.refusedOverMtls.get().isEmpty)
    }

    func testAnIssuedChainOverAnotherKeyIsRefused() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let other = TestKeyPair()
        let (ca, now, day) = (self.ca!, self.now, self.day)
        let api = answering { _, _ in
            .issued(certificateChainPem: [
                Pkcs10Csr.toPem(ca.issue(spki: other.spki, notBefore: Date(timeIntervalSince1970: Double(now) / 1000),
                                         notAfter: Date(timeIntervalSince1970: Double(now + 90 * day) / 1000))),
                ca.pem,
            ])
        }
        let result = await renewer(api).renewIfNeeded()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("device's key"), reason)
        XCTAssertEqual(try pemsStored(), before)
    }

    func testAnExpiredIssuedChainAndAChainThatDoesNotVerifyAreRefused() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let expiredLeaf = Pkcs10Csr.toPem(leaf(keySpki, now - 2 * day, now - day))
        let caPem = ca.pem
        let expired = answering { _, _ in .issued(certificateChainPem: [expiredLeaf, caPem]) }
        let expiredResult = await renewer(expired).renewIfNeeded()
        guard case .failed = expiredResult else { return XCTFail("\(expiredResult)") }

        // Signed by a rogue key under the real CA's name.
        let rogueKey = TestKeyPair()
        let rogueLeaf = Pkcs10Csr.toPem(ca.issue(spki: keySpki, notBefore: date(now), notAfter: date(now + 90 * day), signer: rogueKey))
        let rogue = answering { _, _ in .issued(certificateChainPem: [rogueLeaf, caPem]) }
        let rogueResult = await renewer(rogue).renewIfNeeded()
        guard case .failed = rogueResult else { return XCTFail("\(rogueResult)") }
        XCTAssertEqual(counter.reloads.get(), 0)
    }

    func testAChainFromAnotherCaIsRefusedEvenWhenItShipsItsOwnCa() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let rogueCa = ClientCertTestCA(cn: "Rogue CA", now: date(now))
        let rogueLeaf = Pkcs10Csr.toPem(rogueCa.issue(spki: keySpki, notBefore: date(now), notAfter: date(now + 90 * day)))
        let api = answering { _, _ in .issued(certificateChainPem: [rogueLeaf, rogueCa.pem]) }
        let result = await renewer(api).renewIfNeeded()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("not from the CA"), reason)
        XCTAssertEqual(try pemsStored(), before)
        XCTAssertEqual(counter.reloads.get(), 0)
    }

    func testABackendWithoutRenewalIsNotApplicable() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let result = await renewer(answering { _, _ in .unsupported }).renewIfNeeded()
        XCTAssertEqual(result, .notApplicable)
    }

    func testAChainWithoutItsKeyIsNotApplicable() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        try key.clear()
        let result = await renewer(issuing()).renewIfNeeded()
        XCTAssertEqual(result, .notApplicable)
    }

    // MARK: TLS 1.3: the server's verdict arrives after the handshake

    func testATls13AlertFallsThroughToTheRecoveryUrlOnce() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let good = issuing()
        let api = answering { csr, url in
            if url == nil {
                throw PinVaultError.sslHandshake(
                    message: "An SSL error has occurred (TLSV1_ALERT_CERTIFICATE_REQUIRED)", cause: URLError(.secureConnectionFailed)
                )
            }
            return try good.onRenew!("dev-1", csr, url)
        }
        let result = await renewer(api, block(renewalUrl: "https://recover.test/")).renewIfNeeded()
        guard case .renewed(_, let via) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(via, .recovery)
        XCTAssertEqual(api.renewCalls, [nil, "https://recover.test/"])
    }

    func testWhatCountsAsTheServerRefusingTheClientCertificate() {
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslHandshake(message: "SSLV3_ALERT_BAD_CERTIFICATE", cause: URLError(.clientCertificateRejected))))
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslPeerUnverified(message: "peer not authenticated")))
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(URLError(.clientCertificateRequired)))
        // Our own pin check failing is not: another client certificate would not fix it.
        let pinFailure = PinVaultError.sslHandshake(message: "wrapped", cause: PinVaultError.illegalState("x"))
        XCTAssertTrue(ClientCertRenewer.isClientCertRefusal(pinFailure), "no certificate error in the chain")
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslHandshake(message: "wrapped", cause: PinVaultError.pinMismatch())))
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(PinVaultError.sslHandshake(message: "wrapped", cause: PinVaultError.caTrust(message: "x"))))
        // Other TLS and network failures are plain failures: no second request.
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(PinVaultError.io(message: "Connection reset", cause: URLError(.networkConnectionLost))))
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(PinVaultError.io(message: "timeout", cause: URLError(.timedOut))))
        XCTAssertFalse(ClientCertRenewer.isClientCertRefusal(URLError(.timedOut)))
    }

    func testAProtocolErrorOnTheRecoveryUrlIsAFailureNotALoop() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let api = answering { _, _ in throw PinVaultError.sslHandshake(message: "alert", cause: URLError(.secureConnectionFailed)) }
        let result = await renewer(api).renewIfNeeded()
        guard case .failed = result else { return XCTFail("\(result)") }
        XCTAssertEqual(api.renewCalls.count, 2, "the mTLS attempt, one recovery attempt, nothing more")
    }

    // MARK: A chain must come with its CA

    private func refused(_ body: () throws -> Void) -> String {
        assertSecurityRefusal(nil, body) ?? ""
    }

    func testAChainOfOneIsRefusedAtEnrollmentAndAtRenewal() async throws {
        let single = Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 90 * day))
        let key = self.key!
        XCTAssertTrue(refused { _ = try ClientCertRenewer.acceptIssuedChain([single], key: key) }.contains("CA certificate that signed it"))

        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let result = await renewer(answering { _, _ in .issued(certificateChainPem: [single]) }).renewIfNeeded()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("CA certificate that signed it"), reason)
        XCTAssertEqual(try pemsStored(), before)
    }

    func testAStoredChainOfOneCannotBeRenewedWithoutPinsAndCanWithThem() async throws {
        // What an earlier version accepted: the leaf alone.
        try store.saveChain(label, pemChain: [Pkcs10Csr.toPem(leaf(keySpki, now - 61 * day, now + 29 * day))])
        let api = issuing()

        let unpinned = await renewer(api).renewIfNeeded()
        guard case .failed(let reason, _) = unpinned else { return XCTFail("\(unpinned)") }
        XCTAssertTrue(reason.contains("clientCaPins"), reason)
        XCTAssertTrue(api.renewCalls.isEmpty, "no request: there is nothing to hold the answer to")

        let pinned = await renewer(api, block(caPins: [ca.pin])).renewIfNeeded()
        guard case .renewed = pinned else { return XCTFail("\(pinned)") }
        XCTAssertEqual(try pemsStored()?.count, 2)
    }

    // MARK: clientCaPins

    func testWithPinsTheChainMustBeSignedByAPinnedCaOfTheChain() throws {
        let pins = [ca.pin]
        let key = self.key!
        let good = [Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 90 * day)), ca.pem]
        XCTAssertEqual(try ClientCertRenewer.acceptIssuedChain(good, key: key, caPins: pins).count, 2)

        // A CA of the attacker's own, with the real CA's name: well-formed, valid, over the device's key.
        let rogue = ClientCertTestCA(cn: "PinVault Client CA", now: date(now))
        let rogueChain = [Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 90 * day, by: rogue)), rogue.pem]
        XCTAssertEqual(try ClientCertRenewer.acceptIssuedChain(rogueChain, key: key).count, 2, "without pins a first enrollment takes it")
        XCTAssertTrue(refused { _ = try ClientCertRenewer.acceptIssuedChain(rogueChain, key: key, caPins: pins) }.contains("pinned client CA"))

        // The pinned CA merely attached to a chain it did not sign is not enough.
        let padded = rogueChain + [ca.pem]
        XCTAssertTrue(refused { _ = try ClientCertRenewer.acceptIssuedChain(padded, key: key, caPins: pins) }.contains("pinned client CA"))
    }

    func testWithPinsARenewalFromAHolderOfTheListenerKeyWithItsOwnCaIsRefused() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let rogue = ClientCertTestCA(cn: "Rogue CA", now: date(now))
        let rogueChain = [Pkcs10Csr.toPem(leaf(keySpki, now, now + 90 * day, by: rogue)), rogue.pem]
        let result = await renewer(answering { _, _ in .issued(certificateChainPem: rogueChain) }, block(caPins: [ca.pin])).renewIfNeeded()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("pinned client CA"), reason)
        XCTAssertEqual(try pemsStored(), before)
        XCTAssertEqual(counter.reloads.get(), 0)
    }

    func testWithPinsTheClientCaCanBeReplacedByAnotherPinnedOne() async throws {
        try storeLeaf(now - 61 * day, now + 29 * day)
        let next = ClientCertTestCA(cn: "PinVault Client CA 2", now: date(now))
        let nextChain = [Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 90 * day, by: next)), next.pem]
        let api = answering { _, _ in .issued(certificateChainPem: nextChain) }
        // Without pins the previous issuer rules: a new CA is refused.
        let unpinned = await renewer(api).renewIfNeeded()
        guard case .failed = unpinned else { return XCTFail("\(unpinned)") }
        // Both CAs pinned: the rotation goes through.
        let pinned = await renewer(api, block(caPins: [ca.pin, next.pin])).renewIfNeeded()
        guard case .renewed = pinned else { return XCTFail("\(pinned)") }
    }

    func testClientCaPinsTakesHostPinSyntaxAndRefusesAnythingThatIsNotASha256Hash() throws {
        let pin = ca.pin
        let built = try PinVaultConfig.Builder()
            .configApi("api", url: "https://config.test/") { block in
                block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin, pin])])
                block.allowUnsigned()
                block.clientCaPins("sha256/\(pin)", " \(pin) ")
            }
            .build().configApis["api"]!
        XCTAssertEqual(built.clientCaPins, [pin])
        XCTAssertEqual(built.maxClientCertLifetimeDays, 825)
        XCTAssertFalse(built.allowServerGeneratedKey)

        for bad in ["", "not-a-pin", "AAAA", String(pin.dropLast(4))] {
            XCTAssertThrowsError(
                try PinVaultConfig.Builder().configApi("api", url: "https://config.test/") { block in
                    block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin, pin])])
                    block.clientCaPins(bad)
                }.build(),
                "'\(bad)' should have been refused"
            )
        }
    }

    // MARK: maxClientCertLifetimeDays

    func testACertificateValidForDecadesIsRefusedAtEnrollmentAndAtRenewal() async throws {
        let key = self.key!
        let fiftyYears = [Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 50 * 365 * day)), ca.pem]
        XCTAssertTrue(refused { _ = try ClientCertRenewer.acceptIssuedChain(fiftyYears, key: key) }.contains("825 days"))
        // The default cap leaves room for the day issuers backdate notBefore by.
        let atTheCap = [Pkcs10Csr.toPem(leaf(keySpki, now - day, now + 825 * day)), ca.pem]
        XCTAssertEqual(try ClientCertRenewer.acceptIssuedChain(atTheCap, key: key).count, 2)
        // A block may set its own.
        let ninety = [Pkcs10Csr.toPem(leaf(keySpki, now - 3_600_000, now + 90 * day)), ca.pem]
        XCTAssertTrue(refused { _ = try ClientCertRenewer.acceptIssuedChain(ninety, key: key, maxLifetimeDays: 30) }.contains("30 days"))

        try storeLeaf(now - 61 * day, now + 29 * day)
        let before = try pemsStored()
        let result = await renewer(issuing(ttlDays: 50 * 365)).renewIfNeeded()
        guard case .failed(let reason, _) = result else { return XCTFail("\(result)") }
        XCTAssertTrue(reason.contains("825 days"), reason)
        XCTAssertEqual(try pemsStored(), before)
    }

    func testAStoredCertificateThatOutlivesTheCapIsRenewedAtTheNextCheck() async throws {
        // Stored before the cap existed: by its own dates renewal would not come due for decades.
        let r = renewer(issuing())
        let longLived = leaf(keySpki, now - day, now + 50 * 365 * day)
        XCTAssertEqual(r.decide(longLived, nowMs: now, threshold: 1.0 / 3), .renew)

        try store.saveChain(label, pemChain: [Pkcs10Csr.toPem(longLived), ca.pem])
        let result = await r.renewIfNeeded()
        guard case .renewed(let notAfter, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(Double(notAfter), Double(now + 90 * day), accuracy: 1000)
    }
}
