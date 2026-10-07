import XCTest
@testable import PinVault

/// Managed trust roots: a host with no pin entry is accepted only when the
/// platform validates its chain to a root the signed config lists — and only
/// when the app turned the feature on. Hosts with a pin entry are untouched
/// (Kotlin `ManagedTrustRootsTest`). The "platform" here is `SecTrust` with
/// the test root as its only anchor.
final class ManagedTrustRootsTests: XCTestCase {

    private let pinnedHost = "api.pinned.test"
    private let unpinnedHost = "cdn.unpinned.test"
    private let root = TLSFixture.cert("managed-root")
    private let otherRoot = TLSFixture.cert("other-root")
    private let leaf = TLSFixture.cert("managed-leaf")
    private let leafForOtherName = TLSFixture.cert("managed-elsewhere")

    /// A platform that trusts `root` and appends it as the anchor (host names not checked, like the Kotlin fake).
    private var platformTrustingRoot: any TrustAnchorResolver {
        let anchors = SecTrustCaCheck(anchors: [root.der])
        return ClosureAnchorResolver { chain, _ in
            try anchors.validatedChain(chain, host: "", at: TLSFixture.validNow)
        }
    }

    private func config(_ trustRoots: [String]) -> CertificateConfig {
        CertificateConfig(
            version: 1,
            pins: [HostPin(hostname: pinnedHost, sha256: [pin("A"), pin("B")])],
            trustRoots: trustRoots
        )
    }

    private func manager(enabled: Bool, resolver: (any TrustAnchorResolver)? = nil) -> DynamicSSLManager {
        let manager = testManager()
        manager.managedTrustRootsEnabled = enabled
        manager.anchorResolver = resolver ?? platformTrustingRoot
        return manager
    }

    private func check(_ manager: DynamicSSLManager, _ config: CertificateConfig, _ chain: [X509Certificate], host: String? = nil) throws {
        try manager.checkServerTrusted(chain, hostname: host ?? unpinnedHost, port: 443, config: config)
    }

    func testAnUnpinnedHostValidatingToAListedRootIsAcceptedAndTheRootPinIsWhatMatched() async throws {
        let events = EventRecorder()
        let manager = manager(enabled: true)
        manager.setConnectionListener(events.listener)
        let config = config([root.spkiPin])
        try check(manager, config, [leaf])
        XCTAssertEqual(try manager.matchPins(config, [leaf], hostname: unpinnedHost, port: 443), root.spkiPin)
        let delivered = await eventually { events.connections.count == 1 }
        XCTAssertTrue(delivered)
        guard case .connection(let host, let success, _, _, _, let actual, let expected)? = events.all.first else {
            return XCTFail("no connection event")
        }
        XCTAssertEqual(host, unpinnedHost)
        XCTAssertTrue(success)
        XCTAssertEqual(actual, leaf.spkiPin)
        XCTAssertEqual(expected, [root.spkiPin], "the event names the listed roots")
    }

    func testTheRealPlatformCheckAcceptsItTooWithTheHostName() throws {
        let manager = manager(enabled: true, resolver: SecTrustCaCheck(anchors: [root.der]))
        try check(manager, config([root.spkiPin]), [leaf])
    }

    func testOffByDefaultAnUnpinnedHostIsRefusedAsBefore() {
        let error = assertThrowsPinVault { try check(manager(enabled: false), config([root.spkiPin]), [leaf]) }
        guard case .unpinnedHost(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("No pin entry"), message)
        XCTAssertTrue(message.contains("Configured hosts: \(pinnedHost)"), message)
    }

    func testAConfigWithoutTrustRootsRefusesAnUnpinnedHostEvenWithTheFeatureOn() {
        let error = assertThrowsPinVault { try check(manager(enabled: true), config([]), [leaf]) }
        guard case .unpinnedHost? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAChainValidatingToARootTheConfigDoesNotListIsRefused() {
        let error = assertThrowsPinVault { try check(manager(enabled: true), config([otherRoot.spkiPin]), [leaf]) }
        guard case .managedTrustRoot(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("does not list"), message)
    }

    func testAChainThePlatformDoesNotTrustIsRefusedWhateverTheListSays() {
        let untrusting = ClosureAnchorResolver { _, _ in throw PinVaultError.certificate(message: "unknown CA") }
        var error = assertThrowsPinVault { try check(manager(enabled: true, resolver: untrusting), config([root.spkiPin]), [leaf]) }
        guard case .managedTrustRoot(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains("does not trust"), message)

        // The real check with anchors that do not include the root.
        let other = SecTrustCaCheck(anchors: [otherRoot.der])
        error = assertThrowsPinVault { try check(manager(enabled: true, resolver: other), config([root.spkiPin]), [leaf]) }
        guard case .managedTrustRoot? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testTheLeafMustBeIssuedForTheHost() {
        var error = assertThrowsPinVault { try check(manager(enabled: true), config([root.spkiPin]), [leafForOtherName]) }
        guard case .hostnameMismatch(let message, _)? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(message.contains(unpinnedHost), message)

        // The platform's own SSL policy refuses the name before that.
        let real = SecTrustCaCheck(anchors: [root.der])
        error = assertThrowsPinVault { try check(manager(enabled: true, resolver: real), config([root.spkiPin]), [leafForOtherName]) }
        guard case .managedTrustRoot? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAHostWithAPinEntryIsJudgedByItsPinsNotByTheRoots() {
        // The leaf chains to a listed root, but the pinned host's pins do not name it.
        let pinnedLeaf = TLSFixture.cert("pinned-under-managed")
        let error = assertThrowsPinVault {
            try check(manager(enabled: true), config([root.spkiPin]), [pinnedLeaf], host: pinnedHost)
        }
        guard case .certificate(let message, _)? = error else {
            return XCTFail("a pinned host must match a pin, the roots must not be consulted: \(String(describing: error))")
        }
        XCTAssertTrue(message.contains("pinning failure"), message)
    }

    func testTheValidatorChecksTheRootsLikePins() throws {
        try PinConfigValidator.validate(CertificateConfig(
            version: 1,
            pins: [HostPin(hostname: pinnedHost, sha256: [pin("A"), pin("B")])],
            trustRoots: [root.spkiPin, otherRoot.spkiPin]
        ))
        assertInvalidPinFormat("Trust root at index 0") { try PinConfigValidator.validate(self.config(["not-a-pin"])) }
        assertInvalidPinFormat("more than once") { try PinConfigValidator.validate(self.config([self.root.spkiPin, self.root.spkiPin])) }
        let tooMany = (0...PinConfigValidator.maxTrustRoots).map { Hashing.sha256Base64(Data("\($0)".utf8)) }
        assertInvalidPinFormat("at most") { try PinConfigValidator.validate(self.config(tooMany)) }
    }

    func testMatchRefusesAnEmptyChainOrList() {
        let resolver = platformTrustingRoot
        XCTAssertThrowsError(try ManagedTrustRoots.match([], hostname: unpinnedHost, trustRoots: [root.spkiPin], resolver: resolver, now: TLSFixture.validNow))
        let error = assertThrowsPinVault {
            _ = try ManagedTrustRoots.match([leaf], hostname: unpinnedHost, trustRoots: [], resolver: resolver, now: TLSFixture.validNow)
        }
        XCTAssertEqual(error?.message, "The config lists no managed trust roots")
    }
}
