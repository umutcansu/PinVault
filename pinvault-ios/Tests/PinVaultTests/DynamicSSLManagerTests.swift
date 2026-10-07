import XCTest
@testable import PinVault

/// The composite client identity (which host sees which certificate) and the
/// keystore lifecycle (Kotlin `DynamicSSLManagerTest`).
final class DynamicSSLManagerTests: XCTestCase {

    private let password = "changeit"
    private var manager = testManager()

    override func setUp() {
        manager = testManager()
    }

    private func cn(_ selected: DynamicSSLManager.SelectedClientIdentity?) -> String? {
        selected?.identity.leaf?.subject.commonName
    }

    private func identityFor(_ host: String, _ port: Int, _ config: CertificateConfig? = nil) -> String? {
        cn(manager.buildCompositeKeyManagers(configProvider: { config })?.select(host: host, port: port))
    }

    func testLoadClientKeystoreLoadsTheDefaultCert() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        XCTAssertTrue(manager.hasClientKeystore())
        XCTAssertEqual(manager.defaultClientCertificate()?.subject.commonName, "client-a")
    }

    func testLoadHostClientCertsLoadsSeveralHosts() {
        manager.loadHostClientCerts(["host-a.com": TLSFixture.p12("client-a"), "host-b.com": TLSFixture.p12("client-b")], password: password)
        XCTAssertTrue(manager.hasClientKeystore())
        XCTAssertEqual(identityFor("host-a.com", 443), "client-a")
        XCTAssertEqual(identityFor("host-b.com", 443), "client-b")
    }

    func testBuildClientWithANilConfigIsFailClosedNotSystemTrust() {
        let error = assertThrowsPinVault {
            try manager.checkServerTrusted([TLSFixture.cert("selfsigned")], hostname: "localhost", port: 443, config: nil)
        }
        XCTAssertTrue(error?.message.contains("No pins configured") == true)
        let empty = assertThrowsPinVault {
            try manager.checkServerTrusted([TLSFixture.cert("selfsigned")], hostname: "localhost", port: 443, config: CertificateConfig(pins: []))
        }
        XCTAssertTrue(empty?.message.contains("No pins configured") == true, "a config without pins pins nothing")
        let none = assertThrowsPinVault {
            try manager.checkServerTrusted([], hostname: "localhost", port: 443, config: pinConfig("localhost", [pin("A")]))
        }
        XCTAssertEqual(none?.message, "No server certificate provided")
    }

    func testInvalidP12BytesAreSkippedGracefully() {
        manager.loadHostClientCerts(["valid.host": TLSFixture.p12("client-a"), "invalid.host": Data([1, 2, 3])], password: password)
        XCTAssertEqual(identityFor("valid.host", 443), "client-a")
        XCTAssertNil(identityFor("invalid.host", 443))
    }

    func testHostCertAndDefaultCertMakeOneComposite() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.loadHostClientCerts(["specific.host": TLSFixture.p12("client-b")], password: password)
        let config = pinConfig("server.test", [pin("A")], mtls: true)
        XCTAssertEqual(identityFor("specific.host", 443, config), "client-b")
        XCTAssertEqual(identityFor("server.test", 443, config), "client-a")
    }

    // MARK: clearClientKeystore — unenroll must drop live key material

    func testClearClientKeystoreDropsTheDefaultCert() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        XCTAssertTrue(manager.hasClientKeystore())
        XCTAssertNotNil(manager.buildCompositeKeyManagers())
        manager.clearClientKeystore()
        XCTAssertFalse(manager.hasClientKeystore())
        XCTAssertNil(manager.buildCompositeKeyManagers())
        XCTAssertNil(manager.defaultClientCertificate())
    }

    func testClearClientKeystoreDropsHostCertsToo() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.loadHostClientCerts(["specific.host": TLSFixture.p12("client-b")], password: password)
        manager.clearClientKeystore()
        XCTAssertFalse(manager.hasClientKeystore())
        XCTAssertNil(manager.buildCompositeKeyManagers())
    }

    func testClearClientKeystoreWithoutHostCertsKeepsThem() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.loadHostClientCerts(["specific.host": TLSFixture.p12("client-b")], password: password)
        manager.clearClientKeystore(includeHostCerts: false)
        XCTAssertTrue(manager.hasClientKeystore())
        XCTAssertNotNil(manager.buildCompositeKeyManagers(), "falls back to the surviving host identities")
        XCTAssertEqual(identityFor("specific.host", 443), "client-b")
    }

    func testPinningSurvivesAnUnenroll() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.clearClientKeystore()
        try manager.checkServerTrusted(
            [TLSFixture.cert("selfsigned")], hostname: "localhost", port: 443,
            config: pinConfig("localhost", [TLSFixture.pin("selfsigned")])
        )
    }

    func testIdentityChangesMoveTheSessionGeneration() throws {
        var last = manager.sessionGeneration
        func moved() -> Bool {
            let now = manager.sessionGeneration
            defer { last = now }
            return now != last
        }
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        XCTAssertTrue(moved())
        manager.loadClientKey(TLSFixture.identity("client-b"))
        XCTAssertTrue(moved())
        manager.loadHostClientCerts([:], password: password)
        XCTAssertTrue(moved())
        manager.setIdentityHosts(["https://config.test/"])
        XCTAssertTrue(moved())
        manager.clearClientKeystore()
        XCTAssertTrue(moved())
        manager.onPinsChanged()
        XCTAssertTrue(moved())
        XCTAssertFalse(moved())
    }

    // MARK: CSR flow: a key that stays in the Keychain

    func testLoadClientKeyBecomesTheDefaultIdentity() {
        let identity = TLSFixture.identity("client-a")
        manager.loadClientKey(identity)
        XCTAssertTrue(manager.hasClientKeystore())
        manager.setIdentityHosts(["https://config.test:8092/"])
        let selected = manager.buildCompositeKeyManagers()?.select(host: "config.test", port: 8092)
        XCTAssertEqual(selected?.owner, .defaultIdentity, "offered to the block's own listener; the owner is named")
        XCTAssertTrue(selected?.identity === identity)
        XCTAssertEqual(manager.defaultClientCertificate(), identity.leaf)
        // The credential: the identity plus its intermediates.
        let credential = identity.credential()
        XCTAssertNotNil(credential.identity)
        XCTAssertEqual(credential.certificates.count, identity.chain.count - 1)
        XCTAssertEqual(credential.persistence, .forSession)
    }

    func testLoadClientKeyReplacesAP12IdentityAndIsDroppedByClear() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.loadClientKey(TLSFixture.identity("client-b"))
        XCTAssertEqual(manager.defaultClientCertificate()?.subject.commonName, "client-b")
        manager.clearClientKeystore()
        XCTAssertNil(manager.defaultClientCertificate())
        XCTAssertFalse(manager.hasClientKeystore())
    }

    func testHostSpecificCertsStillWinOverTheDefaultIdentity() {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.loadHostClientCerts(["specific.host": TLSFixture.p12("client-b")], password: password)
        manager.setIdentityHosts(["https://specific.host/"])
        let selected = manager.buildCompositeKeyManagers()?.select(host: "specific.host", port: 443)
        XCTAssertEqual(selected?.owner, .host("specific.host"))
        XCTAssertEqual(cn(selected), "client-b")
    }

    func testAnEmptyChainIsRefused() {
        let identity = TLSFixture.identity("client-a")
        XCTAssertThrowsError(try ClientIdentity(identity: identity.identity, chain: []))
    }

    // MARK: Who gets to see the client identity

    func testTheDefaultIdentityIsOfferedToTheBlocksOwnListenersOnly() {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts(["https://config.test:8092/", "https://config.test:8093/", nil, "not a url", "ftp://config.test/"])
        XCTAssertEqual(identityFor("config.test", 8092), "client-a")
        XCTAssertEqual(identityFor("CONFIG.test", 8093), "client-a")
        // Another port of the same host, and any other host that asks: nothing.
        XCTAssertNil(identityFor("config.test", 8444))
        XCTAssertNil(identityFor("analytics.test", 443))
        XCTAssertNil(identityFor("config.test", 21))
    }

    func testDefaultPortsAndIPv6ListenersAreNamedToo() {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts(["https://config.test/", "https://[::1]:9443/"])
        XCTAssertEqual(identityFor("config.test", 443), "client-a")
        XCTAssertEqual(identityFor("::1", 9443), "client-a")
    }

    func testAPinnedHostGetsTheDefaultIdentityOnlyWhenItsPinEntrySaysMtls() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        let pins = [pin("A"), pin("B")]
        let config = CertificateConfig(version: 1, pins: [
            HostPin(hostname: "mtls.test", sha256: pins, mtls: true),
            HostPin(hostname: "*.mtls.example.com", sha256: pins, mtls: true),
            HostPin(hostname: "door.test:9443", sha256: pins, mtls: true),
            HostPin(hostname: "plain.test", sha256: pins),
        ])
        XCTAssertEqual(identityFor("mtls.test", 443, config), "client-a")
        XCTAssertEqual(identityFor("a.mtls.example.com", 443, config), "client-a")
        XCTAssertEqual(identityFor("door.test", 9443, config), "client-a")
        XCTAssertNil(identityFor("door.test", 443, config), "the entry names one port")
        XCTAssertNil(identityFor("plain.test", 443, config), "pinned, but not an mTLS host")
        XCTAssertNil(identityFor("unknown.test", 443, config), "no pin entry at all")
    }

    func testAnUnknownPeerHostGetsNoClientCertificate() {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        manager.setIdentityHosts(["https://config.test/"])
        let selector = manager.buildCompositeKeyManagers()!
        XCTAssertNil(selector.select(host: nil, port: 443))
        XCTAssertNil(selector.select(host: "", port: 443))
        XCTAssertNil(selector.select(host: "config.test", port: nil), "no port, no listener match")
    }

    func testTwoStoresDoNotGetMixedUp() throws {
        try manager.loadClientKeystore(TLSFixture.p12("client-a"), password: password)
        manager.loadHostClientCerts(["b.host": TLSFixture.p12("client-b")], password: password)
        manager.setIdentityHosts(["https://config.test/"])
        XCTAssertEqual(identityFor("config.test", 443), "client-a")
        XCTAssertEqual(identityFor("b.host", 443), "client-b")
    }

    func testHostEntriesFollowThePinPrecedence() {
        manager.loadHostClientCerts([
            "*.example.com": TLSFixture.p12("client-a"),
            "api.example.com:9443": TLSFixture.p12("client-b"),
        ], password: password)
        XCTAssertEqual(identityFor("api.example.com", 9443), "client-b", "host:port first")
        XCTAssertEqual(identityFor("api.example.com", 443), "client-a", "then the wildcard")
        XCTAssertNil(identityFor("a.b.example.com", 443))
    }

    func testWithClientCertHostsListedAnMtlsPinEntryAddsNoHost() {
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let pins = [pin("A"), pin("B")]
        let config = CertificateConfig(version: 1, pins: [
            HostPin(hostname: "listed.test:9443", sha256: pins, mtls: true),
            HostPin(hostname: "named-by-signer.test", sha256: pins, mtls: true),
        ])
        // The block's own URL plus the app's clientCertHosts: the whole list.
        manager.setIdentityHosts(["https://config.test:8092/", "https://listed.test:9443/"], onlyThese: true)
        XCTAssertEqual(identityFor("config.test", 8092, config), "client-a")
        XCTAssertEqual(identityFor("listed.test", 9443, config), "client-a")
        XCTAssertNil(identityFor("named-by-signer.test", 443, config), "the signed config cannot add a host the app did not list")

        // Without such a list, mtls = true entries still name hosts, as before.
        manager.setIdentityHosts(["https://config.test:8092/"])
        XCTAssertEqual(identityFor("named-by-signer.test", 443, config), "client-a")
    }

    func testP12IdentitiesCarryTheirIssuingChain() {
        let identity = TLSFixture.identity("client-a")
        XCTAssertEqual(identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(identity.chain.count, 2, "leaf + client CA")
        XCTAssertEqual(try X509Certificate(certificate: identity.chain[1]).subject.commonName, "Client CA")
    }
}
