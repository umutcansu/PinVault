import Security
import XCTest
@testable import PinVault

/// A private key that reaches the device in a PKCS12 — a host's client
/// certificate, a server-made enrollment — ends up as a Keychain key with only
/// its certificate chain in storage, and is presented from there (Kotlin
/// `ImportedIdentitiesTest`).
///
/// ``InMemoryImportedClientKeys`` stands in for the Keychain here; the Keychain
/// import itself and the handshake with an imported key are in
/// `IdentityKeychainTests` (hosted simulator suite). The host-certificate
/// cases of the Kotlin test go through `SSLCertificateUpdater` (L2).
final class ImportedIdentitiesTests: XCTestCase {

    private let password = "changeit"
    private var keys: InMemoryImportedClientKeys!
    private var store: ClientCertSecureStore!
    private var identities: ImportedIdentities!

    override func setUpWithError() throws {
        keys = InMemoryImportedClientKeys()
        store = try testCertStore(self)
        identities = ImportedIdentities(certStore: store, keys: keys)
    }

    private func leaf(_ p12: Data) throws -> X509Certificate {
        try XCTUnwrap(ClientIdentity.fromPKCS12(p12, password: password).leaf)
    }

    // MARK: Import

    func testAnRsaP12BecomesAKeychainKeyAndAStoredChainAndTheP12BytesAreNotKept() throws {
        let identity = try XCTUnwrap(identities.import(label: "default", p12: rsaTestP12, password: password))

        XCTAssertEqual(identity.leaf?.der, try leaf(rsaTestP12).der)
        XCTAssertNotNil(keys.privateKey(alias: ImportedKeys.aliasFor("default")))
        XCTAssertEqual(try store.mode("default"), .imported)
        XCTAssertTrue(try store.exists("default"))
        XCTAssertFalse(try store.hasP12("default"), "no P12 in storage")
        XCTAssertNil(try store.load("default"))
        XCTAssertNil(try store.loadChain("default"), "not a CSR identity: nothing to renew")
        XCTAssertEqual(try store.loadImported("default")?.count, 1)
    }

    func testAnEcP12IsImportedTheSameWayWithItsChain() throws {
        let p12 = TLSFixture.p12("client-a")
        let identity = try XCTUnwrap(identities.import(label: "host_ec.example.com", p12: p12, password: password))
        XCTAssertEqual(KeyInspector.algorithm(try XCTUnwrap(keys.privateKey(alias: ImportedKeys.aliasFor("host_ec.example.com")))), "EC")
        XCTAssertEqual(identity.leaf?.subject.commonName, "client-a")
        XCTAssertEqual(try store.mode("host_ec.example.com"), .imported)
    }

    func testTheImportedIdentityIsLoadedAgainFromTheChainAndTheKeychainKey() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)
        let loaded = try XCTUnwrap(ImportedIdentities(certStore: store, keys: keys).load(label: "default"))
        XCTAssertEqual(loaded.leaf?.der, try leaf(rsaTestP12).der)
    }

    func testAWrongPasswordOrAP12WithoutAKeyIsAnErrorAndNothingIsStored() throws {
        XCTAssertThrowsError(try identities.import(label: "default", p12: rsaTestP12, password: "wrong"))
        XCTAssertThrowsError(try identities.import(label: "default", p12: Data([1, 2, 3]), password: password))
        XCTAssertEqual(try store.mode("default"), .none)
        XCTAssertNil(keys.privateKey(alias: ImportedKeys.aliasFor("default")))
    }

    // MARK: A P12 kept where the import was refused

    func testAStoredP12IsMovedIntoTheKeychainTheFirstTimeItIsLoaded() throws {
        try store.save("default", p12: rsaTestP12)
        XCTAssertEqual(try store.mode("default"), .p12)

        let identity = try XCTUnwrap(identities.loadOrMigrate(label: "default", password: password))

        XCTAssertEqual(identity.leaf?.der, try leaf(rsaTestP12).der)
        XCTAssertEqual(try store.mode("default"), .imported)
        XCTAssertFalse(try store.hasP12("default"), "the P12 is gone from storage")
        // The next load finds the imported form and imports nothing again.
        keys.refuse(ImportedKeys.aliasFor("default"))
        XCTAssertNotNil(identities.loadOrMigrate(label: "default", password: password))
    }

    func testWhereThePlatformRefusesTheImportTheP12StaysAsItWas() throws {
        keys.refuse(ImportedKeys.aliasFor("default"))

        XCTAssertNil(try identities.import(label: "default", p12: rsaTestP12, password: password))
        XCTAssertEqual(try store.mode("default"), .none, "nothing stored by a refused import")

        try store.save("default", p12: rsaTestP12)
        XCTAssertNil(identities.loadOrMigrate(label: "default", password: password))
        XCTAssertEqual(try store.mode("default"), .p12, "the old storage is kept for this key")
        XCTAssertEqual(try store.load("default"), rsaTestP12)
    }

    func testAStoredP12ThatCannotBeReadIsLeftAlone() throws {
        try store.save("default", p12: Data([9, 9, 9]))
        XCTAssertNil(identities.loadOrMigrate(label: "default", password: password))
        XCTAssertEqual(try store.mode("default"), .p12)
    }

    func testAChainWhoseKeychainKeyIsGoneIsDropped() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)
        keys.delete(alias: ImportedKeys.aliasFor("default"))   // a restored backup, a reset Keychain

        XCTAssertNil(identities.load(label: "default"))
        XCTAssertEqual(try store.mode("default"), .none)
    }

    func testAKeychainThatCannotBeReadRightNowDoesNotCostTheDeviceItsCertificate() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)

        keys.unreadable = true
        XCTAssertNil(identities.load(label: "default"), "nothing to present for now")
        XCTAssertNil(identities.loadOrMigrate(label: "default", password: password))
        XCTAssertEqual(try store.mode("default"), .imported, "but the chain stays")

        keys.unreadable = false
        XCTAssertNotNil(identities.load(label: "default"))
    }

    func testAnUnreadableChainIsDroppedWithItsKey() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)
        try store.saveImported("default", pemChain: ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"])
        XCTAssertNil(identities.load(label: "default"))
        XCTAssertEqual(try store.mode("default"), .none)
        XCTAssertNil(keys.privateKey(alias: ImportedKeys.aliasFor("default")))
    }

    func testForgetRemovesTheChainAndTheKey() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)
        identities.forget(label: "default")
        XCTAssertEqual(try store.mode("default"), .none)
        XCTAssertNil(keys.privateKey(alias: ImportedKeys.aliasFor("default")))
    }

    func testSavingAnotherFormReplacesTheImportedOne() throws {
        _ = try identities.import(label: "default", p12: rsaTestP12, password: password)
        try store.saveChain("default", pemChain: ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"])
        XCTAssertEqual(try store.mode("default"), .chain)
        XCTAssertFalse(try store.hasImported("default"))
    }

    // MARK: The identity loader

    func testTheLoaderPresentsAnImportedIdentityAndFallsBackToTheBundledKeystore() throws {
        let manager = testManager()
        let block = ConfigApiBlock(
            id: "blk", configUrl: "https://config.test/", bootstrapPins: [],
            clientKeystoreBytes: TLSFixture.p12("client-b"), clientKeyPassword: password, clientCertLabel: "default"
        )
        let loader = ClientIdentityLoader(block: block, certStore: store, sslManager: manager, identityKeys: { ClientIdentityKeys.software(label: $0) }, importedKeys: keys)

        // Nothing enrolled: the keystore bundled with the app, imported under its own alias.
        loader.load()
        XCTAssertEqual(manager.defaultClientCertificate()?.subject.commonName, "client-b")
        XCTAssertNotNil(keys.privateKey(alias: ImportedKeys.aliasFor("bundled_blk")))
        XCTAssertEqual(try store.mode("default"), .none, "the bundled keystore is not an enrollment")

        // An imported enrollment wins over it.
        _ = try identities.import(label: "default", p12: TLSFixture.p12("client-a"), password: password)
        loader.load()
        XCTAssertEqual(manager.defaultClientCertificate()?.subject.commonName, "client-a")

        // A P12 the Keychain refused is loaded as it is.
        try store.save("default", p12: rsaTestP12)
        keys.refuse(ImportedKeys.aliasFor("default"))
        loader.load()
        XCTAssertEqual(manager.defaultClientCertificate()?.subject.commonName, "pinvault-device-test-rsa")
    }

    func testWithoutAnythingStoredOrBundledNoIdentityIsPresented() throws {
        let manager = testManager()
        manager.loadClientKey(TLSFixture.identity("client-a"))
        let block = ConfigApiBlock(id: "blk", configUrl: "https://config.test/", bootstrapPins: [], clientCertLabel: "default")
        ClientIdentityLoader(block: block, certStore: store, sslManager: manager, identityKeys: { ClientIdentityKeys.software(label: $0) }, importedKeys: keys).load()
        XCTAssertNil(manager.defaultClientCertificate())
    }
}
