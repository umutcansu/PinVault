import XCTest
@testable import PinVault

/// P12, imported and certificate-chain credentials side by side, one form per
/// label (Kotlin `store/ClientCertSecureStoreTest`), and the multi-label CRUD
/// of the instrumented test (`androidTest/…/ClientCertSecureStoreTest`) over a
/// real ``SecurePreferences`` file (in-memory store keys here; the Keychain
/// keys in `IdentityKeychainTests`).
final class ClientCertSecureStoreTests: XCTestCase {

    private var store: ClientCertSecureStore!

    private let pemA = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
    private let pemB = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"

    override func setUpWithError() throws {
        store = try testCertStore(self)
    }

    func testAnEmptyStoreHasNoCredentials() throws {
        XCTAssertEqual(try store.mode("default"), .none)
        XCTAssertFalse(try store.exists("default"))
        XCTAssertNil(try store.load("default"))
        XCTAssertNil(try store.loadChain("default"))
    }

    func testP12RoundTripsAndReportsP12Mode() throws {
        try store.save("default", p12: Data([1, 2, 3]))
        XCTAssertEqual(try store.mode("default"), .p12)
        XCTAssertTrue(try store.exists("default"))
        XCTAssertTrue(try store.hasP12("default"))
        XCTAssertFalse(try store.hasChain("default"))
        XCTAssertEqual(try store.load("default"), Data([1, 2, 3]))
    }

    func testAChainRoundTripsInOrderAndReportsChainMode() throws {
        try store.saveChain("default", pemChain: [pemA, pemB])
        XCTAssertEqual(try store.mode("default"), .chain)
        XCTAssertTrue(try store.exists("default"))
        XCTAssertEqual(try store.loadChain("default"), [pemA, pemB])
        XCTAssertNil(try store.load("default"))
    }

    func testSavingAChainReplacesAP12AndViceVersa() throws {
        try store.save("default", p12: Data([9]))
        try store.saveChain("default", pemChain: [pemA])
        XCTAssertFalse(try store.hasP12("default"))
        XCTAssertEqual(try store.mode("default"), .chain)

        try store.save("default", p12: Data([8]))
        XCTAssertFalse(try store.hasChain("default"))
        XCTAssertEqual(try store.mode("default"), .p12)
    }

    func testLabelsAreIndependentAndClearRemovesBothForms() throws {
        try store.saveChain("default", pemChain: [pemA])
        try store.save("host_a", p12: Data([1]))
        XCTAssertEqual(try store.mode("default"), .chain)
        XCTAssertEqual(try store.mode("host_a"), .p12)

        try store.clear("default")
        XCTAssertFalse(try store.exists("default"))
        XCTAssertTrue(try store.exists("host_a"))

        try store.clearAll()
        XCTAssertFalse(try store.exists("host_a"))
    }

    func testAnEmptyChainIsRefused() throws {
        guard case .illegalArgument? = assertThrowsPinVault({ try store.saveChain("default", pemChain: []) }) else {
            return XCTFail("expected IllegalArgumentException")
        }
        XCTAssertFalse(try store.exists("default"))
    }

    func testAPendingEnrollmentRequestRoundTripsAndIsForgottenWhenACredentialArrives() throws {
        XCTAssertNil(try store.loadPendingRequest("default"))
        try store.savePendingRequest("default", requestId: "r-1", clientId: "field-7k2m9x")
        XCTAssertEqual(try store.loadPendingRequest("default"), .init(requestId: "r-1", clientId: "field-7k2m9x"))
        XCTAssertFalse(try store.exists("default"), "waiting is not enrolled")
        XCTAssertNil(try store.loadPendingRequest("other"), "per label")

        try store.saveChain("default", pemChain: [pemA])
        XCTAssertNil(try store.loadPendingRequest("default"))

        try store.savePendingRequest("other", requestId: "r-2", clientId: nil)
        XCTAssertEqual(try store.loadPendingRequest("other"), .init(requestId: "r-2", clientId: nil))
        try store.save("other", p12: Data([1]))
        XCTAssertNil(try store.loadPendingRequest("other"))
    }

    func testClearingALabelGivesUpItsPendingRequest() throws {
        try store.savePendingRequest("default", requestId: "r-1", clientId: nil)
        try store.clear("default")
        XCTAssertNil(try store.loadPendingRequest("default"))
        try store.savePendingRequest("default", requestId: "r-2", clientId: nil)
        try store.clearPendingRequest("default")
        XCTAssertNil(try store.loadPendingRequest("default"))
    }

    // MARK: A key imported into the Keychain: only its chain is stored

    func testAnImportedChainRoundTripsReportsImportedAndReplacesAStoredP12() throws {
        try store.save("default", p12: Data([1, 2, 3]))
        try store.saveImported("default", pemChain: [pemA, pemB])

        XCTAssertEqual(try store.mode("default"), .imported)
        XCTAssertTrue(try store.exists("default"))
        XCTAssertEqual(try store.loadImported("default"), [pemA, pemB])
        XCTAssertFalse(try store.hasP12("default"), "the P12 bytes are dropped")
        XCTAssertNil(try store.load("default"))
        XCTAssertNil(try store.loadChain("default"), "not a CSR identity: the renewer leaves it alone")
    }

    func testEachFormReplacesTheImportedOneAndClearRemovesIt() throws {
        try store.saveImported("a", pemChain: [pemA])
        try store.saveChain("a", pemChain: [pemB])
        XCTAssertEqual(try store.mode("a"), .chain)
        XCTAssertFalse(try store.hasImported("a"))

        try store.saveImported("b", pemChain: [pemA])
        try store.save("b", p12: Data([1]))
        XCTAssertEqual(try store.mode("b"), .p12)

        try store.saveImported("c", pemChain: [pemA])
        try store.clear("c")
        XCTAssertEqual(try store.mode("c"), .none)
        XCTAssertFalse(try store.exists("c"))
    }

    // MARK: Multi-label CRUD over the file (the instrumented test)

    func testSaveAndLoadTheDefaultAndNamedLabels() throws {
        try store.save(ClientCertSecureStore.defaultLabel, p12: Data([1, 2, 3, 4, 5]))
        try store.save("host_api.example.com", p12: Data([10, 20, 30]))
        XCTAssertEqual(try store.load(ClientCertSecureStore.defaultLabel), Data([1, 2, 3, 4, 5]))
        XCTAssertEqual(try store.load("host_api.example.com"), Data([10, 20, 30]))
    }

    func testMultipleLabelsAreStoredIndependently() throws {
        try store.save("default", p12: Data([1, 1, 1]))
        try store.save("host_a.com", p12: Data([2, 2, 2]))
        try store.save("host_b.com", p12: Data([3, 3, 3]))
        XCTAssertEqual(try store.load("default"), Data([1, 1, 1]))
        XCTAssertEqual(try store.load("host_a.com"), Data([2, 2, 2]))
        XCTAssertEqual(try store.load("host_b.com"), Data([3, 3, 3]))
    }

    func testExistsIsTrueForASavedLabelAndLoadIsNilForAMissingOne() throws {
        XCTAssertFalse(try store.exists("my_cert"))
        try store.save("my_cert", p12: Data([9, 8, 7]))
        XCTAssertTrue(try store.exists("my_cert"))
        XCTAssertNil(try store.load("nonexistent"))
    }

    func testClearRemovesOneLabelAndClearAllEverything() throws {
        try store.save("cert_a", p12: Data([1]))
        try store.save("cert_b", p12: Data([2]))
        try store.clear("cert_a")
        XCTAssertNil(try store.load("cert_a"))
        XCTAssertNotNil(try store.load("cert_b"))

        try store.save("host_x", p12: Data([2]))
        try store.clearAll()
        XCTAssertNil(try store.load("cert_b"))
        XCTAssertNil(try store.load("host_x"))
    }

    func testOverwriteAndALargeP12RoundTrip() throws {
        try store.save("cert", p12: Data([1, 2, 3]))
        try store.save("cert", p12: Data([4, 5, 6]))
        XCTAssertEqual(try store.load("cert"), Data([4, 5, 6]))
        let big = Data((0..<4096).map { UInt8(truncatingIfNeeded: $0) })
        try store.save("big_cert", p12: big)
        XCTAssertEqual(try store.load("big_cert"), big)
    }

    func testAnotherStoreOnTheSameFileSeesTheCredentials() throws {
        let environment = try testStoreEnvironment(self)
        try ClientCertSecureStore.open(environment: environment).saveChain("default", pemChain: [pemA, pemB])
        try ClientCertSecureStore.open(environment: environment).savePendingRequest("other", requestId: "r", clientId: nil)
        let strict = try ClientCertSecureStore.openStrict(environment: environment)
        XCTAssertEqual(try strict.loadChain("default"), [pemA, pemB])
        XCTAssertEqual(try strict.loadPendingRequest("other")?.requestId, "r")
        // The file is the one Android names.
        XCTAssertTrue(FileManager.default.fileExists(atPath: environment.directory.appendingPathComponent("pinvault_secure_client_cert.plist").path))
    }
}
