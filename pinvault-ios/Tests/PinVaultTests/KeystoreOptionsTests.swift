import XCTest
@testable import PinVault

/// `requireHardwareBackedKeys()`: what the Keychain reports decides, and a
/// refused key is deleted before the failure is raised (Kotlin `KeystoreOptionsTest`).
final class KeystoreOptionsTests: XCTestCase {

    private let options = KeystoreOptions()

    func testWithoutTheOptionEveryLevelPassesAndIsReturned() throws {
        for level in KeySecurityLevel.allCases {
            var cleaned = false
            XCTAssertEqual(try options.checkLevel("Test key", level, cleanUp: { cleaned = true }), level)
            XCTAssertFalse(cleaned, "level \(level) must not be deleted")
        }
    }

    func testWithTheOptionHardwareLevelsPassAndTheRestAreDeletedAndRefused() throws {
        options.hardwareBackedRequired = true
        XCTAssertEqual(try options.checkLevel("Test key", .secureEnclave), .secureEnclave)
        XCTAssertEqual(try options.checkLevel("Test key", .strongbox), .strongbox)
        XCTAssertEqual(try options.checkLevel("Test key", .trustedEnvironment), .trustedEnvironment)
        for level in [KeySecurityLevel.software, .unknown] {
            var cleaned = false
            let error = assertThrowsPinVault { try options.checkLevel("Client identity key", level, cleanUp: { cleaned = true }) }
            XCTAssertTrue(cleaned, "the refused key is deleted first")
            guard case .hardwareBackedKeyRequired(let keyKind, let refused, _)? = error else {
                return XCTFail("\(level) must be refused, got \(String(describing: error))")
            }
            XCTAssertEqual(refused, level)
            XCTAssertEqual(keyKind, "Client identity key")
            XCTAssertTrue(error!.message.contains(level.wireName), error!.message)
            XCTAssertEqual(error!.exceptionName, "HardwareBackedKeyRequiredException")
        }
    }

    func testAFailingCleanUpDoesNotHideTheRefusal() {
        options.hardwareBackedRequired = true
        let error = assertThrowsPinVault {
            try options.checkLevel("Test key", .software, cleanUp: { throw PinVaultError.crypto(message: "keychain gone") })
        }
        guard case .hardwareBackedKeyRequired(_, _, let cause)? = error else { return XCTFail("must be refused") }
        XCTAssertNil(cause)
    }

    func testTheInMemoryIdentityKeyReportsItselfAsSoftware() throws {
        let provider = ClientIdentityKeys.software(label: uniqueLabel("options-test"))
        XCTAssertEqual(provider.securityLevel(), .unknown)
        try provider.ensureKeyPair()
        XCTAssertEqual(provider.securityLevel(), .software)
        XCTAssertFalse(provider.securityLevel().hardwareBacked)
        try provider.clear()
    }

    func testWireNamesRoundTrip() {
        for level in KeySecurityLevel.allCases { XCTAssertEqual(KeySecurityLevel.fromWireName(level.wireName), level) }
        XCTAssertEqual(KeySecurityLevel.fromWireName("hsm"), .unknown)
        XCTAssertEqual(KeySecurityLevel.fromWireName(nil), .unknown)
        XCTAssertEqual(KeySecurityLevel.fromWireName(" TEE "), .trustedEnvironment)
        XCTAssertEqual(KeySecurityLevel.secureEnclave.wireName, "secure_enclave")
        XCTAssertTrue(KeySecurityLevel.secureEnclave.hardwareBacked)
    }
}
