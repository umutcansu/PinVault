import Security
import XCTest
@testable import PinVault

/// The in-memory identity key that stands in for the Secure Enclave in unit
/// tests (Kotlin `ClientIdentityKeyProviderTest`). The Secure Enclave and
/// Keychain keys themselves: `IdentityKeychainTests` (simulator, hosted).
final class ClientIdentityKeyProviderTests: XCTestCase {

    private let label = uniqueLabel("test")

    override func tearDown() {
        InMemoryClientIdentityKeyProvider.attestation = nil
        try? ClientIdentityKeys.software(label: label).clear()
    }

    func testEnsureKeyPairIsIdempotentAndSharedPerLabel() throws {
        let a = ClientIdentityKeys.software(label: label)
        XCTAssertFalse(a.exists())
        try a.ensureKeyPair()
        XCTAssertTrue(a.exists())
        let first = try a.spkiSha256()

        try a.ensureKeyPair()
        XCTAssertEqual(try a.spkiSha256(), first)

        // A second instance for the same label sees the same key, like the Keychain.
        let b = ClientIdentityKeys.software(label: label)
        XCTAssertTrue(b.exists())
        XCTAssertEqual(try b.spkiSha256(), first)

        try a.clear()
        XCTAssertFalse(b.exists())
    }

    func testSignProducesAVerifiableSHA256withECDSASignature() throws {
        let provider = ClientIdentityKeys.software(label: label)
        try provider.ensureKeyPair()
        let data = Data("certification request info".utf8)
        let signature = try provider.sign(data)
        XCTAssertTrue(SecKeyVerifySignature(try provider.publicKey(), .ecdsaSignatureMessageX962SHA256, data as CFData, signature as CFData, nil))
    }

    func testSpkiHashMatchesTheCsrHelperAndChangesAfterClear() throws {
        let provider = ClientIdentityKeys.software(label: label)
        try provider.ensureKeyPair()
        XCTAssertEqual(try Pkcs10Csr.spkiSha256Base64(provider.publicKey()), try provider.spkiSha256())
        let before = try provider.spkiSha256()

        try provider.clear()
        try provider.ensureKeyPair()
        XCTAssertNotEqual(before, try provider.spkiSha256())
    }

    func testAccessorsFailBeforeTheKeyExists() {
        let provider = ClientIdentityKeys.software(label: label)
        guard case .illegalState? = assertThrowsPinVault({ _ = try provider.publicKey() }) else {
            return XCTFail("expected IllegalStateException")
        }
    }

    func testAliasIsDerivedFromTheLabel() {
        XCTAssertEqual(ClientIdentityKeys.aliasFor("default"), "pinvault_client_identity_ec_default")
    }

    // MARK: Attestation (the in-memory key plays a device that attests)

    func testAKeyGeneratedWithAChallengeCarriesItAnExistingKeyIsLeftAsItIs() throws {
        let provider = ClientIdentityKeys.software(label: label)
        InMemoryClientIdentityKeyProvider.attestation = { challenge in [challenge] }

        // Made without a challenge (an earlier version): no chain.
        try provider.ensureKeyPair()
        let first = try provider.spkiSha256()
        XCTAssertTrue(provider.attestationChain().isEmpty)

        // Asking again with a challenge does not replace or re-attest an existing key.
        let challenge = ClientIdentityKeys.attestationChallenge(deviceUid: "device-1")
        try provider.ensureKeyPair(attestationChallenge: challenge)
        XCTAssertEqual(try provider.spkiSha256(), first)
        XCTAssertTrue(provider.attestationChain().isEmpty)

        // A new key gets the challenge it was asked for.
        try provider.clear()
        try provider.ensureKeyPair(attestationChallenge: challenge)
        XCTAssertEqual(provider.attestationChain(), [challenge])
        // Another instance for the same label sees the same key and chain.
        XCTAssertEqual(ClientIdentityKeys.software(label: label).attestationChain(), [challenge])

        try provider.clear()
        XCTAssertTrue(provider.attestationChain().isEmpty)
    }

    func testTheIdentityChallengeDiffersPerDevice() {
        let a = ClientIdentityKeys.attestationChallenge(deviceUid: "device-1")
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, ClientIdentityKeys.attestationChallenge(deviceUid: "device-2"))
        XCTAssertEqual(a, Hashing.sha256("pinvault-identity-key:v1:device-1"))
    }

    func testTheUnlockedDeviceOptionIsOffUnlessTheConfigTurnsItOn() throws {
        let options = KeystoreOptions()
        XCTAssertFalse(options.unlockedDeviceRequired)
        // Off: the generator is asked once, without the flag.
        var asked: [Bool] = []
        XCTAssertEqual(try options.generating("test") { unlocked in asked.append(unlocked); return "key" }, "key")
        XCTAssertEqual(asked, [false])
    }

    func testTheUnlockedDeviceOptionFallsBackOnceWhenTheKeychainRefuses() throws {
        let options = KeystoreOptions()
        options.unlockedDeviceRequired = true
        var asked: [Bool] = []
        var cleaned = 0
        let key = try options.generating("test", cleanUp: { cleaned += 1 }) { unlocked -> String in
            asked.append(unlocked)
            if unlocked { throw PinVaultError.crypto(message: "refused") }
            return "key"
        }
        XCTAssertEqual(key, "key")
        XCTAssertEqual(asked, [true, false])
        XCTAssertEqual(cleaned, 1)
    }

    func testTheConfigSetsTheOptionsHereAndInTheStores() throws {
        let options = KeystoreOptions()
        let stores = try testStoreEnvironment(self)
        let config = try PinVaultConfig.Builder()
            .configApi("api", url: "https://config.test/") { block in
                block.bootstrapPins([HostPin(hostname: "config.test", sha256: [pin("A"), pin("B")])])
                block.allowUnsigned()
            }
            .requireUnlockedDevice()
            .requireHardwareBackedKeys()
            .build()
        options.apply(config, stores: stores)
        XCTAssertTrue(options.unlockedDeviceRequired)
        XCTAssertTrue(options.hardwareBackedRequired)
        XCTAssertTrue(stores.requireUnlockedDevice)
    }
}
