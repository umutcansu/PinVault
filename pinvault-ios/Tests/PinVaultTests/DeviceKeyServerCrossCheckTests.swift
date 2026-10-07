import Foundation
import Security
import XCTest
@testable import PinVault

/// Cross-check with the demo server (PORTING.md §3/§4): a device key made by
/// ``DeviceKeys/software(alias:)`` was registered as SPKI PEM with
/// `RSA-OAEP-SHA256-MGF1-SHA256` through the server's real
/// `POST …/vault/devices/{id}/public-key` route (both purposes), and the
/// envelopes its real download route made for that key (VaultEncryptionService,
/// end_to_end and user_auth) are fixtures here. They must open on iOS.
///
/// Fixtures (`Fixtures/vault/`, generated, not in the repository): `ios-device-key.spki.txt` (the PEM the provider
/// exported), `ios-device-key.pkcs1.bin` (its private key, test only),
/// `server-end-to-end.envelope.bin`, `server-user-auth.envelope.bin`.
/// Regenerate: `PINVAULT_WRITE_IOS_FIXTURES=1 swift test --filter DeviceKeyServerCrossCheckTests/testWriteTheCrossCheckKey`,
/// then `cd demo-server && PINVAULT_WRITE_IOS_FIXTURES=1 ../gradlew test --tests '*IosDeviceKeyCrossCheckTest*'`.
final class DeviceKeyServerCrossCheckTests: XCTestCase {

    static let endToEndPlaintext = Data("pinvault iOS cross-check: end_to_end".utf8)
    static let userAuthPlaintext = Data("pinvault iOS cross-check: user_auth".utf8)

    private static func fixtureDirectory(_ file: String = #filePath) -> URL {
        URL(fileURLWithPath: file).deletingLastPathComponent().appendingPathComponent("Fixtures/vault", isDirectory: true)
    }

    private func fixture(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures/vault") else {
            // The test key is not in the repository: pinvault-ios/scripts/generate-test-keys.sh makes it.
            throw XCTSkip("missing fixture vault/\(name): run pinvault-ios/scripts/generate-test-keys.sh")
        }
        return try Data(contentsOf: url)
    }

    /// The provider over the committed private key.
    private func provider() throws -> any DeviceKeyProvider {
        let pkcs1 = try fixture("ios-device-key.pkcs1.bin")
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 2048,
        ]
        var error: Unmanaged<CFError>?
        let key = try XCTUnwrap(SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, &error))
        return SoftwareDeviceKeyProvider(alias: DeviceKeys.defaultAlias, privateKey: key)
    }

    func testTheRegisteredPemIsWhatTheProviderExports() throws {
        let committed = String(decoding: try fixture("ios-device-key.spki.txt"), as: UTF8.self)
        XCTAssertEqual(try provider().getPublicKeyPem(), committed.trimmingCharacters(in: .newlines))
    }

    func testTheServersEndToEndEnvelopeOpensWithTheDeviceKey() throws {
        let envelope = try fixture("server-end-to-end.envelope.bin")
        XCTAssertEqual(envelope.prefix(4), Data([0, 0, 1, 0]), "a 256-byte wrapped key: RSA-2048")
        XCTAssertEqual(try VaultFileDecryptor.decrypt(envelope, privateKey: provider().getPrivateKey()), Self.endToEndPlaintext)
    }

    func testTheServersEnvelopeGoesThroughTheRouterAsAnEndToEndFile() async throws {
        let api = VaultApiStub()
        api.answer(VaultFetchResponse(content: try fixture("server-end-to-end.envelope.bin"), version: 1, encryption: "end_to_end"))
        let storage = MemVaultStore()
        let router = VaultFileRouter(clients: [vaultClient(api, vaultBlock())], storageFor: { _ in storage },
                                     deviceKeyProvider: try provider(), deviceIdProvider: { "ios-cross-check" })
        let file = VaultFileConfig(key: "e2e-file", endpoint: "api/v1/vault/e2e-file", encryption: .endToEnd)
        let result = await router.fetchFile(file)
        XCTAssertEqual(result, .updated(key: "e2e-file", version: 1, bytes: Self.endToEndPlaintext))
    }

    func testTheServersUserAuthEnvelopeOpensAfterThePrompt() async throws {
        let keys = SoftwareUserAuthKeys()
        keys.key = try provider().getPrivateKey()
        let storage = UserAuthVaultStorage(inner: MemVaultStore(), keys: keys, policy: .required, serverSealedOnly: true)
        try storage.saveSealedByServer("ua-file", envelope: fixture("server-user-auth.envelope.bin"), version: 1, signatures: [])

        let result = await storage.unlock("ua-file", authenticate: { _, grant in .succeeded(grant) }, verify: { _, _, _ in nil })
        XCTAssertEqual(result, .unlocked(key: "ua-file", version: 1, bytes: Self.userAuthPlaintext))
    }

    /// Writes a fresh key pair (the provider's PEM and its private key) into
    /// the fixture directory. Manual: the demo-server test then makes the envelopes.
    func testWriteTheCrossCheckKey() throws {
        guard ProcessInfo.processInfo.environment["PINVAULT_WRITE_IOS_FIXTURES"] == "1" else {
            throw XCTSkip("set PINVAULT_WRITE_IOS_FIXTURES=1 to write a new cross-check key")
        }
        let provider = DeviceKeys.software(alias: DeviceKeys.defaultAlias)
        try provider.ensureKeyPair()
        var error: Unmanaged<CFError>?
        let pkcs1 = try XCTUnwrap(SecKeyCopyExternalRepresentation(provider.getPrivateKey(), &error) as Data?)
        let directory = Self.fixtureDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data((try provider.getPublicKeyPem() + "\n").utf8).write(to: directory.appendingPathComponent("ios-device-key.spki.txt"))
        try pkcs1.write(to: directory.appendingPathComponent("ios-device-key.pkcs1.bin"))
    }
}
