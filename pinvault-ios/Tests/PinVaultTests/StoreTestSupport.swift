import CryptoKit
import Foundation
import XCTest
@testable import PinVault

/// A P-256 signing key made in-test (Kotlin `ecKeyPair()` + the `pub/id/sign` helpers).
struct TestSigner {
    let privateKey = P256.Signing.PrivateKey()

    /// Base64 SPKI.
    var pub: String { privateKey.publicKey.derRepresentation.base64EncodedString() }

    /// Base64 SHA-256 of the SPKI.
    var id: String { Data(SHA256.hash(data: privateKey.publicKey.derRepresentation)).base64EncodedString() }

    /// `-----BEGIN PUBLIC KEY-----`, 64-character lines, trailing newline.
    var pem: String { PEM.encode(privateKey.publicKey.derRepresentation, label: "PUBLIC KEY") + "\n" }

    /// Base64 DER ECDSA-SHA256 over the UTF-8 bytes of `payload`.
    func sign(_ payload: String) -> String {
        (try! privateKey.signature(for: Data(payload.utf8))).derRepresentation.base64EncodedString()
    }

    /// A signature entry hinting this key's id.
    func entry(_ payload: String) -> SignatureEntry {
        SignatureEntry(keyId: id, signature: sign(payload))
    }

    /// A signature entry with the given (possibly wrong or missing) hint.
    func entry(_ payload: String, keyId: String?) -> SignatureEntry {
        SignatureEntry(keyId: keyId, signature: sign(payload))
    }
}

/// The error a failing Keychain stands in for (Kotlin `ProviderException`).
struct ProviderException: Error, CustomStringConvertible {
    let message: String
    var description: String { "ProviderException: \(message)" }
}

/// A cipher whose `open` can be made to fail the way a broken Keychain does.
final class FlakyCipher: PrefsCipher, @unchecked Sendable {
    private let real = KeyedPrefsCipher(source: InMemoryPrefsKeySource())
    private let state = Locked(false)

    var broken: Bool {
        get { state.get() }
        set { state.set(newValue) }
    }

    func seal(_ plaintext: Data, aad: Data) throws -> Data { try real.seal(plaintext, aad: aad) }

    func open(_ sealed: Data, aad: Data) throws -> Data {
        if broken { throw ProviderException(message: "Keystore operation failed") }
        return try real.open(sealed, aad: aad)
    }

    func mac(_ input: Data) throws -> Data { try real.mac(input) }
}

/// A fresh directory under the temporary directory, removed when the test ends.
func temporaryStoreDirectory(_ testCase: XCTestCase) throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("pinvault-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    testCase.addTeardownBlock {
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        try? FileManager.default.removeItem(at: url)
    }
    return url
}

/// A signing-key set payload as the Kotlin tests build it with Gson (`type`, `version`, `keys`, …).
func keySetPayload(
    type: String = SignatureTrust.keySetType,
    version: Int,
    keys: [String],
    requiredSignatures: Int? = nil,
    configApiId: String? = nil
) -> String {
    var fields: [(String, String)] = [
        ("type", JSONText.string(type)),
        ("version", String(version)),
        ("keys", JSONText.array(keys.map(JSONText.string))),
    ]
    if let requiredSignatures { fields.append(("requiredSignatures", String(requiredSignatures))) }
    if let configApiId { fields.append(("configApiId", JSONText.string(configApiId))) }
    return JSONText.object(fields)
}

/// Asserts that `body` throws ``PinVaultError/security(message:cause:)`` and returns its message.
@discardableResult
func assertSecurityRefusal(
    _ expected: String? = nil,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) -> String? {
    do {
        try body()
        XCTFail("expected a SecurityException", file: file, line: line)
    } catch let PinVaultError.security(message, _) {
        if let expected {
            XCTAssertTrue(message.contains(expected), "'\(message)' does not mention '\(expected)'", file: file, line: line)
        }
        return message
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
    return nil
}

/// Asserts that `body` throws ``PinVaultError/storeUnreadable(message:cause:)`` and returns its cause.
@discardableResult
func assertStoreUnreadable(
    _ what: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) -> (any Error)? {
    do {
        try body()
        XCTFail("\(what): must not read as 'nothing stored'", file: file, line: line)
    } catch let PinVaultError.storeUnreadable(_, cause) {
        return cause
    } catch {
        XCTFail("\(what): unexpected error \(error)", file: file, line: line)
    }
    return nil
}
