import Foundation
import XCTest
@testable import PinVault

/// Fixture files (generated with LibreSSL; see Fixtures/README.md).
enum Fixture {
    static func data(_ name: String, _ ext: String, file: StaticString = #filePath, line: UInt = #line) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures") else {
            XCTFail("missing fixture \(name).\(ext)", file: file, line: line)
            throw CocoaError(.fileNoSuchFile)
        }
        return try Data(contentsOf: url)
    }

    static func text(_ name: String, _ ext: String) throws -> String {
        String(decoding: try data(name, ext), as: UTF8.self)
    }

    /// The expected values in `fixtures.json`.
    static func expected() throws -> [String: [String: Any]] {
        let json = try JSONSerialization.jsonObject(with: try data("fixtures", "json"))
        return json as? [String: [String: Any]] ?? [:]
    }
}

/// A valid pin (Base64 of 32 bytes) made of one repeated letter.
func pin(_ letter: Character) -> String {
    String(repeating: letter, count: 43) + "="
}

/// Asserts that `body` throws ``PinVaultError/invalidConfiguration(_:)`` whose message contains `expected`.
func assertInvalidConfiguration(
    _ expected: String,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) {
    do {
        try body()
        XCTFail("expected a refusal mentioning '\(expected)'", file: file, line: line)
    } catch let PinVaultError.invalidConfiguration(message) {
        XCTAssertTrue(message.contains(expected), "'\(message)' does not mention '\(expected)'", file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
}

/// Asserts that `body` throws ``PinVaultError/invalidPinFormat(message:cause:)`` whose message contains `expected`.
func assertInvalidPinFormat(
    _ expected: String,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) {
    do {
        try body()
        XCTFail("expected a refusal mentioning '\(expected)'", file: file, line: line)
    } catch let PinVaultError.invalidPinFormat(message, _) {
        XCTAssertTrue(message.contains(expected), "'\(message)' does not mention '\(expected)'", file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
}

extension Data {
    init(hex: String) {
        self = Hex.decode(hex.replacingOccurrences(of: " ", with: ""))!
    }
}
