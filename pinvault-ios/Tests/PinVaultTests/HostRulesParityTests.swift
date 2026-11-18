import Foundation
import XCTest
@testable import PinVault

/// The host-name, pin and host-matching decisions every implementation must
/// share, from ONE file: `Fixtures/parity/host-rules.json`. The Android library
/// (`ssl/HostRulesParityTest`) and the server (`HostRulesParityTest`) read the
/// same file. A rule one platform applies and another does not is a config one
/// fleet accepts and the other refuses — or a host one of them pins and the
/// other does not (review 2026-11-17).
final class HostRulesParityTests: XCTestCase {

    private func vectors(_ section: String) throws -> [[String: Any]] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "host-rules", withExtension: "json", subdirectory: "Fixtures/parity"))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        return try XCTUnwrap(json[section] as? [[String: Any]])
    }

    func testHostPatternsAreAcceptedAndRefusedAsTheSharedVectorsSay() throws {
        var mismatches: [String] = []
        for v in try vectors("hostPatterns") {
            let pattern = try XCTUnwrap(v["pattern"] as? String)
            let expected = try XCTUnwrap(v["valid"] as? Bool)
            let actual = PinConfigValidator.hostPatternError(pattern) == nil
            if actual != expected { mismatches.append("pattern \(pattern.debugDescription): expected valid=\(expected), got \(actual)") }
        }
        XCTAssertTrue(mismatches.isEmpty, "differs from host-rules.json:\n" + mismatches.joined(separator: "\n"))
    }

    func testPinsAreAcceptedAndRefusedAsTheSharedVectorsSay() throws {
        var mismatches: [String] = []
        for v in try vectors("pins") {
            let pin = try XCTUnwrap(v["pin"] as? String)
            let expected = try XCTUnwrap(v["valid"] as? Bool)
            let actual = PinConfigValidator.pinError(pin) == nil
            if actual != expected { mismatches.append("pin \(pin.debugDescription): expected valid=\(expected), got \(actual)") }
        }
        XCTAssertTrue(mismatches.isEmpty, "differs from host-rules.json:\n" + mismatches.joined(separator: "\n"))
    }

    func testAHostIsMatchedToTheEntryTheSharedVectorsName() throws {
        var mismatches: [String] = []
        for v in try vectors("matching") {
            let entries = try XCTUnwrap(v["entries"] as? [String])
            let host = try XCTUnwrap(v["host"] as? String)
            let port = v["port"] as? Int
            let expected = v["match"] as? String
            // Each entry maps to its own (lower-cased) name, so the answer says which entry matched.
            let map = PinHostMatcher.build(entries.map { ($0, $0.lowercased()) })
            let actual = PinHostMatcher.match(map, host, port: port)
            if actual != expected { mismatches.append("\(entries) host \(host.debugDescription) port \(String(describing: port)): expected \(String(describing: expected)), got \(String(describing: actual))") }
        }
        XCTAssertTrue(mismatches.isEmpty, "differs from host-rules.json:\n" + mismatches.joined(separator: "\n"))
    }
}
