import XCTest
@testable import PinVault

/// Port of PinConfigValidatorTest.
final class PinConfigValidatorTests: XCTestCase {

    private let pinA = pin("A")
    private let pinB = pin("B")

    private func config(_ hosts: String...) -> CertificateConfig {
        CertificateConfig(version: 1, pins: hosts.map { HostPin(hostname: $0, sha256: [pinA, pinB], version: 1) })
    }

    func testPlainNamesWildcardsPortsAndIPv4AddressesAreAccepted() throws {
        for host in [
            "api.example.com", "API.Example.COM", "localhost", "xn--mnchen-3ya.de", "a-b.example.com",
            "*.example.com", "*.cdn.example.co.uk", "api.example.com:8443", "*.example.com:443",
            "192.168.1.80", "192.168.1.80:8091", "host:1", "host:65535",
        ] {
            XCTAssertNil(PinConfigValidator.hostPatternError(host), host)
        }
        XCTAssertNoThrow(try PinConfigValidator.validate(config("api.example.com", "*.example.com", "192.168.1.80:8091")))
    }

    func testNamesThatCarryTheOldStoresSeparatorsAreRefused() {
        for host in [
            "api.bank.com|9|\(pinA),\(pinB)|false\nx", "api.bank.com=2147483647\nx", "api.bank.com,evil.com",
            "api.bank.com\n", "api.bank.com evil.com",
        ] {
            XCTAssertNotNil(PinConfigValidator.hostPatternError(host), host)
        }
        assertInvalidPinFormat("not a host name") { try PinConfigValidator.validate(self.config("ok.example.com", "api.bank.com|9|x")) }
    }

    func testMalformedNamesAreRefused() {
        let labels255 = Array(repeating: "abc", count: 64).joined(separator: ".")
        for host in [
            "", ".", "example..com", "example.com.", ".example.com", "-a.example.com", "a-.example.com",
            "exa_mple.com", "exam ple.com", "https://example.com", "example.com/path", String(repeating: "a", count: 64) + ".com",
            labels255, "*", "*example.com", "a.*.example.com", "*.*.example.com", "**.example.com",
            "example.com:0", "example.com:65536", "example.com:", "example.com:80a", "example.com:0443", "[::1]", "::1",
        ] {
            XCTAssertNotNil(PinConfigValidator.hostPatternError(host), "'\(host)' should be refused")
        }
        XCTAssertEqual(PinConfigValidator.hostPatternError(nil), "A pin entry has no hostname")
    }

    func testAWildcardOverAPublicSuffixOrAnAddressIsRefused() {
        for host in ["*.com", "*.tr", "*.co.uk", "*.com.tr", "*.github.io", "*.1.80", "*.168.1.80"] {
            XCTAssertNotNil(PinConfigValidator.hostPatternError(host), host)
        }
        assertInvalidPinFormat("public suffix") { try PinConfigValidator.validate(self.config("*.com")) }
    }

    func testTheLengthLimitIs253WithoutThePort() {
        let name = Array(repeating: "abc", count: 63).joined(separator: ".") + ".a"
        XCTAssertEqual(name.count, 253)
        XCTAssertNil(PinConfigValidator.hostPatternError(name))
        XCTAssertNil(PinConfigValidator.hostPatternError(name + ":443"))
        XCTAssertNotNil(PinConfigValidator.hostPatternError(name + "b"))
    }

    func testPinsMustBeTheBase64OfASHA256() {
        XCTAssertNil(PinConfigValidator.pinError(pinA))
        XCTAssertNil(PinConfigValidator.pinError("ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM="))
        for bad: String? in [nil, "", " ", "short", String(repeating: "A", count: 44), String(repeating: "A", count: 42) + "==",
                             String(repeating: "A", count: 43) + "\n", String(repeating: "A", count: 42) + ",=",
                             String(repeating: "A", count: 42) + "|="] {
            XCTAssertNotNil(PinConfigValidator.pinError(bad), "'\(bad ?? "nil")'")
        }
        XCTAssertEqual(PinConfigValidator.pinError("short"), "has invalid length: 5 (expected 44)")
        assertInvalidPinFormat("Hash at index 1") {
            try PinConfigValidator.validate(CertificateConfig(pins: [HostPin(hostname: "a.example.com", sha256: [self.pinA, "not-a-pin"])]))
        }
    }

    func testTheSamePinListedTwiceIsNoBackup() {
        assertInvalidPinFormat("2 different pins") {
            try PinConfigValidator.validate(CertificateConfig(version: 1, pins: [HostPin(hostname: "api.example.com", sha256: [self.pinA, self.pinA], version: 1)]))
        }
        XCTAssertNoThrow(try PinConfigValidator.validate(
            CertificateConfig(version: 1, pins: [HostPin(hostname: "api.example.com", sha256: [pinA, pinB, pinA], version: 1)])
        ))
    }

    func testAnEmptyConfigADuplicateHostAndANegativeVersionAreRefused() {
        assertInvalidPinFormat("at least one pin entry") { try PinConfigValidator.validate(CertificateConfig(pins: [])) }
        assertInvalidPinFormat("more than once") { try PinConfigValidator.validate(self.config("a.example.com", "A.example.com")) }
        assertInvalidPinFormat("negative version") {
            try PinConfigValidator.validate(CertificateConfig(pins: [HostPin(hostname: "a.example.com", sha256: [self.pinA, self.pinB], version: -1)]))
        }
    }

    func testTrustRootsAreValidated() {
        assertInvalidPinFormat("Trust root at index 0 is blank") {
            try PinConfigValidator.validate(CertificateConfig(pins: self.config("a.example.com").pins, trustRoots: [""]))
        }
        assertInvalidPinFormat("A trust root is listed more than once") {
            try PinConfigValidator.validate(CertificateConfig(pins: self.config("a.example.com").pins, trustRoots: [self.pinA, self.pinA]))
        }
        assertInvalidPinFormat("at most 64") {
            try PinConfigValidator.validate(CertificateConfig(pins: self.config("a.example.com").pins, trustRoots: Array(repeating: self.pinA, count: 65)))
        }
    }

    func testWhatGsonLeavesNullIsRefusedNotDereferenced() {
        for json in [
            #"{"version":1}"#,
            #"{"pins":[null]}"#,
            #"{"pins":[{"sha256":["\#(pinA)","\#(pinB)"]}]}"#,
            #"{"pins":[{"hostname":"a.example.com"}]}"#,
            #"{"pins":[{"hostname":"a.example.com","sha256":["\#(pinA)",null]}]}"#,
            #"{"pins":[{"hostname":"a.example.com","sha256":["\#(pinA)"]}]}"#,
        ] {
            do {
                try PinConfigValidator.validate(try JSONDecoder().decode(CertificateConfig.self, from: Data(json.utf8)))
                XCTFail("should have been refused: \(json)")
            } catch PinVaultError.invalidPinFormat {
                // expected
            } catch {
                XCTFail("\(json): \(error)")
            }
        }
    }

    func testPrintableBoundsAndMasksControlCharacters() {
        XCTAssertEqual(PinConfigValidator.printable("a\nb"), "'a?b'")
        XCTAssertEqual(PinConfigValidator.printable(String(repeating: "x", count: 81)), "'" + String(repeating: "x", count: 80) + "…'")
    }
}
