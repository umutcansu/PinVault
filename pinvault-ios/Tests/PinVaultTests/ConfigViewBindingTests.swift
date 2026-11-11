import Foundation
import XCTest
@testable import PinVault

/// Port of ConfigViewBindingTest: the client decision for the signed `view`
/// field (M6; SERVER_IMPLEMENTATION_GUIDE.md §3) over the five fixed payload vectors the Android library runs too, plus
/// the places where Swift strings would otherwise decide differently from
/// Kotlin's (canonical equivalence, grapheme clusters).
final class ConfigViewBindingTests: XCTestCase {

    private let base = #"{"version":3,"pins":[{"hostname":"api.example.com","sha256":["n4Gm1u/KyX6Yh1Yd6m6Ob0HPU+uKiDQqgw7hQvmRvr0=","r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="],"version":3,"forceUpdate":false,"mtls":false}],"forceUpdate":false,"issuedAt":1800000000000,"expiresAt":1800086400000,"configApiId":"default-tls""#

    private var v1Full: String { base + "}" }
    private var v2Scoped: String { base + #","view":{"hosts":["api.example.com","cdn.example.com"],"deviceId":"a1b2c3d4e5f60718"}}"# }
    private var v3NoDevice: String { base + #","view":{"hosts":["api.example.com"]}}"# }
    private var v4DeviceOnly: String { base + #","view":{"deviceId":"a1b2c3d4e5f60718"}}"# }
    private var v5Unknown: String { base + #","view":{"hosts":["api.example.com"],"deviceId":"a1b2c3d4e5f60718","aclVersion":7}}"# }

    private let full: ConfigViewBinding.Expected? = nil

    private func scoped(_ hosts: String..., deviceId: String? = "a1b2c3d4e5f60718") -> ConfigViewBinding.Expected? {
        ConfigViewBinding.expected(wantPinsFor: hosts, deviceIds: deviceId)
    }

    private func accepts(_ payload: String, _ expected: ConfigViewBinding.Expected?, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNoThrow(try ConfigViewBinding.check(payload: payload, expected: expected), file: file, line: line)
    }

    private func refuses(_ payload: String, _ expected: ConfigViewBinding.Expected?, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try ConfigViewBinding.check(payload: payload, expected: expected), file: file, line: line) { error in
            guard case .configViewMismatch(let message)? = error as? PinVaultError else {
                return XCTFail("expected configViewMismatch, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(message.hasPrefix("Signed config rejected:"), message, file: file, line: line)
            XCTAssertEqual((error as? PinVaultError)?.exceptionName, "ConfigViewMismatchException", file: file, line: line)
        }
    }

    /// Exact comparison (Swift `==` on strings is canonical equivalence; Kotlin compares code units).
    private func scalars(_ names: [String]) -> [[UInt32]] { names.map { $0.unicodeScalars.map(\.value) } }

    func testCanonicalHostSet() {
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["cdn.example.com", "api.example.com"])),
                       scalars(["api.example.com", "cdn.example.com"]))
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["CDN.Example.com", " api.example.com", "cdn.example.com,,"])),
                       scalars(["api.example.com", "cdn.example.com"]))
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["b-1.a.com", "A.com:8443", "a.com"])),
                       scalars(["a.com", "a.com:8443", "b-1.a.com"]))
        XCTAssertEqual(ConfigViewBinding.canonicalHosts([" ", ","]), [])
        // Only A-Z folds: no locale rules (Turkish dotted I stays as it is).
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["İ.com", "I.com"])), scalars(["i.com", "İ.com"]))
        // Every ASCII whitespace of the spec is trimmed, nothing else.
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["\t\n\r\u{0B}\u{0C} a.com \u{0C}\u{0B}\r\n\t", "\u{A0}b.com"])),
                       scalars(["a.com", "\u{A0}b.com"]))
    }

    func testCanonicalFormWorksOnCodePointsNotOnSwiftCharacters() {
        // ",\u{301}" is one Swift Character, but still a separator (Kotlin splits UTF-16 at ',').
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["a.com,\u{301}b.com"])), scalars(["a.com", "\u{301}b.com"]))
        // "\r\n" is one Character: both are trimmed.
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["a.com\r\n"])), scalars(["a.com"]))
        // Canonically equivalent but different code points: two names (Kotlin `distinct`), sorted by code point.
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["\u{212B}.com", "\u{C5}.com"])), scalars(["\u{C5}.com", "\u{212B}.com"]))
        // Code point order, not Swift's (NFC-based) string order: U+00C6 < U+212B although NFC(U+212B) = U+00C5.
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["\u{212B}.com", "\u{C6}.com"])), scalars(["\u{C6}.com", "\u{212B}.com"]))
        // A supplementary-plane name sorts after the BMP (code point, as Kotlin's compareCodePoints).
        XCTAssertEqual(scalars(ConfigViewBinding.canonicalHosts(["\u{1F600}.com", "\u{FFFD}.com"])), scalars(["\u{FFFD}.com", "\u{1F600}.com"]))
    }

    func testAViewHostOrDeviceIdOnlyCanonicallyEquivalentToTheRequestIsAnotherRequest() {
        let precomposed = base + #","view":{"hosts":["\#u{E9}.com"],"deviceId":"d\#u{E9}v"}}"#
        accepts(precomposed, ConfigViewBinding.expected(wantPinsFor: ["\u{E9}.com"], deviceIds: "d\u{E9}v"))
        refuses(precomposed, ConfigViewBinding.expected(wantPinsFor: ["e\u{301}.com"], deviceIds: "d\u{E9}v"))
        refuses(precomposed, ConfigViewBinding.expected(wantPinsFor: ["\u{E9}.com"], deviceIds: "de\u{301}v"))
    }

    func testVector1FullPayload() {
        accepts(v1Full, full)
        accepts(v1Full, scoped("api.example.com")) // no view: a full view or an older server
    }

    func testVector2NarrowedForTwoHostsAndADevice() {
        accepts(v2Scoped, scoped("cdn.example.com", "API.example.com"))
        refuses(v2Scoped, full)
        refuses(v2Scoped, scoped("api.example.com"))
        refuses(v2Scoped, scoped("api.example.com", "cdn.example.com", deviceId: "another-device"))
        refuses(v2Scoped, scoped("api.example.com", "cdn.example.com", deviceId: nil))
    }

    func testVector3NarrowedWithoutADeviceId() {
        accepts(v3NoDevice, scoped("api.example.com", deviceId: nil))
        refuses(v3NoDevice, scoped("api.example.com"))
        refuses(v3NoDevice, full)
    }

    func testVector4NarrowedByTheDeviceAclAlone() {
        refuses(v4DeviceOnly, full)
        refuses(v4DeviceOnly, scoped("api.example.com"))
    }

    func testVector5AnUnknownNarrowingIsNeverAccepted() {
        refuses(v5Unknown, full)
        refuses(v5Unknown, scoped("api.example.com"))
    }

    func testAJsonNullViewIsAbsent() {
        accepts(base + #","view":null}"#, full)
        accepts(base + #","view":null}"#, scoped("api.example.com"))
        // A null deviceId is "none"; a null host list is "no host set".
        accepts(base + #","view":{"hosts":["api.example.com"],"deviceId":null}}"#, scoped("api.example.com", deviceId: nil))
        refuses(base + #","view":{"hosts":null,"deviceId":"a1b2c3d4e5f60718"}}"#, scoped("api.example.com"))
    }

    func testAMalformedViewIsRefused() {
        let s = scoped("api.example.com")
        refuses(base + #","view":"api.example.com"}"#, s)
        refuses(base + #","view":["api.example.com"]}"#, s)
        refuses(base + #","view":{"hosts":"api.example.com","deviceId":"a1b2c3d4e5f60718"}}"#, s)
        refuses(base + #","view":{"hosts":["api.example.com",7],"deviceId":"a1b2c3d4e5f60718"}}"#, s)
        refuses(base + #","view":{"hosts":["api.example.com",null],"deviceId":"a1b2c3d4e5f60718"}}"#, s)
        refuses(base + #","view":{"hosts":["api.example.com"],"deviceId":7}}"#, s)
        refuses(base + #","view":{"hosts":["api.example.com"],"deviceId":true}}"#, s)
        refuses(base + #","view":{}}"#, s)
        // Not canonical: an upper-case name, a duplicate, the wrong order are other requests.
        refuses(base + #","view":{"hosts":["API.example.com"],"deviceId":"a1b2c3d4e5f60718"}}"#, s)
        refuses(base + #","view":{"hosts":["api.example.com","api.example.com"],"deviceId":"a1b2c3d4e5f60718"}}"#, s)
        refuses(base + #","view":{"hosts":["cdn.example.com","api.example.com"],"deviceId":"a1b2c3d4e5f60718"}}"#,
                scoped("api.example.com", "cdn.example.com"))
        // Not a JSON object at all.
        refuses("[1]", s)
        refuses("[1]", full)
    }

    func testAStoredViewMayNameTheFetchFormOrTheAttestationFormOfTheDeviceId() {
        let either = ConfigViewBinding.expected(wantPinsFor: ["api.example.com"], deviceIds: nil, AttestationManager.unknownDeviceId)
        accepts(v3NoDevice, either)
        accepts(base + #","view":{"hosts":["api.example.com"],"deviceId":"unknown-device"}}"#, either)
        refuses(v2Scoped, either)
    }

    func testTheRefusalNamesTheRequestAndTheView() {
        XCTAssertThrowsError(try ConfigViewBinding.check(payload: v2Scoped, expected: scoped("api.example.com"))) { error in
            let message = (error as? PinVaultError)?.message ?? ""
            XCTAssertTrue(message.contains("another host set"), message)
            XCTAssertTrue(message.contains("hosts=[api.example.com], deviceId='a1b2c3d4e5f60718'"), message)
            XCTAssertTrue(message.contains(#""cdn.example.com""#), message)
        }
        XCTAssertThrowsError(try ConfigViewBinding.check(payload: v3NoDevice, expected: full)) { error in
            let message = (error as? PinVaultError)?.message ?? ""
            XCTAssertTrue(message.contains("asks for the full config"), message)
        }
    }
}
