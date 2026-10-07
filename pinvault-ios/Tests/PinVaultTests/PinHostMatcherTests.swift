import XCTest
@testable import PinVault

/// H-01 regression coverage (Kotlin `PinHostMatcherTest`). The pre-V2 trust
/// manager merged every host's pin hashes into a single set, silently
/// accepting any pinned hash on any host. These tests lock down the per-host
/// scoping rules so a refactor cannot quietly re-open the cross-host pin-reuse hole.
final class PinHostMatcherTests: XCTestCase {

    private let bankPins: Set<String> = ["BANK_PIN_1", "BANK_PIN_2"]
    private let analyticsPins: Set<String> = ["ANALYTICS_PIN_1", "ANALYTICS_PIN_2"]

    private var pinMap: PinHostMap<Set<String>> {
        PinHostMatcher.build([("bank.example.com", bankPins), ("analytics.example.com", analyticsPins)])
    }

    func testExactHostnameReturnsThatHostsPins() {
        XCTAssertEqual(PinHostMatcher.match(pinMap, "bank.example.com"), bankPins)
        XCTAssertEqual(PinHostMatcher.match(pinMap, "analytics.example.com"), analyticsPins)
    }

    func testPinsFromOneHostNeverMatchADifferentHost() {
        let matched = PinHostMatcher.match(pinMap, "bank.example.com")
        XCTAssertNotNil(matched)
        XCTAssertTrue(matched!.isDisjoint(with: analyticsPins), "bank lookup must not leak analytics pins")
    }

    func testAHostPortEntryPinsOnlyThatPortAndWinsThere() {
        let renewalPins: Set<String> = ["CA_PIN_1", "CA_PIN_2"]
        let map = PinHostMatcher.build([("config.example.com", bankPins), ("config.example.com:8093", renewalPins)])
        XCTAssertEqual(PinHostMatcher.match(map, "config.example.com", port: 8093), renewalPins)
        // Other ports — and callers that know no port — keep the host's own pins.
        XCTAssertEqual(PinHostMatcher.match(map, "config.example.com", port: 8092), bankPins)
        XCTAssertEqual(PinHostMatcher.match(map, "config.example.com"), bankPins)
        XCTAssertEqual(PinHostMatcher.match(map, "CONFIG.example.com", port: 8093), renewalPins)
    }

    func testAHostPortEntryAloneDoesNotPinTheHostsOtherPorts() {
        let map = PinHostMatcher.build([("config.example.com:8093", Set(["CA_PIN_1", "CA_PIN_2"]))])
        XCTAssertNil(PinHostMatcher.match(map, "config.example.com", port: 8092))
        XCTAssertNil(PinHostMatcher.match(map, "config.example.com"))
    }

    func testUnknownHostnameReturnsNil() {
        XCTAssertNil(PinHostMatcher.match(pinMap, "unknown.example.com"))
        XCTAssertNil(PinHostMatcher.match(pinMap, "evil.com"))
    }

    func testHostnameMatchingIsCaseInsensitive() {
        XCTAssertEqual(PinHostMatcher.match(pinMap, "BANK.example.com"), bankPins)
        XCTAssertEqual(PinHostMatcher.match(pinMap, "Bank.Example.COM"), bankPins)
        // Entries are lowercased too.
        let upper = PinHostMatcher.build([("API.Example.com", bankPins)])
        XCTAssertEqual(PinHostMatcher.match(upper, "api.example.com"), bankPins)
    }

    func testWildcardMatchesSingleSubLabel() {
        let wildcard = PinHostMatcher.build([("*.example.com", Set(["WILD_PIN_1", "WILD_PIN_2"]))])
        XCTAssertEqual(PinHostMatcher.match(wildcard, "api.example.com"), ["WILD_PIN_1", "WILD_PIN_2"])
        XCTAssertEqual(PinHostMatcher.match(wildcard, "foo.example.com"), ["WILD_PIN_1", "WILD_PIN_2"])
    }

    func testWildcardDoesNotMatchTheBareApex() {
        let wildcard = PinHostMatcher.build([("*.example.com", Set(["WILD"]))])
        XCTAssertNil(PinHostMatcher.match(wildcard, "example.com"))
    }

    func testWildcardDoesNotMatchMultiLabelSubDomain() {
        let wildcard = PinHostMatcher.build([("*.example.com", Set(["WILD"]))])
        XCTAssertNil(PinHostMatcher.match(wildcard, "a.b.example.com"))
    }

    func testExactEntryWinsOverWildcardEntry() {
        let mixed = PinHostMatcher.build([("*.example.com", Set(["WILD"])), ("api.example.com", Set(["EXACT"]))])
        XCTAssertEqual(PinHostMatcher.match(mixed, "api.example.com"), ["EXACT"])
    }

    func testEmptyMapMatchesNothing() {
        let empty = PinHostMatcher.build([(String, Set<String>)]())
        XCTAssertNil(PinHostMatcher.match(empty, "anything.com"))
    }

    func testTLDLevelWildcardIsRefused() {
        let tld = PinHostMatcher.build([("*.com", Set(["PIN_FOR_STAR_COM"]))])
        XCTAssertNil(PinHostMatcher.match(tld, "example.com"), "*.com must not match any host")
        XCTAssertNil(PinHostMatcher.match(tld, "anything.com"))
    }

    func testNarrowWildcardStillWorks() {
        let narrow = PinHostMatcher.build([("*.example.com", Set(["PIN_NARROW"]))])
        XCTAssertEqual(PinHostMatcher.match(narrow, "api.example.com"), ["PIN_NARROW"])
    }

    func testWildcardWithAPortMatchesThatPortOnly() {
        let map = PinHostMatcher.build([("*.example.com:443", Set(["PIN_443"])), ("*.example.org", Set(["PIN_ANY_PORT"]))])
        XCTAssertEqual(PinHostMatcher.match(map, "api.example.com", port: 443), ["PIN_443"])
        XCTAssertNil(PinHostMatcher.match(map, "api.example.com", port: 8443), "another port")
        XCTAssertNil(PinHostMatcher.match(map, "api.example.com"), "no port known")
        XCTAssertNil(PinHostMatcher.match(map, "a.b.example.com", port: 443), "still one label only")
        XCTAssertEqual(PinHostMatcher.match(map, "api.example.org", port: 443), ["PIN_ANY_PORT"])
    }

    func testWildcardWithAPortYieldsToAnExactHostPortEntryAndWinsOverThePlainHost() {
        let map = PinHostMatcher.build([
            ("api.example.com:443", Set(["EXACT_PORT"])),
            ("*.example.com:443", Set(["WILD_PORT"])),
            ("web.example.com", Set(["PLAIN_HOST"])),
        ])
        XCTAssertEqual(PinHostMatcher.match(map, "api.example.com", port: 443), ["EXACT_PORT"])
        XCTAssertEqual(PinHostMatcher.match(map, "web.example.com", port: 443), ["WILD_PORT"])
        XCTAssertEqual(PinHostMatcher.match(map, "web.example.com", port: 80), ["PLAIN_HOST"])
    }

    func testANonPositivePortIsIgnored() {
        let map = PinHostMatcher.build([("api.example.com:0", Set(["ZERO"])), ("api.example.com", Set(["PLAIN"]))])
        XCTAssertEqual(PinHostMatcher.match(map, "api.example.com", port: 0), ["PLAIN"])
        XCTAssertEqual(PinHostMatcher.match(map, "api.example.com", port: -1), ["PLAIN"])
    }
}
