import XCTest
@testable import PinVault

/// OkHttp's `OkHostnameVerifier` rules, as ported.
final class HostnameVerifierTests: XCTestCase {

    func testDNSNamesFromTheSubjectAltName() {
        let leaf = TLSFixture.cert("leaf")  // localhost, 127.0.0.1, mock-tls.sample, api.chain.test
        XCTAssertTrue(HostnameVerifier.verify("localhost", leaf))
        XCTAssertTrue(HostnameVerifier.verify("LOCALHOST", leaf), "case-insensitive")
        XCTAssertTrue(HostnameVerifier.verify("mock-tls.sample", leaf))
        XCTAssertTrue(HostnameVerifier.verify("localhost.", leaf), "absolute name")
        XCTAssertFalse(HostnameVerifier.verify("other.sample", leaf))
        XCTAssertFalse(HostnameVerifier.verify("", leaf))
        XCTAssertFalse(HostnameVerifier.verify("lócalhost", leaf), "non-ASCII")
    }

    func testIPAddressesMatchIPEntriesOnly() {
        let leaf = TLSFixture.cert("leaf")
        XCTAssertTrue(HostnameVerifier.verify("127.0.0.1", leaf))
        XCTAssertTrue(HostnameVerifier.verify("::ffff:127.0.0.1", leaf), "IPv4-mapped IPv6 is the IPv4 address")
        XCTAssertFalse(HostnameVerifier.verify("127.0.0.2", leaf))
        XCTAssertFalse(HostnameVerifier.verify("::1", leaf))
        XCTAssertFalse(HostnameVerifier.verify("1.2.3", leaf), "looks like an address, is none")
    }

    func testTheCommonNameIsNeverConsulted() {
        // CN=localhost, no subjectAltName.
        XCTAssertFalse(HostnameVerifier.verify("localhost", TLSFixture.cert("nosan")))
    }

    func testWildcardPatterns() {
        XCTAssertTrue(HostnameVerifier.verify(hostname: "api.example.com", pattern: "*.example.com"))
        XCTAssertTrue(HostnameVerifier.verify(hostname: "api.example.com", pattern: "*.EXAMPLE.com"))
        XCTAssertFalse(HostnameVerifier.verify(hostname: "example.com", pattern: "*.example.com"), "apex")
        XCTAssertFalse(HostnameVerifier.verify(hostname: "a.b.example.com", pattern: "*.example.com"), "two labels")
        XCTAssertFalse(HostnameVerifier.verify(hostname: "api.example.com", pattern: "a*.example.com"), "partial label")
        XCTAssertFalse(HostnameVerifier.verify(hostname: "api.example.com", pattern: "*.*.com"), "two asterisks")
        XCTAssertFalse(HostnameVerifier.verify(hostname: "com", pattern: "*."), "bare wildcard")
        XCTAssertFalse(HostnameVerifier.verify(hostname: "api.example.com", pattern: "api.*.com"), "not left-most")
    }

    func testMalformedNamesNeverMatch() {
        XCTAssertFalse(HostnameVerifier.verify(hostname: ".example.com", pattern: ".example.com"))
        XCTAssertFalse(HostnameVerifier.verify(hostname: "example.com..", pattern: "example.com.."))
        XCTAssertFalse(HostnameVerifier.verify(hostname: "example.com", pattern: ""))
    }

    func testCanParseAsIPAddress() {
        XCTAssertTrue(HostnameVerifier.canParseAsIPAddress("10.0.0.1"))
        XCTAssertTrue(HostnameVerifier.canParseAsIPAddress("fe80::1"))
        XCTAssertFalse(HostnameVerifier.canParseAsIPAddress("example.com"))
        XCTAssertEqual(HostnameVerifier.ipAddressBytes("[::1]")?.count, 16)
        XCTAssertNil(HostnameVerifier.ipAddressBytes("300.1.1.1"))
    }
}
