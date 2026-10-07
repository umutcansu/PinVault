import XCTest
@testable import PinVault

/// The request hash an integrity token is bound to. The vectors are shared
/// with the reference server (`IntegrityVerificationTest`) and
/// SERVER_IMPLEMENTATION_GUIDE.md (Kotlin `IntegrityRequestHashTest`).
final class IntegrityRequestHashTests: XCTestCase {

    private let csr = Data((0..<10).map { UInt8($0) })

    func testMatchesTheSharedTestVectors() {
        XCTAssertEqual(IntegrityRequestHash.of(deviceId: "a1b2c3d4e5f60718", csrDer: csr), "rFm1yo7zjKdHsevPadQ1stM-oQ8aG4umNk-CIGhG0ds")
        // No device id: the empty string, not "nil".
        XCTAssertEqual(IntegrityRequestHash.of(deviceId: nil, csrDer: csr), "rYKab7GF91mo9M4VRpmjjOj4gPuKNrCVklCusNHMdno")
        XCTAssertEqual(IntegrityRequestHash.of(deviceId: nil, csrDer: csr), IntegrityRequestHash.of(deviceId: "", csrDer: csr))
    }

    func testIsAValidPlayIntegrityRequestHashAndNonce() {
        let hash = IntegrityRequestHash.of(deviceId: "device", csrDer: csr)
        XCTAssertEqual(hash.count, 43)
        XCTAssertNotNil(hash.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression))
    }

    func testAnotherCsrOrAnotherDeviceIdGivesAnotherHash() {
        let base = IntegrityRequestHash.of(deviceId: "device", csrDer: csr)
        XCTAssertNotEqual(base, IntegrityRequestHash.of(deviceId: "device-2", csrDer: csr))
        XCTAssertNotEqual(base, IntegrityRequestHash.of(deviceId: "device", csrDer: csr + Data([0])))
    }

    func testBase64UrlAgreesWithTheReferenceEncodingForEveryLength() {
        var generator = SystemRandomNumberGenerator()
        for size in 0...70 {
            let bytes = Data((0..<size).map { _ in UInt8.random(in: 0...255, using: &generator) })
            let reference = bytes.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .trimmingCharacters(in: CharacterSet(charactersIn: "="))
            XCTAssertEqual(IntegrityRequestHash.base64Url(bytes), reference, "size \(size)")
            XCTAssertFalse(IntegrityRequestHash.base64Url(bytes).contains("="))
        }
    }
}
