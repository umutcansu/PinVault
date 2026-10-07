import Foundation
import Security
import XCTest
@testable import PinVault

/// Port of BoundedBodyTest: declared lengths, counted lengths, the cut-off
/// prefix — on the collector the transport feeds (``BoundedBuffer``).
final class BoundedBodyTests: XCTestCase {

    private func whole(_ maxBytes: Int64, _ what: String = "test") -> BoundedBuffer {
        BoundedBuffer(limit: .always(maxBytes, what))
    }

    /// Feeds `bytes` in 4 KiB chunks until the buffer refuses; returns how many bytes were offered.
    @discardableResult
    private func feed(_ buffer: inout BoundedBuffer, _ bytes: Data) throws -> Int {
        var offset = 0
        while offset < bytes.count {
            let chunk = bytes[offset..<min(offset + 4096, bytes.count)]
            offset += chunk.count
            try buffer.append(Data(chunk))
            if buffer.isComplete { break }
        }
        return offset
    }

    func testABodyWithinTheLimitComesBackWhole() throws {
        let bytes = Data((0..<10_000).map { UInt8(truncatingIfNeeded: $0) })
        var declared = whole(10_000)
        try declared.begin(statusCode: 200, declaredLength: 10_000)
        try feed(&declared, bytes)
        XCTAssertEqual(declared.data, bytes)

        var chunked = whole(10_000)
        try chunked.begin(statusCode: 200, declaredLength: -1)
        try feed(&chunked, bytes)
        XCTAssertEqual(chunked.data, bytes)
    }

    func testADeclaredLengthOverTheLimitIsRefusedBeforeTheBodyIsRead() {
        var buffer = whole(10_000, "config")
        do {
            try buffer.begin(statusCode: 200, declaredLength: 10_001)
            XCTFail("expected a refusal")
        } catch let error as ResponseTooLargeException {
            XCTAssertEqual(error.maxBytes, 10_000)
            XCTAssertEqual(error.declared, 10_001)
            XCTAssertEqual(error.message, "The config response body exceeds 10000 bytes (Content-Length: 10001); refused")
        } catch {
            XCTFail("\(error)")
        }
        XCTAssertTrue(buffer.data.isEmpty, "nothing was read")
    }

    func testAnUndeclaredBodyIsCutOffOneBytePastTheLimit() throws {
        var buffer = whole(10_000, "config")
        try buffer.begin(statusCode: 200, declaredLength: -1)
        do {
            try feed(&buffer, Data(count: 1_000_000))
            XCTFail("expected a refusal")
        } catch let error as ResponseTooLargeException {
            XCTAssertNil(error.declared)
            XCTAssertEqual(error.message, "The config response body exceeds 10000 bytes; refused")
        }
        XCTAssertEqual(buffer.data.count, 10_001, "at most one byte over the limit is kept")
    }

    func testAStringBodyHonoursTheCharsetAndTheLimit() throws {
        let latin1 = "héllo".data(using: .isoLatin1)!
        let response = HTTPURLResponse(url: URL(string: "https://x")!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["Content-Type": "text/plain; charset=iso-8859-1"])
        XCTAssertEqual(BoundedBody.text(latin1, response), "héllo")
        XCTAssertEqual(BoundedBody.text(Data("héllo".utf8), nil), "héllo")

        var buffer = whole(3)
        try buffer.begin(statusCode: 200, declaredLength: -1)
        XCTAssertThrowsError(try buffer.append(Data("too long".utf8)))
    }

    func testAPrefixIsCutNeverRefused() throws {
        XCTAssertEqual(BoundedBody.prefixText(Data("abcdef".utf8), 3), "abc")
        XCTAssertEqual(BoundedBody.prefixText(Data("abcdef".utf8), 200), "abcdef")
        XCTAssertEqual(BoundedBody.prefixText(Data(), 200), "")

        // An error status under a whole-read limit: kept as a prefix.
        var buffer = BoundedBuffer(limit: BoundedBody.Limit(maxBytes: 10, what: "vault file", prefixBytes: 3))
        try buffer.begin(statusCode: 412, declaredLength: 5_000)
        try feed(&buffer, Data(repeating: 0x78, count: 5_000))
        XCTAssertEqual(buffer.data, Data("xxx".utf8))
        XCTAssertTrue(buffer.isComplete)
    }

    func testWithoutALimitEverythingIsKept() throws {
        var buffer = BoundedBuffer(limit: nil)
        try buffer.begin(statusCode: 200, declaredLength: 3_000_000)
        try feed(&buffer, Data(count: 3_000_000))
        XCTAssertEqual(buffer.data.count, 3_000_000)
    }

    func testTheLimitsAreTheKotlinOnes() {
        XCTAssertEqual(BoundedBody.configMaxBytes, 1_048_576)
        XCTAssertEqual(BoundedBody.smallMaxBytes, 262_144)
        XCTAssertEqual(BoundedBody.vaultMaxBytes, 67_108_864)
    }
}
