import XCTest
@testable import PinVault

/// The code the device shows must equal the one the dashboard shows next to
/// its request: 80 bits of the key's SHA-256, 16 characters. Same vectors as
/// the server's (SERVER_IMPLEMENTATION_GUIDE.md) (Kotlin `VerificationCodeTest`).
final class VerificationCodeTests: XCTestCase {

    private let pinvaultDigest = Data(base64Encoded: "B2kYMhZfDfCB5iZLbIoeW2GaszFr1dWvNKg4Kz97ayY=")!

    func testKnownDigestsGiveTheCodesTheServerGives() throws {
        XCTAssertEqual(try VerificationCode.ofDigest(pinvaultDigest), "0XMH-GCGP-BW6Z-10F6")
        XCTAssertEqual(try VerificationCode.ofDigest(Data(count: 32)), "0000-0000-0000-0000")
        XCTAssertEqual(try VerificationCode.ofDigest(Data(repeating: 0xFF, count: 32)), "ZZZZ-ZZZZ-ZZZZ-ZZZZ")
    }

    func testTheDigestInTheTestIsSha256OfPinvault() {
        XCTAssertEqual(Hashing.sha256("pinvault"), pinvaultDigest)
    }

    func testTheFirstEightCharactersAreThe40BitCodeEarlierVersionsShowed() throws {
        XCTAssertTrue(try VerificationCode.ofDigest(pinvaultDigest).hasPrefix("0XMH-GCGP-"))
    }

    func testTheCodeIsExactlyTheFirstTenBytesOfTheDigest() throws {
        let digest = Hashing.sha256("some key")
        var sameStart = digest
        for i in 10..<sameStart.count { sameStart[i] = sameStart[i] &+ 1 }
        XCTAssertEqual(try VerificationCode.ofDigest(digest), try VerificationCode.ofDigest(sameStart))
        var tenthChanged = digest
        tenthChanged[9] = tenthChanged[9] &+ 1
        XCTAssertNotEqual(try VerificationCode.ofDigest(digest), try VerificationCode.ofDigest(tenthChanged))

        func code(_ index: Int, _ value: UInt8) throws -> String {
            var bytes = Data(count: 32)
            bytes[index] = value
            return try VerificationCode.ofDigest(bytes)
        }
        // 5 bytes = 8 characters: the last byte of each half lands in that half's last characters.
        XCTAssertEqual(try code(4, 1), "0000-0001-0000-0000")
        XCTAssertEqual(try code(9, 1), "0000-0000-0000-0001")
        XCTAssertEqual(try code(0, 0x80), "G000-0000-0000-0000")
    }

    func testAKeysCodeIsTheCodeOfItsSubjectPublicKeyInfoHash() throws {
        let keys = TestKeyPair()
        let code = try VerificationCode.of(publicKey: keys.publicKey)
        XCTAssertEqual(code, try VerificationCode.ofDigest(Hashing.sha256(keys.spki)))
        XCTAssertNotNil(code.range(of: "^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$", options: .regularExpression), code)
    }

    func testATooShortDigestIsRefused() {
        XCTAssertThrowsError(try VerificationCode.ofDigest(Data(count: 9)))
    }
}
