import XCTest
@testable import PinVault

final class DERTests: XCTestCase {

    func testIntegersEncodeMinimallyWithTheRightSign() throws {
        XCTAssertEqual(DER.integer(0), Data(hex: "020100"))
        XCTAssertEqual(DER.integer(127), Data(hex: "02017f"))
        XCTAssertEqual(DER.integer(128), Data(hex: "02020080"))
        XCTAssertEqual(DER.integer(256), Data(hex: "02020100"))
        XCTAssertEqual(DER.integer(-1), Data(hex: "0201ff"))
        XCTAssertEqual(DER.integer(-128), Data(hex: "020180"))
        XCTAssertEqual(DER.integer(-129), Data(hex: "0202ff7f"))
        for value in [0, 1, -1, 127, 128, -128, -129, 65_535, Int(Int32.max), Int(Int32.min), Int.max, Int.min] {
            XCTAssertEqual(try DER.parse(DER.integer(value)).intValue(), value)
        }
    }

    func testUnsignedBigIntegersGetALeadingZeroOnlyWhenTheHighBitIsSet() throws {
        let magnitude = Data(hex: "ff00ff00ff00ff01")
        let encoded = DER.integer(unsigned: magnitude)
        XCTAssertEqual(encoded, Data(hex: "020900ff00ff00ff00ff01"))
        let parsed = try DER.parse(encoded)
        XCTAssertEqual(try parsed.integerBytes(), Data(hex: "00ff00ff00ff00ff01"))
        XCTAssertEqual(try parsed.unsignedIntegerBytes(), magnitude)
        // Leading zeros of the magnitude are dropped.
        XCTAssertEqual(DER.integer(unsigned: Data(hex: "00000105")), Data(hex: "02020105"))
        XCTAssertEqual(DER.integer(unsigned: Data()), Data(hex: "020100"))
        // A 32-byte value with the high bit set (an ECDSA r) is 33 content bytes.
        let r = Data(repeating: 0x80, count: 32)
        XCTAssertEqual(try DER.parse(DER.integer(unsigned: r)).content.count, 33)
        XCTAssertThrowsError(try DER.parse(Data(hex: "0209010000000000000000")).intValue())
    }

    func testObjectIdentifiers() throws {
        let vectors: [(String, String)] = [
            ("1.2.840.10045.2.1", "06072a8648ce3d0201"),
            ("1.2.840.10045.3.1.7", "06082a8648ce3d030107"),
            ("1.2.840.113549.1.1.1", "06092a864886f70d010101"),
            ("2.5.29.17", "0603551d11"),
            ("1.3.6.1.4.1.11129.2.1.17", "060a2b06010401d679020111"),
            ("2.999.3", "0603883703"),
        ]
        for (dotted, hex) in vectors {
            XCTAssertEqual(try DER.objectIdentifier(dotted), Data(hex: hex), dotted)
            XCTAssertEqual(try DER.parse(Data(hex: hex)).objectIdentifier(), dotted)
        }
        for bad in ["", "1", "3.1", "1.40", "1..2", "1.2.a"] {
            XCTAssertThrowsError(try DER.objectIdentifier(bad), bad)
        }
        XCTAssertThrowsError(try DER.parse(Data(hex: "06022a86")).objectIdentifier(), "truncated arc")
        XCTAssertThrowsError(try DER.parse(Data(hex: "0603808001")).objectIdentifier(), "non-minimal arc")
    }

    func testStringsBooleansNullBitAndOctetStrings() throws {
        XCTAssertEqual(DER.null(), Data(hex: "0500"))
        XCTAssertEqual(DER.boolean(true), Data(hex: "0101ff"))
        XCTAssertTrue(try DER.parse(DER.boolean(true)).boolean())
        XCTAssertFalse(try DER.parse(DER.boolean(false)).boolean())
        XCTAssertEqual(try DER.parse(DER.utf8String("Çağrı ✓")).string(), "Çağrı ✓")
        XCTAssertEqual(try DER.parse(DER.printableString("PinVault Test")).string(), "PinVault Test")
        XCTAssertEqual(try DER.parse(DER.ia5String("a@b.c")).string(), "a@b.c")
        XCTAssertEqual(try DER.parse(Data(hex: "1e0400410042")).string(), "AB", "BMPString")
        XCTAssertThrowsError(try DER.parse(DER.integer(1)).string())

        let bits = DER.bitString(Data(hex: "0102"), unusedBits: 0)
        XCTAssertEqual(bits, Data(hex: "0303000102"))
        XCTAssertEqual(try DER.parse(bits).bitStringBytes(), Data(hex: "0102"))
        let partial = try DER.parse(DER.bitString(Data(hex: "a0"), unusedBits: 5)).bitString()
        XCTAssertEqual(partial.unusedBits, 5)
        XCTAssertThrowsError(try DER.parse(DER.bitString(Data(hex: "a0"), unusedBits: 5)).bitStringBytes())
        XCTAssertEqual(try DER.parse(DER.octetString(Data(hex: "deadbeef"))).octetString(), Data(hex: "deadbeef"))
    }

    func testSequencesSetsAndLongLengths() throws {
        let long = Data(repeating: 0xAB, count: 300)
        let encoded = DER.sequence([DER.octetString(long), DER.null()])
        XCTAssertEqual(encoded.prefix(4), Data(hex: "30820132"))
        let children = try DER.parse(encoded).expect(ASN1Tag.sequence).children()
        XCTAssertEqual(children.count, 2)
        XCTAssertEqual(children[0].content, long)
        XCTAssertEqual(children[0].encoded.prefix(4), Data(hex: "0482012c"))
        XCTAssertEqual(children[1].tag, ASN1Tag.null)
        XCTAssertEqual(DER.encodeLength(127), Data(hex: "7f"))
        XCTAssertEqual(DER.encodeLength(128), Data(hex: "8180"))
        XCTAssertEqual(DER.encodeLength(65_536), Data(hex: "83010000"))
        // SET OF is ordered by encoding.
        XCTAssertEqual(DER.set([DER.integer(2), DER.integer(1)]), Data(hex: "3106020101020102"))
    }

    func testExplicitAndImplicitTags() throws {
        let explicit = DER.explicit(0, DER.integer(2))
        XCTAssertEqual(explicit, Data(hex: "a003020102"))
        let parsed = try DER.parse(explicit)
        XCTAssertTrue(parsed.isContextSpecific(0))
        XCTAssertTrue(parsed.isConstructed)
        XCTAssertEqual(try parsed.explicitInner().intValue(), 2)

        let implicit = DER.implicit(2, constructed: false, content: Data("example.com".utf8))
        XCTAssertEqual(implicit.first, 0x82)
        XCTAssertEqual(try DER.implicit(1, retagging: DER.sequence([DER.null()])), Data(hex: "a1020500"))
        XCTAssertEqual(ASN1Tag.contextSpecific(3, constructed: true), 0xA3)
    }

    func testTimes() throws {
        // 2026-10-06T22:39:20Z
        let date = Date(timeIntervalSince1970: 1_791_326_360)
        XCTAssertEqual(String(decoding: DER.utcTime(date).dropFirst(2), as: UTF8.self), "261006223920Z")
        XCTAssertEqual(String(decoding: DER.generalizedTime(date).dropFirst(2), as: UTF8.self), "20261006223920Z")
        XCTAssertEqual(try DER.parse(DER.utcTime(date)).time(), date)
        XCTAssertEqual(try DER.parse(DER.generalizedTime(date)).time(), date)
        // RFC 5280: UTCTime until 2049, GeneralizedTime from 2050.
        XCTAssertEqual(DER.time(date).first, ASN1Tag.utcTime)
        XCTAssertEqual(DER.time(Date(timeIntervalSince1970: 2_737_406_360)).first, ASN1Tag.generalizedTime)
        XCTAssertEqual(DER.time(Date(timeIntervalSince1970: -700_000_000)).first, ASN1Tag.generalizedTime, "1947")

        XCTAssertEqual(try DERTime.parse("500101000000Z", generalized: false), Date(timeIntervalSince1970: -631_152_000))
        XCTAssertEqual(try DERTime.parse("491231235959Z", generalized: false), Date(timeIntervalSince1970: 2_524_607_999))
        XCTAssertEqual(try DERTime.parse("20000229120000Z", generalized: true), Date(timeIntervalSince1970: 951_825_600))
        XCTAssertEqual(try DERTime.parse("20000229120000.5Z", generalized: true).timeIntervalSince1970, 951_825_600.5)
        XCTAssertEqual(try DERTime.parse("000229130000+0100", generalized: false), Date(timeIntervalSince1970: 951_825_600))
        for bad in ["2610062239Q", "261306223920Z", "26100622392", "x61006223920Z"] {
            XCTAssertThrowsError(try DERTime.parse(bad, generalized: false), bad)
        }
        XCTAssertEqual(DERTime.civil(from: 0).year, 1970)
        XCTAssertEqual(DERTime.civil(from: -1).year, 1969)
        XCTAssertEqual(DERTime.daysFromCivil(year: 2026, month: 10, day: 7), 20_733)
    }

    func testMalformedInputIsRefused() {
        XCTAssertThrowsError(try DER.parse(Data())) { XCTAssertEqual($0 as? DERError, .truncated) }
        XCTAssertThrowsError(try DER.parse(Data(hex: "3005020101"))) { XCTAssertEqual($0 as? DERError, .truncated) }
        XCTAssertThrowsError(try DER.parse(Data(hex: "30800000"))) { XCTAssertEqual($0 as? DERError, .indefiniteLength) }
        XCTAssertThrowsError(try DER.parse(Data(hex: "02010100"))) { XCTAssertEqual($0 as? DERError, .trailingData) }
        XCTAssertThrowsError(try DER.parse(Data(hex: "3f0100"))) { XCTAssertEqual($0 as? DERError, .unsupportedTag(0x3f)) }
        XCTAssertThrowsError(try DER.parse(Data(hex: "0285ffffffffff"))) { XCTAssertEqual($0 as? DERError, .invalidLength) }
        XCTAssertThrowsError(try DER.parse(DER.null()).expect(ASN1Tag.sequence)) {
            XCTAssertEqual($0 as? DERError, .unexpectedTag(expected: 0x30, actual: 0x05))
        }
        XCTAssertThrowsError(try DER.parse(DER.null()).children())
    }
}
