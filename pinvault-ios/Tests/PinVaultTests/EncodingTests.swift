import XCTest
@testable import PinVault

final class EncodingTests: XCTestCase {

    func testBase64Forms() {
        let bytes = Data([0xfb, 0xff, 0xfe, 0x00, 0x01])
        XCTAssertEqual(Base64.encode(bytes), "+//+AAE=")
        XCTAssertEqual(Base64.decode("+//+AAE="), bytes)
        XCTAssertNil(Base64.decode("+//+AAE"), "standard decoding wants the padding")
        XCTAssertEqual(Base64.encodeURL(bytes), "-__-AAE")
        XCTAssertEqual(Base64.decodeURL("-__-AAE"), bytes)
        XCTAssertEqual(Base64.decodeURL("-__-AAE="), bytes)
        XCTAssertNil(Base64.decodeURL("+//+AAE="))
        XCTAssertNil(Base64.decodeURL("A"))
    }

    func testLenientDecodingIsOkios() {
        let bytes = Data([0xfb, 0xff, 0xfe, 0x00, 0x01])
        XCTAssertEqual(Base64.decodeLenient("+//+AAE="), bytes)
        XCTAssertEqual(Base64.decodeLenient("-__-AAE"), bytes, "url alphabet, no padding")
        XCTAssertEqual(Base64.decodeLenient("+//+\nAA E=\n"), bytes, "whitespace ignored")
        XCTAssertEqual(Base64.decodeLenient(""), Data())
        XCTAssertNil(Base64.decodeLenient("AAAAA"), "a single trailing character")
        XCTAssertNil(Base64.decodeLenient("AA=A"), "padding in the middle")
        XCTAssertNil(Base64.decodeLenient("AA*A"))
        XCTAssertEqual(Base64.decodeLenient(pin("A"))?.count, 32)
    }

    func testHex() {
        let bytes = Data([0x3c, 0x4f, 0xab, 0x00])
        XCTAssertEqual(Hex.encode(bytes), "3c4fab00")
        XCTAssertEqual(Hex.colon(bytes), "3C:4F:AB:00")
        XCTAssertEqual(Hex.colon(bytes, uppercase: false), "3c:4f:ab:00")
        XCTAssertEqual(Hex.decode("3C:4f:AB:00"), bytes)
        XCTAssertNil(Hex.decode("abc"))
        XCTAssertNil(Hex.decode("zz"))
    }

    func testPEM() throws {
        let der = Data((0..<100).map { UInt8($0) })
        let pem = PEM.encode(der, label: "PUBLIC KEY")
        let lines = pem.split(separator: "\n")
        XCTAssertEqual(lines.first, "-----BEGIN PUBLIC KEY-----")
        XCTAssertEqual(lines.last, "-----END PUBLIC KEY-----")
        XCTAssertEqual(lines[1].count, 64)
        XCTAssertFalse(pem.hasSuffix("\n"), "the Kotlin publicKeyToPem shape: no trailing newline")
        XCTAssertEqual(PEM.decode(pem, label: "PUBLIC KEY"), der)
        XCTAssertNil(PEM.decode(pem, label: "CERTIFICATE"))

        let two = PEM.encode(Data([1]), label: "CERTIFICATE") + "\r\n" + PEM.encode(Data([2]), label: "CERTIFICATE") + "\n"
        XCTAssertEqual(PEM.decodeAll(two).map(\.der), [Data([1]), Data([2])])
        XCTAssertEqual(PEM.decode(try Fixture.text("ca", "pem")), try Fixture.data("ca", "der"))
    }

    func testHashing() {
        XCTAssertEqual(
            Hashing.sha256Hex(Data("abc".utf8)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        XCTAssertEqual(Hashing.sha256Base64(Data()), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        XCTAssertEqual(Hashing.sha256("abc"), Hashing.sha256(Data("abc".utf8)))
        XCTAssertTrue(Hashing.constantTimeEquals(Data([1, 2]), Data([1, 2])))
        XCTAssertFalse(Hashing.constantTimeEquals(Data([1, 2]), Data([1, 3])))
        XCTAssertFalse(Hashing.constantTimeEquals(Data([1]), Data([1, 2])))
    }

    func testLocked() async {
        let counter = Locked(0)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<100 { group.addTask { counter.withLock { $0 += 1 } } }
        }
        XCTAssertEqual(counter.get(), 100)
        counter.set(5)
        XCTAssertEqual(counter.withLock { $0 * 2 }, 10)
    }
}
