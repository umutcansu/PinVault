import Foundation

// A small ASN.1 DER reader and writer: what certificates, SubjectPublicKeyInfo,
// CSRs and ECDSA signatures need. Single-byte tags only (tag numbers 0–30),
// definite lengths only.

/// Why DER input was refused.
enum DERError: Error, Equatable, CustomStringConvertible {
    case truncated
    case indefiniteLength
    case invalidLength
    case unsupportedTag(UInt8)
    case unexpectedTag(expected: UInt8, actual: UInt8)
    case trailingData
    case invalidValue(String)

    var description: String {
        switch self {
        case .truncated: return "DER: input truncated"
        case .indefiniteLength: return "DER: indefinite length is not DER"
        case .invalidLength: return "DER: invalid length"
        case .unsupportedTag(let tag): return String(format: "DER: unsupported tag 0x%02x", tag)
        case .unexpectedTag(let expected, let actual):
            return String(format: "DER: expected tag 0x%02x, found 0x%02x", expected, actual)
        case .trailingData: return "DER: trailing data after the element"
        case .invalidValue(let what): return "DER: \(what)"
        }
    }
}

/// Universal tags (identifier octets) used by the library.
enum ASN1Tag {
    static let boolean: UInt8 = 0x01
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let null: UInt8 = 0x05
    static let objectIdentifier: UInt8 = 0x06
    static let utf8String: UInt8 = 0x0C
    static let printableString: UInt8 = 0x13
    static let t61String: UInt8 = 0x14
    static let ia5String: UInt8 = 0x16
    static let utcTime: UInt8 = 0x17
    static let generalizedTime: UInt8 = 0x18
    static let universalString: UInt8 = 0x1C
    static let bmpString: UInt8 = 0x1E
    static let sequence: UInt8 = 0x30
    static let set: UInt8 = 0x31

    /// `[number]` in the context-specific class.
    static func contextSpecific(_ number: UInt8, constructed: Bool) -> UInt8 {
        precondition(number < 31, "high tag numbers are not supported")
        return 0x80 | (constructed ? 0x20 : 0x00) | number
    }
}

/// One parsed TLV.
struct DERElement: Sendable, Equatable {
    /// The identifier octet.
    let tag: UInt8
    /// The value octets (indices start at 0).
    let content: Data
    /// The whole element: tag, length and value — what a signature covers.
    let encoded: Data

    var isConstructed: Bool { tag & 0x20 != 0 }
    var isContextSpecific: Bool { tag & 0xC0 == 0x80 }
    var tagNumber: UInt8 { tag & 0x1F }

    /// True for `[number]` in the context-specific class (either form).
    func isContextSpecific(_ number: UInt8) -> Bool {
        isContextSpecific && tagNumber == number
    }

    /// Throws unless the tag is `tag`; returns `self` for chaining.
    @discardableResult
    func expect(_ tag: UInt8) throws -> DERElement {
        guard self.tag == tag else { throw DERError.unexpectedTag(expected: tag, actual: self.tag) }
        return self
    }

    /// The elements inside a constructed element.
    func children() throws -> [DERElement] {
        guard isConstructed else { throw DERError.invalidValue("primitive element has no children") }
        return try DER.parseAll(content)
    }

    /// The single element inside an EXPLICIT tag.
    func explicitInner() throws -> DERElement {
        let inner = try children()
        guard inner.count == 1 else { throw DERError.invalidValue("explicit tag must wrap exactly one element") }
        return inner[0]
    }

    // MARK: Values

    /// INTEGER content as encoded (two's complement, big-endian).
    func integerBytes() throws -> Data {
        guard !content.isEmpty else { throw DERError.invalidValue("empty INTEGER") }
        return content
    }

    /// INTEGER magnitude without the sign octet DER adds when the high bit is set.
    func unsignedIntegerBytes() throws -> Data {
        var bytes = try integerBytes()
        while bytes.count > 1, bytes.first == 0x00 { bytes.removeFirst() }
        return Data(bytes)
    }

    /// INTEGER that fits in 64 bits.
    func intValue() throws -> Int {
        let bytes = try integerBytes()
        guard bytes.count <= 8 else { throw DERError.invalidValue("INTEGER too large") }
        var value: Int64 = (bytes.first! & 0x80) != 0 ? -1 : 0
        for byte in bytes { value = (value << 8) | Int64(byte) }
        return Int(value)
    }

    /// OBJECT IDENTIFIER in dotted form.
    func objectIdentifier() throws -> String {
        try DER.decodeObjectIdentifier(content)
    }

    /// BIT STRING: the unused-bit count and the bytes.
    func bitString() throws -> (unusedBits: Int, bytes: Data) {
        guard let first = content.first, first < 8 else { throw DERError.invalidValue("malformed BIT STRING") }
        let bytes = Data(content.dropFirst())
        if bytes.isEmpty, first != 0 { throw DERError.invalidValue("malformed BIT STRING") }
        return (Int(first), bytes)
    }

    /// BIT STRING whose length is a whole number of bytes (keys, signatures).
    func bitStringBytes() throws -> Data {
        let (unused, bytes) = try bitString()
        guard unused == 0 else { throw DERError.invalidValue("BIT STRING is not octet-aligned") }
        return bytes
    }

    func octetString() throws -> Data { content }

    func boolean() throws -> Bool {
        guard content.count == 1 else { throw DERError.invalidValue("malformed BOOLEAN") }
        return content[content.startIndex] != 0
    }

    /// Text of a string type: UTF8String, PrintableString, IA5String,
    /// T61String (read as Latin-1), BMPString, UniversalString.
    func string() throws -> String {
        let decoded: String?
        switch tag {
        case ASN1Tag.utf8String: decoded = String(data: content, encoding: .utf8)
        case ASN1Tag.printableString, ASN1Tag.ia5String: decoded = String(data: content, encoding: .ascii)
        case ASN1Tag.t61String: decoded = String(data: content, encoding: .isoLatin1)
        case ASN1Tag.bmpString: decoded = String(data: content, encoding: .utf16BigEndian)
        case ASN1Tag.universalString: decoded = String(data: content, encoding: .utf32BigEndian)
        default: throw DERError.invalidValue(String(format: "tag 0x%02x is not a string", tag))
        }
        guard let text = decoded else { throw DERError.invalidValue("undecodable string") }
        return text
    }

    /// UTCTime or GeneralizedTime.
    func time() throws -> Date {
        guard let text = String(data: content, encoding: .ascii) else { throw DERError.invalidValue("malformed time") }
        switch tag {
        case ASN1Tag.utcTime: return try DERTime.parse(text, generalized: false)
        case ASN1Tag.generalizedTime: return try DERTime.parse(text, generalized: true)
        default: throw DERError.invalidValue(String(format: "tag 0x%02x is not a time", tag))
        }
    }
}

enum DER {

    // MARK: Reading

    /// Exactly one element; trailing bytes are refused.
    static func parse(_ data: Data) throws -> DERElement {
        let bytes = [UInt8](data)
        var offset = 0
        let element = try readElement(bytes, &offset)
        guard offset == bytes.count else { throw DERError.trailingData }
        return element
    }

    /// The elements of `data`, one after another.
    static func parseAll(_ data: Data) throws -> [DERElement] {
        let bytes = [UInt8](data)
        var offset = 0
        var elements: [DERElement] = []
        while offset < bytes.count {
            elements.append(try readElement(bytes, &offset))
        }
        return elements
    }

    private static func readElement(_ bytes: [UInt8], _ offset: inout Int) throws -> DERElement {
        let start = offset
        guard offset < bytes.count else { throw DERError.truncated }
        let tag = bytes[offset]
        offset += 1
        if tag & 0x1F == 0x1F { throw DERError.unsupportedTag(tag) }
        guard offset < bytes.count else { throw DERError.truncated }
        let first = bytes[offset]
        offset += 1
        var length = 0
        if first < 0x80 {
            length = Int(first)
        } else if first == 0x80 {
            throw DERError.indefiniteLength
        } else {
            let count = Int(first & 0x7F)
            guard count <= 4 else { throw DERError.invalidLength }
            guard offset + count <= bytes.count else { throw DERError.truncated }
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[offset])
                offset += 1
            }
        }
        guard length >= 0, offset + length <= bytes.count else { throw DERError.truncated }
        let content = Data(bytes[offset..<(offset + length)])
        offset += length
        return DERElement(tag: tag, content: content, encoded: Data(bytes[start..<offset]))
    }

    static func decodeObjectIdentifier(_ content: Data) throws -> String {
        guard !content.isEmpty else { throw DERError.invalidValue("empty OBJECT IDENTIFIER") }
        var arcs: [UInt64] = []
        var value: UInt64 = 0
        var started = false
        for byte in content {
            if !started && byte == 0x80 { throw DERError.invalidValue("non-minimal OBJECT IDENTIFIER arc") }
            guard value <= (UInt64.max >> 7) else { throw DERError.invalidValue("OBJECT IDENTIFIER arc too large") }
            value = (value << 7) | UInt64(byte & 0x7F)
            started = true
            if byte & 0x80 == 0 {
                arcs.append(value)
                value = 0
                started = false
            }
        }
        guard !started else { throw DERError.invalidValue("truncated OBJECT IDENTIFIER") }
        let first = arcs[0]
        var parts: [String]
        switch first {
        case ..<40: parts = ["0", String(first)]
        case ..<80: parts = ["1", String(first - 40)]
        default: parts = ["2", String(first - 80)]
        }
        parts += arcs.dropFirst().map { String($0) }
        return parts.joined(separator: ".")
    }

    // MARK: Writing

    /// Tag, length and `content`.
    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(encodeLength(content.count))
        out.append(content)
        return out
    }

    static func encodeLength(_ length: Int) -> Data {
        precondition(length >= 0)
        if length < 0x80 { return Data([UInt8(length)]) }
        var bytes: [UInt8] = []
        var remaining = length
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    static func sequence(_ items: [Data]) -> Data {
        tlv(ASN1Tag.sequence, items.reduce(into: Data()) { $0.append($1) })
    }

    /// SET OF: DER orders the encodings.
    static func set(_ items: [Data]) -> Data {
        let sorted = items.sorted { $0.lexicographicallyPrecedes($1) }
        return tlv(ASN1Tag.set, sorted.reduce(into: Data()) { $0.append($1) })
    }

    static func integer(_ value: Int) -> Data {
        var bytes: [UInt8] = []
        var remaining = Int64(value)
        repeat {
            bytes.insert(UInt8(truncatingIfNeeded: remaining), at: 0)
            remaining >>= 8
        } while remaining != 0 && remaining != -1
        // Keep the sign bit right.
        if value >= 0, bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        if value < 0, bytes[0] & 0x80 == 0 { bytes.insert(0xFF, at: 0) }
        return tlv(ASN1Tag.integer, Data(bytes))
    }

    /// A non-negative INTEGER from its big-endian magnitude (leading zeros
    /// stripped, a 0x00 added when the high bit is set).
    static func integer(unsigned magnitude: Data) -> Data {
        var bytes = [UInt8](magnitude)
        while bytes.count > 1, bytes[0] == 0x00 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0x00] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
        return tlv(ASN1Tag.integer, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tlv(ASN1Tag.boolean, Data([value ? 0xFF : 0x00]))
    }

    static func null() -> Data {
        Data([ASN1Tag.null, 0x00])
    }

    static func objectIdentifier(_ dotted: String) throws -> Data {
        let arcs = try dotted.split(separator: ".", omittingEmptySubsequences: false).map { part -> UInt64 in
            guard !part.isEmpty, part.allSatisfy(\.isASCIIDigit), let arc = UInt64(part) else {
                throw DERError.invalidValue("'\(dotted)' is not an OBJECT IDENTIFIER")
            }
            return arc
        }
        guard arcs.count >= 2, arcs[0] <= 2, arcs[0] == 2 || arcs[1] < 40 else {
            throw DERError.invalidValue("'\(dotted)' is not an OBJECT IDENTIFIER")
        }
        let (firstArc, overflow) = arcs[0].multipliedReportingOverflow(by: 40)
        let (combined, overflow2) = firstArc.addingReportingOverflow(arcs[1])
        guard !overflow, !overflow2 else { throw DERError.invalidValue("OBJECT IDENTIFIER arc too large") }
        var content = Data()
        for arc in [combined] + arcs.dropFirst(2) {
            var chunk: [UInt8] = [UInt8(arc & 0x7F)]
            var remaining = arc >> 7
            while remaining > 0 {
                chunk.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
                remaining >>= 7
            }
            content.append(contentsOf: chunk)
        }
        return tlv(ASN1Tag.objectIdentifier, content)
    }

    static func bitString(_ bytes: Data, unusedBits: UInt8 = 0) -> Data {
        precondition(unusedBits < 8)
        var content = Data([unusedBits])
        content.append(bytes)
        return tlv(ASN1Tag.bitString, content)
    }

    static func octetString(_ bytes: Data) -> Data { tlv(ASN1Tag.octetString, bytes) }
    static func utf8String(_ text: String) -> Data { tlv(ASN1Tag.utf8String, Data(text.utf8)) }
    static func printableString(_ text: String) -> Data { tlv(ASN1Tag.printableString, Data(text.utf8)) }
    static func ia5String(_ text: String) -> Data { tlv(ASN1Tag.ia5String, Data(text.utf8)) }
    static func utcTime(_ date: Date) -> Data { tlv(ASN1Tag.utcTime, Data(DERTime.format(date, generalized: false).utf8)) }
    static func generalizedTime(_ date: Date) -> Data {
        tlv(ASN1Tag.generalizedTime, Data(DERTime.format(date, generalized: true).utf8))
    }

    /// The X.509 rule (RFC 5280 §4.1.2.5): UTCTime for 1950–2049, GeneralizedTime otherwise.
    static func time(_ date: Date) -> Data {
        let year = DERTime.civil(from: Int64(date.timeIntervalSince1970.rounded(.down))).year
        return (1950...2049).contains(year) ? utcTime(date) : generalizedTime(date)
    }

    /// `[number] EXPLICIT`: a constructed context-specific element around `inner` (a whole TLV).
    static func explicit(_ number: UInt8, _ inner: Data) -> Data {
        tlv(ASN1Tag.contextSpecific(number, constructed: true), inner)
    }

    /// `[number] IMPLICIT` with the given content octets.
    static func implicit(_ number: UInt8, constructed: Bool, content: Data) -> Data {
        tlv(ASN1Tag.contextSpecific(number, constructed: constructed), content)
    }

    /// `[number] IMPLICIT` applied to an encoded element: its tag is replaced, the constructed bit kept.
    static func implicit(_ number: UInt8, retagging element: Data) throws -> Data {
        let parsed = try parse(element)
        return implicit(number, constructed: parsed.isConstructed, content: parsed.content)
    }
}

/// UTCTime / GeneralizedTime text, always UTC. Civil-date arithmetic instead
/// of `Calendar` so the result never depends on the device's locale or calendar.
enum DERTime {

    static func parse(_ text: String, generalized: Bool) throws -> Date {
        let chars = Array(text)
        var index = 0
        func digits(_ count: Int) throws -> Int {
            guard index + count <= chars.count else { throw DERError.invalidValue("malformed time '\(text)'") }
            var value = 0
            for _ in 0..<count {
                guard let digit = chars[index].wholeNumberValue, chars[index].isASCII else {
                    throw DERError.invalidValue("malformed time '\(text)'")
                }
                value = value * 10 + digit
                index += 1
            }
            return value
        }
        var year: Int
        if generalized {
            year = try digits(4)
        } else {
            let yy = try digits(2)
            year = yy >= 50 ? 1900 + yy : 2000 + yy
        }
        let month = try digits(2)
        let day = try digits(2)
        let hour = try digits(2)
        let minute = try digits(2)
        var second = 0
        if index < chars.count, chars[index].isASCIIDigit { second = try digits(2) }
        var fraction = 0.0
        if generalized, index < chars.count, chars[index] == "." || chars[index] == "," {
            index += 1
            var scale = 0.1
            var any = false
            while index < chars.count, chars[index].isASCIIDigit {
                fraction += Double(chars[index].wholeNumberValue!) * scale
                scale /= 10
                index += 1
                any = true
            }
            guard any else { throw DERError.invalidValue("malformed time '\(text)'") }
        }
        var offsetSeconds = 0
        if index < chars.count {
            switch chars[index] {
            case "Z":
                index += 1
            case "+", "-":
                let sign = chars[index] == "+" ? 1 : -1
                index += 1
                let hours = try digits(2)
                let minutes = try digits(2)
                offsetSeconds = sign * (hours * 3600 + minutes * 60)
            default:
                throw DERError.invalidValue("malformed time '\(text)'")
            }
        } else if !generalized {
            throw DERError.invalidValue("UTCTime without a zone '\(text)'")
        }
        guard index == chars.count,
              (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second < 61 else {
            throw DERError.invalidValue("malformed time '\(text)'")
        }
        let days = daysFromCivil(year: year, month: month, day: day)
        let seconds = days * 86_400 + Int64(hour * 3600 + minute * 60 + second) - Int64(offsetSeconds)
        return Date(timeIntervalSince1970: TimeInterval(seconds) + fraction)
    }

    static func format(_ date: Date, generalized: Bool) -> String {
        let seconds = Int64(date.timeIntervalSince1970.rounded(.down))
        let civil = civil(from: seconds)
        let secondOfDay = Int(((seconds % 86_400) + 86_400) % 86_400)
        let year = generalized ? String(format: "%04d", civil.year) : String(format: "%02d", civil.year % 100)
        return year + String(
            format: "%02d%02d%02d%02d%02dZ",
            civil.month, civil.day, secondOfDay / 3600, (secondOfDay % 3600) / 60, secondOfDay % 60
        )
    }

    /// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int64 {
        let y = Int64(month <= 2 ? year - 1 : year)
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let m = Int64(month)
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + Int64(day) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    /// The civil date of a Unix time (seconds).
    static func civil(from unixSeconds: Int64) -> (year: Int, month: Int, day: Int) {
        let z0 = unixSeconds >= 0 ? unixSeconds / 86_400 : (unixSeconds - 86_399) / 86_400
        let z = z0 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let day = doy - (153 * mp + 2) / 5 + 1
        let month = mp < 10 ? mp + 3 : mp - 9
        let year = yoe + era * 400 + (month <= 2 ? 1 : 0)
        return (Int(year), Int(month), Int(day))
    }
}

extension Character {
    /// `0`–`9` only (not other Unicode digits).
    var isASCIIDigit: Bool { isASCII && isNumber }
}
