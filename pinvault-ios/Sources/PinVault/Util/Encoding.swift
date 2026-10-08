import Foundation

/// Base64 in the forms the library sends and reads.
enum Base64 {

    /// Standard alphabet, with padding, no line breaks (Android `NO_WRAP`).
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    /// Standard alphabet, padding required: exactly what ``encode(_:)`` writes.
    static func decode(_ text: String) -> Data? {
        Data(base64Encoded: text)
    }

    /// URL-safe alphabet without padding (RFC 4648 §5).
    static func encodeURL(_ data: Data) -> String {
        encode(data)
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// URL-safe alphabet, padding optional.
    static func decodeURL(_ text: String) -> Data? {
        guard !text.contains("+"), !text.contains("/") else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = standard.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 { standard += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: standard)
    }

    /// Okio's `decodeBase64()`: either alphabet, whitespace ignored, padding
    /// optional; null for anything else. Used where the Kotlin code decodes
    /// with Okio (`clientCaPins`).
    static func decodeLenient(_ text: String) -> Data? {
        var chars = Array(text.utf8)
        while let last = chars.last, last == UInt8(ascii: "=") || isWhitespace(last) {
            chars.removeLast()
        }
        var out = Data()
        out.reserveCapacity(chars.count * 3 / 4)
        var word: UInt32 = 0
        var count = 0
        for c in chars {
            let bits: UInt32
            switch c {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): bits = UInt32(c - UInt8(ascii: "A"))
            case UInt8(ascii: "a")...UInt8(ascii: "z"): bits = UInt32(c - UInt8(ascii: "a")) + 26
            case UInt8(ascii: "0")...UInt8(ascii: "9"): bits = UInt32(c - UInt8(ascii: "0")) + 52
            case UInt8(ascii: "+"), UInt8(ascii: "-"): bits = 62
            case UInt8(ascii: "/"), UInt8(ascii: "_"): bits = 63
            default:
                if isWhitespace(c) { continue }
                return nil
            }
            word = (word << 6) | bits
            count += 1
            if count % 4 == 0 {
                out.append(UInt8((word >> 16) & 0xFF))
                out.append(UInt8((word >> 8) & 0xFF))
                out.append(UInt8(word & 0xFF))
                word = 0
            }
        }
        switch count % 4 {
        case 1: return nil
        case 2:
            word <<= 12
            out.append(UInt8((word >> 16) & 0xFF))
        case 3:
            word <<= 6
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
        default: break
        }
        return out
    }

    private static func isWhitespace(_ c: UInt8) -> Bool {
        c == UInt8(ascii: "\n") || c == UInt8(ascii: "\r") || c == UInt8(ascii: " ") || c == UInt8(ascii: "\t")
    }
}

/// Hex text.
enum Hex {

    /// Lowercase, no separators (`3c4fab…`).
    static func encode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Colon separated (`3C:4F:AB` / `3c:4f:ab`), as `keytool` and `openssl -c` print digests.
    static func colon(_ data: Data, uppercase: Bool = true) -> String {
        data.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined(separator: ":")
    }

    /// Either case, optional colons; nil for anything else or an odd number of digits.
    static func decode(_ text: String) -> Data? {
        let digits = Array(text.replacingOccurrences(of: ":", with: "").utf8)
        guard digits.count % 2 == 0 else { return nil }
        var out = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            guard let high = nibble(digits[index]), let low = nibble(digits[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}

/// PEM armour (RFC 7468).
enum PEM {

    /// One block: 64-character lines, no trailing newline — the shape of the
    /// Kotlin `publicKeyToPem` (`-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----`).
    static func encode(_ der: Data, label: String) -> String {
        let body = Base64.encode(der)
        var lines: [String] = []
        var index = body.startIndex
        while index < body.endIndex {
            let end = body.index(index, offsetBy: 64, limitedBy: body.endIndex) ?? body.endIndex
            lines.append(String(body[index..<end]))
            index = end
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----"
    }

    /// Every block in `text`, in order, with its label.
    static func decodeAll(_ text: String) -> [(label: String, der: Data)] {
        var blocks: [(label: String, der: Data)] = []
        var label: String?
        var body = ""
        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if label == nil {
                if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
                    label = String(line.dropFirst("-----BEGIN ".count).dropLast(5))
                    body = ""
                }
            } else if line.hasPrefix("-----END ") {
                let endLabel = String(line.dropFirst("-----END ".count).dropLast(5))
                if endLabel == label, let der = Data(base64Encoded: body) {
                    blocks.append((endLabel, der))
                }
                label = nil
            } else if !line.isEmpty, !line.contains(":") {
                // RFC 1421 headers ("Proc-Type: …") are skipped.
                body += line
            }
        }
        return blocks
    }

    /// The first block with `label` (any label when nil).
    static func decode(_ text: String, label: String? = nil) -> Data? {
        decodeAll(text).first { label == nil || $0.label == label }?.der
    }
}
