import Foundation

/// A JSON value written in the order it was built — the counterpart of the
/// insertion-ordered `org.json.JSONObject` the Kotlin report is made with.
/// The attestation report is serialised once and that string is what is
/// signed, hashed and sent, so the order only has to be stable, not
/// canonical; keeping the order of `ATTESTATION.md` §3 makes reports (and
/// test fixtures) readable.
indirect enum IntegrityJSON: Sendable, Equatable {
    case string(String)
    case int(Int64)
    case bool(Bool)
    case null
    case array([IntegrityJSON])
    case object([Member])

    struct Member: Sendable, Equatable {
        let key: String
        let value: IntegrityJSON

        init(_ key: String, _ value: IntegrityJSON) {
            self.key = key
            self.value = value
        }
    }

    /// `.string(value)`, or `.null` for nil.
    static func optional(_ value: String?) -> IntegrityJSON {
        value.map(IntegrityJSON.string) ?? .null
    }

    static func strings(_ values: [String]) -> IntegrityJSON {
        .array(values.map(IntegrityJSON.string))
    }

    /// Compact JSON text (no whitespace), strings escaped per RFC 8259.
    var serialized: String {
        var out = ""
        write(into: &out)
        return out
    }

    private func write(into out: inout String) {
        switch self {
        case .string(let value):
            Self.writeString(value, into: &out)
        case .int(let value):
            out += String(value)
        case .bool(let value):
            out += value ? "true" : "false"
        case .null:
            out += "null"
        case .array(let values):
            out += "["
            for (index, value) in values.enumerated() {
                if index > 0 { out += "," }
                value.write(into: &out)
            }
            out += "]"
        case .object(let members):
            out += "{"
            for (index, member) in members.enumerated() {
                if index > 0 { out += "," }
                Self.writeString(member.key, into: &out)
                out += ":"
                member.value.write(into: &out)
            }
            out += "}"
        }
    }

    private static func writeString(_ value: String, into out: inout String) {
        out += "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 || scalar.value == 0x2028 || scalar.value == 0x2029 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }
}

/// Lenient reads of a parsed JSON object (`JSONSerialization`), the way
/// `org.json`'s `opt*` accessors read one: a missing key or `null` gives the
/// default, numbers and numeric strings convert into each other.
enum LenientJSON {

    /// The object `data` holds, or nil when it is not a JSON object.
    static func object(_ data: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: Any]
    }

    /// `optString`: the string, a number or boolean as text, "" otherwise.
    static func string(_ object: [String: Any], _ key: String) -> String {
        switch object[key] {
        case let value as String: return value
        case let value as NSNumber:
            if CFGetTypeID(value) == CFBooleanGetTypeID() { return value.boolValue ? "true" : "false" }
            return value.stringValue
        default: return ""
        }
    }

    /// `optString(key).ifBlank { null }`.
    static func nonBlankString(_ object: [String: Any], _ key: String) -> String? {
        let value = string(object, key)
        return value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : value
    }

    /// `optLong(key, default)`.
    static func long(_ object: [String: Any], _ key: String, _ defaultValue: Int64 = 0) -> Int64 {
        switch object[key] {
        case let value as NSNumber where CFGetTypeID(value) != CFBooleanGetTypeID():
            let double = value.doubleValue
            guard double.isFinite, abs(double) < 9.2e18 else { return defaultValue }
            return value.int64Value
        case let value as String:
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            if let long = Int64(trimmed) { return long }
            if let double = Double(trimmed), double.isFinite, abs(double) < 9.2e18 { return Int64(double) }
            return defaultValue
        default:
            return defaultValue
        }
    }

    /// True when `key` is present and not `null` (`has(key) && !isNull(key)`).
    static func hasValue(_ object: [String: Any], _ key: String) -> Bool {
        guard let value = object[key] else { return false }
        return !(value is NSNull)
    }

    /// The non-blank strings of an array (`optJSONArray` + `optString`), in order.
    static func strings(_ object: [String: Any], _ key: String) -> [String] {
        guard let array = object[key] as? [Any] else { return [] }
        return array.compactMap { element -> String? in
            let text: String
            switch element {
            case let value as String: text = value
            case let value as NSNumber: text = value.stringValue
            default: return nil
            }
            return text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : text
        }
    }
}
