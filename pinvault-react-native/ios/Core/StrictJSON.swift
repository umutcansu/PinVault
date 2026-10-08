// Strict JSON for bridge input (the Swift twin of StrictJson.kt).
//
// JSON from JS → Foundation values; `Fields` reads an object key by key and
// `finish()` refuses every key nobody read. Nothing is coerced: a "1" is not a
// number, a 1 is not a boolean (JSONSerialization hands both out as NSNumber;
// the CFBoolean type id tells them apart).
import Foundation

/// A refusal of bridge input; the message names the path (`config.configApis[0].url`).
public struct BridgeInputError: Error, CustomStringConvertible, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

public enum StrictJSON {
    public static let maxInputChars = 256 * 1024
    static let maxDepth = 8

    public static func parseObject(_ json: String, path: String, maxChars: Int = maxInputChars) throws -> Fields {
        if json.utf16.count > maxChars { throw BridgeInputError("\(path): larger than \(maxChars) characters") }
        let value: Any
        do {
            value = try JSONSerialization.jsonObject(with: Data(json.utf8), options: [])
        } catch {
            throw BridgeInputError("\(path): not valid JSON")
        }
        guard let object = value as? [String: Any] else { throw BridgeInputError("\(path): must be an object") }
        try checkDepth(object, path: path, depth: 0)
        return Fields(path: path, map: object)
    }

    private static func checkDepth(_ value: Any, path: String, depth: Int) throws {
        if depth > maxDepth { throw BridgeInputError("\(path): nested too deeply") }
        if let object = value as? [String: Any] {
            for (k, v) in object { try checkDepth(v, path: "\(path).\(k)", depth: depth + 1) }
        } else if let array = value as? [Any] {
            for (i, v) in array.enumerated() { try checkDepth(v, path: "\(path)[\(i)]", depth: depth + 1) }
        }
    }

    static func isBool(_ value: Any) -> Bool {
        guard let n = value as? NSNumber else { return false }
        return CFGetTypeID(n) == CFBooleanGetTypeID()
    }
}

/// One JSON object; every accessor marks its key as known. JSON `null` counts as absent.
public final class Fields {
    public let path: String
    private let map: [String: Any]
    private var known = Set<String>()

    init(path: String, map: [String: Any]) {
        self.path = path
        self.map = map
    }

    private func raw(_ key: String) -> Any? {
        known.insert(key)
        guard let v = map[key], !(v is NSNull) else { return nil }
        return v
    }

    /// Refuses every key no accessor asked for.
    public func finish() throws {
        let unknown = map.keys.filter { !known.contains($0) }.sorted()
        if !unknown.isEmpty {
            throw BridgeInputError(
                "\(path): unknown key\(unknown.count > 1 ? "s" : "") \(unknown.map { "'\($0)'" }.joined(separator: ", "))"
            )
        }
    }

    private static func badChar(_ c: Unicode.Scalar, multiline: Bool) -> Bool {
        (c.value < 0x20 || c.value == 0x7f) && !(multiline && (c == "\n" || c == "\r"))
    }

    public func string(_ key: String, maxLength: Int = 2048, allowEmpty: Bool = false, multiline: Bool = false) throws -> String? {
        guard let v = raw(key) else { return nil }
        guard let s = v as? String else { throw BridgeInputError("\(path).\(key): must be a string") }
        if s.count > maxLength { throw BridgeInputError("\(path).\(key): longer than \(maxLength) characters") }
        if !allowEmpty && s.isEmpty { throw BridgeInputError("\(path).\(key): must not be empty") }
        if s.unicodeScalars.contains(where: { Fields.badChar($0, multiline: multiline) }) {
            throw BridgeInputError("\(path).\(key): control characters are not allowed")
        }
        return s
    }

    public func requireString(_ key: String, maxLength: Int = 2048) throws -> String {
        guard let s = try string(key, maxLength: maxLength) else { throw BridgeInputError("\(path).\(key): required") }
        return s
    }

    /// Free text (a request body): any characters, bounded length.
    public func text(_ key: String, maxLength: Int) throws -> String? {
        guard let v = raw(key) else { return nil }
        guard let s = v as? String else { throw BridgeInputError("\(path).\(key): must be a string") }
        if s.utf16.count > maxLength { throw BridgeInputError("\(path).\(key): longer than \(maxLength) characters") }
        return s
    }

    public func bool(_ key: String) throws -> Bool? {
        guard let v = raw(key) else { return nil }
        guard StrictJSON.isBool(v), let n = v as? NSNumber else { throw BridgeInputError("\(path).\(key): must be a boolean") }
        return n.boolValue
    }

    public func int64(_ key: String, min: Int64, max: Int64) throws -> Int64? {
        guard let v = raw(key) else { return nil }
        guard !StrictJSON.isBool(v), let n = v as? NSNumber else { throw BridgeInputError("\(path).\(key): must be a number") }
        let d = n.doubleValue
        if d != d.rounded() { throw BridgeInputError("\(path).\(key): must be a whole number") }
        if d < Double(min) || d > Double(max) { throw BridgeInputError("\(path).\(key): must be between \(min) and \(max)") }
        return Int64(d)
    }

    public func int(_ key: String, min: Int, max: Int) throws -> Int? {
        try int64(key, min: Int64(min), max: Int64(max)).map { Int($0) }
    }

    public func double(_ key: String, min: Double, max: Double) throws -> Double? {
        guard let v = raw(key) else { return nil }
        guard !StrictJSON.isBool(v), let n = v as? NSNumber else { throw BridgeInputError("\(path).\(key): must be a number") }
        let d = n.doubleValue
        if d < min || d > max { throw BridgeInputError("\(path).\(key): must be between \(min) and \(max)") }
        return d
    }

    public func stringList(_ key: String, maxItems: Int = 64, maxLength: Int = 2048, multiline: Bool = false) throws -> [String]? {
        guard let v = raw(key) else { return nil }
        guard let list = v as? [Any] else { throw BridgeInputError("\(path).\(key): must be a list of strings") }
        if list.count > maxItems { throw BridgeInputError("\(path).\(key): more than \(maxItems) items") }
        return try list.enumerated().map { i, item in
            guard let s = item as? String else { throw BridgeInputError("\(path).\(key)[\(i)]: must be a string") }
            if s.isEmpty || s.count > maxLength {
                throw BridgeInputError("\(path).\(key)[\(i)]: must be 1 to \(maxLength) characters")
            }
            if s.unicodeScalars.contains(where: { Fields.badChar($0, multiline: multiline) }) {
                throw BridgeInputError("\(path).\(key)[\(i)]: control characters are not allowed")
            }
            return s
        }
    }

    public func object(_ key: String) throws -> Fields? {
        guard let v = raw(key) else { return nil }
        guard let o = v as? [String: Any] else { throw BridgeInputError("\(path).\(key): must be an object") }
        return Fields(path: "\(path).\(key)", map: o)
    }

    public func objectList(_ key: String, maxItems: Int) throws -> [Fields]? {
        guard let v = raw(key) else { return nil }
        guard let list = v as? [Any] else { throw BridgeInputError("\(path).\(key): must be a list of objects") }
        if list.count > maxItems { throw BridgeInputError("\(path).\(key): more than \(maxItems) items") }
        return try list.enumerated().map { i, item in
            guard let o = item as? [String: Any] else { throw BridgeInputError("\(path).\(key)[\(i)]: must be an object") }
            return Fields(path: "\(path).\(key)[\(i)]", map: o)
        }
    }

    /// A string → string map (`ios.resolve`, request headers).
    public func stringMap(_ key: String, maxItems: Int, maxKeyLength: Int, maxValueLength: Int) throws -> [String: String]? {
        guard let v = raw(key) else { return nil }
        guard let o = v as? [String: Any] else { throw BridgeInputError("\(path).\(key): must be an object") }
        if o.count > maxItems { throw BridgeInputError("\(path).\(key): more than \(maxItems) entries") }
        var out: [String: String] = [:]
        for (name, value) in o {
            if name.isEmpty || name.count > maxKeyLength {
                throw BridgeInputError("\(path).\(key): key '\(name.prefix(40))' has a bad length")
            }
            guard let s = value as? String else { throw BridgeInputError("\(path).\(key).\(name): must be a string") }
            if s.count > maxValueLength { throw BridgeInputError("\(path).\(key).\(name): longer than \(maxValueLength) characters") }
            out[name] = s
        }
        return out
    }

    /// An enum by its raw value (= the Kotlin constant name).
    public func enumValue<E: RawRepresentable & CaseIterable>(_ key: String, _ type: E.Type) throws -> E? where E.RawValue == String {
        guard let s = try string(key, maxLength: 64) else { return nil }
        guard let e = E(rawValue: s) else {
            throw BridgeInputError("\(path).\(key): '\(s)' is not one of \(E.allCases.map(\.rawValue).joined(separator: ", "))")
        }
        return e
    }
}
