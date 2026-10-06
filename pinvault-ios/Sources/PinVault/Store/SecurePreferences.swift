import Foundation

/// Preferences whose values are encrypted (AES-256-GCM) and whose names are
/// hidden (HMAC-SHA256) with the store keys (``PrefsCipher``), over one
/// ``PrefsFile``.
///
/// Several stores can share one `fileName`, each in its own `namespace`: an
/// entry is stored under `<namespace tag>.<key tag>`, both HMACs, so
/// `edit().clear()` removes one namespace and leaves the others. The sealed
/// value carries its type and logical key and is bound to its file and stored
/// name (GCM associated data): an entry copied to another name or file does
/// not open. An entry that does not open reads as absent and is dropped.
///
/// Keys that fail outright (Keychain locked or failing) or a file that cannot
/// be read are a different thing: the entry may be perfectly good, it just
/// cannot be read now. It is kept. What the read returns then depends on
/// `strict`: a strict store throws ``PinVaultError/storeUnreadable(message:cause:)``,
/// so its owner can tell "unreadable" from "absent" and fail closed (the pin
/// config and the signing-key set: an unreadable replay watermark or key set
/// must not read as "none"). The other stores get the default value. Writes
/// throw that error in either kind of store.
///
/// Change listeners are called on the thread that writes.
final class SecurePreferences: PreferenceStore, Sendable {

    static let namespaceTagLength = 12
    static let keyTagLength = 32

    private static let tString: UInt8 = 1
    private static let tInt: UInt8 = 2
    private static let tLong: UInt8 = 3
    private static let tFloat: UInt8 = 4
    private static let tBoolean: UInt8 = 5
    private static let tStringSet: UInt8 = 6

    typealias Listener = @Sendable (_ key: String) -> Void

    private let backing: PrefsFile
    private let fileName: String
    private let namespace: String
    private let cipher: any PrefsCipher
    private let strict: Bool
    private let namespaceTag: String
    private let storedNames = Locked<[String: String]>([:])
    private let listeners = Locked<[UUID: Listener]>([:])
    private let log = PinVaultLog.tag("SecurePreferences")

    /// Throws ``PinVaultError/storeUnreadable(message:cause:)`` when the keys
    /// cannot be used right now (the namespace tag is an HMAC).
    init(backing: PrefsFile, fileName: String, namespace: String, cipher: any PrefsCipher, strict: Bool = false) throws {
        self.backing = backing
        self.fileName = fileName
        self.namespace = namespace
        self.cipher = cipher
        self.strict = strict
        do {
            namespaceTag = Self.tag(try cipher.mac(Self.utf8("ns\u{0}\(namespace)")), Self.namespaceTagLength) + "."
        } catch {
            throw Self.unreadableError(fileName, error)
        }
    }

    /// `namespace` of `fileName` in the app's stores.
    static func open(fileName: String, namespace: String, environment: SecureStoreEnvironment = .shared) throws -> SecurePreferences {
        try SecurePreferences(backing: environment.file(fileName), fileName: fileName, namespace: namespace, cipher: environment.cipher)
    }

    /// ``open(fileName:namespace:environment:)`` for a store that must tell
    /// "unreadable" from "absent": a failure on a read throws instead of
    /// returning the default.
    static func openStrict(fileName: String, namespace: String, environment: SecureStoreEnvironment = .shared) throws -> SecurePreferences {
        try SecurePreferences(
            backing: environment.file(fileName), fileName: fileName, namespace: namespace, cipher: environment.cipher, strict: true
        )
    }

    // MARK: Names

    private func storedName(_ key: String) throws -> String {
        if let name = storedNames.withLock({ $0[key] }) { return name }
        let name = namespaceTag + Self.tag(try cipher.mac(Self.utf8("key\u{0}\(namespace)\u{0}\(key)")), Self.keyTagLength)
        storedNames.withLock { $0[key] = name }
        return name
    }

    private func aad(_ storedName: String) -> Data { Self.utf8("\(fileName)\u{0}\(storedName)") }

    // MARK: Reads

    func value(_ key: String) throws -> PrefValue? {
        let name: String
        let sealed: String?
        do {
            name = try storedName(key)
            sealed = try backing.string(name)
        } catch {
            try unreadable(error)
            return nil
        }
        guard let sealed, let opened = try open(name, sealed) else { return nil }
        if opened.key != key {
            drop(name, "belongs to another key")
            return nil
        }
        return opened.value
    }

    func contains(_ key: String) throws -> Bool {
        do {
            return try backing.contains(try storedName(key))
        } catch {
            try unreadable(error)
            return false
        }
    }

    func all() throws -> [String: PrefValue] {
        let entries: [String: String]
        do {
            entries = try backing.entries()
        } catch {
            try unreadable(error)
            return [:]
        }
        var all: [String: PrefValue] = [:]
        for (name, sealed) in entries where name.hasPrefix(namespaceTag) {
            guard let opened = try open(name, sealed) else { continue }
            let expected: String
            do {
                expected = try storedName(opened.key)
            } catch {
                try unreadable(error)
                continue
            }
            if expected == name { all[opened.key] = opened.value } else { drop(name, "belongs to another key") }
        }
        return all
    }

    /// The (key, value) sealed under `name`, or nil when it does not open.
    private func open(_ name: String, _ sealed: String) throws -> (key: String, value: PrefValue)? {
        let plaintext: Data
        do {
            guard let bytes = Base64.decodeLenient(sealed) else { throw PrefsCipherError.badTag("not Base64") }
            plaintext = try cipher.open(bytes, aad: aad(name))
        } catch PrefsCipherError.badTag {
            drop(name, "does not open with this app's key")
            return nil
        } catch {
            try unreadable(error)
            return nil
        }
        guard let decoded = Self.decode(plaintext) else {
            drop(name, "is malformed")
            return nil
        }
        return (decoded.0, decoded.1)
    }

    /// The keys or the file failed: the entry is kept; a strict store reports
    /// it (throws) instead of reading "absent", the others return and read the default.
    private func unreadable(_ error: any Error) throws {
        log.e("SecurePreferences[\(fileName)]: Keystore error, entry kept", error)
        if strict { throw Self.unreadableError(fileName, error) }
    }

    private static func unreadableError(_ fileName: String, _ error: any Error) -> PinVaultError {
        if let error = error as? PinVaultError, case .storeUnreadable = error { return error }
        return .storeUnreadable(
            message: "Encrypted storage '\(fileName)' cannot be read right now (\(describe(error)))",
            cause: error
        )
    }

    /// `SimpleName: message`, as the Kotlin text prints `e.javaClass.simpleName: e.message`.
    private static func describe(_ error: any Error) -> String {
        if let error = error as? PinVaultError { return "\(error.exceptionName): \(error.message)" }
        return String(describing: error)
    }

    private func drop(_ name: String, _ why: String) {
        log.w("SecurePreferences[\(fileName)]: dropping an entry that \(why)")
        _ = try? backing.write(removing: [name])
    }

    // MARK: Writes

    @discardableResult
    func write(_ changes: PreferenceChanges, sync: Bool) throws -> Bool {
        var removing: [String] = []
        var setting: [String: String] = [:]
        do {
            // Like the platform editor: clear() first, whatever the call order.
            if changes.clear {
                removing = try backing.entries().keys.filter { $0.hasPrefix(namespaceTag) }
            }
            for (key, value) in changes.entries {
                let name = try storedName(key)
                if let value {
                    setting[name] = Base64.encode(try cipher.seal(Self.encode(key, value), aad: aad(name)))
                } else {
                    removing.append(name)
                    setting.removeValue(forKey: name)
                }
            }
        } catch {
            log.e("SecurePreferences[\(fileName)]: Keystore error, nothing written", error)
            throw Self.unreadableError(fileName, error)
        }
        let written: Bool
        do {
            written = try backing.write(removing: removing, setting: setting)
        } catch {
            throw Self.unreadableError(fileName, error)
        }
        let toNotify = Array(listeners.get().values)
        for (key, _) in changes.entries { toNotify.forEach { $0(key) } }
        return written
    }

    // MARK: Listeners

    /// Called with the logical key of every entry a write touches. Returns the
    /// token for ``removeChangeListener(_:)``.
    @discardableResult
    func addChangeListener(_ listener: @escaping Listener) -> UUID {
        let token = UUID()
        listeners.withLock { $0[token] = listener }
        return token
    }

    func removeChangeListener(_ token: UUID) {
        listeners.withLock { _ = $0.removeValue(forKey: token) }
    }

    // MARK: Encoding

    private static func utf8(_ text: String) -> Data { Data(text.utf8) }

    private static func tag(_ mac: Data, _ length: Int) -> String {
        String(Base64.encodeURL(mac).prefix(length))
    }

    /// `[type][key length][key][value]`, integers big-endian.
    static func encode(_ key: String, _ value: PrefValue) -> Data {
        var out = Data()
        func header(_ type: UInt8) {
            let k = utf8(key)
            out.append(type)
            appendInt32(&out, Int32(k.count))
            out.append(k)
        }
        switch value {
        case .string(let string):
            header(tString)
            out.append(utf8(string))
        case .int(let int):
            header(tInt)
            appendInt32(&out, int)
        case .long(let long):
            header(tLong)
            withUnsafeBytes(of: long.bigEndian) { out.append(contentsOf: $0) }
        case .float(let float):
            header(tFloat)
            appendInt32(&out, Int32(bitPattern: float.bitPattern))
        case .bool(let bool):
            header(tBoolean)
            out.append(bool ? 1 : 0)
        case .stringSet(let set):
            header(tStringSet)
            appendInt32(&out, Int32(set.count))
            for item in set.sorted() {
                let bytes = utf8(item)
                appendInt32(&out, Int32(bytes.count))
                out.append(bytes)
            }
        }
        return out
    }

    /// Inverse of ``encode(_:_:)``; nil when malformed.
    static func decode(_ plaintext: Data) -> (String, PrefValue)? {
        var reader = ByteReader(Array(plaintext))
        guard let type = reader.byte(), let keyLength = reader.int32(),
              keyLength >= 0, Int(keyLength) <= plaintext.count,
              let keyBytes = reader.bytes(Int(keyLength)) else { return nil }
        let key = String(decoding: keyBytes, as: UTF8.self)
        let value: PrefValue
        switch type {
        case tString:
            value = .string(String(decoding: reader.rest(), as: UTF8.self))
        case tInt:
            guard let int = reader.int32() else { return nil }
            value = .int(int)
        case tLong:
            guard let long = reader.int64() else { return nil }
            value = .long(long)
        case tFloat:
            guard let bits = reader.int32() else { return nil }
            value = .float(Float(bitPattern: UInt32(bitPattern: bits)))
        case tBoolean:
            guard let byte = reader.byte() else { return nil }
            value = .bool(byte != 0)
        case tStringSet:
            guard let count = reader.int32(), count >= 0, Int(count) <= plaintext.count else { return nil }
            var set = Set<String>()
            for _ in 0..<Int(count) {
                guard let length = reader.int32(), length >= 0, Int(length) <= plaintext.count,
                      let bytes = reader.bytes(Int(length)) else { return nil }
                set.insert(String(decoding: bytes, as: UTF8.self))
            }
            value = .stringSet(set)
        default:
            return nil
        }
        return (key, value)
    }

    private static func appendInt32(_ out: inout Data, _ value: Int32) {
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
    }

    private struct ByteReader {
        private let bytes: [UInt8]
        private var offset = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        mutating func byte() -> UInt8? {
            guard offset < bytes.count else { return nil }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func bytes(_ count: Int) -> ArraySlice<UInt8>? {
            guard count >= 0, bytes.count - offset >= count else { return nil }
            defer { offset += count }
            return bytes[offset..<offset + count]
        }

        mutating func int32() -> Int32? {
            guard let raw = bytes(4) else { return nil }
            return Int32(bitPattern: raw.reduce(0) { $0 << 8 | UInt32($1) })
        }

        mutating func int64() -> Int64? {
            guard let raw = bytes(8) else { return nil }
            return Int64(bitPattern: raw.reduce(0) { $0 << 8 | UInt64($1) })
        }

        mutating func rest() -> ArraySlice<UInt8> {
            defer { offset = bytes.count }
            return bytes[offset...]
        }
    }
}
