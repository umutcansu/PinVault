import Foundation

/// One stored preference value: the types of Android `SharedPreferences`.
enum PrefValue: Sendable, Equatable {
    case string(String)
    case int(Int32)
    case long(Int64)
    case float(Float)
    case bool(Bool)
    case stringSet(Set<String>)

    /// The Kotlin simple class name, for type-mismatch messages.
    var typeName: String {
        switch self {
        case .string: return "String"
        case .int: return "Integer"
        case .long: return "Long"
        case .float: return "Float"
        case .bool: return "Boolean"
        case .stringSet: return "Set"
        }
    }
}

/// What one editor commits: `clear` first (whatever the call order, like the
/// platform editor), then every key in the order it was first touched; nil removes.
struct PreferenceChanges: Sendable {
    var clear = false
    private(set) var keys: [String] = []
    private(set) var values: [String: PrefValue?] = [:]

    mutating func set(_ key: String, _ value: PrefValue?) {
        if !values.keys.contains(key) { keys.append(key) }
        values[key] = .some(value)
    }

    /// `(key, value)` in order; a nil value removes the key.
    var entries: [(key: String, value: PrefValue?)] {
        keys.map { ($0, values[$0] ?? nil) }
    }
}

/// The `SharedPreferences` contract the stores are written against:
/// ``SecurePreferences`` on a device, ``InMemoryPreferences`` in tests.
///
/// Reads throw ``PinVaultError/storeUnreadable(message:cause:)`` when a strict
/// store cannot be read right now, and ``PinVaultError/illegalState(_:)`` when
/// a value has another type than asked for (Kotlin `ClassCastException`).
protocol PreferenceStore: AnyObject, Sendable {
    func value(_ key: String) throws -> PrefValue?
    func contains(_ key: String) throws -> Bool
    func all() throws -> [String: PrefValue]
    /// Applies `changes`. `sync` = `commit()` (the result says whether it reached
    /// the disk) rather than `apply()`; both write before returning here.
    @discardableResult func write(_ changes: PreferenceChanges, sync: Bool) throws -> Bool
}

extension PreferenceStore {
    func edit() -> PreferenceEditor { PreferenceEditor(self) }

    func getString(_ key: String, _ defValue: String?) throws -> String? {
        guard let value = try value(key) else { return defValue }
        guard case .string(let string) = value else { throw Self.mismatch(key, value) }
        return string
    }

    /// Stored as a Kotlin `Int` (32 bits).
    func getInt(_ key: String, _ defValue: Int) throws -> Int {
        guard let value = try value(key) else { return defValue }
        guard case .int(let int) = value else { throw Self.mismatch(key, value) }
        return Int(int)
    }

    func getLong(_ key: String, _ defValue: Int64) throws -> Int64 {
        guard let value = try value(key) else { return defValue }
        guard case .long(let long) = value else { throw Self.mismatch(key, value) }
        return long
    }

    func getFloat(_ key: String, _ defValue: Float) throws -> Float {
        guard let value = try value(key) else { return defValue }
        guard case .float(let float) = value else { throw Self.mismatch(key, value) }
        return float
    }

    func getBoolean(_ key: String, _ defValue: Bool) throws -> Bool {
        guard let value = try value(key) else { return defValue }
        guard case .bool(let bool) = value else { throw Self.mismatch(key, value) }
        return bool
    }

    func getStringSet(_ key: String, _ defValues: Set<String>?) throws -> Set<String>? {
        guard let value = try value(key) else { return defValues }
        guard case .stringSet(let set) = value else { throw Self.mismatch(key, value) }
        return set
    }

    private static func mismatch(_ key: String, _ value: PrefValue) -> PinVaultError {
        .illegalState("\(key) is a \(value.typeName)")
    }
}

/// `SharedPreferences.Editor`: collects changes, then ``commit()`` or ``apply()``.
/// Used by one caller at a time.
final class PreferenceEditor {
    private let store: any PreferenceStore
    private var changes = PreferenceChanges()

    init(_ store: any PreferenceStore) {
        self.store = store
    }

    @discardableResult func putString(_ key: String, _ value: String?) -> PreferenceEditor {
        changes.set(key, value.map(PrefValue.string))
        return self
    }

    /// A Kotlin `Int`: values outside 32 bits are clamped.
    @discardableResult func putInt(_ key: String, _ value: Int) -> PreferenceEditor {
        changes.set(key, .int(Int32(clamping: value)))
        return self
    }

    @discardableResult func putLong(_ key: String, _ value: Int64) -> PreferenceEditor {
        changes.set(key, .long(value))
        return self
    }

    @discardableResult func putFloat(_ key: String, _ value: Float) -> PreferenceEditor {
        changes.set(key, .float(value))
        return self
    }

    @discardableResult func putBoolean(_ key: String, _ value: Bool) -> PreferenceEditor {
        changes.set(key, .bool(value))
        return self
    }

    @discardableResult func putStringSet(_ key: String, _ values: Set<String>?) -> PreferenceEditor {
        changes.set(key, values.map(PrefValue.stringSet))
        return self
    }

    @discardableResult func remove(_ key: String) -> PreferenceEditor {
        changes.set(key, nil)
        return self
    }

    @discardableResult func clear() -> PreferenceEditor {
        changes.clear = true
        return self
    }

    /// Writes now; false when the changes could not be written to disk (they
    /// still apply in memory, as on Android).
    @discardableResult func commit() throws -> Bool {
        defer { changes = PreferenceChanges() }
        return try store.write(changes, sync: true)
    }

    func apply() throws {
        defer { changes = PreferenceChanges() }
        try store.write(changes, sync: false)
    }
}

/// Plain preferences in memory: the unencrypted `SharedPreferences` the Kotlin
/// store tests use, and a stand-in wherever nothing must persist.
final class InMemoryPreferences: PreferenceStore, Sendable {
    private let values = Locked<[String: PrefValue]>([:])

    init(_ initial: [String: PrefValue] = [:]) {
        values.set(initial)
    }

    func value(_ key: String) throws -> PrefValue? { values.get()[key] }

    func contains(_ key: String) throws -> Bool { values.get()[key] != nil }

    func all() throws -> [String: PrefValue] { values.get() }

    @discardableResult func write(_ changes: PreferenceChanges, sync: Bool) throws -> Bool {
        values.withLock { values in
            if changes.clear { values.removeAll() }
            for (key, value) in changes.entries { values[key] = value }
        }
        return true
    }
}

// MARK: - The backing file

/// File protection of a store file (iOS; ignored on macOS).
enum PrefsFileProtection: Sendable {
    /// `NSFileProtectionCompleteUntilFirstUserAuthentication` (the default).
    case untilFirstUserAuthentication
    /// `NSFileProtectionComplete` (`requireUnlockedDevice`).
    case complete
}

/// The raw contents of one store file: stored name → Base64 sealed value, a
/// property-list dictionary at `<directory>/<fileName>.plist` (the
/// counterpart of the `shared_prefs/<fileName>.xml` behind SecurePreferences).
///
/// Loaded once and kept in memory, like `SharedPreferences`. A missing file
/// is empty; a file that exists but cannot be read (device locked under
/// complete protection, I/O error) throws ``PrefsFileError/unreadable(_:)``
/// and is never overwritten while so. Every write replaces the file
/// atomically, excluded from backup.
final class PrefsFile: @unchecked Sendable {
    let url: URL
    private let protection: @Sendable () -> PrefsFileProtection
    private let state = Locked<[String: String]?>(nil)
    private let log = PinVaultLog.tag("SecurePreferences")

    init(url: URL, protection: @escaping @Sendable () -> PrefsFileProtection = { .untilFirstUserAuthentication }) {
        self.url = url
        self.protection = protection
    }

    func entries() throws -> [String: String] {
        try state.withLock { cached in
            if let cached { return cached }
            let loaded = try read()
            cached = loaded
            return loaded
        }
    }

    func string(_ name: String) throws -> String? { try entries()[name] }

    func contains(_ name: String) throws -> Bool { try entries()[name] != nil }

    /// Removes `removing`, then sets `setting`. Throws when the file cannot be
    /// read (nothing changes then); returns false when the new contents could
    /// not be written to disk (they apply in memory all the same).
    @discardableResult
    func write(removing: [String] = [], setting: [String: String] = [:]) throws -> Bool {
        try state.withLock { cached in
            var current = try cached ?? read()
            for name in removing { current.removeValue(forKey: name) }
            for (name, value) in setting { current[name] = value }
            cached = current
            return persist(current)
        }
    }

    private func read() throws -> [String: String] {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return [:]
        } catch let error as NSError where error.domain == NSPOSIXErrorDomain && error.code == Int(ENOENT) {
            return [:]
        } catch {
            throw PrefsFileError.unreadable("\(url.lastPathComponent): \(error.localizedDescription)")
        }
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dictionary = plist as? [String: Any] else {
            // What Android does with a corrupt preferences file: start empty.
            log.e("SecurePreferences[\(url.deletingPathExtension().lastPathComponent)]: the file is not a property list — starting empty")
            return [:]
        }
        return dictionary.compactMapValues { $0 as? String }
    }

    private func persist(_ entries: [String: String]) -> Bool {
        do {
            let directory = url.deletingLastPathComponent()
            try SecureStoreEnvironment.prepareDirectory(directory)
            let data = try PropertyListSerialization.data(fromPropertyList: entries, format: .binary, options: 0)
            var options: Data.WritingOptions = [.atomic]
            #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            switch protection() {
            case .untilFirstUserAuthentication: options.insert(.completeFileProtectionUntilFirstUserAuthentication)
            case .complete: options.insert(.completeFileProtection)
            }
            #endif
            try data.write(to: url, options: options)
            // An atomic write replaces the file, and the exclusion with it.
            var fileURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try fileURL.setResourceValues(values)
            return true
        } catch {
            log.e("SecurePreferences[\(url.deletingPathExtension().lastPathComponent)]: could not write the file", error)
            return false
        }
    }
}

enum PrefsFileError: Error, CustomStringConvertible {
    /// The file exists but cannot be read right now.
    case unreadable(String)

    var description: String {
        switch self {
        case .unreadable(let reason): return "IOException: \(reason)"
        }
    }
}

// MARK: - Environment

/// Where the encrypted stores live and where their keys come from.
///
/// ``shared`` is the app's: `Library/Application Support/pinvault` (on macOS
/// under a folder named after the bundle id) with keys in the Keychain.
/// Tests make their own over a temporary directory and ``InMemoryPrefsKeySource``.
/// One ``PrefsFile`` per file name, shared by every store opened on it.
final class SecureStoreEnvironment: Sendable {
    let directory: URL
    let cipher: any PrefsCipher
    private let options: Locked<Bool>
    private let files = Locked<[String: PrefsFile]>([:])

    /// The app's stores (Application Support + Keychain).
    static let shared: SecureStoreEnvironment = {
        let options = Locked(false)
        return SecureStoreEnvironment(
            directory: defaultDirectory(),
            cipher: KeyedPrefsCipher(source: KeychainPrefsKeySource(requireUnlockedDevice: { options.get() })),
            options: options
        )
    }()

    init(directory: URL, keySource: any PrefsKeySource = InMemoryPrefsKeySource()) {
        self.directory = directory
        self.cipher = KeyedPrefsCipher(source: keySource)
        self.options = Locked(false)
    }

    init(directory: URL, cipher: any PrefsCipher) {
        self.directory = directory
        self.cipher = cipher
        self.options = Locked(false)
    }

    private init(directory: URL, cipher: any PrefsCipher, options: Locked<Bool>) {
        self.directory = directory
        self.cipher = cipher
        self.options = options
    }

    /// `PinVaultConfig.Builder.requireUnlockedDevice()`: store files written
    /// from now on get complete protection and store keys made from now on
    /// are `WhenUnlockedThisDeviceOnly` (Kotlin `KeystoreOptions.unlockedDeviceRequired`).
    var requireUnlockedDevice: Bool {
        get { options.get() }
        set { options.set(newValue) }
    }

    /// The backing file `<directory>/<fileName>.plist`.
    func file(_ fileName: String) -> PrefsFile {
        files.withLock { files in
            if let file = files[fileName] { return file }
            let options = self.options
            let file = PrefsFile(
                url: directory.appendingPathComponent(fileName + ".plist", isDirectory: false),
                protection: { options.get() ? .complete : .untilFirstUserAuthentication }
            )
            files[fileName] = file
            return file
        }
    }

    static func defaultDirectory() -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        #if os(macOS)
        let owner = Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName
        return support.appendingPathComponent(owner, isDirectory: true).appendingPathComponent("pinvault", isDirectory: true)
        #else
        return support.appendingPathComponent("pinvault", isDirectory: true)
        #endif
    }

    /// Creates `directory` (and its parents) when missing and excludes it from
    /// backup (also when another part of the library created it first).
    static func prepareDirectory(_ directory: URL) throws {
        var url = directory
        if !FileManager.default.fileExists(atPath: directory.path) {
            var attributes: [FileAttributeKey: Any] = [:]
            #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
            #endif
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: attributes)
        } else if (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup) == true {
            return
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }
}
