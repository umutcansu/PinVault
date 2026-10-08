import CryptoKit
import Foundation
import Security

/// Encrypted file storage for large vault files (Kotlin
/// `EncryptedFileStorageProvider`): AES-256-GCM with a per-file key in the
/// Keychain, one file per vault file at
/// `Library/Application Support/pinvault/vault_files/<key>.enc`:
///
///     "PVF2" [version, 4 bytes BE] [IV length, 1] [IV] [ciphertext + tag]
///
/// The file's name and version are part of what the GCM tag covers
/// (`pinvault-vault-file-store:v2:<key>:<version>`), and the version is read
/// from the file itself: a blob moved under another file's name, or given
/// another version, does not decrypt — it is deleted, and the next fetch
/// downloads the file again. A Keychain that fails says nothing about the copy:
/// it is kept.
///
/// The directory and every file are excluded from backup and written with
/// `NSFileProtectionCompleteUntilFirstUserAuthentication` (`Complete` with
/// `requireUnlockedDevice`). The per-file keys are Keychain generic passwords
/// `pinvault_vault_<key>` (ThisDeviceOnly). Android's earlier unbound form
/// never existed on iOS: nothing to migrate.
final class EncryptedFileStorageProvider: VaultStorageProvider {
    static let directoryName = "vault_files"
    static let keyAliasPrefix = "pinvault_vault_"
    private static let magic = Data("PVF2".utf8)
    private static let ivLength = 12
    private static let tagLength = 16

    /// The AES key of a file. Throws when the Keychain cannot be used right now.
    typealias KeySource = @Sendable (_ key: String) throws -> SymmetricKey
    /// Deletes the AES key of a file (on clear).
    typealias KeyRemover = @Sendable (_ key: String) -> Void

    let directory: URL
    private let keyFor: KeySource
    private let removeKey: KeyRemover
    private let protection: @Sendable () -> PrefsFileProtection
    /// One file operation at a time: a save's move and a load's read must not interleave.
    private let lock = Locked(())
    private let log = PinVaultLog.tag("EncryptedFileStorageProvider")

    init(
        directory: URL,
        keyFor: @escaping KeySource,
        removeKey: @escaping KeyRemover = { _ in },
        protection: @escaping @Sendable () -> PrefsFileProtection = { .untilFirstUserAuthentication }
    ) {
        self.directory = directory
        self.keyFor = keyFor
        self.removeKey = removeKey
        self.protection = protection
    }

    /// The app's store under `environment.directory`, keys in the Keychain.
    static func keychain(environment: SecureStoreEnvironment = .shared) -> EncryptedFileStorageProvider {
        let keys = VaultFileKeychainKeys(requireUnlockedDevice: { environment.requireUnlockedDevice })
        return EncryptedFileStorageProvider(
            directory: environment.directory.appendingPathComponent(directoryName, isDirectory: true),
            keyFor: { try keys.key(for: $0) },
            removeKey: { keys.remove($0) },
            protection: { environment.requireUnlockedDevice ? .complete : .untilFirstUserAuthentication }
        )
    }

    func save(key: String, bytes: Data, version: Int) throws {
        lock.withLock { _ in
            let file = fileFor(key)
            // Encrypted first, then written atomically (beside the copy and moved
            // over it): a failure (a locked or busy Keychain, a full disk) leaves
            // the copy that was there intact.
            do {
                let secretKey = try keyFor(key)
                let box = try AES.GCM.seal(bytes, using: secretKey, nonce: AES.GCM.Nonce(), authenticating: Self.aad(key, version))
                var out = Self.magic
                withUnsafeBytes(of: Int32(truncatingIfNeeded: version).bigEndian) { out.append(contentsOf: $0) }
                out.append(UInt8(Self.ivLength))
                out.append(contentsOf: box.nonce)
                out.append(box.ciphertext)
                out.append(box.tag)

                try SecureStoreEnvironment.prepareDirectory(directory)
                try out.write(to: file, options: writeOptions())
                // An atomic write replaces the file, and the exclusion with it.
                Self.excludeFromBackup(file)
                log.d("Vault file saved to disk [\(key)] — version: \(version), \(bytes.count) bytes")
            } catch {
                log.e("Failed to save vault file to disk [\(key)] — the previous copy, if any, was kept", error)
            }
        }
    }

    func load(key: String) throws -> Data? {
        lock.withLock { _ in
            let file = fileFor(key)
            guard FileManager.default.fileExists(atPath: file.path) else { return nil }
            do {
                let secretKey = try keyFor(key)
                let data = try Data(contentsOf: file)
                guard let parsed = Self.parse(data) else {
                    log.e("Vault file [\(key)] is malformed — stored copy deleted, fetch it again")
                    clearLocked(key)
                    return nil
                }
                do {
                    let box = try AES.GCM.SealedBox(
                        nonce: AES.GCM.Nonce(data: parsed.iv), ciphertext: parsed.ciphertext, tag: parsed.tag
                    )
                    let plain = try AES.GCM.open(box, using: secretKey, authenticating: Self.aad(key, parsed.version))
                    log.d("Vault file loaded from disk [\(key)] — \(plain.count) bytes")
                    return plain
                } catch {
                    // Not this file at this version under this key: rewritten, moved
                    // here from another file, or relabelled. It will never open.
                    log.e("Vault file [\(key)] did not decrypt for this name and version — stored copy deleted, fetch it again")
                    clearLocked(key)
                    return nil
                }
            } catch {
                // A Keychain (or a file read) that fails says nothing about the copy: keep it.
                log.e("Failed to load vault file from disk [\(key)] — copy kept", error)
                return nil
            }
        }
    }

    /// From the file itself (authenticated when it is read).
    func getVersion(key: String) throws -> Int {
        lock.withLock { _ in
            let file = fileFor(key)
            guard FileManager.default.fileExists(atPath: file.path) else { return 0 }
            guard let handle = try? FileHandle(forReadingFrom: file) else {
                log.w("Could not read the version of vault file [\(key)]")
                return 0
            }
            defer { try? handle.close() }
            let header = (try? handle.read(upToCount: Self.magic.count + 4)) ?? Data()
            guard header.count == Self.magic.count + 4, header.prefix(Self.magic.count) == Self.magic else { return 0 }
            return Int(Self.int32(header, at: Self.magic.count))
        }
    }

    func exists(key: String) throws -> Bool {
        FileManager.default.fileExists(atPath: fileFor(key).path)
    }

    func clear(key: String) throws {
        lock.withLock { _ in clearLocked(key) }
    }

    // MARK: Internals

    private func clearLocked(_ key: String) {
        try? FileManager.default.removeItem(at: fileFor(key))
        removeKey(key)
        log.d("Vault file cleared from disk [\(key)]")
    }

    func fileFor(_ key: String) -> URL {
        directory.appendingPathComponent("\(key).enc", isDirectory: false)
    }

    private func writeOptions() -> Data.WritingOptions {
        var options: Data.WritingOptions = [.atomic]
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        switch protection() {
        case .untilFirstUserAuthentication: options.insert(.completeFileProtectionUntilFirstUserAuthentication)
        case .complete: options.insert(.completeFileProtection)
        }
        #endif
        return options
    }

    private static func excludeFromBackup(_ url: URL) {
        var file = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? file.setResourceValues(values)
    }

    private static func aad(_ key: String, _ version: Int) -> Data {
        Data("pinvault-vault-file-store:v2:\(key):\(version)".utf8)
    }

    private struct Parsed {
        let version: Int
        let iv: Data
        let ciphertext: Data
        let tag: Data
    }

    /// The parts of a current-form file; nil when it is malformed.
    private static func parse(_ data: Data) -> Parsed? {
        let bytes = Data(data)
        guard bytes.count >= magic.count + 4 + 1, bytes.prefix(magic.count) == magic else { return nil }
        let version = Int(int32(bytes, at: magic.count))
        var offset = magic.count + 4
        let ivLength = Int(bytes[bytes.startIndex + offset])
        offset += 1
        // AES.GCM takes a 12-byte nonce; anything else was not written here.
        guard ivLength == Self.ivLength, bytes.count >= offset + ivLength + tagLength else { return nil }
        let iv = bytes.subdata(in: offset..<(offset + ivLength))
        offset += ivLength
        let sealed = bytes.subdata(in: offset..<bytes.count)
        return Parsed(
            version: version, iv: iv,
            ciphertext: sealed.prefix(sealed.count - tagLength), tag: sealed.suffix(tagLength)
        )
    }

    private static func int32(_ data: Data, at offset: Int) -> Int32 {
        let bytes = [UInt8](data[(data.startIndex + offset)..<(data.startIndex + offset + 4)])
        return Int32(bitPattern: UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3]))
    }
}

/// The per-file AES-256 keys of ``EncryptedFileStorageProvider``: Keychain
/// generic passwords `pinvault_vault_<key>` (service `io.github.umutcansu.pinvault`),
/// 32 random bytes, `AfterFirstUnlockThisDeviceOnly` — `WhenUnlockedThisDeviceOnly`
/// for keys made while `requireUnlockedDevice` is on.
final class VaultFileKeychainKeys: Sendable {
    static let service = "io.github.umutcansu.pinvault"
    private static let keyLength = 32

    private let requireUnlockedDevice: @Sendable () -> Bool
    private let log = PinVaultLog.tag("EncryptedFileStorageProvider")

    init(requireUnlockedDevice: @escaping @Sendable () -> Bool) {
        self.requireUnlockedDevice = requireUnlockedDevice
    }

    private func query(_ key: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: EncryptedFileStorageProvider.keyAliasPrefix + key,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    /// The file's key, created on first use.
    func key(for key: String) throws -> SymmetricKey {
        for _ in 0..<2 {
            var lookup = query(key)
            lookup[kSecReturnData] = true
            lookup[kSecMatchLimit] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(lookup as CFDictionary, &item)
            switch status {
            case errSecSuccess:
                if let data = item as? Data, data.count == Self.keyLength { return SymmetricKey(data: data) }
                // Not a key this library wrote: unusable for good (the copy will not open and is dropped).
                log.e("Vault file key: the Keychain item for [\(key)] is not a \(Self.keyLength)-byte key — replacing it")
                SecItemDelete(query(key) as CFDictionary)
            case errSecItemNotFound:
                var bytes = Data(count: Self.keyLength)
                let generated = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Self.keyLength, $0.baseAddress!) }
                guard generated == errSecSuccess else {
                    throw DeviceKeyKeychainError(status: generated, operation: "make the vault file key for [\(key)]")
                }
                let unlockedOnly = requireUnlockedDevice()
                var add = query(key)
                add[kSecValueData] = bytes
                add[kSecAttrAccessible] = unlockedOnly
                    ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                let added = SecItemAdd(add as CFDictionary, nil)
                if added == errSecSuccess { return SymmetricKey(data: bytes) }
                if added == errSecDuplicateItem { continue }
                throw DeviceKeyKeychainError(status: added, operation: "store the vault file key for [\(key)]")
            default:
                throw DeviceKeyKeychainError(status: status, operation: "read the vault file key for [\(key)]")
            }
        }
        throw DeviceKeyKeychainError(status: errSecInternalComponent, operation: "read the vault file key for [\(key)]")
    }

    func remove(_ key: String) {
        let status = SecItemDelete(query(key) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            log.w("Failed to remove Keychain entry [\(key)] (OSStatus \(status))")
        }
    }
}
