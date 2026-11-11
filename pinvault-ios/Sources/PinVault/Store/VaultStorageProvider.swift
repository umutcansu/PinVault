import Foundation

/// Pluggable storage for vault files (`VaultFileConfig.Builder.storage(_:)`).
/// The default stores are encrypted with keys in the Keychain (L4).
///
/// Every method may throw: a store that cannot be read right now should throw
/// (``PinVaultError/storeUnreadable(message:cause:)``) rather than report
/// "nothing stored". A non-throwing implementation satisfies the protocol too.
public protocol VaultStorageProvider: Sendable {
    /// Must throw (preferably ``VaultStorageWriteError``) when the copy was not
    /// stored: returning normally tells the library the new version is on
    /// disk, and it records that version's signatures, so the copy really
    /// there would fail its check at the next read and be deleted.
    func save(key: String, bytes: Data, version: Int) throws
    func load(key: String) throws -> Data?
    func getVersion(key: String) throws -> Int
    func exists(key: String) throws -> Bool
    func clear(key: String) throws
}
