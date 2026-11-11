package io.github.umutcansu.pinvault.store

/**
 * Pluggable storage backend for vault files.
 *
 * Implement this interface to provide a custom storage mechanism
 * (e.g., hardware-backed Keystore, custom file encryption).
 *
 * Default implementation: [VaultFileStore], encrypted preferences with keys in the Android Keystore.
 */
interface VaultStorageProvider {
    /**
     * Stores [bytes] as [version] of [key]. Must throw (preferably
     * [VaultStorageWriteException]) when the copy was not stored: returning
     * normally tells the library the new version is on disk, and it records
     * that version's signatures, so the copy that is really there would fail
     * its check at the next read and be deleted.
     */
    fun save(key: String, bytes: ByteArray, version: Int)
    fun load(key: String): ByteArray?
    fun getVersion(key: String): Int
    fun exists(key: String): Boolean
    fun clear(key: String)
}
