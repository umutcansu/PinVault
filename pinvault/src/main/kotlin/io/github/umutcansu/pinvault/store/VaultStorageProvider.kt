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
    fun save(key: String, bytes: ByteArray, version: Int)
    fun load(key: String): ByteArray?
    fun getVersion(key: String): Int
    fun exists(key: String): Boolean
    fun clear(key: String)
}
