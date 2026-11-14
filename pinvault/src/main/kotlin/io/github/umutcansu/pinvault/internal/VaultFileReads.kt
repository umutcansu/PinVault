package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileStatus
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import timber.log.Timber

/**
 * What the read side of the vault-file API answers for a key: `loadFile`,
 * `fileStatus`, `hasFile`, `fileVersion`, `isFileLocked` (and `unlockFile`,
 * which asks [declared] first).
 *
 * Only a file the running config declares can be read. A key it does not
 * name used to be read straight from storage — no offline lifetime, no
 * signature re-check, no `userAuth` — because every one of those rules lives
 * in the file's declaration: an app version (or, through the bridges, a
 * bundle) that dropped a file from its config could still read the copy an
 * earlier one stored, for as long as it sat on the device (review
 * 2026-11-14). Such a key now reads as "no such file": null / `NOT_STORED` /
 * false / 0. Nothing is deleted — declared again, the copy is back under its
 * rules — and `clearFile` still removes a copy whatever the config says.
 */
internal class VaultFileReads(
    private val files: () -> Map<String, VaultFileConfig>?,
    private val storageFor: (String) -> VaultStorageProvider,
    private val guard: () -> VaultFileGuard?,
    private val verifierFor: (VaultFileConfig) -> StoredVerifier?
) {

    /** The file as the config declares it, or null: then there is no such file for a reader. */
    fun declared(key: String): VaultFileConfig? = files()?.get(key) ?: run {
        Timber.d("Vault file '%s' is not declared in this config — a stored copy, if any, is not read", key)
        null
    }

    fun load(key: String): ByteArray? {
        val file = declared(key) ?: return null
        val storage = storageFor(key)
        val guard = guard() ?: return storage.load(key)
        return when (val read = guard.load(file, storage, verifierFor(file))) {
            is VaultFileGuard.Read.Content -> read.bytes
            else -> null
        }
    }

    fun status(key: String): VaultFileStatus {
        val file = declared(key) ?: return VaultFileStatus.NOT_STORED
        val storage = storageFor(key)
        val guard = guard()
            ?: return if (storage.exists(key)) VaultFileStatus.AVAILABLE else VaultFileStatus.NOT_STORED
        return guard.status(file, storage, verifierFor(file))
    }

    fun has(key: String): Boolean = declared(key) != null && storageFor(key).exists(key)

    fun version(key: String): Int = if (declared(key) == null) 0 else storageFor(key).getVersion(key)

    fun isLocked(key: String): Boolean =
        declared(key) != null && (storageFor(key) as? UserAuthVaultStorage)?.isLocked(key) == true
}
