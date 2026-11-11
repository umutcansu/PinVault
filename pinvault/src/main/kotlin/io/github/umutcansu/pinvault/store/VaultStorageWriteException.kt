package io.github.umutcansu.pinvault.store

import java.io.IOException

/**
 * A [VaultStorageProvider] could not store a copy (a full disk, a locked or
 * failing Keystore). Thrown by [VaultStorageProvider.save] instead of being
 * swallowed: the library then keeps the signatures of the copy that IS on
 * disk and reports the fetch as failed (`storage_failed`). A save that only
 * logged its failure let the library record the new version's signatures
 * over the old copy, and the old copy, still valid, was deleted at the next
 * read (review 2026-11-11).
 */
class VaultStorageWriteException(message: String, cause: Throwable? = null) : IOException(message, cause)
