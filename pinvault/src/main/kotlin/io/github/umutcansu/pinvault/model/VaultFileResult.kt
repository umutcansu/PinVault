package io.github.umutcansu.pinvault.model

/**
 * Result of a vault file fetch/sync operation.
 */
sealed class VaultFileResult {
    /** File downloaded and stored successfully. */
    data class Updated(val key: String, val version: Int, val bytes: ByteArray) : VaultFileResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Updated) return false
            return key == other.key && version == other.version && bytes.contentEquals(other.bytes)
        }
        override fun hashCode(): Int = 31 * (31 * key.hashCode() + version) + bytes.contentHashCode()
    }

    /** File is already at the latest version. */
    data class AlreadyCurrent(val key: String, val version: Int) : VaultFileResult()

    /** File fetch failed. */
    data class Failed(val key: String, val reason: String, val exception: Exception? = null) : VaultFileResult()
}
