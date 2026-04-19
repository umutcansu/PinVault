package io.github.umutcansu.pinvault.model

/**
 * Response from a vault file download, including encryption metadata.
 *
 * Added in V2 to support per-file encryption strategies. The library uses
 * [encryption] to decide whether to pass [content] directly to the storage
 * provider (plain / at_rest) or to route through [io.github.umutcansu.pinvault.crypto.VaultFileDecryptor]
 * first (end_to_end).
 *
 * @property content Raw response bytes. For encryption=end_to_end these are
 *                   the RSA+AES wrapped envelope; the device must decrypt.
 * @property version Server-reported X-Vault-Version header value.
 * @property encryption Server-reported X-Vault-Encryption header:
 *                     "plain" | "at_rest" | "end_to_end".
 * @property notModified True when server returned 304. [content] is empty.
 */
data class VaultFetchResponse(
    val content: ByteArray,
    val version: Int,
    val encryption: String = "plain",
    val notModified: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultFetchResponse) return false
        return version == other.version &&
                encryption == other.encryption &&
                notModified == other.notModified &&
                content.contentEquals(other.content)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + encryption.hashCode()
        result = 31 * result + notModified.hashCode()
        result = 31 * result + content.contentHashCode()
        return result
    }
}
