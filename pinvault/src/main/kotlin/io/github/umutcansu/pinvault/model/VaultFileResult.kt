package io.github.umutcansu.pinvault.model

/**
 * Result of a vault file fetch/sync operation.
 */
sealed class VaultFileResult {
    /**
     * File downloaded and stored successfully. [bytes] is the content, except
     * for a file locked with [VaultFileConfig.userAuth]: then it is empty, and
     * only `PinVault.unlockFile` hands the content out, after the prompt.
     *
     * For an `encryption(USER_AUTH)` file that already has a stored copy, the
     * new version waits in a pending slot until the next `unlockFile` has
     * opened and verified it; `PinVault.fileVersion` names the verified copy
     * until then.
     */
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

    /**
     * File fetch failed. [reason] says what happened, for the app and the
     * local log; [code] is a fixed classification (one of the `CODE_*`
     * constants, or `http_<status>`) and is what the distribution report
     * sends to the server as `failureReason`. The server never gets the text
     * of an exception: the exact way an envelope failed to decrypt would
     * tell whoever answers the request how its padding fared.
     */
    data class Failed(
        val key: String,
        val reason: String,
        val exception: Exception? = null,
        val code: String = CODE_OTHER
    ) : VaultFileResult() {
        companion object {
            /** Anything not classified below. */
            const val CODE_OTHER = "other"
            /** The file names an unknown Config API, needs a key provider or a user-auth setup the app lacks. */
            const val CODE_NOT_CONFIGURED = "not_configured"
            /** The server refused the request; the HTTP status follows: `http_401`, `http_404`, `http_412`, … */
            const val CODE_HTTP_PREFIX = "http_"
            /** The request did not complete (connection, TLS, timeout). */
            const val CODE_NETWORK = "network_error"
            /** The response body was longer than the library reads. */
            const val CODE_RESPONSE_TOO_LARGE = "response_too_large"
            /** A locked file needs a screen lock the device has not got. */
            const val CODE_SCREEN_LOCK = "screen_lock_required"
            /** The user-auth key could not be registered with the Config API. */
            const val CODE_USER_AUTH_KEY = "user_auth_key_rejected"
            /** The server answered with another encryption than the file declares. */
            const val CODE_ENCRYPTION_MISMATCH = "encryption_mismatch"
            /** An end_to_end envelope did not open (the device key or the envelope is wrong); one code whatever the step. */
            const val CODE_DECRYPT_FAILED = "decrypt_failed"
            /** A verifying key is configured and the answer carries no signature. */
            const val CODE_SIGNATURE_MISSING = "signature_missing"
            /** The signature does not verify. */
            const val CODE_SIGNATURE_INVALID = "signature_invalid"
            /** An older version than the stored one, or a version jump beyond the bound. */
            const val CODE_VERSION_REJECTED = "version_rejected"

            /** The code for a refused request with HTTP [status]. */
            fun http(status: Int): String = "$CODE_HTTP_PREFIX$status"
        }
    }
}
