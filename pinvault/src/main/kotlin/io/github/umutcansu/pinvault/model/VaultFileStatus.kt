package io.github.umutcansu.pinvault.model

/**
 * What `PinVault.fileStatus(key)` says about the stored copy of a vault file:
 * whether `loadFile` / `unlockFile` will hand it out, and if not, why.
 */
enum class VaultFileStatus {
    /** A copy is stored and `loadFile` returns it. */
    AVAILABLE,

    /** A copy is stored and sealed with [UserAuth]: `unlockFile` opens it, `loadFile` returns null. */
    LOCKED,

    /** Nothing is stored: the file was never fetched, or was cleared. */
    NOT_STORED,

    /**
     * The copy is older than the file's `maxOfflineAge` (the server has not
     * confirmed it for that long, never on record, or the recorded time lies
     * ahead of the trusted clock). It is not handed out;
     * a successful `fetchFile` makes it readable again. With `wipeWhenStale()`
     * the copy has been deleted — except for a recorded time ahead of the
     * clock, which proves nothing and deletes nothing.
     */
    STALE,

    /**
     * The file's Config API signs its files, and this copy has no signature
     * on record: it was stored by an earlier version of the library (which
     * checked the signature at download only). It is not handed out; the next
     * `fetchFile` downloads it again and keeps the signature.
     */
    NEEDS_FETCH,

    /**
     * The last time the copy was read it did not pass its checks — the
     * stored signature did not verify, or the copy did not decrypt for this
     * file and version — and was deleted. Fetch it again.
     */
    INTEGRITY_FAILED,

    /**
     * The encrypted storage cannot be read right now (the Android Keystore
     * failed, or the device is locked and the config asked for
     * `requireUnlockedDevice()`). Nothing was deleted; try again later.
     */
    STORAGE_UNAVAILABLE
}
