package io.github.umutcansu.pinvault.model

/**
 * Whether opening a vault file needs the person holding the phone.
 *
 * A locked file is sealed to a Keystore key (one per device) that the
 * TEE/StrongBox uses only after the user has passed the screen lock (PIN,
 * pattern, password) or a strong biometric. Fetching and storing need no
 * prompt, so periodic sync keeps working; reading goes through
 * [io.github.umutcansu.pinvault.PinVault.unlockFile].
 *
 * What it protects depends on who seals the file:
 *
 * - With [VaultFileEncryption.USER_AUTH] the server seals the file for that
 *   key, so the content never reaches the app — not the fetch result, not the
 *   update listener, not storage — until the user passes the prompt. The
 *   device registers that key with an Android key attestation chain. Code
 *   running as the app on a rooted phone gets only sealed copies ONLY when
 *   the server enforces that attestation (the reference server:
 *   `USER_AUTH_ATTESTATION=enforce` with the app's package name and signing
 *   certificate digest; it needs a locked bootloader): then a software key cannot be registered in its
 *   place. Without enforcement the first key a device registers is trusted
 *   as it comes (trust on first use), so code holding the app's credentials
 *   can register a key of its own before the app does; replacing a
 *   registered key needs the device's credential together with a passing
 *   attestation, or an administrator reset.
 *   Only server-sealed copies are accepted for such a file: anything else in
 *   storage is deleted unread.
 * - Without it the library seals the file after download. That protects the
 *   copy at rest only: the download itself arrives in the app's memory, and
 *   anyone who can run code as the app can fetch the file from the server
 *   again with the app's own credentials.
 *
 * In both cases what [io.github.umutcansu.pinvault.PinVault.unlockFile]
 * returns is in the app's memory from then on.
 *
 * Android 11+ asks on every unlock (strong biometric or the screen lock). That
 * key is bound to the screen lock itself: only removing the screen lock
 * retires it; enrolling or deleting a fingerprint or face does NOT. On Android
 * 7–10 the key is made one of two ways: when the phone has a strong
 * fingerprint at that moment, every unlock asks for the fingerprint (the
 * screen lock does not open it), and because that key is bound to the
 * enrolled biometrics, a new fingerprint, removing all fingerprints or
 * removing the screen lock retires it; otherwise the screen lock opens the
 * key for [UserAuthKeyKind.TIME_BOUND_WINDOW_SECONDS] seconds — after the
 * prompt, but also after the phone itself is unlocked — and only removing
 * the screen lock retires it. [UserAuthKeyKind] has the table;
 * `PinVault.userAuthKeyKind()` says which kind this device's key is.
 *
 * The reference server holds registered keys to rules of its own: on Android
 * 11+ it refuses a key that is not per-use (the library's keys there always
 * are), and with `USER_AUTH_REQUIRE_PER_USE=true` it refuses time-bound keys
 * on every Android version — a phone on Android 7–10 without a strong
 * fingerprint then cannot receive [VaultFileEncryption.USER_AUTH] files, and
 * the fetch fails with the server's reason.
 */
enum class UserAuth {
    /** No prompt: the file opens with [io.github.umutcansu.pinvault.PinVault.loadFile] (default). */
    NONE,

    /**
     * Locked. Without a screen lock the file is not stored: the fetch fails
     * with [ScreenLockRequiredException] and the app can send the user to
     * the security settings.
     */
    REQUIRED,

    /**
     * Locked when the device has a screen lock; stored as with [NONE] when it
     * has none, and sealed on the next open or fetch once a lock exists. A
     * [VaultFileEncryption.USER_AUTH] file cannot be received without a
     * screen lock at all, so its fetch fails then as for [REQUIRED].
     */
    IF_SCREEN_LOCK
}

/**
 * Texts of the unlock prompt. With the screen lock allowed the system adds
 * the PIN/pattern/password option itself; a fingerprint-only prompt (Android
 * 7–10 with a fingerprint key) shows [negativeButtonText] to close it.
 */
data class VaultFileUnlockPrompt @JvmOverloads constructor(
    val title: String,
    val subtitle: String? = null,
    val description: String? = null,
    val negativeButtonText: String = "Cancel"
)

/** Result of [io.github.umutcansu.pinvault.PinVault.unlockFile]. */
sealed class VaultFileUnlockResult {
    abstract val key: String

    data class Unlocked(override val key: String, val version: Int, val bytes: ByteArray) : VaultFileUnlockResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unlocked) return false
            return key == other.key && version == other.version && bytes.contentEquals(other.bytes)
        }
        override fun hashCode(): Int = 31 * (31 * key.hashCode() + version) + bytes.contentHashCode()
    }

    /** Nothing stored yet: call fetchFile first. */
    data class NotFound(override val key: String) : VaultFileUnlockResult()

    /** The user closed the prompt. */
    data class Cancelled(override val key: String) : VaultFileUnlockResult()

    /**
     * The key no longer works: Android retired it (the screen lock was
     * removed, or — only for the fingerprint-only key of Android 7–10 — the
     * enrolled fingerprints changed; see [UserAuth]),
     * or the copy was sealed with a key that is gone. The stored copy is
     * deleted; fetchFile downloads it again with a new key (and fails with
     * [ScreenLockRequiredException] if the policy needs a lock that is gone).
     */
    data class Invalidated(override val key: String) : VaultFileUnlockResult()

    /**
     * The stored copy is older than the file's `maxOfflineAge`: the server
     * has not confirmed it for that long. No prompt was shown. A successful
     * fetchFile makes it readable again; with `wipeWhenStale()` the copy has
     * been deleted.
     */
    data class Stale(override val key: String) : VaultFileUnlockResult()

    /**
     * Too many wrong attempts, a Keystore error, a copy that failed its
     * signature check and the like; [reason] says which. A Keystore error
     * leaves the copy and the key in place (try again); a copy that is damaged
     * or fails its signature is deleted (fetch it again).
     */
    data class Failed(override val key: String, val reason: String, val exception: Exception? = null) : VaultFileUnlockResult()
}

/**
 * A [UserAuth] file could not be stored or received because the device has
 * no screen lock: a [UserAuth.REQUIRED] file, or any
 * [VaultFileEncryption.USER_AUTH] file. Nothing was stored.
 */
class ScreenLockRequiredException @JvmOverloads constructor(
    val key: String,
    message: String = "Vault file '$key' needs a screen lock (userAuth = REQUIRED); the device has none, so it was not stored"
) : Exception(message)
