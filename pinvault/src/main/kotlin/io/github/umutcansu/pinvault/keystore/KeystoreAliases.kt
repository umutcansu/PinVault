package io.github.umutcansu.pinvault.keystore

import java.security.KeyStore
import java.security.KeyStoreException
import timber.log.Timber

/**
 * Whether the Keystore holds a key under an alias, told apart from "it cannot
 * say right now".
 *
 * On Keystore2 (Android 12+) `containsAlias` logs every error but
 * `KEY_NOT_FOUND` and answers false, so a busy or restarting keystore daemon
 * looks like a missing key. `getKey` throws for those errors instead. A false
 * `containsAlias` is therefore asked again with `getKey` before a key is
 * generated over the alias, or a credential is dropped because of it: a key
 * the Keystore merely could not read is never replaced.
 *
 * One `getKey` failure is not "cannot say": a key the Keystore reports as
 * permanently invalidated (the screen lock removed under a user-auth key).
 * Keystore2's `engineGetKey` turns that `KeyPermanentlyInvalidatedException`
 * into a plain `UnrecoverableKeyException` with only its message left, so the
 * message is what tells it apart ([Presence.INVALIDATED]): such a key is
 * there, retired, and may be replaced. The legacy Keystore (Android 7–11)
 * reports the same event differently: a key bound to the screen lock is
 * encrypted with it, and once the lock is removed or changed its blob no
 * longer decrypts — `getKey` fails with a `KeyStoreException` "Key blob
 * corrupted" (VALUE_CORRUPTED) as the cause. A blob that does not decrypt
 * never will again, so that counts as invalidated too.
 */
internal object KeystoreAliases {

    enum class Presence { PRESENT, ABSENT, INVALIDATED, UNKNOWN }

    /** The message Keystore2 gives a permanently invalidated key (`AndroidKeyStoreProvider`). */
    private const val INVALIDATED_MESSAGE = "User changed or deleted their auth credentials"

    /** The legacy Keystore's VALUE_CORRUPTED (`KeyStore.getKeyStoreException`): a blob that no longer decrypts. */
    private const val CORRUPTED_BLOB_MESSAGE = "Key blob corrupted"

    fun presence(keyStore: KeyStore, alias: String): Presence {
        try {
            if (keyStore.containsAlias(alias)) return Presence.PRESENT
        } catch (e: Exception) {
            Timber.w(e, "The Keystore cannot list a key right now")
            return Presence.UNKNOWN
        }
        return try {
            if (keyStore.getKey(alias, null) != null) Presence.PRESENT else Presence.ABSENT
        } catch (e: Exception) {
            if (isInvalidated(e)) return Presence.INVALIDATED
            Timber.w(e, "The Keystore cannot read a key right now")
            Presence.UNKNOWN
        }
    }

    /** A permanently invalidated key: as the exception itself says, as Keystore2 rewrites it, or a legacy blob that no longer decrypts. */
    fun isInvalidated(e: Throwable): Boolean =
        generateSequence(e) { it.cause?.takeIf { cause -> cause !== it } }.take(8).any {
            it is android.security.keystore.KeyPermanentlyInvalidatedException ||
                (it is java.security.UnrecoverableKeyException && it.message?.contains(INVALIDATED_MESSAGE) == true) ||
                // android.security.KeyStoreException on Android 7–11 (a hidden class there).
                (it.javaClass.simpleName == "KeyStoreException" && it.message == CORRUPTED_BLOB_MESSAGE)
        }

    /**
     * True when the key is there, false when it is not.
     * @throws KeystoreUnreadableException when the Keystore cannot say: nothing
     *   may be generated over the alias or dropped because of it.
     */
    fun exists(keyStore: KeyStore, alias: String, what: String): Boolean =
        when (presence(keyStore, alias)) {
            // Invalidated is there too: not something to generate over unasked.
            Presence.PRESENT, Presence.INVALIDATED -> true
            Presence.ABSENT -> false
            Presence.UNKNOWN -> throw KeystoreUnreadableException("The Keystore cannot say whether the $what exists right now")
        }

    /**
     * Deletes [alias] unless the Keystore is sure there is nothing under it: a
     * delete that is asked for (unenroll, forget, a retired key) is not skipped
     * because the Keystore could not list the alias for a moment.
     */
    fun deleteUnlessAbsent(keyStore: KeyStore, alias: String) {
        if (presence(keyStore, alias) != Presence.ABSENT) keyStore.deleteEntry(alias)
    }
}

/** The Keystore could not say whether a key exists: retry later, change nothing. */
internal class KeystoreUnreadableException(message: String) : KeyStoreException(message)
