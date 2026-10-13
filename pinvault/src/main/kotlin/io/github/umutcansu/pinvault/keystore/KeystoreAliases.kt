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
 */
internal object KeystoreAliases {

    enum class Presence { PRESENT, ABSENT, UNKNOWN }

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
            Timber.w(e, "The Keystore cannot read a key right now")
            Presence.UNKNOWN
        }
    }

    /**
     * True when the key is there, false when it is not.
     * @throws KeystoreUnreadableException when the Keystore cannot say: nothing
     *   may be generated over the alias or dropped because of it.
     */
    fun exists(keyStore: KeyStore, alias: String, what: String): Boolean =
        when (presence(keyStore, alias)) {
            Presence.PRESENT -> true
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
