package io.github.umutcansu.pinvault.store

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import timber.log.Timber
import java.io.File
import java.security.KeyStore
import javax.crypto.AEADBadTagException

/**
 * Reads the files PinVault 2.0.x wrote with androidx.security's
 * EncryptedSharedPreferences, once, so [SecurePreferences.open] can move them
 * to the Keystore store. The only remaining use of that library (deprecated
 * upstream in April 2025); drop it once apps are past the migration.
 *
 * The EncryptedSharedPreferences master key is left in the Keystore: the app
 * may use EncryptedSharedPreferences for its own files.
 */
@Suppress("DEPRECATION")
internal object LegacyEncryptedPrefs {

    /**
     * Every entry of `shared_prefs/<name>.xml`. Null when there is no such
     * file, and also when it could not be read this time (the caller keeps
     * the file and tries again at the next start). Empty only when it can
     * never open again: its master key is gone, or the key there is not the
     * one that encrypted it — the caller then deletes it.
     */
    fun readAll(context: Context, name: String): Map<String, *>? {
        if (!File(File(context.applicationInfo.dataDir, "shared_prefs"), "$name.xml").exists()) return null
        return read(
            name,
            masterKeyPresent = {
                KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            },
            open = {
                // masterKeyPresent runs first: build() makes a missing master
                // key, after which "gone" could no longer be told apart.
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                EncryptedSharedPreferences.create(
                    context,
                    name,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                ).all
            }
        )
    }

    /**
     * [readAll] once the file is known to exist. A Keystore that fails (busy,
     * locked, a binder error) says nothing about the file, and deleting it
     * then would lose a 2.0.x store for good: only a confirmed missing master
     * key or a key mismatch (the keyset does not decrypt: AEADBadTagException)
     * gives it up.
     */
    internal fun read(name: String, masterKeyPresent: () -> Boolean, open: () -> Map<String, *>): Map<String, *>? {
        val present = try {
            masterKeyPresent()
        } catch (e: Exception) {
            Timber.w(e, "Legacy store %s.xml: the Keystore cannot be read now — kept for the next start", name)
            return null
        }
        if (!present) {
            Timber.w("Legacy store %s.xml: its master key is gone; its entries are dropped", name)
            return emptyMap<String, Any?>()
        }
        return try {
            open()
        } catch (e: Exception) {
            if (isKeyMismatch(e)) {
                Timber.w(e, "Legacy store %s.xml does not open with its master key; its entries are dropped", name)
                emptyMap<String, Any?>()
            } else {
                Timber.w(e, "Legacy store %s.xml could not be read now — kept for the next start", name)
                null
            }
        }
    }

    /** The master key is there but did not decrypt the file's keyset. */
    internal fun isKeyMismatch(e: Throwable): Boolean =
        generateSequence(e) { it.cause?.takeIf { cause -> cause !== it } }.take(8).any { it is AEADBadTagException }
}
