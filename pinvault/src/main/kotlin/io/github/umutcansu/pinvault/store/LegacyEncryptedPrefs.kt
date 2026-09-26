package io.github.umutcansu.pinvault.store

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import timber.log.Timber
import java.io.File

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
     * Every entry of `shared_prefs/<name>.xml`; null when there is no such
     * file; empty when it no longer opens (its Keystore key is gone).
     */
    fun readAll(context: Context, name: String): Map<String, *>? {
        if (!File(File(context.applicationInfo.dataDir, "shared_prefs"), "$name.xml").exists()) return null
        return try {
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
        } catch (e: Exception) {
            Timber.w(e, "Legacy store %s.xml does not open; its entries are dropped", name)
            emptyMap<String, Any?>()
        }
    }
}
