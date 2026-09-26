package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.VisibleForTesting
import com.google.gson.Gson
import io.github.umutcansu.pinvault.model.SignedKeySet
import timber.log.Timber

/**
 * Encrypted persistence for the latest applied signing-key set of each
 * Config API block.
 *
 * Deliberately a separate file from [CertificateConfigStore]: that store is
 * wiped by `PinVault.reset()`, by corrupt-store recovery and by a health-gate
 * rollback with nothing to roll back to. A key set carries revocations, and
 * forgetting one would put a revoked signing key back into trust — so it
 * survives all of those. It is excluded from cloud backup and device transfer
 * for the same reason (a restored older set would un-revoke keys).
 *
 * One file for every block (`pinvault_secure_signing_keys.xml`, keys in the
 * Android Keystore via [SecurePreferences]), because Android's backup rules
 * cannot exclude files by wildcard.
 *
 * The signed set is stored as received — payload plus signatures — and is
 * re-verified against the app's recovery keys every time it is read, so a
 * set is only ever trusted while the current build still vouches for it.
 * It is (de)serialized as the `model` class itself, never through a generic
 * TypeToken, so R8-minified apps read it back correctly.
 */
internal class SigningKeyStore private constructor(private val prefs: SharedPreferences) {

    constructor(context: Context) : this(
        SecurePreferences.open(context, FILE_NAME, namespace = PREFS_NAME, legacyName = PREFS_NAME)
    )

    private val gson = Gson()

    fun load(configApiId: String): SignedKeySet? {
        val json = prefs.getString(key(configApiId), null) ?: return null
        return try {
            gson.fromJson(json, SignedKeySet::class.java)
        } catch (e: Exception) {
            Timber.w(e, "Stored signing-key set for '%s' is unreadable — ignoring it", configApiId)
            null
        }
    }

    fun save(configApiId: String, keySet: SignedKeySet) {
        // commit(), not apply(): a revocation must be on disk before the
        // device acts on it — a crash right after must not un-revoke a key.
        prefs.edit().putString(key(configApiId), gson.toJson(keySet)).commit()
    }

    fun clear(configApiId: String) {
        prefs.edit().remove(key(configApiId)).apply()
    }

    private fun key(id: String) = "keyset_$id"

    companion object {
        /** Keep in sync with res/xml/pinvault_backup_rules.xml and pinvault_data_extraction_rules.xml. */
        internal const val FILE_NAME = "pinvault_secure_signing_keys"
        /** Namespace, and the file PinVault 2.0.x used (migrated on first open). */
        internal const val PREFS_NAME = "pinvault_signing_keys"

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = SigningKeyStore(prefs)
    }
}
