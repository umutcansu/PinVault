package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.annotation.VisibleForTesting
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import timber.log.Timber

/**
 * Default encrypted storage for vault files using EncryptedSharedPreferences.
 *
 * Best for small/medium files (<1MB). For larger files, use [EncryptedFileStorageProvider].
 * Both use Android Keystore for hardware-backed key management.
 */
internal class VaultFileStore private constructor(
    private val prefs: SharedPreferences
) : VaultStorageProvider {

    constructor(context: Context) : this(
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    )

    override fun save(key: String, bytes: ByteArray, version: Int) {
        prefs.edit()
            .putString(dataKey(key), Base64.encodeToString(bytes, Base64.NO_WRAP))
            .putInt(versionKey(key), version)
            .apply()
        Timber.d("Vault file saved [%s] — version: %d, %d bytes", key, version, bytes.size)
    }

    override fun load(key: String): ByteArray? {
        val encoded = prefs.getString(dataKey(key), null) ?: return null
        return try {
            Base64.decode(encoded, Base64.NO_WRAP).also {
                Timber.d("Vault file loaded [%s] — %d bytes", key, it.size)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to decode vault file [%s]", key)
            null
        }
    }

    override fun getVersion(key: String): Int = prefs.getInt(versionKey(key), 0)

    override fun exists(key: String): Boolean = prefs.contains(dataKey(key))

    override fun clear(key: String) {
        prefs.edit()
            .remove(dataKey(key))
            .remove(versionKey(key))
            .apply()
        Timber.d("Vault file cleared [%s]", key)
    }

    private fun dataKey(key: String) = "${DATA_PREFIX}$key"
    private fun versionKey(key: String) = "${VERSION_PREFIX}$key"

    companion object {
        private const val PREFS_NAME = "pinvault_vault_files"
        private const val DATA_PREFIX = "vault_data_"
        private const val VERSION_PREFIX = "vault_ver_"

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = VaultFileStore(prefs)
    }
}
