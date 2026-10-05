package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.annotation.VisibleForTesting
import timber.log.Timber

/**
 * Default encrypted storage for vault files: [SecurePreferences] (keys in the
 * Android Keystore), `pinvault_secure_vault_files.xml`.
 *
 * Best for small/medium files (<1MB). For larger files, use [EncryptedFileStorageProvider].
 * Both use Android Keystore for hardware-backed key management.
 *
 * A file is ONE sealed entry, `2:<version>:<Base64 content>`: [SecurePreferences]
 * binds an entry to its name, so content and version cannot be taken from
 * two different moments, and neither can be moved under another file's
 * name. Earlier versions kept the version in an entry of its own; such a
 * copy is read once and written again as one entry.
 */
internal class VaultFileStore private constructor(
    private val prefs: SharedPreferences
) : VaultStorageProvider {

    constructor(context: Context) : this(
        SecurePreferences.open(context, FILE_NAME, namespace = PREFS_NAME, legacyName = PREFS_NAME)
    )

    override fun save(key: String, bytes: ByteArray, version: Int) {
        prefs.edit()
            .putString(dataKey(key), "$RECORD_PREFIX$version:" + Base64.encodeToString(bytes, Base64.NO_WRAP))
            .remove(versionKey(key))
            .apply()
        Timber.d("Vault file saved [%s] — version: %d, %d bytes", key, version, bytes.size)
    }

    override fun load(key: String): ByteArray? {
        val stored = prefs.getString(dataKey(key), null) ?: return null
        return try {
            val record = parse(stored)
            if (record == null) {
                // An earlier version's copy: content here, version in its own entry.
                val bytes = Base64.decode(stored, Base64.NO_WRAP)
                save(key, bytes, prefs.getInt(versionKey(key), 0))
                return bytes
            }
            Base64.decode(record.second, Base64.NO_WRAP).also {
                Timber.d("Vault file loaded [%s] — %d bytes", key, it.size)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to decode vault file [%s]", key)
            null
        }
    }

    override fun getVersion(key: String): Int {
        val stored = prefs.getString(dataKey(key), null) ?: return 0
        return parse(stored)?.first ?: prefs.getInt(versionKey(key), 0)
    }

    /** (version, Base64 content) of a current-form entry; null for an earlier version's. */
    private fun parse(stored: String): Pair<Int, String>? {
        if (!stored.startsWith(RECORD_PREFIX)) return null
        val rest = stored.substring(RECORD_PREFIX.length)
        val version = rest.substringBefore(':', "").toIntOrNull() ?: return null
        return version to rest.substringAfter(':')
    }

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
        /** Keep in sync with res/xml/pinvault_backup_rules.xml and pinvault_data_extraction_rules.xml. */
        internal const val FILE_NAME = "pinvault_secure_vault_files"
        /** Namespace, and the file PinVault 2.0.x used (migrated on first open). */
        private const val PREFS_NAME = "pinvault_vault_files"
        private const val DATA_PREFIX = "vault_data_"
        private const val VERSION_PREFIX = "vault_ver_"
        /** Base64 has no `:`, so an earlier version's entry never starts with this. */
        private const val RECORD_PREFIX = "2:"

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = VaultFileStore(prefs)
    }
}
