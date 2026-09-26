package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import timber.log.Timber

/**
 * Encrypted storage for client PKCS12 keystores (mTLS).
 * Supports multiple certificates via labels.
 *
 * Each certificate is stored with a label key:
 * - `client_p12_default` — default (backward compatible)
 * - `client_p12_config` — for config API mTLS
 * - `client_p12_host` — for host mTLS
 *
 * P12 bytes are Base64-encoded and stored in [SecurePreferences] (keys in the
 * Android Keystore), `pinvault_secure_client_cert.xml`.
 */
internal class ClientCertSecureStore(context: Context) {

    private val prefs: SharedPreferences by lazy {
        SecurePreferences.open(context, FILE_NAME, namespace = PREFS_NAME, legacyName = PREFS_NAME)
    }

    fun save(p12Bytes: ByteArray) = save(DEFAULT_LABEL, p12Bytes)

    fun save(label: String, p12Bytes: ByteArray) {
        prefs.edit()
            .putString(keyFor(label), Base64.encodeToString(p12Bytes, Base64.NO_WRAP))
            .apply()
        Timber.d("Client P12 saved [%s]", label)
    }

    fun load(): ByteArray? = load(DEFAULT_LABEL)

    fun load(label: String): ByteArray? {
        val encoded = prefs.getString(keyFor(label), null) ?: return null
        return try {
            Base64.decode(encoded, Base64.NO_WRAP).also {
                Timber.d("Client P12 loaded [%s] (%d bytes)", label, it.size)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to decode stored P12 [%s]", label)
            null
        }
    }

    fun exists(): Boolean = exists(DEFAULT_LABEL)

    fun exists(label: String): Boolean = prefs.contains(keyFor(label))

    fun clear() = clear(DEFAULT_LABEL)

    fun clear(label: String) {
        prefs.edit().remove(keyFor(label)).apply()
        Timber.d("Client P12 cleared [%s]", label)
    }

    fun clearAll() {
        prefs.edit().clear().apply()
        Timber.d("All client P12s cleared")
    }

    private fun keyFor(label: String): String = "$KEY_PREFIX$label"

    companion object {
        /** Keep in sync with res/xml/pinvault_backup_rules.xml and pinvault_data_extraction_rules.xml. */
        internal const val FILE_NAME = "pinvault_secure_client_cert"
        /** Namespace, and the file PinVault 2.0.x used (migrated on first open). */
        private const val PREFS_NAME = "pinvault_client_cert"
        private const val KEY_PREFIX = "client_p12_"
        internal const val DEFAULT_LABEL = "default"
    }
}
