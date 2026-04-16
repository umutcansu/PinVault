package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.VisibleForTesting
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import timber.log.Timber

/**
 * Encrypted local persistence for [CertificateConfig].
 *
 * Uses EncryptedSharedPreferences to store config at rest.
 * Pin hashes aren't readable even on rooted devices.
 */
internal class CertificateConfigStore private constructor(private val prefs: SharedPreferences) {

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

    fun getCurrentVersion(): Int = prefs.getInt(KEY_VERSION, 0)

    fun save(config: CertificateConfig) {
        prefs.edit().apply {
            putInt(KEY_VERSION, config.computedVersion())

            // Format: hostname|version|hash1,hash2
            val pinsData = config.pins.joinToString(ENTRY_SEPARATOR) { pin ->
                "${pin.hostname}$FIELD_SEPARATOR${pin.version}$FIELD_SEPARATOR${pin.sha256.joinToString(HASH_SEPARATOR)}"
            }
            putString(KEY_PINS, pinsData)

            apply()
        }
        Timber.d("Certificate config saved — version: %d", config.computedVersion())
    }

    fun load(): CertificateConfig? {
        val version = prefs.getInt(KEY_VERSION, 0)
        if (version == 0) return null

        val pinsData = prefs.getString(KEY_PINS, null) ?: return null

        val pins = parsePins(pinsData)
        if (pins.isEmpty()) return null

        return CertificateConfig(
            version = version,
            pins = pins,
            forceUpdate = false
        ).also {
            Timber.d("Certificate config loaded — version: %d, %d pins", it.version, it.pins.size)
        }
    }

    fun clear() {
        prefs.edit().clear().apply()
        Timber.d("Certificate config store cleared")
    }

    private fun parsePins(data: String): List<HostPin> {
        return try {
            data.split(ENTRY_SEPARATOR).mapNotNull { entry ->
                val parts = entry.split(FIELD_SEPARATOR)
                when {
                    // New format: hostname|version|hash1,hash2
                    parts.size >= 3 -> {
                        val hostname = parts[0]
                        val version = parts[1].toIntOrNull() ?: 0
                        val hashes = parts.drop(2).joinToString(FIELD_SEPARATOR)
                            .split(HASH_SEPARATOR).filter { it.isNotBlank() }
                        if (hashes.size >= 2) HostPin(hostname, hashes, version) else null
                    }
                    // Old format migration: hostname|hash1,hash2
                    parts.size == 2 -> {
                        val hostname = parts[0]
                        val hashes = parts[1].split(HASH_SEPARATOR).filter { it.isNotBlank() }
                        if (hashes.size >= 2) HostPin(hostname, hashes, version = 0) else null
                    }
                    else -> null
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse stored pins")
            emptyList()
        }
    }

    companion object {
        private const val PREFS_NAME = "ssl_cert_config"
        internal const val KEY_VERSION = "config_version"
        internal const val KEY_PINS = "config_pins"
        private const val ENTRY_SEPARATOR = "\n"
        private const val FIELD_SEPARATOR = "|"
        private const val HASH_SEPARATOR = ","

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = CertificateConfigStore(prefs)
    }
}
