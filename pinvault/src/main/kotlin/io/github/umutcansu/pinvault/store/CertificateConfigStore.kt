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

    /** Default constructor — single shared namespace (legacy / single Config API). */
    constructor(context: Context) : this(context, DEFAULT_PREFS_NAME)

    /**
     * V2: per-Config-API namespaced constructor. Each Config API block gets
     * its own EncryptedSharedPreferences file so pins from different APIs
     * never collide even if they share a hostname.
     *
     * The raw [prefsName] is sanitized — non-alphanumeric chars replaced with
     * underscores to keep filesystem-safe file names.
     */
    constructor(context: Context, prefsName: String) : this(
        EncryptedSharedPreferences.create(
            context,
            prefsName.replace(Regex("[^A-Za-z0-9_-]"), "_"),
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    )

    fun getCurrentVersion(): Int = prefs.getInt(KEY_VERSION, 0)

    /**
     * Returns the [CertificateConfig.issuedAt] of the most recently applied
     * config, or 0 if no config has ever been saved (or if the stored config
     * predates the freshness-tracking change).
     *
     * Used by the updater to reject replays: a freshly fetched config must
     * have `issuedAt > getCurrentIssuedAt()` before being persisted.
     */
    fun getCurrentIssuedAt(): Long = prefs.getLong(KEY_ISSUED_AT, 0L)

    fun save(config: CertificateConfig) {
        prefs.edit().apply {
            putInt(KEY_VERSION, config.computedVersion())
            putLong(KEY_ISSUED_AT, config.issuedAt)
            putBoolean(KEY_FORCE_UPDATE, config.forceUpdate)

            // Format: hostname|version|hash1,hash2
            val pinsData = config.pins.joinToString(ENTRY_SEPARATOR) { pin ->
                "${pin.hostname}$FIELD_SEPARATOR${pin.version}$FIELD_SEPARATOR${pin.sha256.joinToString(HASH_SEPARATOR)}"
            }
            putString(KEY_PINS, pinsData)

            apply()
        }
        Timber.d("Certificate config saved — version: %d, issuedAt: %d, forceUpdate: %s",
            config.computedVersion(), config.issuedAt, config.forceUpdate)
    }

    fun load(): CertificateConfig? {
        val version = prefs.getInt(KEY_VERSION, 0)
        if (version == 0) return null

        val pinsData = prefs.getString(KEY_PINS, null) ?: return null

        val pins = parsePins(pinsData)
        if (pins.isEmpty()) return null

        val issuedAt = prefs.getLong(KEY_ISSUED_AT, 0L)
        val forceUpdate = prefs.getBoolean(KEY_FORCE_UPDATE, false)
        return CertificateConfig(
            version = version,
            pins = pins,
            forceUpdate = forceUpdate,
            issuedAt = issuedAt
        ).also {
            Timber.d("Certificate config loaded — version: %d, issuedAt: %d, forceUpdate: %s, %d pins",
                it.version, it.issuedAt, it.forceUpdate, it.pins.size)
        }
    }

    fun clear() {
        prefs.edit().clear().apply()
        Timber.d("Certificate config store cleared")
    }

    private fun parsePins(data: String): List<HostPin> {
        // Per-entry try/catch so one malformed row (e.g. a host the server
        // shipped with a single pin, violating HostPin's invariant) only
        // drops that row rather than poisoning the whole cache. The outer
        // try/catch below stays as a last-resort blob-corruption guard
        // (L-01) — it fires only if the entire prefs string is unreadable,
        // not if a single row fails validation.
        return try {
            data.split(ENTRY_SEPARATOR).mapNotNull { entry ->
                try {
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
                } catch (e: Exception) {
                    Timber.w(e, "Skipping malformed pin entry — other hosts preserved")
                    null
                }
            }
        } catch (e: Exception) {
            // Wipe the corrupt blob so subsequent loads don't loop on it (L-01).
            // The next fetch will repopulate from the backend; in the meantime
            // an empty pin list is fail-safe (DynamicSSLManager refuses
            // connections when no pins are configured).
            Timber.e(e, "Failed to parse stored pins — clearing corrupt store")
            prefs.edit().clear().apply()
            emptyList()
        }
    }

    companion object {
        private const val DEFAULT_PREFS_NAME = "ssl_cert_config"

        /** Build the per-Config-API prefs file name. */
        fun prefsNameFor(configApiId: String): String =
            if (configApiId.isBlank()) DEFAULT_PREFS_NAME
            else "ssl_cert_config_$configApiId"

        internal const val KEY_VERSION = "config_version"
        internal const val KEY_PINS = "config_pins"
        internal const val KEY_ISSUED_AT = "config_issued_at"
        internal const val KEY_FORCE_UPDATE = "config_force_update"
        private const val ENTRY_SEPARATOR = "\n"
        private const val FIELD_SEPARATOR = "|"
        private const val HASH_SEPARATOR = ","

        @VisibleForTesting
        internal fun createForTest(prefs: SharedPreferences) = CertificateConfigStore(prefs)
    }
}
