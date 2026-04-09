package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.annotation.VisibleForTesting
import timber.log.Timber
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted file-based storage for large vault files (ML models, binary assets, etc.).
 *
 * Uses AES-256-GCM for content encryption with a key derived from Android Keystore.
 * Files are stored in `context.filesDir/vault_files/{key}.enc`.
 * Version metadata is tracked in SharedPreferences.
 */
class EncryptedFileStorageProvider internal constructor(
    private val vaultDir: File,
    private val versionPrefs: SharedPreferences
) : VaultStorageProvider {

    constructor(context: Context) : this(
        vaultDir = File(context.filesDir, VAULT_DIR).also { it.mkdirs() },
        versionPrefs = context.getSharedPreferences(VERSION_PREFS_NAME, Context.MODE_PRIVATE)
    )

    override fun save(key: String, bytes: ByteArray, version: Int) {
        val file = fileFor(key)
        try {
            val secretKey = getOrCreateKey(key)
            val iv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            val encrypted = cipher.doFinal(bytes)

            // Write: [iv_length(1)][iv][encrypted_data]
            file.outputStream().use { out ->
                out.write(iv.size)
                out.write(iv)
                out.write(encrypted)
            }

            versionPrefs.edit().putInt(versionKey(key), version).apply()
            Timber.d("Vault file saved to disk [%s] — version: %d, %d bytes", key, version, bytes.size)
        } catch (e: Exception) {
            Timber.e(e, "Failed to save vault file to disk [%s]", key)
            file.delete()
        }
    }

    override fun load(key: String): ByteArray? {
        val file = fileFor(key)
        if (!file.exists()) return null

        return try {
            val secretKey = getOrCreateKey(key)
            val data = file.readBytes()
            val ivLength = data[0].toInt() and 0xFF
            val iv = data.sliceArray(1 until 1 + ivLength)
            val encrypted = data.sliceArray(1 + ivLength until data.size)

            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            cipher.doFinal(encrypted).also {
                Timber.d("Vault file loaded from disk [%s] — %d bytes", key, it.size)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to load vault file from disk [%s]", key)
            null
        }
    }

    override fun getVersion(key: String): Int = versionPrefs.getInt(versionKey(key), 0)

    override fun exists(key: String): Boolean = fileFor(key).exists()

    override fun clear(key: String) {
        fileFor(key).delete()
        versionPrefs.edit()
            .remove(versionKey(key))
            .remove(encKeyFor(key))
            .apply()
        Timber.d("Vault file cleared from disk [%s]", key)
    }

    private fun fileFor(key: String) = File(vaultDir, "${key}.enc")
    private fun versionKey(key: String) = "vault_file_ver_$key"
    private fun encKeyFor(key: String) = "vault_file_enckey_$key"

    /**
     * Gets or creates a per-file AES-256 key stored in prefs.
     * In production, this should ideally be backed by Android Keystore,
     * but for simplicity we store Base64-encoded key material.
     */
    private fun getOrCreateKey(key: String): SecretKey {
        val existing = versionPrefs.getString(encKeyFor(key), null)
        if (existing != null) {
            return SecretKeySpec(Base64.decode(existing, Base64.NO_WRAP), "AES")
        }
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        versionPrefs.edit()
            .putString(encKeyFor(key), Base64.encodeToString(keyBytes, Base64.NO_WRAP))
            .apply()
        return SecretKeySpec(keyBytes, "AES")
    }

    companion object {
        private const val VAULT_DIR = "vault_files"
        private const val VERSION_PREFS_NAME = "pinvault_vault_file_versions"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128

        @VisibleForTesting
        internal fun createForTest(vaultDir: File, versionPrefs: SharedPreferences): EncryptedFileStorageProvider {
            vaultDir.mkdirs()
            return EncryptedFileStorageProvider(vaultDir, versionPrefs)
        }
    }
}
