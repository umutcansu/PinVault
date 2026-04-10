package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.VisibleForTesting
import timber.log.Timber
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
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
        // Remove Keystore entry
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val alias = KEYSTORE_ALIAS_PREFIX + key
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        } catch (e: Exception) {
            Timber.w(e, "Failed to remove Keystore entry [%s]", key)
        }
        Timber.d("Vault file cleared from disk [%s]", key)
    }

    private fun fileFor(key: String) = File(vaultDir, "${key}.enc")
    private fun versionKey(key: String) = "vault_file_ver_$key"
    private fun encKeyFor(key: String) = "vault_file_enckey_$key"

    /**
     * Gets or creates a per-file AES-256 key backed by Android Keystore.
     * Migrates legacy keys from SharedPreferences on first access.
     */
    private fun getOrCreateKey(key: String): SecretKey {
        val alias = KEYSTORE_ALIAS_PREFIX + key
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        // 1. Try Keystore first
        keyStore.getKey(alias, null)?.let { return it as SecretKey }

        // 2. Migrate legacy key from SharedPreferences if present
        val legacyKey = versionPrefs.getString(encKeyFor(key), null)
        if (legacyKey != null) {
            val file = fileFor(key)
            if (file.exists()) {
                migrateLegacyFile(key, legacyKey, alias, keyStore)
            }
            versionPrefs.edit().remove(encKeyFor(key)).apply()
            keyStore.getKey(alias, null)?.let { return it as SecretKey }
        }

        // 3. Generate new Keystore-backed key
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return keyGen.generateKey()
    }

    /**
     * Decrypts a file with the legacy SharedPreferences key, then re-encrypts
     * with a new Android Keystore-backed key.
     */
    private fun migrateLegacyFile(key: String, legacyKeyBase64: String, alias: String, keyStore: KeyStore) {
        try {
            val legacySecret = SecretKeySpec(Base64.decode(legacyKeyBase64, Base64.NO_WRAP), "AES")
            val file = fileFor(key)
            val data = file.readBytes()
            val ivLength = data[0].toInt() and 0xFF
            val iv = data.sliceArray(1 until 1 + ivLength)
            val encrypted = data.sliceArray(1 + ivLength until data.size)

            val decCipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            decCipher.init(Cipher.DECRYPT_MODE, legacySecret, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            val plaintext = decCipher.doFinal(encrypted)

            // Create new Keystore key
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            keyGen.init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            val newKey = keyGen.generateKey()

            // Re-encrypt with Keystore key
            val newIv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
            val encCipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            encCipher.init(Cipher.ENCRYPT_MODE, newKey, GCMParameterSpec(GCM_TAG_LENGTH, newIv))
            val reEncrypted = encCipher.doFinal(plaintext)

            file.outputStream().use { out ->
                out.write(newIv.size)
                out.write(newIv)
                out.write(reEncrypted)
            }
            Timber.d("Vault file key migrated to Keystore [%s]", key)
        } catch (e: Exception) {
            Timber.e(e, "Failed to migrate vault file key [%s] — file will be re-downloaded", key)
            fileFor(key).delete()
        }
    }

    companion object {
        private const val VAULT_DIR = "vault_files"
        private const val VERSION_PREFS_NAME = "pinvault_vault_file_versions"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS_PREFIX = "pinvault_vault_"

        @VisibleForTesting
        internal fun createForTest(vaultDir: File, versionPrefs: SharedPreferences): EncryptedFileStorageProvider {
            vaultDir.mkdirs()
            return EncryptedFileStorageProvider(vaultDir, versionPrefs)
        }
    }
}
