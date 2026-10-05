package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.VisibleForTesting
import timber.log.Timber
import io.github.umutcansu.pinvault.keystore.KeystoreOptions
import java.io.File
import java.nio.ByteBuffer
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
 * Uses AES-256-GCM for content encryption with a per-file key generated in
 * the Android Keystore. Files are stored in `context.filesDir/vault_files/{key}.enc`:
 *
 * `PVF2` `[version, 4 bytes]` `[IV length, 1]` `[IV]` `[ciphertext + tag]`
 *
 * The file's name and version are part of what the GCM tag covers
 * (associated data), and the version is read from the file itself: a blob
 * moved under another file's name, or given another version, does not
 * decrypt — it is deleted, and the next fetch downloads the file again.
 *
 * Earlier versions wrote `[IV length][IV][ciphertext]` with nothing bound to
 * it and kept the version in a plain preferences file, where anyone who can
 * write the app's storage could change it. Such a copy is read once and
 * written again in the current form.
 */
class EncryptedFileStorageProvider internal constructor(
    private val vaultDir: File,
    private val versionPrefs: SharedPreferences,
    /** The AES key of a file; null = the Android Keystore (tests pass software keys). */
    private val keyFor: ((String) -> SecretKey)? = null
) : VaultStorageProvider {

    constructor(context: Context) : this(
        vaultDir = File(context.filesDir, VAULT_DIR).also { it.mkdirs() },
        versionPrefs = context.getSharedPreferences(VERSION_PREFS_NAME, Context.MODE_PRIVATE)
    )

    override fun save(key: String, bytes: ByteArray, version: Int) {
        val file = fileFor(key)
        // Written beside the copy and moved over it: a failure (a locked or
        // busy Keystore, a full disk) leaves the copy that was there intact.
        val temp = File(vaultDir, "${key}.enc.tmp")
        try {
            val secretKey = keyOf(key)
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            // Android Keystore RSA/AES key'leri caller-provided IV'yi reddediyor.
            // Cipher.init'i sadece key ile çağırıp Keystore'un kendi IV'sini
            // üretmesine izin ver, sonra ciphertext'i IV+data formatında yaz.
            // Legacy non-Keystore anahtarlarla geriye uyumluluk için fallback var.
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            } catch (_: Exception) {
                val iv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            }
            val iv = cipher.iv ?: throw IllegalStateException("the cipher produced no IV")
            cipher.updateAAD(aad(key, version))
            val encrypted = cipher.doFinal(bytes)

            temp.outputStream().use { out ->
                out.write(MAGIC)
                out.write(ByteBuffer.allocate(4).putInt(version).array())
                out.write(iv.size)
                out.write(iv)
                out.write(encrypted)
            }
            if (!temp.renameTo(file)) {
                file.delete()
                if (!temp.renameTo(file)) throw java.io.IOException("could not move the new copy into place")
            }
            // The version lives in the file now.
            versionPrefs.edit().remove(versionKey(key)).apply()
            Timber.d("Vault file saved to disk [%s] — version: %d, %d bytes", key, version, bytes.size)
        } catch (e: Exception) {
            Timber.e(e, "Failed to save vault file to disk [%s] — the previous copy, if any, was kept", key)
            temp.delete()
        }
    }

    override fun load(key: String): ByteArray? {
        val file = fileFor(key)
        if (!file.exists()) return null

        return try {
            // The key first: fetching it may move a file of the oldest form
            // (its key in preferences) under a Keystore key, rewriting the file.
            val secretKey = keyOf(key)
            val data = file.readBytes()
            if (!isCurrentFormat(data)) return loadLegacy(key, data, secretKey)
            val version = ByteBuffer.wrap(data, MAGIC.size, 4).int
            var offset = MAGIC.size + 4
            val ivLength = data[offset].toInt() and 0xFF
            offset += 1
            require(ivLength in 1..32 && data.size > offset + ivLength) { "malformed vault file" }

            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, data, offset, ivLength))
            cipher.updateAAD(aad(key, version))
            offset += ivLength
            cipher.doFinal(data, offset, data.size - offset).also {
                Timber.d("Vault file loaded from disk [%s] — %d bytes", key, it.size)
            }
        } catch (e: javax.crypto.AEADBadTagException) {
            // Not this file at this version under this key: rewritten, moved
            // here from another file, or relabelled. It will never open.
            Timber.e("Vault file [%s] did not decrypt for this name and version — stored copy deleted, fetch it again", key)
            clear(key)
            null
        } catch (e: IllegalArgumentException) {
            Timber.e(e, "Vault file [%s] is malformed — stored copy deleted, fetch it again", key)
            clear(key)
            null
        } catch (e: Exception) {
            // A Keystore that fails says nothing about the copy: keep it.
            Timber.e(e, "Failed to load vault file from disk [%s] — copy kept", key)
            null
        }
    }

    /**
     * A copy in the form earlier versions wrote: opened without associated
     * data, with the version from the preferences file, and written again in
     * the current form.
     */
    private fun loadLegacy(key: String, data: ByteArray, secretKey: SecretKey): ByteArray? {
        val ivLength = data[0].toInt() and 0xFF
        require(ivLength in 1..32 && data.size > 1 + ivLength) { "malformed vault file" }
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, data, 1, ivLength))
        val plain = cipher.doFinal(data, 1 + ivLength, data.size - 1 - ivLength)
        save(key, plain, versionPrefs.getInt(versionKey(key), 0))
        Timber.d("Vault file [%s] rewritten in the current form (name and version bound)", key)
        return plain
    }

    /** From the file itself (authenticated when it is read); an earlier-form copy has it in preferences. */
    override fun getVersion(key: String): Int {
        val file = fileFor(key)
        if (!file.exists()) return 0
        val header = ByteArray(MAGIC.size + 4)
        val read = try {
            file.inputStream().use { it.read(header) }
        } catch (e: Exception) {
            Timber.w(e, "Could not read the version of vault file [%s]", key)
            return 0
        }
        return if (read == header.size && isCurrentFormat(header)) ByteBuffer.wrap(header, MAGIC.size, 4).int
        else versionPrefs.getInt(versionKey(key), 0)
    }

    override fun exists(key: String): Boolean = fileFor(key).exists()

    override fun clear(key: String) {
        fileFor(key).delete()
        versionPrefs.edit()
            .remove(versionKey(key))
            .remove(encKeyFor(key))
            .apply()
        // Remove Keystore entry
        if (keyFor == null) {
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                val alias = KEYSTORE_ALIAS_PREFIX + key
                if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            } catch (e: Exception) {
                Timber.w(e, "Failed to remove Keystore entry [%s]", key)
            }
        }
        Timber.d("Vault file cleared from disk [%s]", key)
    }

    private fun isCurrentFormat(data: ByteArray): Boolean =
        data.size >= MAGIC.size + 4 && MAGIC.indices.all { data[it] == MAGIC[it] }

    private fun aad(key: String, version: Int) = "pinvault-vault-file-store:v2:$key:$version".toByteArray(Charsets.UTF_8)

    private fun keyOf(key: String): SecretKey = keyFor?.invoke(key) ?: getOrCreateKey(key)

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
        return generateKey(alias)
    }

    private fun generateKey(alias: String): SecretKey =
        KeystoreOptions.generating("Vault file key") { unlockedDeviceRequired ->
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            keyGen.init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .apply {
                        if (unlockedDeviceRequired && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                            setUnlockedDeviceRequired(true)
                        }
                    }
                    .build()
            )
            keyGen.generateKey()
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
            val newKey = generateKey(alias)

            // Re-encrypt with Keystore key (the Keystore picks the IV). Still
            // the earlier file form: load() rewrites it with name and version bound.
            val encCipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            encCipher.init(Cipher.ENCRYPT_MODE, newKey)
            val newIv = encCipher.iv
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
        /** Marks the current file form; an earlier-form file starts with its IV length (12). */
        private val MAGIC = "PVF2".toByteArray(Charsets.US_ASCII)
        private const val VAULT_DIR = "vault_files"
        private const val VERSION_PREFS_NAME = "pinvault_vault_file_versions"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS_PREFIX = "pinvault_vault_"

        @VisibleForTesting
        internal fun createForTest(
            vaultDir: File,
            versionPrefs: SharedPreferences,
            keyFor: ((String) -> SecretKey)? = null
        ): EncryptedFileStorageProvider {
            vaultDir.mkdirs()
            return EncryptedFileStorageProvider(vaultDir, versionPrefs, keyFor)
        }
    }
}
