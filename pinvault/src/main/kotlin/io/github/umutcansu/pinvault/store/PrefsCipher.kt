package io.github.umutcansu.pinvault.store

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The two operations [SecurePreferences] needs: authenticated encryption of
 * values and a keyed hash for preference names.
 */
internal interface PrefsCipher {
    /** AES-256-GCM over [plaintext] with [aad]; returns `iv || ciphertext+tag`. */
    fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray

    /**
     * Inverse of [seal].
     * @throws AEADBadTagException when [sealed] was not produced by this key with this [aad].
     */
    fun open(sealed: ByteArray, aad: ByteArray): ByteArray

    /** HMAC-SHA256 of [input]. */
    fun mac(input: ByteArray): ByteArray
}

/**
 * [PrefsCipher] whose keys are generated inside the Android Keystore and
 * never leave it: every operation runs in the Keystore (TEE where the device
 * has one). One pair of keys per app, shared by every PinVault store.
 */
internal class KeystorePrefsCipher private constructor(
    private val aesKey: SecretKey,
    private val macKey: SecretKey
) : PrefsCipher {

    override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey) // the Keystore chooses a random IV
        cipher.updateAAD(aad)
        return cipher.iv + cipher.doFinal(plaintext)
    }

    override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
        if (sealed.size < IV_LENGTH + TAG_LENGTH) throw AEADBadTagException("sealed value too short")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(TAG_LENGTH * 8, sealed, 0, IV_LENGTH))
        cipher.updateAAD(aad)
        return cipher.doFinal(sealed, IV_LENGTH, sealed.size - IV_LENGTH)
    }

    override fun mac(input: ByteArray): ByteArray =
        Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).run {
            init(macKey)
            doFinal(input)
        }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val AES_ALIAS = "pinvault_prefs_aes"
        private const val MAC_ALIAS = "pinvault_prefs_mac"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val TAG_LENGTH = 16

        @Volatile private var instance: KeystorePrefsCipher? = null

        /** The app's keys, generated on first use. */
        fun get(): KeystorePrefsCipher =
            instance ?: synchronized(this) { instance ?: create().also { instance = it } }

        private fun create(): KeystorePrefsCipher {
            val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
            val aes = keyStore.getKey(AES_ALIAS, null) as SecretKey?
                ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
                    init(
                        KeyGenParameterSpec.Builder(AES_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(256)
                            .build()
                    )
                    generateKey()
                }
            val mac = keyStore.getKey(MAC_ALIAS, null) as SecretKey?
                ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER).run {
                    init(KeyGenParameterSpec.Builder(MAC_ALIAS, KeyProperties.PURPOSE_SIGN).build())
                    generateKey()
                }
            return KeystorePrefsCipher(aes, mac)
        }
    }
}
