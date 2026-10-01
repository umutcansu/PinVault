package io.github.umutcansu.pinvault.util

import io.github.umutcansu.pinvault.store.PrefsCipher
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM + HMAC-SHA256 with keys in memory — the stand-in for the
 * Android Keystore cipher in Robolectric tests of the secure stores.
 */
class SoftwarePrefsCipher : PrefsCipher {
    private val aes: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val macKey: SecretKey = KeyGenerator.getInstance("HmacSHA256").generateKey()
    private val random = SecureRandom()

    override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aes, GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return iv + cipher.doFinal(plaintext)
    }

    override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
        if (sealed.size < 28) throw AEADBadTagException("short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, aes, GCMParameterSpec(128, sealed, 0, 12))
        cipher.updateAAD(aad)
        return cipher.doFinal(sealed, 12, sealed.size - 12)
    }

    override fun mac(input: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run { init(macKey); doFinal(input) }
}
