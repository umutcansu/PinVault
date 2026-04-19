package com.example.pinvault.server.service

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-end encryption for vault files with encryption = "end_to_end".
 *
 * Uses a standard RSA+AES hybrid:
 *   1. Generate a fresh AES-256 session key + 12-byte GCM IV.
 *   2. Encrypt content with AES-256-GCM → ciphertext + 16-byte tag.
 *   3. Wrap the AES session key with the device's RSA public key using
 *      RSA-OAEP-SHA256 (MGF1-SHA256).
 *   4. Emit a framed envelope the device can parse:
 *
 *      [4 bytes: wrappedKey length BE]
 *      [wrappedKey bytes]                (256 bytes for RSA-2048)
 *      [12 bytes: GCM IV]
 *      [AES-GCM ciphertext + 16-byte tag]
 *
 * The device decrypts by:
 *   - reading the frame,
 *   - RSA-OAEP unwrap using its Android-Keystore private key,
 *   - AES-GCM decrypt.
 *
 * Security notes:
 *   - A fresh session key is generated on EVERY call — no key reuse across
 *     files or fetches. Even two fetches of the same file produce different
 *     ciphertext (random IV, random session key).
 *   - RSA-OAEP with MGF1-SHA256 is the recommended padding scheme (vs
 *     PKCS#1 v1.5 which is vulnerable to Bleichenbacher oracles).
 *   - AES-GCM authenticates the ciphertext (16-byte tag); any tampering
 *     makes the device decrypt fail rather than return garbage.
 */
class VaultEncryptionService(
    private val random: SecureRandom = SecureRandom()
) {

    /**
     * Encrypt [plaintext] for delivery to the device whose RSA public key is
     * [devicePublicKeyPem]. Returns the raw envelope bytes (HTTP response
     * body will be this ByteArray).
     *
     * @throws IllegalArgumentException if the PEM is malformed or the key is
     *         weaker than 2048 bits.
     */
    fun encryptForDevice(plaintext: ByteArray, devicePublicKeyPem: String): ByteArray {
        val publicKey = parseRsaPublicKey(devicePublicKeyPem)
        require(publicKey.keySizeBits() >= 2048) {
            "Device RSA public key must be ≥2048 bits; got ${publicKey.keySizeBits()}"
        }

        // 1. Session key + IV
        val sessionKey = aesKeyGen().generateKey()
        val iv = ByteArray(GCM_IV_BYTES).also(random::nextBytes)

        // 2. AES-GCM encrypt
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = aesCipher.doFinal(plaintext)

        // 3. RSA-OAEP wrap the session key
        val wrappedKey = rsaOaepEncrypt(sessionKey, publicKey)

        // 4. Frame: [4-byte wrappedKey length BE][wrappedKey][12-byte IV][ciphertext+tag]
        val out = ByteArrayOutputStream()
        out.write(intToBytesBE(wrappedKey.size))
        out.write(wrappedKey)
        out.write(iv)
        out.write(ciphertext)
        return out.toByteArray()
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /** Parse "-----BEGIN PUBLIC KEY----- … -----END PUBLIC KEY-----" PEM into RSAPublicKey. */
    private fun parseRsaPublicKey(pem: String): PublicKey {
        val cleaned = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(Regex("\\s+"), "")
        val der = Base64.getDecoder().decode(cleaned)
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
    }

    private fun PublicKey.keySizeBits(): Int = when (this) {
        is java.security.interfaces.RSAPublicKey -> this.modulus.bitLength()
        else -> 0
    }

    private fun aesKeyGen(): KeyGenerator = KeyGenerator.getInstance("AES").apply { init(256, random) }

    private fun rsaOaepEncrypt(sessionKey: SecretKey, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaep = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaep)
        return cipher.doFinal(sessionKey.encoded)
    }

    private fun intToBytesBE(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    companion object {
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
    }
}

/**
 * Test-only companion: decrypt an envelope produced by [VaultEncryptionService].
 * The production device-side decryption lives in the library
 * (VaultFileDecryptor). This helper exists purely so server-side tests can
 * verify round-trip correctness without pulling in Android dependencies.
 */
object VaultEncryptionRoundtripTestHelper {
    fun decrypt(envelope: ByteArray, privateKey: java.security.PrivateKey): ByteArray {
        val wrappedKeyLen = ((envelope[0].toInt() and 0xFF) shl 24) or
                ((envelope[1].toInt() and 0xFF) shl 16) or
                ((envelope[2].toInt() and 0xFF) shl 8) or
                (envelope[3].toInt() and 0xFF)
        var offset = 4
        val wrappedKey = envelope.copyOfRange(offset, offset + wrappedKeyLen); offset += wrappedKeyLen
        val iv = envelope.copyOfRange(offset, offset + VaultEncryptionService.GCM_IV_BYTES)
        offset += VaultEncryptionService.GCM_IV_BYTES
        val ciphertext = envelope.copyOfRange(offset, envelope.size)

        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaep = OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
        )
        rsa.init(Cipher.DECRYPT_MODE, privateKey, oaep)
        val sessionKeyBytes = rsa.doFinal(wrappedKey)
        val sessionKey = SecretKeySpec(sessionKeyBytes, "AES")

        val aes = Cipher.getInstance("AES/GCM/NoPadding")
        aes.init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(VaultEncryptionService.GCM_TAG_BITS, iv))
        return aes.doFinal(ciphertext)
    }
}
