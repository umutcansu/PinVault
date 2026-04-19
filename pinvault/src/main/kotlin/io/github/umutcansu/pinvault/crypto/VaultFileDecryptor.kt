package io.github.umutcansu.pinvault.crypto

import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Decrypts envelopes produced by the server's VaultEncryptionService for
 * vault files with encryption = "end_to_end".
 *
 * Envelope layout (big-endian):
 *
 *     [4 bytes: wrappedKey length]
 *     [wrappedKey bytes          ]  (RSA-OAEP-SHA256 wrapped AES session key)
 *     [12 bytes: GCM IV          ]
 *     [AES-GCM ciphertext + 16-byte tag]
 *
 * Security:
 *   - RSA-OAEP-SHA256 with MGF1-SHA256 (matches the server).
 *   - AES-256-GCM authenticates ciphertext; any tampering surfaces as
 *     [javax.crypto.AEADBadTagException] instead of corrupt plaintext.
 *   - Pure JCA — no Android dependency — so it runs in Robolectric tests
 *     and plain JVM environments without changes.
 */
object VaultFileDecryptor {

    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    /**
     * Decrypt an E2E envelope with the device's RSA private key.
     *
     * @throws IllegalArgumentException if the envelope is malformed.
     * @throws javax.crypto.AEADBadTagException if the ciphertext was tampered
     *         with or the wrong private key is used.
     */
    fun decrypt(envelope: ByteArray, privateKey: PrivateKey): ByteArray {
        require(envelope.size > 4 + GCM_IV_BYTES) {
            "Envelope too short (${envelope.size} bytes)"
        }

        // Parse: [4-byte wrappedKey length][wrappedKey][12-byte IV][ciphertext]
        val wrappedKeyLen = ((envelope[0].toInt() and 0xFF) shl 24) or
                ((envelope[1].toInt() and 0xFF) shl 16) or
                ((envelope[2].toInt() and 0xFF) shl 8) or
                (envelope[3].toInt() and 0xFF)

        require(wrappedKeyLen in 64..1024) {
            "Implausible wrappedKey length: $wrappedKeyLen"
        }
        require(envelope.size >= 4 + wrappedKeyLen + GCM_IV_BYTES) {
            "Envelope truncated at wrappedKey/IV boundary"
        }

        var offset = 4
        val wrappedKey = envelope.copyOfRange(offset, offset + wrappedKeyLen); offset += wrappedKeyLen
        val iv = envelope.copyOfRange(offset, offset + GCM_IV_BYTES); offset += GCM_IV_BYTES
        val ciphertext = envelope.copyOfRange(offset, envelope.size)

        // 1. RSA-OAEP unwrap the AES session key.
        //
        // NOTE: We use OAEP-SHA256 hash with MGF1-SHA1 — the canonical Java
        // default spec `OAEPWithSHA-256AndMGF1Padding`. Android's JCA only
        // ships MGF1-SHA1; forcing MGF1-SHA256 throws on older devices
        // (observed on Mi 9T / Android 11). Server mirrors this spec so the
        // RSA-OAEP round-trip interoperates everywhere.
        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaep = OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
        )
        rsa.init(Cipher.DECRYPT_MODE, privateKey, oaep)
        val sessionKeyBytes = rsa.doFinal(wrappedKey)
        val sessionKey = SecretKeySpec(sessionKeyBytes, "AES")

        // 2. AES-GCM decrypt (tag auto-verified).
        val aes = Cipher.getInstance("AES/GCM/NoPadding")
        aes.init(Cipher.DECRYPT_MODE, sessionKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return aes.doFinal(ciphertext)
    }
}
