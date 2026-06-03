package com.example.pinvault.server.service

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Transparent at-rest encryption for vault file content (encryption = "at_rest").
 *
 * A file uploaded with `encryption=at_rest` is stored AES-256-GCM encrypted in
 * the DB and decrypted again before it is served (the wire format is identical
 * to `plain` — the device never sees the at-rest layer). [VaultFileStore]
 * applies this transparently on put/get.
 *
 * Encrypted blob layout: `[MAGIC(8)][salt(16)][iv(12)][AES-256-GCM ct+tag]`.
 * The key is PBKDF2-SHA256 derived from the `VAULT_AT_REST_PASSWORD` env var.
 *
 * DEMO ONLY: when the env var is unset it falls back to a fixed demo password
 * (a warning is logged) so the sample runs out-of-the-box. A production
 * deployment MUST set `VAULT_AT_REST_PASSWORD` (or use a KMS) — otherwise the
 * at-rest key is public and the encryption is cosmetic.
 */
object VaultAtRestCipher {

    /** 8-byte marker so reads can tell an at-rest blob from raw plaintext. */
    private val MAGIC = byteArrayOf(0x56, 0x4C, 0x54, 0x2D, 0x45, 0x4E, 0x43, 0x31) // "VLT-ENC1"
    private const val PBKDF2_ITERATIONS = 200_000
    private const val SALT_LEN = 16
    private const val IV_LEN = 12
    private val rng = SecureRandom()

    private val password: String by lazy {
        System.getenv("VAULT_AT_REST_PASSWORD")?.takeIf { it.isNotBlank() } ?: run {
            println(
                "VaultAtRestCipher: WARNING — VAULT_AT_REST_PASSWORD not set; using a demo key. " +
                "Set it (or use a KMS) in production, otherwise at-rest encryption is cosmetic."
            )
            "pinvault-demo-at-rest-key"
        }
    }

    /** True if [blob] was produced by [encrypt] (starts with the marker). */
    fun isEncrypted(blob: ByteArray): Boolean =
        blob.size >= MAGIC.size && MAGIC.indices.all { blob[it] == MAGIC[it] }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val salt = ByteArray(SALT_LEN).also(rng::nextBytes)
        val iv = ByteArray(IV_LEN).also(rng::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(salt), GCMParameterSpec(128, iv))
        return MAGIC + salt + iv + cipher.doFinal(plaintext)
    }

    /**
     * Decrypt an at-rest blob produced by [encrypt]. If [blob] is not actually
     * an at-rest blob (no marker, or the marker collides with raw content that
     * fails GCM auth) the original bytes are returned unchanged, so a plain
     * file can never be corrupted by a read.
     */
    fun decryptIfPresent(blob: ByteArray): ByteArray {
        if (!isEncrypted(blob) || blob.size < MAGIC.size + SALT_LEN + IV_LEN) return blob
        return try {
            val off = MAGIC.size
            val salt = blob.copyOfRange(off, off + SALT_LEN)
            val iv = blob.copyOfRange(off + SALT_LEN, off + SALT_LEN + IV_LEN)
            val ct = blob.copyOfRange(off + SALT_LEN + IV_LEN, blob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(salt), GCMParameterSpec(128, iv))
            cipher.doFinal(ct)
        } catch (_: Exception) {
            blob // not our ciphertext (rare marker collision) — leave untouched
        }
    }

    private fun deriveKey(salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }
}
