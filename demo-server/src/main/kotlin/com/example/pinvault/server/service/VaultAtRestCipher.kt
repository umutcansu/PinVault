package com.example.pinvault.server.service

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * At-rest encryption for vault file content (encryption = "at_rest" and
 * "end_to_end"). [com.example.pinvault.server.store.VaultFileStore] encrypts
 * on write and decrypts on read; the device never sees this layer.
 *
 * Encrypted blob layout: `[MAGIC(8)][salt(16)][iv(12)][AES-256-GCM ct+tag]`.
 * The key is PBKDF2-SHA256 derived from [password] (`VAULT_AT_REST_PASSWORD`).
 *
 * DEMO ONLY: with the env var unset the password is [DEMO_PASSWORD], which is
 * public (a warning is logged). The sample host's setup.sh generates one.
 *
 * Changing the password: [previous] passwords (`VAULT_AT_REST_PASSWORD_PREVIOUS`,
 * and always the demo password) are tried only by the startup migration, which
 * re-encrypts every file under [password]. Reads use [password] alone and fail
 * loudly ([VaultKeyMismatchException]) instead of handing out ciphertext.
 */
class VaultAtRestCipher(
    private val password: String,
    previous: List<String> = emptyList()
) {
    private val previous: List<String> = previous.filter { it.isNotBlank() && it != password }.distinct()

    val usesDemoPassword: Boolean get() = password == DEMO_PASSWORD

    fun encrypt(plaintext: ByteArray): ByteArray {
        val salt = ByteArray(SALT_LEN).also(rng::nextBytes)
        val iv = ByteArray(IV_LEN).also(rng::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return MAGIC + salt + iv + cipher.doFinal(plaintext)
    }

    /**
     * Opens a blob written by [encrypt] with the current password.
     * @throws VaultKeyMismatchException when it does not open (other password, or damaged).
     */
    fun decrypt(blob: ByteArray): ByteArray =
        tryDecrypt(blob, password) ?: throw VaultKeyMismatchException()

    /** How [blob] opens: with the current password, with a previous one (plaintext returned), or not at all. */
    fun open(blob: ByteArray): Opened {
        tryDecrypt(blob, password)?.let { return Opened.Current }
        for (candidate in previous) tryDecrypt(blob, candidate)?.let { return Opened.Previous(it) }
        return Opened.Unreadable
    }

    sealed interface Opened {
        data object Current : Opened
        class Previous(val plaintext: ByteArray) : Opened
        data object Unreadable : Opened
    }

    private fun tryDecrypt(blob: ByteArray, candidate: String): ByteArray? {
        if (!isEncrypted(blob) || blob.size < HEADER_LEN + TAG_LEN) return null
        return try {
            val salt = blob.copyOfRange(MAGIC.size, MAGIC.size + SALT_LEN)
            val iv = blob.copyOfRange(MAGIC.size + SALT_LEN, HEADER_LEN)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(candidate, salt), GCMParameterSpec(128, iv))
            cipher.doFinal(blob, HEADER_LEN, blob.size - HEADER_LEN)
        } catch (_: java.security.GeneralSecurityException) {
            null
        }
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    companion object {
        /** 8-byte marker so reads can tell an at-rest blob from raw plaintext. */
        private val MAGIC = byteArrayOf(0x56, 0x4C, 0x54, 0x2D, 0x45, 0x4E, 0x43, 0x31) // "VLT-ENC1"
        private const val PBKDF2_ITERATIONS = 200_000
        private const val SALT_LEN = 16
        private const val IV_LEN = 12
        private const val TAG_LEN = 16
        private val HEADER_LEN = MAGIC.size + SALT_LEN + IV_LEN
        private val rng = SecureRandom()

        /** Used when `VAULT_AT_REST_PASSWORD` is unset. It is in the source code: encryption with it is cosmetic. */
        const val DEMO_PASSWORD = "pinvault-demo-at-rest-key"

        fun fromEnv(env: Map<String, String> = System.getenv()): VaultAtRestCipher {
            val password = env["VAULT_AT_REST_PASSWORD"]?.takeIf { it.isNotBlank() } ?: run {
                println(
                    "VaultAtRestCipher: WARNING — VAULT_AT_REST_PASSWORD not set; using a demo key. " +
                    "Set it (or use a KMS) in production, otherwise at-rest encryption is cosmetic."
                )
                DEMO_PASSWORD
            }
            return VaultAtRestCipher(password, listOfNotNull(env["VAULT_AT_REST_PASSWORD_PREVIOUS"], DEMO_PASSWORD))
        }

        /** True if [blob] was produced by [encrypt] (starts with the marker). */
        fun isEncrypted(blob: ByteArray): Boolean =
            blob.size >= MAGIC.size && MAGIC.indices.all { blob[it] == MAGIC[it] }

        /** Size of the content inside [blob], without decrypting it (GCM adds a fixed tag). */
        fun plaintextSize(blob: ByteArray): Int =
            if (isEncrypted(blob) && blob.size >= HEADER_LEN + TAG_LEN) blob.size - HEADER_LEN - TAG_LEN else blob.size
    }
}

/** A stored vault file does not open with the current `VAULT_AT_REST_PASSWORD`. */
class VaultKeyMismatchException(message: String = "vault file does not open with VAULT_AT_REST_PASSWORD") :
    IllegalStateException(message)
