package com.example.pinvault.server.service

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * At-rest encryption for vault file content (encryption = "at_rest",
 * "end_to_end" and "user_auth"). [com.example.pinvault.server.store.VaultFileStore] encrypts
 * on write and decrypts on read; the device never sees this layer.
 *
 * Encrypted blob layout: `[MAGIC(8)][salt(16)][iv(12)][AES-256-GCM ct+tag]`.
 * The key is PBKDF2-SHA256 derived from [password] (`VAULT_AT_REST_PASSWORD`).
 *
 * DEMO ONLY: with the env var unset the password is [DEMO_PASSWORD], which is
 * public (a warning is logged). The server starts that way only with
 * `ALLOW_DEMO_SECRETS=true` ([StartupSecrets]); the sample host's setup.sh
 * generates a real one.
 *
 * Changing the password: [previous] passwords (`VAULT_AT_REST_PASSWORD_PREVIOUS`,
 * and always the demo password) are tried only by the startup migration, which
 * re-encrypts every file under [password]. Reads use [password] alone and fail
 * loudly ([VaultKeyMismatchException]) instead of handing out ciphertext.
 *
 * The key derivation (200 000 PBKDF2 rounds, about 0.2 s of CPU) runs once per
 * process per salt, not once per read: keys derived from [password] are kept
 * in a small bounded map, and everything this instance writes shares one salt
 * (a fresh IV per blob), so a download costs one AES-GCM pass. Downloads used
 * to derive on every request — before the access check — which let anyone who
 * knew a file name keep every core busy. The blob format is unchanged; blobs
 * written earlier (a salt each) are derived once, on their first read.
 */
class VaultAtRestCipher(
    private val password: String,
    previous: List<String> = emptyList()
) {
    private val previous: List<String> = previous.filter { it.isNotBlank() && it != password }.distinct()

    /** The salt of every blob this instance writes; the IV is what differs between blobs. */
    private val writeSalt: ByteArray = ByteArray(SALT_LEN).also(rng::nextBytes)

    /** Keys derived from [password], by salt (hex); the least recently used goes beyond [MAX_CACHED_KEYS]. */
    private val derivedKeys = object : LinkedHashMap<String, SecretKeySpec>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, SecretKeySpec>?) = size > MAX_CACHED_KEYS
    }
    private val derivationCounter = java.util.concurrent.atomic.AtomicLong()

    /** How many PBKDF2 derivations this instance has run (tests assert that a refused request costs none). */
    val derivations: Long get() = derivationCounter.get()

    val usesDemoPassword: Boolean get() = password == DEMO_PASSWORD

    fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also(rng::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, currentKey(writeSalt), GCMParameterSpec(128, iv))
        return MAGIC + writeSalt + iv + cipher.doFinal(plaintext)
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
            // A previous password is tried by the startup pass only: not kept.
            val key = if (candidate == password) currentKey(salt) else deriveKey(candidate, salt)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(blob, HEADER_LEN, blob.size - HEADER_LEN)
        } catch (_: java.security.GeneralSecurityException) {
            null
        }
    }

    /**
     * The key for [password] and [salt], derived at most once. Under one lock:
     * requests arriving together for the same salt wait for the one derivation
     * instead of each running their own.
     */
    private fun currentKey(salt: ByteArray): SecretKeySpec = synchronized(derivedKeys) {
        derivedKeys.getOrPut(salt.joinToString("") { "%02x".format(it) }) { deriveKey(password, salt) }
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        derivationCounter.incrementAndGet()
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
        /** Older blobs carry a salt each; this many derived keys (32 bytes apiece) stay in memory. */
        private const val MAX_CACHED_KEYS = 1024
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
