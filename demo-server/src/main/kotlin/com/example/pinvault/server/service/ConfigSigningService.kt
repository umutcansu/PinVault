package com.example.pinvault.server.service

import java.io.File
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * ECDSA P-256 ile pin config response'larını imzalar.
 *
 * Startup'ta [keyFile]'dan keypair yükler; dosya yoksa yeni üretir.
 * Private key backend'de kalır, [publicKeyBase64] APK'ya gömülür.
 *
 * ## At-rest protection (H-04)
 *
 * When the `SIGNING_KEY_PASSWORD` env var is set, the private key is
 * stored as AES-256-GCM ciphertext on disk (PBKDF2-SHA256 derives the
 * encryption key from the password). When unset, the key is written
 * unencrypted — a warning is logged and the file should at least be
 * `chmod 600`. For production use a KMS / sealed secret instead of the
 * env var; this is a sample-grade default.
 *
 * Migration: an existing plaintext key file is automatically re-encrypted
 * on first startup with `SIGNING_KEY_PASSWORD` set.
 */
class ConfigSigningService(private val keyFile: File) {

    private val keyPair: KeyPair = loadOrGenerate()

    /** APK'ya gömülecek public key (Base64, X.509 encoded) */
    val publicKeyBase64: String =
        Base64.getEncoder().encodeToString(keyPair.public.encoded)

    /** Payload string'ini ECDSA-SHA256 ile imzalar, Base64 döner. */
    fun sign(payload: String): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    /** İmzayı doğrular (test/debug için). */
    fun verify(payload: String, signature: String): Boolean {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(keyPair.public)
        sig.update(payload.toByteArray(Charsets.UTF_8))
        return sig.verify(Base64.getDecoder().decode(signature))
    }

    private fun loadOrGenerate(): KeyPair {
        if (keyFile.exists()) {
            val kp = loadFromFile()
            // Auto-migrate plaintext → encrypted when a password is now set.
            val raw = keyFile.readText().trim()
            val password = System.getenv("SIGNING_KEY_PASSWORD")
            if (password != null && !raw.startsWith(ENCRYPTED_PREFIX)) {
                println("ConfigSigningService: Re-encrypting plaintext signing key (H-04)")
                saveToFile(kp)
            }
            return kp
        }
        val kp = generateKeyPair()
        saveToFile(kp)
        println("ConfigSigningService: New ECDSA P-256 keypair generated")
        return kp
    }

    private fun generateKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun saveToFile(kp: KeyPair) {
        keyFile.parentFile?.mkdirs()
        val plaintext = Base64.getEncoder().encodeToString(kp.private.encoded) +
                "\n" +
                Base64.getEncoder().encodeToString(kp.public.encoded)

        val password = System.getenv("SIGNING_KEY_PASSWORD")
        if (password == null) {
            println("ConfigSigningService: WARNING — SIGNING_KEY_PASSWORD not set, " +
                "writing signing key in plaintext. Set the env var for at-rest encryption.")
            keyFile.writeText(plaintext)
        } else {
            val encrypted = encrypt(plaintext.toByteArray(Charsets.UTF_8), password)
            keyFile.writeText(ENCRYPTED_PREFIX + Base64.getEncoder().encodeToString(encrypted))
        }
        // Restrict permissions so other local users can't read the key.
        try { keyFile.setReadable(false, false); keyFile.setReadable(true, true) }
        catch (_: Exception) { /* best-effort, depends on filesystem */ }
    }

    private fun loadFromFile(): KeyPair {
        val raw = keyFile.readText().trim()
        val plaintext = if (raw.startsWith(ENCRYPTED_PREFIX)) {
            val password = System.getenv("SIGNING_KEY_PASSWORD")
                ?: error("Signing key file is encrypted but SIGNING_KEY_PASSWORD is not set")
            val ciphertext = Base64.getDecoder().decode(raw.removePrefix(ENCRYPTED_PREFIX))
            String(decrypt(ciphertext, password), Charsets.UTF_8)
        } else {
            raw
        }

        val lines = plaintext.split("\n")
        require(lines.size == 2) { "Invalid signing key file format" }

        val kf = KeyFactory.getInstance("EC")
        val privateKey = kf.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(lines[0])))
        val publicKey = kf.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(lines[1])))

        return KeyPair(publicKey, privateKey)
    }

    /** AES-256-GCM with a PBKDF2-derived key. Layout: [16-byte salt][12-byte IV][ciphertext+tag]. */
    private fun encrypt(plaintext: ByteArray, password: String): ByteArray {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plaintext)
        return salt + iv + ct
    }

    private fun decrypt(blob: ByteArray, password: String): ByteArray {
        require(blob.size > 28) { "Encrypted signing key blob is truncated" }
        val salt = blob.copyOfRange(0, 16)
        val iv = blob.copyOfRange(16, 28)
        val ct = blob.copyOfRange(28, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    companion object {
        private const val ENCRYPTED_PREFIX = "ENCv1:"
        private const val PBKDF2_ITERATIONS = 200_000
    }
}
