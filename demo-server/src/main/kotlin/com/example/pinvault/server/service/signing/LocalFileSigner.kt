package com.example.pinvault.server.service.signing

import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
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
 * ECDSA P-256 key kept in a file on this server — the default signer.
 *
 * Loads the key from [keyFile] at startup and generates one when the file is
 * missing. The private key stays here; its public half goes into the app.
 *
 * ## At-rest protection (H-04)
 *
 * When [password] (the `SIGNING_KEY_PASSWORD` env var) is set, the private
 * key is stored as AES-256-GCM ciphertext on disk (PBKDF2-SHA256 derives the
 * encryption key from the password). When unset, the key is written
 * unencrypted — a warning is logged and the file is still `chmod 600`. An
 * HSM ([Pkcs11Signer]) or KMS ([CommandSigner]) keeps the key off this disk
 * altogether.
 *
 * Migration: an existing plaintext key file is automatically re-encrypted
 * on first startup with a password set.
 */
class LocalFileSigner(
    private val keyFile: File,
    private val password: String? = System.getenv("SIGNING_KEY_PASSWORD")?.takeIf { it.isNotBlank() },
    override val name: String = "local"
) : ConfigSigner {

    /**
     * Held in a volatile field, not a `val`, so [regenerate] swaps the key for
     * every holder of this signer. The routes capture it once at startup;
     * before this, regenerating replaced only the local variable in the admin
     * handler, so the server kept signing with the old key (silently, until
     * the next restart) while the dashboard reported success.
     */
    @Volatile
    private var keyPair: KeyPair = loadOrGenerate()

    override val type: String = "local"

    override val description: String
        get() = "Key file ${keyFile.name}" + if (password != null) " (encrypted at rest)" else " (plaintext on disk)"

    override val publicKeyBase64: String
        get() = Base64.getEncoder().encodeToString(keyPair.public.encoded)

    /**
     * Deletes the key file and generates a fresh ECDSA P-256 key, effective
     * immediately for every caller.
     *
     * Every client that trusts only the previous public key stops accepting
     * configs from this server — unless the new key reaches it first through
     * a signing-key set, or it already trusted it as a backup key.
     */
    @Synchronized
    fun regenerate(): String {
        keyFile.delete()
        keyPair = loadOrGenerate()
        return publicKeyBase64
    }

    override fun sign(data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(data)
        return sig.sign()
    }

    private fun loadOrGenerate(): KeyPair {
        if (keyFile.exists()) {
            val kp = loadFromFile()
            // Auto-migrate plaintext → encrypted when a password is now set.
            val raw = keyFile.readText().trim()
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

        val content = if (password == null) {
            println("ConfigSigningService: WARNING — SIGNING_KEY_PASSWORD not set, " +
                "writing signing key in plaintext. Set the env var for at-rest encryption.")
            plaintext
        } else {
            val encrypted = encrypt(plaintext.toByteArray(Charsets.UTF_8), password)
            ENCRYPTED_PREFIX + Base64.getEncoder().encodeToString(encrypted)
        }
        writeOwnerOnly(content)
    }

    /**
     * Write [content] to [keyFile] with owner-only (0600) permissions applied
     * BEFORE any bytes hit disk, then atomically swap it into place. Closes the
     * audit-L-3 race where the key briefly existed world-readable because the
     * chmod previously ran only AFTER writeText(). Falls back to best-effort
     * chmod on non-POSIX filesystems.
     */
    private fun writeOwnerOnly(content: String) {
        val target = keyFile.toPath()
        val tmp = File(keyFile.parentFile, keyFile.name + ".tmp").toPath()
        try {
            val ownerOnly = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")
            java.nio.file.Files.deleteIfExists(tmp)
            java.nio.file.Files.createFile(
                tmp, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(ownerOnly)
            )
            java.nio.file.Files.write(tmp, content.toByteArray(Charsets.UTF_8))
            try {
                java.nio.file.Files.move(
                    tmp, target,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE
                )
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                java.nio.file.Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            } catch (e: java.nio.file.FileSystemException) {
                // The key file itself is a mount point (a single-file Docker bind
                // mount): renaming over it fails with EBUSY, which used to abort
                // startup whenever SIGNING_KEY_PASSWORD triggered the at-rest
                // migration, and broke "regenerate signing key" in the dashboard.
                // Fall back to writing in place; permissions are already 0600 on
                // the existing file, and we re-apply them after the write.
                java.nio.file.Files.write(target, content.toByteArray(Charsets.UTF_8))
                try {
                    java.nio.file.Files.setPosixFilePermissions(target, ownerOnly)
                } catch (_: Exception) { /* non-POSIX filesystem */ }
            }
        } catch (_: UnsupportedOperationException) {
            // Non-POSIX filesystem (e.g. Windows): best-effort fallback.
            keyFile.writeText(content)
            try { keyFile.setReadable(false, false); keyFile.setReadable(true, true) }
            catch (_: Exception) { /* depends on filesystem */ }
        } finally {
            try { java.nio.file.Files.deleteIfExists(tmp) } catch (_: Exception) {}
        }
    }

    private fun loadFromFile(): KeyPair {
        val raw = keyFile.readText().trim()
        val plaintext = if (raw.startsWith(ENCRYPTED_PREFIX)) {
            val password = password
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
