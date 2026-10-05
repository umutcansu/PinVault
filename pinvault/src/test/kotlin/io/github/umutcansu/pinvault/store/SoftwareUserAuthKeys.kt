package io.github.umutcansu.pinvault.store

import android.security.keystore.KeyPermanentlyInvalidatedException
import io.github.umutcansu.pinvault.keystore.UserAuthKeyKind
import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A software stand-in for the Keystore's user-auth key. The hardware's part
 * (refusing the key without a passed prompt, retiring it, failing for a
 * moment) is played by the flags.
 */
internal class SoftwareUserAuthKeys : UserAuthKeys {
    var screenLock = true
    var kind = UserAuthKeyKind.PER_USE
    var pair: KeyPair? = null
    var retired = false
    /** Thrown by [state] / [unwrap] while set: a Keystore hiccup, not a retired key. */
    var stateError: Exception? = null
    var unwrapError: Exception? = null
    var generated = 0

    override fun isScreenLockSet() = screenLock

    override fun state(): UserAuthKeys.State {
        stateError?.let { throw it }
        return when {
            pair == null -> UserAuthKeys.State.MISSING
            retired -> UserAuthKeys.State.INVALIDATED
            else -> UserAuthKeys.State.USABLE
        }
    }

    override fun ensureKey(): Boolean {
        if (state() == UserAuthKeys.State.USABLE) return false
        pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        retired = false
        generated++
        return true
    }

    override fun publicKey(): PublicKey = pair?.public ?: throw KeyPermanentlyInvalidatedException("no key")

    override fun kind() = kind

    override fun cipherForPrompt(): Cipher? {
        if (pair == null || retired) throw KeyPermanentlyInvalidatedException("retired")
        return if (kind == UserAuthKeyKind.TIME_BOUND) null else decryptCipher()
    }

    override fun unwrap(authorised: Cipher?, wrapped: ByteArray): ByteArray {
        unwrapError?.let { throw it }
        return (authorised ?: decryptCipher()).doFinal(wrapped)
    }

    /** What [attestationChain] returns: empty unless a test sets one. */
    var chain: List<ByteArray> = emptyList()

    override fun attestationChain(): List<ByteArray> = chain

    override fun delete() { pair = null; retired = false }

    private fun decryptCipher() = Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, pair!!.private, UserAuthKeys.OAEP)
    }

    companion object {
        /** What the server sends for a `user_auth` file: the end_to_end envelope over [publicKey]. */
        fun serverEnvelope(content: ByteArray, publicKey: PublicKey): ByteArray {
            val random = SecureRandom()
            val aesKey = ByteArray(32).also(random::nextBytes)
            val iv = ByteArray(12).also(random::nextBytes)
            val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, iv))
                doFinal(content)
            }
            val wrapped = Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).run {
                init(Cipher.ENCRYPT_MODE, publicKey, UserAuthKeys.OAEP)
                doFinal(aesKey)
            }
            return ByteBuffer.allocate(4 + wrapped.size + iv.size + ciphertext.size)
                .putInt(wrapped.size).put(wrapped).put(iv).put(ciphertext).array()
        }
    }
}

/** In-memory [VaultStorageProvider]. */
internal class MemVaultStore : VaultStorageProvider {
    val blobs = linkedMapOf<String, ByteArray>()
    val versions = linkedMapOf<String, Int>()
    override fun save(key: String, bytes: ByteArray, version: Int) { blobs[key] = bytes; versions[key] = version }
    override fun load(key: String): ByteArray? = blobs[key]
    override fun getVersion(key: String): Int = versions[key] ?: 0
    override fun exists(key: String): Boolean = blobs.containsKey(key)
    override fun clear(key: String) { blobs.remove(key); versions.remove(key) }
}
