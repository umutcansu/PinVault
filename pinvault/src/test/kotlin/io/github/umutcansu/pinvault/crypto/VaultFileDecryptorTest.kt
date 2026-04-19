package io.github.umutcansu.pinvault.crypto

import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.junit.Assert.*
import org.junit.Test

/**
 * Server-client envelope-format compatibility. Builds envelopes identical to
 * VaultEncryptionService (server-side) and verifies VaultFileDecryptor
 * roundtrips them exactly. If either side's framing changes, this fails.
 */
class VaultFileDecryptorTest {

    private fun newKeyPair() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    /** Envelope format: [4-byte wrappedKey len BE][wrappedKey][12-byte IV][AES-GCM ciphertext+tag] */
    private fun buildEnvelope(plaintext: ByteArray, publicKey: java.security.PublicKey): ByteArray {
        val sessionKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }

        val aes = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, sessionKey, GCMParameterSpec(128, iv))
        }
        val ciphertext = aes.doFinal(plaintext)

        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").apply {
            init(Cipher.ENCRYPT_MODE, publicKey,
                OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT))
        }
        val wrappedKey = rsa.doFinal(sessionKey.encoded)

        val buf = ByteBuffer.allocate(4 + wrappedKey.size + iv.size + ciphertext.size)
        buf.putInt(wrappedKey.size); buf.put(wrappedKey); buf.put(iv); buf.put(ciphertext)
        return buf.array()
    }

    @Test
    fun `decrypts server-style envelope`() {
        val kp = newKeyPair()
        val plaintext = "hello decryptor world".toByteArray()
        val result = VaultFileDecryptor.decrypt(buildEnvelope(plaintext, kp.public), kp.private)
        assertArrayEquals(plaintext, result)
    }

    @Test
    fun `empty plaintext roundtrips`() {
        val kp = newKeyPair()
        val result = VaultFileDecryptor.decrypt(buildEnvelope(ByteArray(0), kp.public), kp.private)
        assertEquals(0, result.size)
    }

    @Test
    fun `wrong private key causes exception`() {
        val kpA = newKeyPair()
        val kpB = newKeyPair()
        val envelope = buildEnvelope("secret".toByteArray(), kpA.public)
        try {
            VaultFileDecryptor.decrypt(envelope, kpB.private)
            fail("expected exception")
        } catch (e: Exception) { /* expected */ }
    }

    @Test
    fun `tampered ciphertext caught by GCM tag`() {
        val kp = newKeyPair()
        val envelope = buildEnvelope("original".toByteArray(), kp.public)
        val tampered = envelope.copyOf().also {
            it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte()
        }
        try {
            VaultFileDecryptor.decrypt(tampered, kp.private)
            fail("expected exception on tampered ciphertext")
        } catch (e: Exception) { /* expected */ }
    }

    @Test
    fun `truncated envelope rejected before decryption`() {
        val kp = newKeyPair()
        try {
            VaultFileDecryptor.decrypt(ByteArray(10), kp.private)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) { /* expected */ }
    }

    @Test
    fun `absurd wrappedKey length rejected`() {
        val kp = newKeyPair()
        val malformed = ByteBuffer.allocate(100).apply {
            putInt(10_000_000)   // claim wrappedKey is 10MB
            put(ByteArray(96))
        }.array()
        try {
            VaultFileDecryptor.decrypt(malformed, kp.private)
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) { /* expected */ }
    }
}
