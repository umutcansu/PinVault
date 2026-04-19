package com.example.pinvault.server.service

import java.security.KeyPairGenerator
import java.util.Base64
import kotlin.test.*

/**
 * Server-side E2E encryption correctness. The library provides its own
 * VaultFileDecryptor with identical framing; this test covers both directions
 * (encrypt server-side → decrypt via VaultEncryptionRoundtripTestHelper) so
 * either side breaking the envelope format is caught immediately.
 */
class VaultEncryptionServiceTest {

    private val service = VaultEncryptionService()

    private fun generateKeyPair(size: Int = 2048) = KeyPairGenerator.getInstance("RSA").apply {
        initialize(size)
    }.generateKeyPair()

    private fun pemOf(publicKey: java.security.PublicKey): String {
        val b64 = Base64.getEncoder().encodeToString(publicKey.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----"
    }

    @Test
    fun `encrypt then decrypt returns identical bytes`() {
        val kp = generateKeyPair()
        val plaintext = "hello encrypted vault world".toByteArray()

        val envelope = service.encryptForDevice(plaintext, pemOf(kp.public))
        val decrypted = VaultEncryptionRoundtripTestHelper.decrypt(envelope, kp.private)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `empty plaintext roundtrips cleanly`() {
        val kp = generateKeyPair()
        val envelope = service.encryptForDevice(ByteArray(0), pemOf(kp.public))
        val decrypted = VaultEncryptionRoundtripTestHelper.decrypt(envelope, kp.private)
        assertEquals(0, decrypted.size)
    }

    @Test
    fun `large payload (64KB) roundtrips`() {
        val kp = generateKeyPair()
        val plaintext = ByteArray(64 * 1024) { (it % 256).toByte() }

        val envelope = service.encryptForDevice(plaintext, pemOf(kp.public))
        val decrypted = VaultEncryptionRoundtripTestHelper.decrypt(envelope, kp.private)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `same input produces different ciphertext (fresh IV + session key per call)`() {
        val kp = generateKeyPair()
        val plaintext = "deterministic input".toByteArray()
        val pem = pemOf(kp.public)

        val first = service.encryptForDevice(plaintext, pem)
        val second = service.encryptForDevice(plaintext, pem)

        assertFalse(first.contentEquals(second),
            "Two encryptions of same plaintext must differ (fresh IV + fresh session key)")
    }

    @Test
    fun `decrypting with wrong private key fails with an exception`() {
        val pairA = generateKeyPair()
        val pairB = generateKeyPair()
        val envelope = service.encryptForDevice("x".toByteArray(), pemOf(pairA.public))

        val ex = assertFailsWith<Exception> {
            VaultEncryptionRoundtripTestHelper.decrypt(envelope, pairB.private)
        }
        // Either the RSA unwrap fails or the AES-GCM tag check fails — both
        // are acceptable as long as it doesn't silently return garbage.
        assertNotNull(ex.message)
    }

    @Test
    fun `tampered ciphertext is rejected by AES-GCM tag check`() {
        val kp = generateKeyPair()
        val envelope = service.encryptForDevice("original".toByteArray(), pemOf(kp.public))

        // Flip one bit in the ciphertext tail
        val tampered = envelope.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()

        assertFailsWith<Exception> {
            VaultEncryptionRoundtripTestHelper.decrypt(tampered, kp.private)
        }
    }

    @Test
    fun `rejects RSA keys smaller than 2048 bits`() {
        val weak = generateKeyPair(size = 1024)
        val ex = assertFailsWith<IllegalArgumentException> {
            service.encryptForDevice("x".toByteArray(), pemOf(weak.public))
        }
        assertTrue(ex.message!!.contains("2048"))
    }
}
