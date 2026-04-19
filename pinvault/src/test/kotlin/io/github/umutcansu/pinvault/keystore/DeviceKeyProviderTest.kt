package io.github.umutcansu.pinvault.keystore

import io.github.umutcansu.pinvault.crypto.VaultFileDecryptor
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Covers the software fallback of [DeviceKeyProvider] (the Android Keystore
 * variant can't run in plain JVM / Robolectric tests). This is the
 * code path used whenever an Android Keystore isn't available — custom
 * backends and test harnesses.
 *
 * End-to-end: generate key pair, export PEM, have "server" encrypt via the
 * exported PEM, library decrypts via the provider's private key. This
 * mirrors the real server ↔ device round trip without bringing up the
 * full stack.
 */
class DeviceKeyProviderTest {

    @Test
    fun `ensureKeyPair is idempotent`() {
        val provider = DeviceKeyProvider.software("test-idempotent")
        provider.ensureKeyPair()
        val firstPem = provider.getPublicKeyPem()
        provider.ensureKeyPair()   // second call must be no-op
        val secondPem = provider.getPublicKeyPem()
        assertEquals(firstPem, secondPem)
    }

    @Test
    fun `clear removes the key — next ensureKeyPair generates a new one`() {
        val provider = DeviceKeyProvider.software("test-clear")
        provider.ensureKeyPair()
        val firstPem = provider.getPublicKeyPem()

        provider.clear()
        provider.ensureKeyPair()
        val secondPem = provider.getPublicKeyPem()

        assertNotEquals("A fresh key pair must have a different PEM",
            firstPem, secondPem)
    }

    @Test
    fun `getPublicKeyPem before ensureKeyPair throws`() {
        val provider = DeviceKeyProvider.software("test-not-ready")
        try {
            provider.getPublicKeyPem()
            fail("expected exception")
        } catch (e: Exception) { /* expected */ }
    }

    @Test
    fun `getPrivateKey before ensureKeyPair throws`() {
        val provider = DeviceKeyProvider.software("test-not-ready-2")
        try {
            provider.getPrivateKey()
            fail("expected exception")
        } catch (e: Exception) { /* expected */ }
    }

    @Test
    fun `PEM format matches X509 public-key encoding`() {
        val provider = DeviceKeyProvider.software("test-pem-format")
        provider.ensureKeyPair()
        val pem = provider.getPublicKeyPem()

        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertTrue(pem.trim().endsWith("-----END PUBLIC KEY-----"))
        // Each body line ≤ 64 chars (per RFC 7468)
        pem.lines()
            .filter { !it.startsWith("-----") }
            .forEach { assertTrue("line too long: $it", it.length <= 64) }
    }

    /**
     * Full server-side encrypt / client-side decrypt round trip using
     * nothing but the software provider. This is the exact flow an
     * end_to_end vault file goes through in production.
     */
    @Test
    fun `E2E round trip — encrypt with exported PEM, decrypt with provider private key`() {
        val provider = DeviceKeyProvider.software("test-e2e")
        provider.ensureKeyPair()

        // Reconstitute the public key from the PEM (simulates what the server does).
        val pemBody = provider.getPublicKeyPem()
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(Regex("\\s+"), "")
        val der = java.util.Base64.getDecoder().decode(pemBody)
        val publicKey = java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.X509EncodedKeySpec(der))

        // Server-side: wrap plaintext.
        val plaintext = "end-to-end-round-trip".toByteArray()
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

        val envelope = ByteBuffer.allocate(4 + wrappedKey.size + iv.size + ciphertext.size).apply {
            putInt(wrappedKey.size); put(wrappedKey); put(iv); put(ciphertext)
        }.array()

        // Client-side: decrypt with the provider's private key.
        val result = VaultFileDecryptor.decrypt(envelope, provider.getPrivateKey())
        assertArrayEquals(plaintext, result)
    }

    @Test
    fun `two separate providers have independent key pairs`() {
        val a = DeviceKeyProvider.software("alias-a").also { it.ensureKeyPair() }
        val b = DeviceKeyProvider.software("alias-b").also { it.ensureKeyPair() }
        assertNotEquals(a.getPublicKeyPem(), b.getPublicKeyPem())
    }
}
