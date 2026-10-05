package io.github.umutcansu.pinvault.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * The code the device shows must equal the one the dashboard shows next to its
 * request: 80 bits of the key's SHA-256, 16 characters. Same vectors as the
 * server's (SERVER_IMPLEMENTATION_GUIDE.md), computed independently
 * (SHA-256("pinvault"), all zeros, all ones).
 */
class VerificationCodeTest {

    private val pinvaultDigest = Base64.getDecoder().decode("B2kYMhZfDfCB5iZLbIoeW2GaszFr1dWvNKg4Kz97ayY=")

    @Test
    fun `known digests give the codes the server gives`() {
        assertEquals("0XMH-GCGP-BW6Z-10F6", VerificationCode.ofDigest(pinvaultDigest))
        assertEquals("0000-0000-0000-0000", VerificationCode.ofDigest(ByteArray(32)))
        assertEquals("ZZZZ-ZZZZ-ZZZZ-ZZZZ", VerificationCode.ofDigest(ByteArray(32) { -1 }))
    }

    @Test
    fun `the digest in the test is SHA-256 of pinvault`() {
        assertEquals(
            Base64.getEncoder().encodeToString(pinvaultDigest),
            Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest("pinvault".toByteArray()))
        )
    }

    @Test
    fun `the first eight characters are the 40-bit code earlier versions showed`() {
        assertTrue(VerificationCode.ofDigest(pinvaultDigest).startsWith("0XMH-GCGP-"))
    }

    @Test
    fun `the code is exactly the first ten bytes of the digest`() {
        val digest = MessageDigest.getInstance("SHA-256").digest("some key".toByteArray())
        // Byte 10 and after do not matter; byte 9 does.
        val sameStart = digest.copyOf().also { for (i in 10 until it.size) it[i] = (it[i] + 1).toByte() }
        assertEquals(VerificationCode.ofDigest(digest), VerificationCode.ofDigest(sameStart))
        val tenthChanged = digest.copyOf().also { it[9] = (it[9] + 1).toByte() }
        assertTrue(VerificationCode.ofDigest(digest) != VerificationCode.ofDigest(tenthChanged))
        // 5 bytes = 8 characters: the last byte of each half lands in that half's last characters.
        assertEquals("0000-0001-0000-0000", VerificationCode.ofDigest(ByteArray(32).also { it[4] = 1 }))
        assertEquals("0000-0000-0000-0001", VerificationCode.ofDigest(ByteArray(32).also { it[9] = 1 }))
        assertEquals("G000-0000-0000-0000", VerificationCode.ofDigest(ByteArray(32).also { it[0] = 0x80.toByte() }))
    }

    @Test
    fun `a key's code is the code of its SubjectPublicKeyInfo hash`() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public
        val code = VerificationCode.of(key)
        assertEquals(VerificationCode.ofDigest(MessageDigest.getInstance("SHA-256").digest(key.encoded)), code)
        assertTrue(code, code.matches(Regex("[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}")))
    }
}
