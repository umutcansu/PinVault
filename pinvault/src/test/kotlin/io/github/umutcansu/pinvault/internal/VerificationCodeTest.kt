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
 * request. Same vectors as demo-server's EnrollmentPolicyTest, computed
 * independently (SHA-256("pinvault"), all zeros, all ones).
 */
class VerificationCodeTest {

    @Test
    fun `known digests give the codes the server gives`() {
        assertEquals("0XMH-GCGP", VerificationCode.ofDigest(Base64.getDecoder().decode("B2kYMhZfDfCB5iZLbIoeW2GaszFr1dWvNKg4Kz97ayY=")))
        assertEquals("0000-0000", VerificationCode.ofDigest(ByteArray(32)))
        assertEquals("ZZZZ-ZZZZ", VerificationCode.ofDigest(ByteArray(32) { -1 }))
    }

    @Test
    fun `a key's code is the code of its SubjectPublicKeyInfo hash`() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public
        val code = VerificationCode.of(key)
        assertEquals(VerificationCode.ofDigest(MessageDigest.getInstance("SHA-256").digest(key.encoded)), code)
        assertTrue(code, code.matches(Regex("[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}")))
    }
}
