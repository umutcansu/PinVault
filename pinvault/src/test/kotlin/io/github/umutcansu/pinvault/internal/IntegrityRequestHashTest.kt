package io.github.umutcansu.pinvault.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import kotlin.random.Random

/**
 * The request hash an integrity token is bound to. The vectors are shared
 * with the reference server (`IntegrityVerificationTest`), which recomputes
 * the hash from the request it receives.
 */
class IntegrityRequestHashTest {

    private val csr = ByteArray(10) { it.toByte() }

    @Test
    fun `matches the shared test vectors`() {
        assertEquals("rFm1yo7zjKdHsevPadQ1stM-oQ8aG4umNk-CIGhG0ds", IntegrityRequestHash.of("a1b2c3d4e5f60718", csr))
        // No device id: the empty string, not "null".
        assertEquals("rYKab7GF91mo9M4VRpmjjOj4gPuKNrCVklCusNHMdno", IntegrityRequestHash.of(null, csr))
        assertEquals(IntegrityRequestHash.of(null, csr), IntegrityRequestHash.of("", csr))
    }

    @Test
    fun `is a valid Play Integrity request hash and nonce`() {
        val hash = IntegrityRequestHash.of("device", csr)
        assertEquals(43, hash.length)
        assertTrue(hash.matches(Regex("^[A-Za-z0-9_-]+$")))
    }

    @Test
    fun `another CSR or another device id gives another hash`() {
        val base = IntegrityRequestHash.of("device", csr)
        assertNotEquals(base, IntegrityRequestHash.of("device-2", csr))
        assertNotEquals(base, IntegrityRequestHash.of("device", csr + byteArrayOf(0)))
    }

    @Test
    fun `base64url agrees with the JDK encoder for every length`() {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val random = Random(42)
        for (size in 0..70) {
            val bytes = random.nextBytes(size)
            assertEquals("size $size", encoder.encodeToString(bytes), IntegrityRequestHash.base64Url(bytes))
        }
    }
}
