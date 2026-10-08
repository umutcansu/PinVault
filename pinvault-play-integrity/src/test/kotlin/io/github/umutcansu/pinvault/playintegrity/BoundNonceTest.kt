package io.github.umutcansu.pinvault.playintegrity

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/** The v2 nonce is the one the server computes (`PlayIntegrityVerifier`). */
class BoundNonceTest {

    @Test
    fun `the v2 nonce is base64url of SHA-256 over the round's nonce and the device id`() {
        val nonce = "AAABoxhcUABlXgZtPT5a3NmuxAEpGZDd8ON4O2ALApeMsxX1e7oSzw"
        val deviceId = "6f1c2b6a0e2f4c1a"
        val expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest("pinvault-play-integrity:v2:$nonce:$deviceId".toByteArray(Charsets.UTF_8))
        )
        assertEquals(expected, PlayIntegrityVerdictProvider.boundNonce(nonce, deviceId))
        assertEquals(43, expected.length)
    }

    @Test
    fun `the encoder matches the JDK's for every length`() {
        for (length in 0..40) {
            val bytes = ByteArray(length) { (it * 37 + 11).toByte() }
            assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), PlayIntegrityVerdictProvider.base64UrlNoPad(bytes))
        }
    }
}
