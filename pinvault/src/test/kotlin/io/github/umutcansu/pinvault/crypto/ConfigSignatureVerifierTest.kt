package io.github.umutcansu.pinvault.crypto

import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

/**
 * D.25 — Signed config: tampered config reddedilmeli
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ConfigSignatureVerifierTest {

    @Test
    fun `valid signature — verify returns true`() {
        val keyPair = TestCertUtil.generateEcKeyPair()
        val payload = """{"version":1,"pins":[]}"""
        val signature = TestCertUtil.signPayload(payload, keyPair.private)
        val publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

        val result = ConfigSignatureVerifier.verify(payload, signature, publicKeyB64)
        assertTrue(result)
    }

    @Test
    fun `tampered payload — verify returns false`() {
        val keyPair = TestCertUtil.generateEcKeyPair()
        val payload = """{"version":1,"pins":[]}"""
        val signature = TestCertUtil.signPayload(payload, keyPair.private)
        val publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

        val tampered = """{"version":999,"pins":[]}"""
        val result = ConfigSignatureVerifier.verify(tampered, signature, publicKeyB64)
        assertFalse(result)
    }

    @Test
    fun `tampered signature — verify returns false`() {
        val keyPair = TestCertUtil.generateEcKeyPair()
        val payload = """{"version":1,"pins":[]}"""
        val signature = TestCertUtil.signPayload(payload, keyPair.private)
        val publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

        // Flip a byte in signature
        val sigBytes = Base64.getDecoder().decode(signature)
        sigBytes[0] = (sigBytes[0].toInt() xor 0xFF).toByte()
        val tamperedSig = Base64.getEncoder().encodeToString(sigBytes)

        val result = ConfigSignatureVerifier.verify(payload, tamperedSig, publicKeyB64)
        assertFalse(result)
    }

    @Test
    fun `wrong public key — verify returns false`() {
        val keyPair1 = TestCertUtil.generateEcKeyPair()
        val keyPair2 = TestCertUtil.generateEcKeyPair()
        val payload = """{"version":1}"""
        val signature = TestCertUtil.signPayload(payload, keyPair1.private)
        val wrongKey = Base64.getEncoder().encodeToString(keyPair2.public.encoded)

        val result = ConfigSignatureVerifier.verify(payload, signature, wrongKey)
        assertFalse(result)
    }

    @Test
    fun `invalid base64 key — verify returns false`() {
        val result = ConfigSignatureVerifier.verify("payload", "sig", "not-valid-base64!!!")
        assertFalse(result)
    }

    @Test
    fun `empty payload — still verifiable`() {
        val keyPair = TestCertUtil.generateEcKeyPair()
        val payload = ""
        val signature = TestCertUtil.signPayload(payload, keyPair.private)
        val publicKeyB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)

        assertTrue(ConfigSignatureVerifier.verify(payload, signature, publicKeyB64))
    }
}
