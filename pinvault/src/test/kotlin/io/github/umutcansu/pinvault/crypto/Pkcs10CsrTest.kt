package io.github.umutcansu.pinvault.crypto

import io.github.umutcansu.pinvault.util.TestCertUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.Signature

/**
 * The hand-rolled PKCS#10 encoder, checked against BouncyCastle's parser —
 * the library must not depend on BC at runtime, the tests may.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class Pkcs10CsrTest {

    private val keyPair: KeyPair = TestCertUtil.generateEcKeyPair()

    private fun signer(kp: KeyPair = keyPair): (ByteArray) -> ByteArray = { tbs ->
        Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(tbs); sign() }
    }

    private fun parse(der: ByteArray) = PKCS10CertificationRequest(der)

    private fun PKCS10CertificationRequest.signatureValid(): Boolean =
        isSignatureValid(
            JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(subjectPublicKeyInfo)
        )

    @Test
    fun `BouncyCastle parses the request and its signature verifies`() {
        val der = Pkcs10Csr.encode("device-42", keyPair.public, signer())
        val csr = parse(der)

        assertTrue(csr.signatureValid())
        assertEquals("CN=device-42", csr.subject.toString())
        assertArrayEquals(keyPair.public.encoded, csr.subjectPublicKeyInfo.encoded)
        assertEquals("1.2.840.10045.4.3.2", csr.signatureAlgorithm.algorithm.id)
        assertEquals(0, csr.attributes.size)
    }

    @Test
    fun `a common name longer than 127 bytes uses long-form lengths`() {
        val cn = "x".repeat(300)
        val csr = parse(Pkcs10Csr.encode(cn, keyPair.public, signer()))
        assertTrue(csr.signatureValid())
        assertEquals("CN=$cn", csr.subject.toString())
    }

    @Test
    fun `non-ASCII common name survives as UTF-8`() {
        val csr = parse(Pkcs10Csr.encode("cihaz-ğüş", keyPair.public, signer()))
        assertTrue(csr.signatureValid())
        assertEquals("CN=cihaz-ğüş", csr.subject.toString())
    }

    @Test
    fun `tampering with the request info invalidates the signature`() {
        val der = Pkcs10Csr.encode("device-42", keyPair.public, signer())
        // Flip a byte inside the CN ("device-42" → "device-43" style change).
        val index = der.indexOfSubArray("device-42".toByteArray()) + 8
        der[index] = (der[index] + 1).toByte()
        assertFalse(parse(der).signatureValid())
    }

    @Test
    fun `signature from a different key does not verify`() {
        val other = TestCertUtil.generateEcKeyPair()
        val der = Pkcs10Csr.encode("device-42", keyPair.public, signer(other))
        assertFalse(parse(der).signatureValid())
    }

    @Test
    fun `blank common name is refused`() {
        try {
            Pkcs10Csr.encode("  ", keyPair.public, signer())
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) { }
    }

    @Test
    fun `spki hash matches the pin form of the same key`() {
        assertEquals(TestCertUtil.sha256Base64(keyPair.public.encoded), Pkcs10Csr.spkiSha256Base64(keyPair.public))
    }

    @Test
    fun `PEM round-trips a certificate chain in order`() {
        val a = TestCertUtil.generateSelfSigned(cn = "leaf").certificate
        val b = TestCertUtil.generateSelfSigned(cn = "issuer").certificate

        val pems = listOf(Pkcs10Csr.toPem(a), Pkcs10Csr.toPem(b))
        assertTrue(pems[0].startsWith("-----BEGIN CERTIFICATE-----\n"))
        assertTrue(pems[0].endsWith("\n-----END CERTIFICATE-----"))

        val parsed = Pkcs10Csr.parsePemChain(pems)
        assertEquals(listOf(a, b), parsed)
    }

    @Test
    fun `garbage PEM is rejected`() {
        try {
            Pkcs10Csr.parsePemChain(listOf("-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----"))
            fail("expected an exception")
        } catch (_: Exception) { }
    }

    private fun ByteArray.indexOfSubArray(needle: ByteArray): Int {
        outer@ for (i in 0..size - needle.size) {
            for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}
