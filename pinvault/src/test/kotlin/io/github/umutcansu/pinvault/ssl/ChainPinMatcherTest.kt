package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLContext
import javax.net.ssl.X509ExtendedTrustManager

/**
 * Pins may name the leaf or an issuer the leaf really chains to. The issuer
 * case must not open a hole in a library that does no CA validation: a forged
 * leaf with the genuine intermediate appended has to be refused.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ChainPinMatcherTest {

    private val host = "api.chain.test"

    private val rootKeys = keys()
    private val root = cert("CN=Chain Test Root", rootKeys, "CN=Chain Test Root", rootKeys.private, ca = true)
    private val intKeys = keys()
    private val intermediate = cert("CN=Chain Test Intermediate", intKeys, "CN=Chain Test Root", rootKeys.private, ca = true)
    private val leafKeys = keys()
    private val leaf = cert("CN=$host", leafKeys, "CN=Chain Test Intermediate", intKeys.private, ca = false, san = host)

    @Test
    fun `leaf pin is accepted as before`() {
        trustManager(listOf(pin(leaf), randomPin())).checkServerTrusted(arrayOf(leaf, intermediate), "RSA", engine())
    }

    @Test
    fun `intermediate pin is accepted when the leaf is issued by it`() {
        trustManager(listOf(pin(intermediate), randomPin())).checkServerTrusted(arrayOf(leaf, intermediate), "RSA", engine())
    }

    @Test
    fun `root pin is accepted through a valid intermediate`() {
        trustManager(listOf(pin(root), randomPin())).checkServerTrusted(arrayOf(leaf, intermediate, root), "RSA", engine())
    }

    @Test
    fun `forged leaf with the genuine intermediate appended is refused`() {
        // Same issuer name, signed by the attacker's own key.
        val attacker = keys()
        val forged = cert("CN=$host", keys(), "CN=Chain Test Intermediate", attacker.private, ca = false, san = host)
        assertRefused(listOf(pin(intermediate), randomPin()), arrayOf(forged, intermediate))
    }

    @Test
    fun `a certificate without CA rights cannot vouch for the leaf`() {
        val notCaKeys = keys()
        val notCa = cert("CN=Not A CA", notCaKeys, "CN=Chain Test Root", rootKeys.private, ca = false)
        val leafUnderNotCa = cert("CN=$host", keys(), "CN=Not A CA", notCaKeys.private, ca = false, san = host)
        assertRefused(listOf(pin(root), randomPin()), arrayOf(leafUnderNotCa, notCa, root))
    }

    @Test
    fun `expired pinned intermediate is refused`() {
        val oldKeys = keys()
        val expired = cert(
            "CN=Old Intermediate", oldKeys, "CN=Chain Test Root", rootKeys.private, ca = true,
            notBefore = Date(System.currentTimeMillis() - 10 * DAY), notAfter = Date(System.currentTimeMillis() - DAY)
        )
        val leafUnderExpired = cert("CN=$host", keys(), "CN=Old Intermediate", oldKeys.private, ca = false, san = host)
        assertRefused(listOf(pin(expired), randomPin()), arrayOf(leafUnderExpired, expired))
    }

    @Test
    fun `an unrelated certificate in the middle breaks the path to a pinned root`() {
        val strangerKeys = keys()
        val stranger = cert("CN=Stranger CA", strangerKeys, "CN=Chain Test Root", rootKeys.private, ca = true)
        assertRefused(listOf(pin(root), randomPin()), arrayOf(leaf, stranger, root))
    }

    @Test
    fun `issuer pin of another host does not apply`() {
        val config = CertificateConfig(version = 1, pins = listOf(HostPin("other.chain.test", listOf(pin(intermediate), randomPin()))))
        try {
            (DynamicSSLManager().buildClient(config).x509TrustManager as X509ExtendedTrustManager)
                .checkServerTrusted(arrayOf(leaf, intermediate), "RSA", engine())
            fail("A pin for another host must not be accepted")
        } catch (e: CertificateException) {
            assertTrue(e.message!!.contains("No pin entry"))
        }
    }

    @Test
    fun `matcher reports which pin matched`() {
        val accepted = setOf(pin(intermediate), pin(root))
        assertEquals(pin(intermediate), ChainPinMatcher.match(arrayOf(leaf, intermediate, root), accepted, ::pin))
        assertNull(ChainPinMatcher.match(arrayOf(leaf), accepted, ::pin))
        assertTrue(ChainPinMatcher.chainsTo(arrayOf(leaf, intermediate), 1))
        assertFalse(ChainPinMatcher.chainsTo(arrayOf(leaf, root), 1))
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun assertRefused(pins: List<String>, chain: Array<X509Certificate>) {
        try {
            trustManager(pins).checkServerTrusted(chain, "RSA", engine())
            fail("The chain must be refused")
        } catch (e: CertificateException) {
            assertTrue(e.message, e.message!!.contains("pinning failure"))
        }
    }

    private fun trustManager(pins: List<String>) =
        DynamicSSLManager().buildClient(CertificateConfig(version = 1, pins = listOf(HostPin(host, pins))))
            .x509TrustManager as X509ExtendedTrustManager

    private fun engine() = SSLContext.getDefault().createSSLEngine(host, 443)

    private fun pin(cert: X509Certificate): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    private fun randomPin(): String = Base64.getEncoder().encodeToString(ByteArray(32).also { java.util.Random().nextBytes(it) })

    private fun keys(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun cert(
        subject: String,
        subjectKeys: KeyPair,
        issuer: String,
        issuerKey: PrivateKey,
        ca: Boolean,
        san: String? = null,
        notBefore: Date = Date(System.currentTimeMillis() - DAY),
        notAfter: Date = Date(System.currentTimeMillis() + 30 * DAY)
    ): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(serials.incrementAndGet()), notBefore, notAfter, X500Name(subject), subjectKeys.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
        if (ca) builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        if (san != null) builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, san)))
        return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)))
    }

    private companion object {
        const val DAY = 86_400_000L
        val serials = AtomicLong(System.currentTimeMillis())
    }
}
