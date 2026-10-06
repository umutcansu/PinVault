package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HostnameMismatchException
import io.github.umutcansu.pinvault.model.InvalidPinFormatException
import io.github.umutcansu.pinvault.model.ManagedTrustRootException
import io.github.umutcansu.pinvault.model.UnpinnedHostException
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
 * Managed trust roots: a host with no pin entry is accepted only when the
 * platform validates its chain to a root the signed config lists — and only
 * when the app turned the feature on. Hosts with a pin entry are untouched.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ManagedTrustRootsTest {

    private val pinnedHost = "api.pinned.test"
    private val unpinnedHost = "cdn.unpinned.test"

    private val rootKeys = keys()
    private val root = cert("CN=Managed Root", rootKeys, "CN=Managed Root", rootKeys.private, ca = true)
    private val otherRootKeys = keys()
    private val otherRoot = cert("CN=Other Root", otherRootKeys, "CN=Other Root", otherRootKeys.private, ca = true)
    private val leafKeys = keys()
    private val leaf = cert("CN=$unpinnedHost", leafKeys, "CN=Managed Root", rootKeys.private, ca = false, san = unpinnedHost)
    private val leafForOtherName = cert("CN=elsewhere", keys(), "CN=Managed Root", rootKeys.private, ca = false, san = "elsewhere.test")

    /** A "platform" that trusts [root] and appends it as the anchor. */
    private val platformTrustingRoot = TrustAnchorResolver { chain, _, _ ->
        if (chain.isEmpty() || runCatching { chain.last().verify(rootKeys.public) }.isFailure) {
            throw CertificateException("not issued by a trusted CA")
        }
        chain.toList() + root
    }

    private fun config(trustRoots: List<String>) = CertificateConfig(
        version = 1,
        pins = listOf(HostPin(pinnedHost, listOf(randomPin(), randomPin()))),
        trustRoots = trustRoots
    )

    private fun manager(enabled: Boolean, resolver: TrustAnchorResolver = platformTrustingRoot) =
        DynamicSSLManager().apply {
            managedTrustRootsEnabled = enabled
            anchorResolver = resolver
        }

    private fun trustManager(manager: DynamicSSLManager, config: CertificateConfig) =
        manager.buildClient(config).x509TrustManager as X509ExtendedTrustManager

    private fun engine(host: String) = SSLContext.getDefault().createSSLEngine(host, 443)

    @Test
    fun `an unpinned host validating to a listed root is accepted, and the root pin is what matched`() {
        val manager = manager(enabled = true)
        val config = config(listOf(pin(root)))
        trustManager(manager, config).checkServerTrusted(arrayOf(leaf), "RSA", engine(unpinnedHost))
        assertEquals(pin(root), manager.matchPins(config, arrayOf(leaf), unpinnedHost, 443))
    }

    @Test
    fun `off by default, an unpinned host is refused as before`() {
        try {
            trustManager(manager(enabled = false), config(listOf(pin(root)))).checkServerTrusted(arrayOf(leaf), "RSA", engine(unpinnedHost))
            fail("an unpinned host must be refused while managed trust roots are off")
        } catch (e: UnpinnedHostException) {
            assertTrue(e.message, e.message!!.contains("No pin entry"))
        }
    }

    @Test
    fun `a config without trust roots refuses an unpinned host even with the feature on`() {
        try {
            trustManager(manager(enabled = true), config(emptyList())).checkServerTrusted(arrayOf(leaf), "RSA", engine(unpinnedHost))
            fail("no roots listed: refused")
        } catch (e: UnpinnedHostException) {
            // expected
        }
    }

    @Test
    fun `a chain validating to a root the config does not list is refused`() {
        try {
            trustManager(manager(enabled = true), config(listOf(pin(otherRoot)))).checkServerTrusted(arrayOf(leaf), "RSA", engine(unpinnedHost))
            fail("the platform's root is not in the list: refused")
        } catch (e: ManagedTrustRootException) {
            assertTrue(e.message, e.message!!.contains("does not list"))
        }
    }

    @Test
    fun `a chain the platform does not trust is refused whatever the list says`() {
        val untrustingPlatform = TrustAnchorResolver { _, _, _ -> throw CertificateException("unknown CA") }
        try {
            trustManager(manager(enabled = true, resolver = untrustingPlatform), config(listOf(pin(root))))
                .checkServerTrusted(arrayOf(leaf), "RSA", engine(unpinnedHost))
            fail("the platform refused the chain: refused")
        } catch (e: ManagedTrustRootException) {
            assertTrue(e.message, e.message!!.contains("does not trust"))
        }
    }

    @Test
    fun `the leaf must be issued for the host`() {
        try {
            trustManager(manager(enabled = true), config(listOf(pin(root)))).checkServerTrusted(arrayOf(leafForOtherName), "RSA", engine(unpinnedHost))
            fail("a certificate for another name must be refused")
        } catch (e: HostnameMismatchException) {
            assertTrue(e.message, e.message!!.contains(unpinnedHost))
        }
    }

    @Test
    fun `a host with a pin entry is judged by its pins, not by the roots`() {
        // The leaf chains to a listed root, but the pinned host's pins do not name it.
        val pinnedLeaf = cert("CN=$pinnedHost", keys(), "CN=Managed Root", rootKeys.private, ca = false, san = pinnedHost)
        try {
            trustManager(manager(enabled = true), config(listOf(pin(root)))).checkServerTrusted(arrayOf(pinnedLeaf), "RSA", engine(pinnedHost))
            fail("a pinned host must match a pin")
        } catch (e: ManagedTrustRootException) {
            fail("the roots must not be consulted for a pinned host")
        } catch (e: CertificateException) {
            assertTrue(e.message, e.message!!.contains("pinning failure"))
        }
    }

    @Test
    fun `the validator checks the roots like pins`() {
        PinConfigValidator.validate(config(listOf(pin(root), pin(otherRoot))))
        assertRefused(config(listOf("not-a-pin")), "Trust root at index 0")
        assertRefused(config(listOf(pin(root), pin(root))), "more than once")
        assertRefused(config(List(PinConfigValidator.MAX_TRUST_ROOTS + 1) { randomPin() }), "at most")
    }

    private fun assertRefused(config: CertificateConfig, expected: String) {
        try {
            PinConfigValidator.validate(config)
            fail("the config should have been refused")
        } catch (e: InvalidPinFormatException) {
            assertTrue(e.message, e.message!!.contains(expected))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

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
        san: String? = null
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(serials.incrementAndGet()), Date(now - DAY), Date(now + 30 * DAY),
            X500Name(subject), subjectKeys.public
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
