package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * A listener whose leaf is signed by the backend's own CA and served with that
 * CA in the chain — the certificate-renewal door. Pinned through a
 * `host:port` entry holding the CA's pin, it is accepted however often the
 * leaf changes; the same CA pin does not open the host's other ports.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class PortPinningIntegrationTest {

    private lateinit var server: MockWebServer
    private lateinit var ca: KeyPair
    private lateinit var caCert: X509Certificate

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) Security.addProvider(BouncyCastleProvider())
        ca = ecKey()
        val caName = X500Name("CN=Test Server CA")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(caName, BigInteger.ONE, Date(now - 60_000), Date(now + 86_400_000L * 3650), caName, ca.public)
            .addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        caCert = JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(builder.build(JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(ca.private)))
        server = MockWebServer()
    }

    @After
    fun tearDown() { server.shutdown() }

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun pin(cert: X509Certificate) =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    /** Starts the server with a fresh leaf signed by the CA, served as `[leaf, ca]`. */
    private fun startWithCaSignedLeaf(): X509Certificate {
        val leafKey = ecKey()
        val now = System.currentTimeMillis()
        val leaf = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(X500Name("CN=Test Server CA"), BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000L),
                X500Name("CN=localhost"), leafKey.public)
                .addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, "localhost")))
                .build(JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(ca.private))
        )
        val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        ks.setKeyEntry("server", leafKey.private, "pw".toCharArray(), arrayOf(leaf, caCert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "pw".toCharArray()) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        server.useHttps(ctx.socketFactory, false)
        server.start()
        return leaf
    }

    private fun get(pins: List<HostPin>): Int {
        val manager = DynamicSSLManager()
        val builder = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }
        manager.applyTo(builder) { CertificateConfig(version = 1, pins = pins) }
        server.enqueue(MockResponse().setBody("ok"))
        return builder.build().newCall(Request.Builder().url(server.url("/renew")).build()).execute().use { it.code }
    }

    @Test
    fun `the CA pin on a host-port entry accepts any leaf the CA signs`() {
        val leaf = startWithCaSignedLeaf()
        val port = server.port
        val code = get(listOf(
            HostPin("localhost", listOf("SOME_OTHER_LEAF_PIN_AAAAAAAAAAAAAAAAAAAAAAA=", "BACKUP_PIN_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")),
            HostPin("localhost:$port", listOf(pin(caCert), "CA_BACKUP_PIN_CCCCCCCCCCCCCCCCCCCCCCCCCCCC="))
        ))
        assertEquals(200, code)
        // Sanity: the leaf itself is not among any pins.
        assertEquals(false, pin(leaf) == pin(caCert))
    }

    @Test
    fun `the same CA pin under the bare host does not cover the host's other ports`() {
        startWithCaSignedLeaf()
        // CA pin only on a DIFFERENT port; this port falls back to the host entry, whose pins do not match.
        val code = runCatching {
            get(listOf(
                HostPin("localhost", listOf("SOME_OTHER_LEAF_PIN_AAAAAAAAAAAAAAAAAAAAAAA=", "BACKUP_PIN_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")),
                HostPin("localhost:${server.port + 1}", listOf(pin(caCert), "CA_BACKUP_PIN_CCCCCCCCCCCCCCCCCCCCCCCCCCCC="))
            ))
        }
        if (code.isSuccess) fail("expected the handshake to be refused, got HTTP ${code.getOrNull()}")
    }
}
