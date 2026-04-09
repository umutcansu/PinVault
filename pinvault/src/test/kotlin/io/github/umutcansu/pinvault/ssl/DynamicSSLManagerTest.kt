package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** A.3 — DynamicSSLManager composite KeyManager, host bazlı cert seçimi */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DynamicSSLManagerTest {

    private lateinit var manager: DynamicSSLManager
    private val password = "changeit"

    @Before
    fun setUp() {
        manager = DynamicSSLManager()
    }

    @Test
    fun `loadClientKeystore — default cert yüklenir`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        // Should not throw
        manager.loadClientKeystore(cert.p12Bytes, password)
    }

    @Test
    fun `loadHostClientCerts — birden fazla host cert yüklenir`() {
        val hostA = TestCertUtil.generateSelfSigned(cn = "host-a.com", password = password)
        val hostB = TestCertUtil.generateSelfSigned(cn = "host-b.com", password = password)

        val certs = mapOf(
            "host-a.com" to hostA.p12Bytes,
            "host-b.com" to hostB.p12Bytes
        )
        // Should not throw
        manager.loadHostClientCerts(certs, password)
    }

    @Test
    fun `buildClient — pinned client with config`() {
        val serverCert = TestCertUtil.generateSelfSigned(cn = "server.test")
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("server.test", listOf(serverCert.sha256Pin, serverCert.sha256Pin))
            )
        )
        val client = manager.buildClient(config)
        assertNotNull(client)
    }

    @Test
    fun `buildClient — null config returns system-default client`() {
        val client = manager.buildClient(null)
        assertNotNull(client)
    }

    @Test
    fun `buildBootstrapClient — with pins`() {
        val cert = TestCertUtil.generateSelfSigned()
        val pins = listOf(HostPin("localhost", listOf(cert.sha256Pin, cert.sha256Pin)))
        val client = manager.buildBootstrapClient(pins)
        assertNotNull(client)
    }

    @Test
    fun `buildBootstrapClient — no pins returns unpinned client`() {
        val client = manager.buildBootstrapClient(emptyList())
        assertNotNull(client)
    }

    @Test
    fun `applyTo — config with mtls hosts logs correctly`() {
        val cert1 = TestCertUtil.generateSelfSigned(cn = "tls.host")
        val cert2 = TestCertUtil.generateSelfSigned(cn = "mtls.host")
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("tls.host", listOf(cert1.sha256Pin, cert1.sha256Pin), mtls = false),
                HostPin("mtls.host", listOf(cert2.sha256Pin, cert2.sha256Pin), mtls = true, clientCertVersion = 1)
            )
        )
        val builder = okhttp3.OkHttpClient.Builder()
        // Should not throw
        manager.applyTo(builder, config)
        val client = builder.build()
        assertNotNull(client)
    }

    @Test
    fun `loadHostClientCerts — invalid P12 bytes handled gracefully`() {
        val validCert = TestCertUtil.generateSelfSigned(cn = "valid.host", password = password)
        val certs = mapOf(
            "valid.host" to validCert.p12Bytes,
            "invalid.host" to byteArrayOf(1, 2, 3) // garbage
        )
        // Should not throw — invalid cert logged and skipped
        manager.loadHostClientCerts(certs, password)
    }

    @Test
    fun `host cert + default cert — composite KeyManager oluşturulur`() {
        val defaultCert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        manager.loadClientKeystore(defaultCert.p12Bytes, password)

        val hostCert = TestCertUtil.generateSelfSigned(cn = "specific.host", password = password)
        manager.loadHostClientCerts(mapOf("specific.host" to hostCert.p12Bytes), password)

        val serverCert = TestCertUtil.generateSelfSigned(cn = "server.test")
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("server.test", listOf(serverCert.sha256Pin, serverCert.sha256Pin), mtls = true, clientCertVersion = 1)
            )
        )
        val client = manager.buildClient(config)
        assertNotNull(client)
    }

    @Test
    fun `İki farklı host iki farklı cert — P12 parse doğru`() {
        val certA = TestCertUtil.generateSelfSigned(cn = "CN-Alpha", password = password, alias = "server")
        val certB = TestCertUtil.generateSelfSigned(cn = "CN-Beta", password = password, alias = "server")

        // Verify the P12 contents are different
        val ksA = KeyStore.getInstance("PKCS12").apply { load(certA.p12Bytes.inputStream(), password.toCharArray()) }
        val ksB = KeyStore.getInstance("PKCS12").apply { load(certB.p12Bytes.inputStream(), password.toCharArray()) }

        val cnA = (ksA.getCertificate(ksA.aliases().nextElement()) as java.security.cert.X509Certificate)
            .subjectX500Principal.name
        val cnB = (ksB.getCertificate(ksB.aliases().nextElement()) as java.security.cert.X509Certificate)
            .subjectX500Principal.name

        assertTrue(cnA.contains("CN-Alpha"))
        assertTrue(cnB.contains("CN-Beta"))
        assertNotEquals(certA.sha256Pin, certB.sha256Pin)

        // Load both into manager
        manager.loadHostClientCerts(
            mapOf("alpha.host" to certA.p12Bytes, "beta.host" to certB.p12Bytes),
            password
        )
    }
}
