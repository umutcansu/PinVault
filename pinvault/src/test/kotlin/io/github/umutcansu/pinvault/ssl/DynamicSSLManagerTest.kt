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
    fun `buildClient — null config is fail-closed, not system trust`() {
        val client = manager.buildClient(null)
        // Pinning must be installed even without a config: the trust manager
        // refuses the handshake instead of deferring to the platform CAs.
        val cert = TestCertUtil.generateSelfSigned(cn = "server.test").certificate
        val engine = SSLContext.getDefault().createSSLEngine("server.test", 443)
        try {
            (client.x509TrustManager as javax.net.ssl.X509ExtendedTrustManager)
                .checkServerTrusted(arrayOf(cert), "RSA", engine)
            fail("Expected the handshake to be refused with no config")
        } catch (e: java.security.cert.CertificateException) {
            assertTrue(e.message!!.contains("No pins configured"))
        }
    }

    @Test
    fun `buildBootstrapClient — with pins`() {
        val cert = TestCertUtil.generateSelfSigned()
        val pins = listOf(HostPin("localhost", listOf(cert.sha256Pin, cert.sha256Pin)))
        val client = manager.buildBootstrapClient(pins)
        assertNotNull(client)
    }

    @Test
    fun `buildBootstrapClient — no pins is unpinned only when asked for`() {
        // Fail-closed by default (see BootstrapClientRulesTest); system trust
        // only with allowUnpinnedConfigApi().
        assertTrue(manager.buildBootstrapClient(emptyList()).networkInterceptors.isNotEmpty())
        assertTrue(manager.buildBootstrapClient(emptyList(), allowUnpinned = true).networkInterceptors.isEmpty())
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
        manager.applyTo(builder) { config }
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

    // ── L-4: clearClientKeystore — unenroll must drop live key material ──────

    @Test
    fun `clearClientKeystore — default cert bellekten dusuruluyor`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        manager.loadClientKeystore(cert.p12Bytes, password)

        assertTrue(manager.hasClientKeystore())
        assertNotNull(manager.buildCompositeKeyManagers())

        manager.clearClientKeystore()

        // This is the bug L-4 fixes: deleting the P12 from the encrypted store
        // left this KeyManager alive, so mTLS kept working until the process
        // restarted. After clearing, SSLContext.init gets null key managers and
        // the handshake presents no client certificate.
        assertFalse(manager.hasClientKeystore())
        assertNull(manager.buildCompositeKeyManagers())
    }

    @Test
    fun `clearClientKeystore — host bazli certler de temizlenir`() {
        val defaultCert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        val hostCert = TestCertUtil.generateSelfSigned(cn = "specific.host", password = password)
        manager.loadClientKeystore(defaultCert.p12Bytes, password)
        manager.loadHostClientCerts(mapOf("specific.host" to hostCert.p12Bytes), password)

        assertTrue(manager.hasClientKeystore())

        manager.clearClientKeystore()

        assertFalse(manager.hasClientKeystore())
        assertNull(manager.buildCompositeKeyManagers())
    }

    @Test
    fun `clearClientKeystore — includeHostCerts false ise host certler kalir`() {
        val defaultCert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        val hostCert = TestCertUtil.generateSelfSigned(cn = "specific.host", password = password)
        manager.loadClientKeystore(defaultCert.p12Bytes, password)
        manager.loadHostClientCerts(mapOf("specific.host" to hostCert.p12Bytes), password)

        manager.clearClientKeystore(includeHostCerts = false)

        assertTrue(manager.hasClientKeystore())
        // Composite falls back to the surviving host KeyManagers.
        assertNotNull(manager.buildCompositeKeyManagers())
    }

    @Test
    fun `clearClientKeystore — sonrasinda pinned client hala kurulabilir`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "default-client", password = password)
        manager.loadClientKeystore(cert.p12Bytes, password)
        manager.clearClientKeystore()

        val serverCert = TestCertUtil.generateSelfSigned(cn = "server.test")
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("server.test", listOf(serverCert.sha256Pin, serverCert.sha256Pin)))
        )
        // Pinning must survive an unenroll — only the client cert goes away.
        assertNotNull(manager.buildClient(config))
    }

    // ── CSR flow: a key that stays in the Keystore ─────────────────────

    @Test
    fun `loadClientKey — key plus chain becomes the default identity`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1", password = password)
        manager.loadClientKey(cert.keyPair.private, arrayOf(cert.certificate))

        assertTrue(manager.hasClientKeystore())
        manager.setIdentityHosts(listOf("https://config.test:8092/"))
        val kms = manager.buildCompositeKeyManagers()!!
        assertEquals(1, kms.size)
        val km = kms[0] as javax.net.ssl.X509ExtendedKeyManager
        // Offered to the block's own listener; the alias names its owner.
        val alias = km.chooseEngineClientAlias(arrayOf("RSA"), null, engine("config.test", 8092))
        assertEquals("d/pinvault-client", alias)
        assertSame(cert.keyPair.private, km.getPrivateKey(alias))
        assertEquals(cert.certificate, km.getCertificateChain(alias)!![0])
        assertEquals(cert.certificate, manager.defaultClientCertificate())
    }

    @Test
    fun `loadClientKey — replaces a P12 identity and is dropped by clearClientKeystore`() {
        val p12 = TestCertUtil.generateSelfSigned(cn = "old-p12", password = password)
        manager.loadClientKeystore(p12.p12Bytes, password)
        val chain = TestCertUtil.generateSelfSigned(cn = "new-chain", password = password)
        manager.loadClientKey(chain.keyPair.private, arrayOf(chain.certificate))

        assertEquals(chain.certificate, manager.defaultClientCertificate())

        manager.clearClientKeystore()
        assertNull(manager.defaultClientCertificate())
        assertFalse(manager.hasClientKeystore())
    }

    @Test
    fun `loadClientKey — host-specific certs still win over the default identity`() {
        val default = TestCertUtil.generateSelfSigned(cn = "default-identity", password = password)
        val host = TestCertUtil.generateSelfSigned(cn = "specific.host", password = password)
        manager.loadClientKey(default.keyPair.private, arrayOf(default.certificate))
        manager.loadHostClientCerts(mapOf("specific.host" to host.p12Bytes), password)

        val km = manager.buildCompositeKeyManagers()!![0] as javax.net.ssl.X509ExtendedKeyManager
        // Aliases from both managers are visible through the composite.
        val aliases = km.getClientAliases("RSA", null)!!.toList()
        assertTrue(aliases.contains("d/pinvault-client"))
        assertTrue(aliases.size >= 2)
        assertSame(default.keyPair.private, km.getPrivateKey("d/pinvault-client"))
        // The host's own certificate wins for that host …
        val hostAlias = km.chooseEngineClientAlias(arrayOf("RSA"), null, engine("specific.host", 443))!!
        assertTrue(hostAlias, hostAlias.startsWith("h/specific.host/"))
        assertEquals(host.certificate, km.getCertificateChain(hostAlias)!![0])
    }

    // ── Who gets to see the client identity ────────────────────────────

    private fun engine(host: String, port: Int) = javax.net.ssl.SSLContext.getDefault().createSSLEngine(host, port)

    private fun identityFor(host: String, port: Int, config: CertificateConfig? = null): java.security.cert.X509Certificate? {
        val km = manager.buildCompositeKeyManagers { config }!![0] as javax.net.ssl.X509ExtendedKeyManager
        val alias = km.chooseEngineClientAlias(arrayOf("RSA", "EC"), null, engine(host, port)) ?: return null
        return km.getCertificateChain(alias)!![0]
    }

    @Test
    fun `the default identity is offered to the block's own listeners only`() {
        val device = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1", password = password)
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        manager.setIdentityHosts(listOf("https://config.test:8092/", "https://config.test:8093/", null))

        assertEquals(device.certificate, identityFor("config.test", 8092))
        assertEquals(device.certificate, identityFor("CONFIG.test", 8093))
        // Another port of the same host, and any other host that asks: nothing.
        assertNull(identityFor("config.test", 8444))
        assertNull(identityFor("analytics.test", 443))
    }

    @Test
    fun `a pinned host gets the default identity only when its pin entry says mtls`() {
        val device = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1", password = password)
        manager.loadClientKeystore(device.p12Bytes, password)
        val pins = listOf(device.sha256Pin, device.sha256Pin)
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("mtls.test", pins, mtls = true),
                HostPin("*.mtls.example.com", pins, mtls = true),
                HostPin("door.test:9443", pins, mtls = true),
                HostPin("plain.test", pins)
            )
        )

        assertEquals(device.certificate, identityFor("mtls.test", 443, config))
        assertEquals(device.certificate, identityFor("a.mtls.example.com", 443, config))
        assertEquals(device.certificate, identityFor("door.test", 9443, config))
        assertNull("the entry names one port", identityFor("door.test", 443, config))
        assertNull("pinned, but not an mTLS host", identityFor("plain.test", 443, config))
        assertNull("no pin entry at all", identityFor("unknown.test", 443, config))
    }

    @Test
    fun `an unknown peer host gets no client certificate`() {
        val device = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1", password = password)
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        manager.setIdentityHosts(listOf("https://config.test/"))
        val km = manager.buildCompositeKeyManagers()!![0] as javax.net.ssl.X509ExtendedKeyManager

        // No socket, and a socket nobody named a host for: fail closed, no
        // reverse DNS lookup of the remote address.
        assertNull(km.chooseClientAlias(arrayOf("RSA"), null, null))
        assertNull(km.chooseClientAlias(arrayOf("RSA"), null, java.net.Socket()))
        assertNull(km.chooseEngineClientAlias(arrayOf("RSA"), null, javax.net.ssl.SSLContext.getDefault().createSSLEngine()))
    }

    @Test
    fun `two key stores with the same alias do not get mixed up`() {
        val a = TestCertUtil.generateSelfSigned(cn = "client-a", password = password, alias = "client")
        val b = TestCertUtil.generateSelfSigned(cn = "client-b", password = password, alias = "client")
        manager.loadClientKeystore(a.p12Bytes, password)
        manager.loadHostClientCerts(mapOf("b.host" to b.p12Bytes), password)
        manager.setIdentityHosts(listOf("https://config.test/"))

        assertEquals(a.certificate, identityFor("config.test", 443))
        assertEquals(b.certificate, identityFor("b.host", 443))
    }

    @Test
    fun `defaultClientCertificate — reads the P12 identity too`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "p12-identity", password = password)
        manager.loadClientKeystore(cert.p12Bytes, password)
        assertEquals(cert.certificate, manager.defaultClientCertificate())
    }

    @Test
    fun `with clientCertHosts listed, an mtls pin entry adds no host`() {
        val device = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1", password = password)
        manager.loadClientKey(device.keyPair.private, arrayOf(device.certificate))
        val pins = listOf(device.sha256Pin, device.sha256Pin)
        val config = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("listed.test:9443", pins, mtls = true), HostPin("named-by-signer.test", pins, mtls = true))
        )
        // The block's own URL plus the app's clientCertHosts: the whole list.
        manager.setIdentityHosts(listOf("https://config.test:8092/", "https://listed.test:9443/"), onlyThese = true)

        assertEquals(device.certificate, identityFor("config.test", 8092, config))
        assertEquals(device.certificate, identityFor("listed.test", 9443, config))
        assertNull("the signed config cannot add a host the app did not list", identityFor("named-by-signer.test", 443, config))

        // Without such a list, mtls = true entries still name hosts, as before.
        manager.setIdentityHosts(listOf("https://config.test:8092/"))
        assertEquals(device.certificate, identityFor("named-by-signer.test", 443, config))
    }
}
