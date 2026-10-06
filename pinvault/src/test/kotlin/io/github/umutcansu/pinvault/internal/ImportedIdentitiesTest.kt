package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.keystore.ImportedClientKeys
import io.github.umutcansu.pinvault.keystore.SoftwareImportedClientKeys
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.SecurePreferences
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * A private key that reaches the device in a PKCS12 — a host's client
 * certificate, a server-made enrollment, a P12 an earlier version stored —
 * ends up as a Keystore key with only its certificate chain in storage, and
 * is presented from there.
 *
 * `ImportedClientKeys.software()` stands in for the Android Keystore
 * (Robolectric has none). What only a device can show — that the Keystore
 * accepts the import with the purposes, digests and paddings chosen, and that
 * Conscrypt signs a handshake with such a key — is in the lead's checklist.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ImportedIdentitiesTest {

    private val password = "changeit"
    private val keys = ImportedClientKeys.software()
    private lateinit var store: ClientCertSecureStore
    private lateinit var identities: ImportedIdentities

    @Before
    fun setUp() {
        SoftwareImportedClientKeys.reset()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences("imported-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, "imported-test", "ns", SoftwarePrefsCipher()))
        identities = ImportedIdentities(store, keys)
    }

    @After
    fun tearDown() = SoftwareImportedClientKeys.reset()

    /** An EC key and self-signed certificate in a P12, as an EC-issuing server would send. */
    private fun ecP12(cn: String): Pair<ByteArray, X509Certificate> {
        TestCertUtil.generateEcKeyPair() // registers BouncyCastle
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=$cn")
        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(System.nanoTime()), Date(System.currentTimeMillis() - 3600_000),
            Date(System.currentTimeMillis() + 86_400_000L), name, pair.public
        )
        val cert = JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(builder.build(JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(pair.private)))
        val p12 = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("client", pair.private, password.toCharArray(), arrayOf(cert))
        }
        return java.io.ByteArrayOutputStream().also { p12.store(it, password.toCharArray()) }.toByteArray() to cert
    }

    // ── Import ──────────────────────────────────────────────────────────

    @Test
    fun `an RSA P12 becomes a Keystore key and a stored chain, and the P12 bytes are not kept`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")

        val identity = identities.import("default", cert.p12Bytes, password)!!

        assertEquals(cert.certificate, identity.chain[0])
        assertSame(keys.privateKey(ImportedClientKeys.aliasFor("default")), identity.privateKey)
        assertEquals(ClientCertSecureStore.Mode.IMPORTED, store.mode("default"))
        assertTrue(store.exists("default"))
        assertFalse("no P12 in storage", store.hasP12("default"))
        assertNull(store.load("default"))
        assertNull("not a CSR identity: nothing to renew", store.loadChain("default"))
        assertEquals(1, store.loadImported("default")!!.size)
    }

    @Test
    fun `an EC P12 is imported the same way`() {
        val (p12, cert) = ecP12("device-ec")
        val identity = identities.import("host_ec.example.com", p12, password)!!
        assertEquals("EC", identity.privateKey.algorithm)
        assertEquals(cert, identity.chain[0])
        assertEquals(ClientCertSecureStore.Mode.IMPORTED, store.mode("host_ec.example.com"))
    }

    @Test
    fun `the imported identity is loaded again from the chain and the Keystore key`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        identities.import("default", cert.p12Bytes, password)

        val loaded = ImportedIdentities(store, keys).load("default")!!
        assertEquals(cert.certificate, loaded.chain[0])
        assertEquals(cert.keyPair.private, loaded.privateKey)
    }

    @Test
    fun `a wrong password or a P12 without a key is an error, and nothing is stored`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        assertTrue(runCatching { identities.import("default", cert.p12Bytes, "wrong") }.isFailure)
        assertTrue(runCatching { identities.import("default", byteArrayOf(1, 2, 3), password) }.isFailure)
        assertEquals(ClientCertSecureStore.Mode.NONE, store.mode("default"))
        assertNull(keys.privateKey(ImportedClientKeys.aliasFor("default")))
    }

    // ── Identities stored by earlier versions ───────────────────────────

    @Test
    fun `a P12 an earlier version stored is moved into the Keystore the first time it is loaded`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        store.save("default", cert.p12Bytes)                 // what 2.1.x left behind
        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("default"))

        val identity = identities.loadOrMigrate("default", password)!!

        assertEquals(cert.certificate, identity.chain[0])
        assertEquals(ClientCertSecureStore.Mode.IMPORTED, store.mode("default"))
        assertFalse("the P12 is gone from storage", store.hasP12("default"))
        // The next load finds the imported form and imports nothing again.
        SoftwareImportedClientKeys.refused += ImportedClientKeys.aliasFor("default")
        assertNotNull(identities.loadOrMigrate("default", password))
    }

    @Test
    fun `where the platform refuses the import the P12 stays as it was`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        SoftwareImportedClientKeys.refused += ImportedClientKeys.aliasFor("default")

        assertNull(identities.import("default", cert.p12Bytes, password))
        assertEquals("nothing stored by a refused import", ClientCertSecureStore.Mode.NONE, store.mode("default"))

        store.save("default", cert.p12Bytes)
        assertNull(identities.loadOrMigrate("default", password))
        assertEquals("the old storage is kept for this key", ClientCertSecureStore.Mode.P12, store.mode("default"))
        assertTrue(store.load("default")!!.contentEquals(cert.p12Bytes))
    }

    @Test
    fun `a stored P12 that cannot be read is left alone`() {
        store.save("default", byteArrayOf(9, 9, 9))
        assertNull(identities.loadOrMigrate("default", password))
        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("default"))
    }

    @Test
    fun `a chain whose Keystore key is gone is dropped`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        identities.import("default", cert.p12Bytes, password)
        keys.delete(ImportedClientKeys.aliasFor("default"))       // a restored backup, a wiped Keystore

        assertNull(identities.load("default"))
        assertEquals(ClientCertSecureStore.Mode.NONE, store.mode("default"))
    }

    @Test
    fun `a Keystore that cannot be read right now does not cost the device its certificate`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        identities.import("default", cert.p12Bytes, password)

        SoftwareImportedClientKeys.unreadable = true
        assertNull("nothing to present for now", identities.load("default"))
        assertNull(identities.loadOrMigrate("default", password))
        assertEquals("but the chain stays", ClientCertSecureStore.Mode.IMPORTED, store.mode("default"))

        SoftwareImportedClientKeys.unreadable = false
        assertNotNull(identities.load("default"))
    }

    @Test
    fun `forget removes the chain and the key`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        identities.import("default", cert.p12Bytes, password)
        identities.forget("default")
        assertEquals(ClientCertSecureStore.Mode.NONE, store.mode("default"))
        assertNull(keys.privateKey(ImportedClientKeys.aliasFor("default")))
    }

    @Test
    fun `saving another form replaces the imported one`() {
        val cert = TestCertUtil.generateSelfSigned(cn = "device-1", password = password, alias = "client")
        identities.import("default", cert.p12Bytes, password)
        store.saveChain("default", listOf("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"))
        assertEquals(ClientCertSecureStore.Mode.CHAIN, store.mode("default"))
        assertFalse(store.hasImported("default"))
    }

    // ── Host client certificates ────────────────────────────────────────

    private fun updater(api: CertificateConfigApi, sslManager: DynamicSSLManager, importedKeys: ImportedClientKeys?): SSLCertificateUpdater {
        val configStore = mockk<CertificateConfigStore>(relaxed = true)
        every { configStore.getCurrentVersion() } returns 0
        every { configStore.load() } returns null
        return SSLCertificateUpdater(
            context = mockk(relaxed = true),
            configApi = api,
            configStore = configStore,
            httpClientProvider = HttpClientProvider(sslManager),
            sslManager = sslManager,
            certStore = store,
            clientKeyPassword = password,
            maxRetryCount = 1,
            importedKeys = importedKeys
        )
    }

    private val BACKUP_PIN = "A".repeat(43) + "="

    private fun mtlsConfig(host: String, pin: String) = CertificateConfig(
        version = 1,
        pins = listOf(HostPin(host, listOf(pin, BACKUP_PIN), version = 1, mtls = true, clientCertVersion = 1))
    )

    @Test
    fun `a downloaded host client certificate is stored as a chain with its key in the Keystore`() = runTest {
        val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
        val hostCert = TestCertUtil.generateSelfSigned(cn = "host-client", password = password, alias = "client")
        val api = mockk<CertificateConfigApi>()
        coEvery { api.fetchConfig(any()) } returns mtlsConfig("localhost", serverCert.sha256Pin)
        coEvery { api.downloadHostClientCert("localhost") } returns hostCert.p12Bytes
        val sslManager = DynamicSSLManager()

        assertTrue(updater(api, sslManager, keys).updateNow() is UpdateResult.Updated)

        assertEquals(ClientCertSecureStore.Mode.IMPORTED, store.mode("host_localhost"))
        assertFalse(store.hasP12("host_localhost"))
        assertNotNull(keys.privateKey(ImportedClientKeys.aliasFor("host_localhost")))
        assertEquals("CN=host-client", presentedTo(serverCert, sslManager, mtlsConfig("localhost", serverCert.sha256Pin)))
    }

    @Test
    fun `a host certificate the platform will not import is kept as a P12 and still presented`() = runTest {
        val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
        val hostCert = TestCertUtil.generateSelfSigned(cn = "host-client", password = password, alias = "client")
        SoftwareImportedClientKeys.refused += ImportedClientKeys.aliasFor("host_localhost")
        val api = mockk<CertificateConfigApi>()
        coEvery { api.fetchConfig(any()) } returns mtlsConfig("localhost", serverCert.sha256Pin)
        coEvery { api.downloadHostClientCert("localhost") } returns hostCert.p12Bytes
        val sslManager = DynamicSSLManager()

        assertTrue(updater(api, sslManager, keys).updateNow() is UpdateResult.Updated)

        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("host_localhost"))
        assertEquals("CN=host-client", presentedTo(serverCert, sslManager, mtlsConfig("localhost", serverCert.sha256Pin)))
    }

    // ── The key manager, with Keystore-held keys ────────────────────────

    /** Subject of the client certificate a pinned client of [sslManager] presents to an mTLS server, or null. */
    private fun presentedTo(serverCert: TestCertUtil.CertResult, sslManager: DynamicSSLManager, config: CertificateConfig): String? {
        val server = MockWebServer()
        val ks = KeyStore.getInstance("PKCS12").apply { load(serverCert.p12Bytes.inputStream(), password.toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password.toCharArray()) }
        val acceptAnyClient = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        server.useHttps(SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, arrayOf(acceptAnyClient), null) }.socketFactory, false)
        server.requestClientAuth()
        server.start()
        try {
            server.enqueue(MockResponse().setBody("ok"))
            // The pin entry names "localhost" without a port; the server's port is whatever it got.
            val client = OkHttpClient.Builder().hostnameVerifier { _, _ -> true }.also { sslManager.applyTo(it) { config } }.build()
            client.newCall(Request.Builder().url(server.url("/")).build()).execute().use { assertEquals(200, it.code) }
            val presented = server.takeRequest().handshake?.peerCertificates?.firstOrNull() as? X509Certificate
            return presented?.subjectX500Principal?.name
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `a default identity held as a Keystore key is presented in a handshake`() {
        val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
        val device = TestCertUtil.generateSelfSigned(cn = "imported-device", password = password, alias = "client")
        val identity = identities.import("default", device.p12Bytes, password)!!
        val sslManager = DynamicSSLManager()
        sslManager.loadClientKey(identity.privateKey, identity.chain)

        assertEquals(device.certificate, sslManager.defaultClientCertificate())
        assertEquals("CN=imported-device", presentedTo(serverCert, sslManager, mtlsConfig("localhost", serverCert.sha256Pin)))
    }

    @Test
    fun `a host identity held as a Keystore key wins over the default one for its host`() {
        val serverCert = TestCertUtil.generateSelfSigned(cn = "localhost", password = password)
        val device = TestCertUtil.generateSelfSigned(cn = "default-device", password = password, alias = "client")
        val (hostP12, _) = ecP12("host-ec-client")
        val default = identities.import("default", device.p12Bytes, password)!!
        val host = identities.import("host_localhost", hostP12, password)!!
        val sslManager = DynamicSSLManager()
        sslManager.loadClientKey(default.privateKey, default.chain)
        sslManager.loadHostClientIdentities(mapOf("localhost" to (host.privateKey to host.chain)), emptyMap(), password)
        val config = mtlsConfig("localhost", serverCert.sha256Pin)

        assertEquals("CN=host-ec-client", presentedTo(serverCert, sslManager, config))

        // The composite names each key's owner: both identities are reachable by alias.
        val composite = sslManager.buildCompositeKeyManagers { config }!!.single() as javax.net.ssl.X509ExtendedKeyManager
        val aliases = listOf("EC", "RSA").flatMap { type -> composite.getClientAliases(type, null)?.toList().orEmpty() }.toSet()
        assertEquals(2, aliases.size)
        assertEquals(
            setOf(default.privateKey, host.privateKey),
            aliases.map { composite.getPrivateKey(it) }.toSet()
        )
        // Dropping the host identities leaves the default one for the mtls host.
        sslManager.loadHostClientIdentities(emptyMap(), emptyMap(), password)
        assertEquals("CN=default-device", presentedTo(serverCert, sslManager, config))
    }
}
