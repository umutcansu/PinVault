package com.example.pinvault.server

import com.example.pinvault.server.route.clientCertRenewalRoute
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.RecoveryListener
import com.example.pinvault.server.store.ClientIdentityStore
import com.example.pinvault.server.store.DatabaseManager
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * The recovery door: a real Netty TLS listener that asks for no client
 * certificate, serves its CA-signed certificate with the CA in the chain, and
 * renews a registered device by CSR signature alone.
 */
class RecoveryListenerTest {

    private lateinit var certsDir: File
    private lateinit var dbFile: File
    private lateinit var certService: CertificateService
    private lateinit var identityStore: ClientIdentityStore
    private var listener: RecoveryListener? = null

    @BeforeTest
    fun setUp() {
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-recovery-${System.nanoTime()}").also { it.mkdirs() }
        dbFile = File.createTempFile("pinvault-recovery-", ".db").also { it.deleteOnExit() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(DatabaseManager(dbFile.absolutePath))
    }

    @AfterTest
    fun tearDown() {
        listener?.stop()
        certsDir.deleteRecursively()
        dbFile.delete()
    }

    private fun pin(cert: X509Certificate) =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csr(key: KeyPair): ByteArray =
        JcaPKCS10CertificationRequestBuilder(X500Name("CN=x"), key.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded

    /** Enrolls [clientId] with [key] the way the enroll route does. */
    private fun register(clientId: String, key: KeyPair) {
        val issued = certService.issueClientCertificate(clientId, certService.parseCsr(csr(key)), Duration.ofDays(90))
        assertTrue(identityStore.register(clientId, "default-tls", issued.spkiSha256, issued.serialHex,
            issued.notBefore.toString(), issued.notAfter.toString(), null, null, "now"))
    }

    /** Trusts anything and records the chain the server presented. */
    private class RecordingTrust : X509TrustManager {
        var served: List<X509Certificate> = emptyList()
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { served = chain.toList() }
        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    }

    private fun start(): Pair<Int, RecordingTrust> {
        val port = java.net.ServerSocket(0).use { it.localPort }
        listener = RecoveryListener(certService, port, host = "127.0.0.1") {
            clientCertRenewalRoute("recovery", certService, identityStore, { Duration.ofDays(90) })
        }.also { it.start() }
        return port to RecordingTrust()
    }

    private fun client(trust: RecordingTrust): HttpClient {
        val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust), null) }
        return HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(5)).build()
    }

    @Test
    fun `server CA has two distinct pins and is stable across calls`() {
        val first = certService.ensureServerCa()
        val again = certService.ensureServerCa()
        assertEquals(2, first.pins.distinct().size)
        assertEquals(first.pins, again.pins)
        assertEquals(first.certificate, again.certificate)
        assertTrue(first.certificate.basicConstraints >= 0, "CA bit")
    }

    @Test
    fun `recovery certificate is CA-signed, kept while fresh, reissued with a new key near expiry`() {
        val ca = certService.ensureServerCa()
        val first = certService.ensureRecoveryCertificate()
        assertTrue(first.regenerated)
        first.leaf.verify(ca.certificate.publicKey)
        assertEquals(ca.certificate, first.issuer)
        assertTrue(first.leaf.extendedKeyUsage.contains("1.3.6.1.5.5.7.3.1"), "serverAuth")

        val kept = certService.ensureRecoveryCertificate()
        assertFalse(kept.regenerated)
        assertEquals(first.leaf, kept.leaf)

        // "Within 1000 days of expiry" is always true → reissue.
        val reissued = certService.ensureRecoveryCertificate(renewBeforeDays = 1000)
        assertTrue(reissued.regenerated)
        assertNotEquals(pin(first.leaf), pin(reissued.leaf), "a new key")
        reissued.leaf.verify(ca.certificate.publicKey)
        // The pin apps carry — the CA's — does not change.
        assertEquals(ca.pins, certService.ensureServerCa().pins)
    }

    @Test
    fun `the door serves leaf plus CA and renews by CSR signature without a client certificate`() {
        val (port, trust) = start()
        val key = deviceKey()
        register("dev-r", key)

        val body = """{"clientId":"dev-r","csr":"${Base64.getEncoder().encodeToString(csr(key))}"}"""
        val response = client(trust).send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port/api/v1/client-certs/renew"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString()
        )
        assertEquals(200, response.statusCode(), response.body())
        assertTrue(response.body().contains("\"via\":\"recovery\""))
        assertEquals(1, identityStore.get("dev-r")!!.renewCount)

        // The chain carries the server CA, so an app pinning the CA can match it.
        assertEquals(2, trust.served.size)
        assertEquals(certService.ensureServerCa().pins.first(), pin(trust.served[1]))
    }

    @Test
    fun `the door serves nothing but renewal and health`() {
        val (port, trust) = start()
        val http = client(trust)
        fun status(path: String) = http.send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port$path")).GET().build(),
            HttpResponse.BodyHandlers.discarding()
        ).statusCode()
        assertEquals(200, status("/health"))
        assertEquals(404, status("/api/v1/certificate-config"))
        assertEquals(404, status("/api/v1/client-certs/192.168.1.217/download"))
        // EncodedPathGuard: a separator hidden in an escape is refused outright.
        assertEquals(400, status("/api/v1/client-certs%2Frenew"))
    }

    @Test
    fun `a wrong key is refused at the door`() {
        val (port, trust) = start()
        register("dev-w", deviceKey())
        val body = """{"clientId":"dev-w","csr":"${Base64.getEncoder().encodeToString(csr(deviceKey()))}"}"""
        val response = client(trust).send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port/api/v1/client-certs/renew"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString()
        )
        assertEquals(403, response.statusCode())
        assertTrue(response.body().contains("reenroll_required"))
    }
}
