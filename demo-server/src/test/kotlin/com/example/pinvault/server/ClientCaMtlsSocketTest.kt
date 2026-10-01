package com.example.pinvault.server

import com.example.pinvault.server.service.CertificateService
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.File
import java.io.FileInputStream
import java.math.BigInteger
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * A real Netty mTLS listener whose truststore holds only the client CA — the
 * way every mTLS Config API and mock host runs once the CA exists. Proves
 * that a CA-issued device certificate is accepted without any per-device
 * truststore entry, and that an expired one or one from another CA is not.
 */
class ClientCaMtlsSocketTest {

    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private var server: EmbeddedServer<*, *>? = null
    private var port = 0

    @BeforeTest
    fun setUp() {
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-socket-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        val serverKeystore = certService.generateCertificate("sock", "localhost").keystorePath
        port = java.net.ServerSocket(0).use { it.localPort }

        val keyStore = KeyStore.getInstance("JKS").apply {
            FileInputStream(serverKeystore).use { load(it, CertificateService.KEYSTORE_PASSWORD.toCharArray()) }
        }
        val environment = applicationEnvironment {}
        server = embeddedServer(Netty, environment, configure = {
            sslConnector(
                keyStore = keyStore,
                keyAlias = "server",
                keyStorePassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() },
                privateKeyPassword = { CertificateService.KEYSTORE_PASSWORD.toCharArray() }
            ) {
                this.port = this@ClientCaMtlsSocketTest.port
                this.host = "127.0.0.1"
                this.trustStore = certService.getTrustStore()
            }
        }) {
            routing { get("/health") { call.respondText("""{"status":"ok"}""") } }
        }.also { it.start(wait = false) }
    }

    @AfterTest
    fun tearDown() {
        server?.stop(100, 500)
        certsDir.deleteRecursively()
    }

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun issued(key: KeyPair, ttl: Duration): List<X509Certificate> {
        val csr = JcaPKCS10CertificationRequestBuilder(X500Name("CN=x"), key.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private))
        val cert = certService.issueClientCertificate("sock-dev", certService.parseCsr(csr.encoded), ttl)
        return listOf(cert.leaf, cert.issuer)
    }

    /** A leaf over [key] signed by a CA this server has never heard of. */
    private fun foreignChain(key: KeyPair): List<X509Certificate> {
        val ca = deviceKey()
        val caName = X500Name("CN=Somebody Else CA")
        val now = System.currentTimeMillis()
        val caCert = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(caName, BigInteger.ONE, Date(now - 1000), Date(now + 86_400_000), caName, ca.public)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(ca.private))
        )
        val leaf = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(caName, BigInteger.TWO, Date(now - 1000), Date(now + 86_400_000), X500Name("CN=PinVault Client: sock-dev"), key.public)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(ca.private))
        )
        return listOf(leaf, caCert)
    }

    private fun clientWith(key: KeyPair?, chain: List<X509Certificate>?): HttpClient {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        })
        val keyManagers = if (key != null && chain != null) {
            val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
            ks.setKeyEntry("device", key.private, "pw".toCharArray(), chain.toTypedArray())
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "pw".toCharArray()) }.keyManagers
        } else null
        val ctx = SSLContext.getInstance("TLS").apply { init(keyManagers, trustAll, null) }
        return HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(5)).build()
    }

    private fun health(client: HttpClient): Int =
        client.send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port/health")).timeout(Duration.ofSeconds(5)).GET().build(),
            HttpResponse.BodyHandlers.ofString()
        ).statusCode()

    @Test
    fun `a certificate the client CA issued is accepted with only the CA in the truststore`() {
        val key = deviceKey()
        assertEquals(200, health(clientWith(key, issued(key, Duration.ofDays(1)))))
    }

    @Test
    fun `an expired certificate is refused at the handshake`() {
        val key = deviceKey()
        val chain = issued(key, Duration.ofSeconds(1))
        Thread.sleep(1500)
        assertFails("expired client cert must not complete the handshake") { health(clientWith(key, chain)) }
    }

    @Test
    fun `a certificate from another CA and no certificate at all are refused`() {
        val key = deviceKey()
        assertFails { health(clientWith(key, foreignChain(key))) }
        assertFails { health(clientWith(null, null)) }
    }
}
