package com.example.pinvault.server

import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.presentedLeafOnRecord
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse as JdkResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * Server-made P12 certificates and per-certificate trust anchors.
 *
 * P12s used to be self-signed leaves without basicConstraints, each added to
 * the mTLS truststore as its own anchor, and the identity is read from the CN:
 * JSSE does not look at an anchor's CA flag, so a P12 holder could sign a leaf
 * naming ANOTHER client id and be accepted as that device. Now P12s come from
 * the client CA (nothing is added to the truststore), every mTLS request must
 * present the certificate on record for the id its CN names, and an old
 * anchor leaves the truststore (its key retired) when the id enrolls again.
 */
class P12TrustAnchorTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private lateinit var identityStore: ClientIdentityStore
    private lateinit var clientCertStore: ClientCertStore
    private lateinit var tokenStore: EnrollmentTokenStore
    private lateinit var auditStore: AuditLogStore
    private val scope = "p12-tls"

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-p12-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-p12-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        auditStore = AuditLogStore(db)
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); certsDir.deleteRecursively() }

    private fun ecKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sha256(bytes: ByteArray) = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun csr(key: KeyPair): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
        return Base64.getEncoder().encodeToString(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded)
    }

    /** Puts [cert] into the client truststore as its own anchor, as the server used to; returns its fingerprint. */
    private fun trust(alias: String, cert: X509Certificate): String {
        val file = certService.getTrustStoreFile()
        val password = CertificateService.KEYSTORE_PASSWORD.toCharArray()
        val store = KeyStore.getInstance("JKS").apply { file.inputStream().use { load(it, password) } }
        store.setCertificateEntry(alias, cert)
        file.outputStream().use { store.store(it, password) }
        return sha256(cert.encoded)
    }

    /** The subject of an old self-signed P12 of [clientId], as the string it was built from (the issuer of what it signs). */
    private fun anchorName(clientId: String) = "CN=PinVault Client: $clientId,O=PinVault Client,C=TR"

    /** A P12 as the server issued them before: self-signed, no extensions — an anchor in the truststore, its row on record. */
    private fun legacyAnchor(clientId: String): Pair<KeyPair, X509Certificate> {
        val key = ecKey()
        val name = anchorName(clientId)
        val cert = TestPki.build(name, key.public, name, key.private, basicConstraints = false)
        val fingerprint = trust(clientId, cert)
        clientCertStore.add(clientId, "PinVault Client: $clientId", fingerprint, Instant.now().toString())
        return key to cert
    }

    private fun aliases(): List<String> = certService.getTrustStore()!!.aliases().toList().sorted()

    @Test
    fun `a server-made P12 is a client-CA leaf and touches no truststore`() {
        val before = aliases()
        val result = certService.generateClientCertificate("kiosk-1", "pw")
        assertEquals(before, aliases(), "no per-certificate anchor")
        val p12 = KeyStore.getInstance("PKCS12", "BC").apply { load(result.p12Bytes.inputStream(), "pw".toCharArray()) }
        val chain = p12.getCertificateChain("kiosk-1").map { it as X509Certificate }
        assertEquals(2, chain.size, "leaf, then the client CA")
        val (leaf, ca) = chain
        assertEquals(certService.clientCaCertificate(), ca)
        leaf.verify(ca.publicKey)
        assertEquals(-1, leaf.basicConstraints, "CA:false")
        assertTrue("1.3.6.1.5.5.7.3.2" in leaf.extendedKeyUsage, "client authentication")
        assertTrue(leaf.subjectX500Principal.name.contains("CN=PinVault Client: kiosk-1"))
        assertEquals(sha256(leaf.encoded), result.fingerprint)
        assertEquals(sha256(leaf.publicKey.encoded), result.spkiSha256)
        assertEquals(leaf.serialNumber.toString(16), result.serialHex)
    }

    @Test
    fun `only the certificate on record for an id passes`() {
        // A CSR identity: any certificate over its key (a renewal overlap included), nothing else.
        val deviceKey = ecKey()
        val issued = certService.issueClientCertificate("tablet-1", certService.parseCsr(csr(deviceKey)), Duration.ofDays(1))
        val now = Instant.now().toString()
        assertTrue(identityStore.register("tablet-1", scope, issued.spkiSha256, issued.serialHex, now, now, null, null, now))
        assertTrue(presentedLeafOnRecord("tablet-1", issued.leaf, clientCertStore, identityStore))
        val renewed = certService.issueClientCertificate("tablet-1", certService.parseCsr(csr(deviceKey)), Duration.ofDays(1))
        assertTrue(presentedLeafOnRecord("tablet-1", renewed.leaf, clientCertStore, identityStore))
        val (anchorKey, anchor) = legacyAnchor("attacker")
        val other = ecKey()
        val forged = TestPki.build("CN=PinVault Client: tablet-1", other.public, anchorName("attacker"), anchorKey.private, basicConstraints = false)
        assertFalse(presentedLeafOnRecord("tablet-1", forged, clientCertStore, identityStore))

        // A P12 identity (no client_identities row): exactly the stored certificate.
        assertTrue(presentedLeafOnRecord("attacker", anchor, clientCertStore, identityStore))
        val p12 = certService.generateClientCertificate("kiosk-2", "pw")
        clientCertStore.add("kiosk-2", p12.commonName, p12.fingerprint, now)
        val p12Leaf = KeyStore.getInstance("PKCS12", "BC").apply { load(p12.p12Bytes.inputStream(), "pw".toCharArray()) }
            .getCertificate("kiosk-2") as X509Certificate
        assertTrue(presentedLeafOnRecord("kiosk-2", p12Leaf, clientCertStore, identityStore))
        val forgedP12 = TestPki.build("CN=PinVault Client: kiosk-2", other.public, anchorName("attacker"), anchorKey.private, basicConstraints = false)
        assertFalse(presentedLeafOnRecord("kiosk-2", forgedP12, clientCertStore, identityStore))

        // An uploaded certificate is on record under its row id, whatever its subject.
        val partnerKey = ecKey()
        val partner = TestPki.build("CN=partner-gateway", partnerKey.public, "CN=partner-gateway", partnerKey.private,
            eku = listOf("1.3.6.1.5.5.7.3.2"))
        clientCertStore.add("partner", "Uploaded: partner", certService.importClientCertificate("partner", TestPki.pem(partner)), now)
        assertTrue(presentedLeafOnRecord("partner-gateway", partner, clientCertStore, identityStore))
        // An id nobody holds, signed by an anchor: nothing on record.
        val nobody = TestPki.build("CN=PinVault Client: nobody", other.public, anchorName("attacker"), anchorKey.private, basicConstraints = false)
        assertFalse(presentedLeafOnRecord("nobody", nobody, clientCertStore, identityStore))
    }

    // ── re-enrollment retires the old anchor (D1) ────────────────────────

    private val restarts = mutableListOf<String>()

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(certsDir, "signing.pem")), ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                onClientCertEnrolled = { restarts += "trust" },
                audit = AuditLog(auditStore, null), clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) }
            )
        }
    }

    private suspend fun ApplicationTestBuilder.enroll(clientId: String, key: KeyPair?): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", if (key != null) "p12password,csr" else "p12password")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("token", tokenStore.create(clientId))
                put("deviceUid", "uid-$clientId")
                key?.let { put("csr", csr(it)) }
            }.toString())
        }

    @Test
    fun `a P12 holder enrolling over a CSR loses its old anchor and its old key`() = testApplication {
        configureApp()
        val (oldKey, _) = legacyAnchor("dev-old")
        assertTrue("dev-old" in aliases())
        val response = enroll("dev-old", ecKey())
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertFalse("dev-old" in aliases(), "the anchor left the truststore")
        assertTrue(identityStore.isRetired(sha256(oldKey.public.encoded)), "and its key is retired")
        assertEquals(listOf("trust"), restarts, "the listeners drop it")
        val issued = auditStore.page(10, 0, "client_cert_issued").single()
        assertTrue(issued.detail.contains("legacyAnchorRemoved"), issued.detail)
        // A CSR enrollment of an id without an anchor restarts nothing.
        assertEquals(HttpStatusCode.OK, enroll("dev-new", ecKey()).status)
        assertEquals(1, restarts.size)
    }

    @Test
    fun `a new P12 for the same id replaces the old anchor and retires the keys before it`() = testApplication {
        configureApp()
        val (oldKey, _) = legacyAnchor("dev-p12")
        assertEquals(HttpStatusCode.OK, enroll("dev-p12", null).status)
        assertFalse("dev-p12" in aliases())
        assertTrue(identityStore.isRetired(sha256(oldKey.public.encoded)))
        assertEquals(1, restarts.size)

        // Once more: the CA-issued P12 before it is retired, no anchor, no restart.
        assertEquals(HttpStatusCode.OK, enroll("dev-p12", null).status)
        assertEquals(1, restarts.size)
        assertEquals(2, identityStore.retiredKeys("dev-p12"))
    }

    // ── the attack, over a real socket ───────────────────────────────────

    private fun health(port: Int, key: KeyPair, chain: List<X509Certificate>): Int {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        })
        val ks = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        ks.setKeyEntry("device", key.private, "pw".toCharArray(), chain.toTypedArray())
        val kms = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "pw".toCharArray()) }.keyManagers
        val ctx = SSLContext.getInstance("TLS").apply { init(kms, trustAll, null) }
        val http = HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(5)).build()
        return try {
            http.send(
                HttpRequest.newBuilder(URI("https://127.0.0.1:$port/health")).timeout(Duration.ofSeconds(5)).GET().build(),
                JdkResponse.BodyHandlers.ofString()
            ).statusCode()
        } catch (e: javax.net.ssl.SSLException) {
            HANDSHAKE_REFUSED
        }
    }

    private companion object {
        /** [health] when the handshake itself failed. */
        const val HANDSHAKE_REFUSED = -1
    }

    /**
     * A per-certificate anchor JSSE lets sign: a v1 certificate (no extensions,
     * so nothing says it is not a CA — uploads accepted it like any leaf until
     * now, and one may still sit in a truststore), or — with
     * `jdk.security.allowNonCaAnchor=true`, or on an older JDK — any
     * self-signed P12 of before.
     */
    private fun v1Anchor(clientId: String): Pair<KeyPair, X509Certificate> {
        val key = ecKey()
        val name = X500Name(anchorName(clientId))
        val now = System.currentTimeMillis()
        val holder = org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder(name, java.math.BigInteger.valueOf(now),
            java.util.Date(now - 60_000), java.util.Date(now + 86_400_000), name, key.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private))
        val cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder)
        val fingerprint = trust(clientId, cert)
        clientCertStore.add(clientId, "Uploaded: $clientId", fingerprint, Instant.now().toString())
        return key to cert
    }

    @Test
    fun `an anchor cannot sign its way into another device's identity`() {
        // The victim, enrolled over its own key.
        val victimKey = ecKey()
        val victim = certService.issueClientCertificate("victim", certService.parseCsr(csr(victimKey)), Duration.ofDays(1))
        val now = Instant.now().toString()
        assertTrue(identityStore.register("victim", scope, victim.spkiSha256, victim.serialHex, now, now, null, "uid-victim", now,
            certRecord = ClientIdentityStore.CertRecord(victim.commonName, victim.fingerprint)))
        // Two anchors: a self-signed v3 P12 of before, and a v1 certificate.
        val (p12Key, _) = legacyAnchor("attacker")
        val (v1Key, v1) = v1Anchor("attacker-v1")
        // Each signs a leaf naming the victim, over a key of its own.
        val forgedKey = ecKey()
        fun forgedBy(issuer: String, signer: KeyPair) = TestPki.build("CN=PinVault Client: victim,O=PinVault Client,C=TR",
            forgedKey.public, anchorName(issuer), signer.private, basicConstraints = false)

        val mocks = MockServerManager()
        mocks.revocationGate = {
            isRevoked = { id -> clientCertStore.get(id)?.revoked == true || identityStore.get(id)?.revoked == true }
            isRetiredKey = { cert -> identityStore.isRetired(certService.spkiSha256(cert.publicKey)) }
            isOnRecord = { id, cert -> presentedLeafOnRecord(id, cert, clientCertStore, identityStore) }
        }
        val keystore = certService.generateCertificate("mockhost-p12", "localhost").keystorePath
        val port = java.net.ServerSocket(0).use { it.localPort }
        mocks.start("mock.p12.test", port, keystore, certService.getTrustStoreFile().absolutePath)
        try {
            assertEquals(200, health(port, victimKey, listOf(victim.leaf, victim.issuer)), "the victim itself")
            assertEquals(200, health(port, v1Key, listOf(v1)), "the v1 anchor as itself")
            // JSSE accepts the leaf the v1 anchor signed: the gate refuses it.
            assertEquals(403, health(port, forgedKey, listOf(forgedBy("attacker-v1", v1Key), v1)), "the attacker as the victim")
            // A v3 anchor without basicConstraints: refused at the handshake by this JDK
            // (jdk.security.allowNonCaAnchor=false), by the gate where the JDK lets it through.
            val viaP12 = health(port, forgedKey, listOf(forgedBy("attacker", p12Key)))
            assertTrue(viaP12 == 403 || viaP12 == HANDSHAKE_REFUSED, "got $viaP12")
        } finally {
            mocks.stopAll()
        }
    }
}
