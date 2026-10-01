package com.example.pinvault.server

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.RateLimiter
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.test.*

/**
 * CSR enrollment and renewal against the Config API routes: the client CA
 * issues over the device's key, the identity registry is the only thing a
 * renewal is checked against, and an expired or revoked identity is never
 * accepted.
 */
class ClientCertLifecycleTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certService: CertificateService
    private lateinit var certsDir: File
    private lateinit var identityStore: ClientIdentityStore
    private lateinit var clientCertStore: ClientCertStore
    private lateinit var tokenStore: EnrollmentTokenStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var audit: AuditLog
    private lateinit var signingService: ConfigSigningService
    private val scope = "test-tls"
    private var ttl: Duration = Duration.ofDays(90)
    private val ttlOverrides = mutableMapOf<String, Duration>()

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-lifecycle-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-lifecycle-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        auditStore = AuditLogStore(db)
        audit = AuditLog(auditStore, null)
        signingService = ConfigSigningService(File(certsDir, "signing.pem"))
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); certsDir.deleteRecursively() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csr(key: KeyPair, cn: String = "whatever-the-device-says"): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=$cn"), key.public)
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(key.private)
        return Base64.getEncoder().encodeToString(builder.build(signer).encoded)
    }

    private fun parseChain(body: String): List<X509Certificate> {
        val cf = CertificateFactory.getInstance("X.509")
        return Json.parseToJsonElement(body).jsonObject["chain"]!!.jsonArray.map {
            cf.generateCertificate(it.jsonPrimitive.content.byteInputStream()) as X509Certificate
        }
    }

    private fun ApplicationTestBuilder.configureApp(
        enrollmentMode: String = "token",
        presented: X509Certificate? = null,
        limiter: RateLimiter? = null,
        failures: AuthFailureRecorder? = null
    ) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        if (presented != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
            })
        }
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signingService, ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                enrollmentMode = enrollmentMode, audit = audit,
                clientIdentityStore = identityStore,
                clientCertTtl = { ttl },
                testTtlOverride = { ttlOverrides.remove(it) },
                renewLimiter = limiter, renewFailures = failures
            )
        }
    }

    private suspend fun ApplicationTestBuilder.enroll(key: KeyPair, clientId: String, withFeature: Boolean = true): HttpResponse {
        val token = tokenStore.create(clientId)
        return client.post("/api/v1/client-certs/enroll") {
            if (withFeature) header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token","deviceAlias":"Pixel","deviceUid":"uid-$clientId","csr":"${csr(key)}"}""")
        }
    }

    private suspend fun ApplicationTestBuilder.renew(key: KeyPair, clientId: String?): HttpResponse =
        client.post("/api/v1/client-certs/renew") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("csr", csr(key))
                if (clientId != null) put("clientId", clientId)
            }.toString())
        }

    private fun actions() = auditStore.page(100, 0).map { it.action }

    // ── enrollment ───────────────────────────────────────────────────────

    @Test
    fun `CSR enrollment issues a CA-signed chain over the device key and registers the identity`() = testApplication {
        configureApp()
        val key = deviceKey()
        val response = enroll(key, "dev-1")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals("pem-chain", response.headers["X-PinVault-Cert-Format"])
        assertEquals("no-store", response.headers["Cache-Control"])
        assertTrue(response.contentType()!!.match(ContentType.Application.Json))

        val body = response.bodyAsText()
        val chain = parseChain(body)
        assertEquals(2, chain.size)
        val leaf = chain[0]
        assertTrue(leaf.subjectX500Principal.name.contains("CN=PinVault Client: dev-1"), "subject from the client id, not the CSR: ${leaf.subjectX500Principal.name}")
        assertFalse(leaf.subjectX500Principal.name.contains("whatever-the-device-says"))
        assertEquals(key.public, leaf.publicKey)
        assertEquals(certService.clientCaCertificate(), chain[1])
        leaf.verify(chain[1].publicKey)
        assertEquals(-1, leaf.basicConstraints, "not a CA")
        assertTrue(leaf.extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2"), "clientAuth")
        val now = Instant.now()
        assertTrue(leaf.notBefore.toInstant().isBefore(now.minusSeconds(3500)), "notBefore backdated for clock skew")
        assertTrue(leaf.notAfter.toInstant().isAfter(now.plus(Duration.ofDays(89))))

        val identity = assertNotNull(identityStore.get("dev-1"))
        assertEquals(certService.spkiSha256(key.public), identity.spkiSha256)
        assertEquals(leaf.serialNumber.toString(16), identity.serial)
        assertEquals("uid-dev-1", identity.deviceUid)
        assertEquals(scope, identity.configApiId)

        val record = assertNotNull(clientCertStore.get("dev-1"))
        assertEquals("csr", record.keyType)
        assertEquals(identity.notAfter, record.notAfter)
        assertEquals(0, record.renewCount)

        // The truststore holds the CA only — no per-device entry was added.
        val ts = assertNotNull(certService.getTrustStore())
        assertNull(ts.getCertificate("dev-1"))
        assertNotNull(ts.getCertificate(CertificateService.CLIENT_CA_ALIAS))
        assertTrue(actions().contains("client_cert_issued"))
    }

    @Test
    fun `without the csr feature the same request gets a P12`() = testApplication {
        configureApp()
        val response = enroll(deviceKey(), "dev-p12", withFeature = false)
        assertEquals(HttpStatusCode.OK, response.status)
        assertNull(response.headers["X-PinVault-Cert-Format"])
        assertNotNull(response.headers["X-P12-SHA256"])
        assertNull(identityStore.get("dev-p12"))
        assertEquals("p12", assertNotNull(clientCertStore.get("dev-p12")).keyType)
    }

    @Test
    fun `a CSR whose signature does not verify is a 400`() = testApplication {
        configureApp()
        val token = tokenStore.create("dev-bad")
        val tampered = Base64.getDecoder().decode(csr(deviceKey())).also { it[it.size - 5] = (it[it.size - 5] + 1).toByte() }
        val response = client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "csr")
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token","csr":"${Base64.getEncoder().encodeToString(tampered)}"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.bodyAsText().contains("invalid_csr"))
        assertNull(identityStore.get("dev-bad"))

        // The refusal did not spend the token: the device can retry with it.
        val retry = client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "csr")
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token","csr":"${csr(deviceKey())}"}""")
        }
        assertEquals(HttpStatusCode.OK, retry.status, retry.bodyAsText())
        assertNotNull(identityStore.get("dev-bad"))
    }

    @Test
    fun `requests racing with one token get exactly one certificate`() {
        // Real sockets and threads: the test host would run the handlers one
        // after another and never interleave the token check with its use.
        val port = java.net.ServerSocket(0).use { it.localPort }
        val server = io.ktor.server.engine.embeddedServer(io.ktor.server.netty.Netty, port = port, host = "127.0.0.1") {
            install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
            routing {
                certificateConfigRoutes(
                    scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                    signingService, ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                    audit = audit, clientIdentityStore = identityStore, clientCertTtl = { ttl }
                )
            }
        }.start(wait = false)
        try {
            val token = tokenStore.create("dev-race")
            val bodies = (1..12).map { """{"token":"$token","csr":"${csr(deviceKey())}"}""" }
            val http = java.net.http.HttpClient.newHttpClient()
            val start = java.util.concurrent.CountDownLatch(1)
            val pool = java.util.concurrent.Executors.newFixedThreadPool(bodies.size)
            val statuses = try {
                bodies.map { body ->
                    pool.submit<Int> {
                        start.await()
                        val request = java.net.http.HttpRequest.newBuilder(java.net.URI("http://127.0.0.1:$port/api/v1/client-certs/enroll"))
                            .header("Content-Type", "application/json")
                            .header("X-PinVault-Features", "p12password,csr")
                            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build()
                        http.send(request, java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode()
                    }
                }.also { start.countDown() }.map { it.get(30, java.util.concurrent.TimeUnit.SECONDS) }
            } finally {
                pool.shutdownNow()
            }

            assertEquals(1, statuses.count { it == 200 }, "statuses: $statuses")
            assertEquals(statuses.size - 1, statuses.count { it == 401 }, "statuses: $statuses")
            assertEquals(1, actions().count { it == "client_cert_issued" })
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun `a revoked client id cannot enroll again and stays revoked`() = testApplication {
        configureApp()
        enroll(deviceKey(), "dev-rev")
        identityStore.revoke("dev-rev")
        clientCertStore.revoke("dev-rev")

        val response = enroll(deviceKey(), "dev-rev")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("revoked"))
        assertTrue(assertNotNull(identityStore.get("dev-rev")).revoked)
        assertTrue(assertNotNull(clientCertStore.get("dev-rev")).revoked)
        assertTrue(actions().contains("client_cert_enroll_refused"))
        // The token was not spent on a refusal.
        assertTrue(tokenStore.getAll().any { it.clientId == "dev-rev" && !it.used })
    }

    private suspend fun ApplicationTestBuilder.enrollAs(
        clientId: String,
        deviceUid: String?,
        token: String = tokenStore.create(clientId)
    ): HttpResponse = client.post("/api/v1/client-certs/enroll") {
        header("X-PinVault-Features", "p12password,csr")
        contentType(ContentType.Application.Json)
        setBody(buildJsonObject {
            put("token", token)
            if (deviceUid != null) put("deviceUid", deviceUid)
            put("csr", csr(deviceKey()))
        }.toString())
    }

    @Test
    fun `a device id belongs to one active identity`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, enrollAs("tablet-07", "android-1").status)

        // Another client id claiming the same device is refused, and keeps its token.
        val token = tokenStore.create("tablet-08")
        val refused = enrollAs("tablet-08", "android-1", token)
        assertEquals(HttpStatusCode.Conflict, refused.status)
        assertTrue(refused.bodyAsText().contains("device_already_enrolled"))
        assertNull(identityStore.get("tablet-08"))
        assertTrue(actions().contains("client_cert_enroll_refused"))

        // Once the old identity is revoked the same token goes through.
        clientCertStore.revoke("tablet-07")
        identityStore.revoke("tablet-07")
        assertEquals(HttpStatusCode.OK, enrollAs("tablet-08", "android-1", token).status)
        assertEquals("android-1", assertNotNull(clientCertStore.get("tablet-08")).deviceUid)
    }

    @Test
    fun `re-enrolling the same client id from the same device is allowed`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, enrollAs("tablet-07", "android-1").status)
        assertEquals(HttpStatusCode.OK, enrollAs("tablet-07", "android-1").status)
    }

    @Test
    fun `ids that could carry markup or extra name parts are refused`() = testApplication {
        configureApp(enrollmentMode = "open")
        val openMode = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"deviceId":"<img src=x onerror=alert(1)>"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, openMode.status)
        assertTrue(openMode.bodyAsText().contains("invalid_client_id"))

        val token = tokenStore.create("tablet-09")
        val badUid = enrollAs("tablet-09", "a,b=c", token)
        assertEquals(HttpStatusCode.BadRequest, badUid.status)
        assertTrue(badUid.bodyAsText().contains("invalid_device_uid"))
        assertTrue(tokenStore.getAll().any { it.clientId == "tablet-09" && !it.used }, "the token was not spent")

        // A token minted before ids were checked, for an id that would break the subject.
        assertEquals(HttpStatusCode.BadRequest, enrollAs("x, O=Evil", null, tokenStore.create("x, O=Evil")).status)
    }

    @Test
    fun `a client id cannot add name parts to the certificate subject`() {
        val parsed = certService.parseCsr(Base64.getDecoder().decode(csr(deviceKey())))
        val issued = certService.issueClientCertificate("x, O=Evil", parsed, Duration.ofDays(1))
        val subject = X500Name.getInstance(issued.leaf.subjectX500Principal.encoded)
        val organisations = subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.O)
        assertEquals(1, organisations.size)
        assertEquals("PinVault Client", organisations.single().first.value.toString())
        assertEquals("PinVault Client: x, O=Evil",
            subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN).single().first.value.toString())
    }

    // ── renewal over mTLS (certificate presented) ────────────────────────

    @Test
    fun `renewal with the presented certificate issues a new serial and counts`() = testApplication {
        val key = deviceKey()
        var leaf: X509Certificate? = null
        testApplication {
            configureApp()
            leaf = parseChain(enroll(key, "dev-2").bodyAsText())[0]
        }
        configureApp(presented = leaf)
        val response = renew(key, clientId = null)
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("mtls", json["via"]!!.jsonPrimitive.content)
        assertEquals(1, json["renewCount"]!!.jsonPrimitive.int)
        val renewed = parseChain(response.bodyAsText())[0]
        assertNotEquals(leaf!!.serialNumber, renewed.serialNumber)
        assertEquals(key.public, renewed.publicKey)

        val identity = assertNotNull(identityStore.get("dev-2"))
        assertEquals(renewed.serialNumber.toString(16), identity.serial)
        assertEquals(1, identity.renewCount)
        assertEquals(certService.spkiSha256(key.public), identity.spkiSha256)
        assertTrue(actions().contains("client_cert_renewed"))
    }

    @Test
    fun `presented certificate and CSR must carry the same key`() = testApplication {
        val key = deviceKey()
        var leaf: X509Certificate? = null
        testApplication { configureApp(); leaf = parseChain(enroll(key, "dev-3").bodyAsText())[0] }
        configureApp(presented = leaf)
        val response = renew(deviceKey(), clientId = null)
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals("reenroll_required", Json.parseToJsonElement(response.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        assertEquals(0, assertNotNull(identityStore.get("dev-3")).renewCount)
    }

    @Test
    fun `an expired presented certificate is refused even with the right key`() = testApplication {
        val key = deviceKey()
        ttlOverrides["dev-exp"] = Duration.ofSeconds(1)
        var leaf: X509Certificate? = null
        testApplication { configureApp(); leaf = parseChain(enroll(key, "dev-exp").bodyAsText())[0] }
        Thread.sleep(1500)
        assertFails { leaf!!.checkValidity() }

        configureApp(presented = leaf)
        val response = renew(key, clientId = null)
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertEquals(0, assertNotNull(identityStore.get("dev-exp")).renewCount)
    }

    // ── renewal over recovery (no certificate) ───────────────────────────

    @Test
    fun `recovery renewal accepts a CSR signed by the registered key`() = testApplication {
        val key = deviceKey()
        testApplication { configureApp(); enroll(key, "dev-4") }
        configureApp()
        val response = renew(key, clientId = "dev-4")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals("recovery", Json.parseToJsonElement(response.bodyAsText()).jsonObject["via"]!!.jsonPrimitive.content)
        assertEquals(1, assertNotNull(identityStore.get("dev-4")).renewCount)
    }

    @Test
    fun `recovery renewal refuses a foreign key, a revoked or unknown identity, and needs a client id`() = testApplication {
        val key = deviceKey()
        testApplication { configureApp(); enroll(key, "dev-5"); enroll(deviceKey(), "dev-6") }
        identityStore.revoke("dev-6")
        val failures = AuthFailureRecorder(audit, action = "client_cert_auth_failed", what = "Client certificate renewal refused")
        configureApp(failures = failures)

        fun assertRefused(response: HttpResponse) = kotlinx.coroutines.runBlocking {
            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertEquals("reenroll_required", Json.parseToJsonElement(response.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        }
        assertRefused(renew(deviceKey(), clientId = "dev-5"))   // wrong key
        assertRefused(renew(key, clientId = "dev-6"))           // (any) revoked
        assertRefused(renew(key, clientId = "nobody"))          // unknown
        assertEquals(HttpStatusCode.BadRequest, renew(key, clientId = null).status)
        assertEquals(HttpStatusCode.BadRequest, client.post("/api/v1/client-certs/renew") {
            contentType(ContentType.Application.Json); setBody("""{"clientId":"dev-5"}""")
        }.status)

        assertEquals(0, assertNotNull(identityStore.get("dev-5")).renewCount)
        val entries = auditStore.page(100, 0).filter { it.action == "client_cert_auth_failed" }
        assertTrue(entries.isNotEmpty(), actions().toString())
        assertEquals("dev-5", entries.last().actor)
    }

    @Test
    fun `renewal attempts are rate limited per source and client id`() = testApplication {
        val key = deviceKey()
        testApplication { configureApp(); enroll(key, "dev-7") }
        configureApp(limiter = RateLimiter(maxAttempts = 2, windowMs = 60_000))
        assertEquals(HttpStatusCode.OK, renew(key, "dev-7").status)
        assertEquals(HttpStatusCode.OK, renew(key, "dev-7").status)
        val third = renew(key, "dev-7")
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertEquals("rate_limited", Json.parseToJsonElement(third.bodyAsText()).jsonObject["error"]!!.jsonPrimitive.content)
        assertEquals(2, assertNotNull(identityStore.get("dev-7")).renewCount)
    }

    @Test
    fun `the test hook lifetime applies once`() = testApplication {
        configureApp()
        ttlOverrides["dev-ttl"] = Duration.ofSeconds(120)
        val short = parseChain(enroll(deviceKey(), "dev-ttl").bodyAsText())[0]
        assertTrue(short.notAfter.toInstant().isBefore(Instant.now().plusSeconds(130)))
        val normal = parseChain(enroll(deviceKey(), "dev-ttl-2").bodyAsText())[0]
        assertTrue(normal.notAfter.toInstant().isAfter(Instant.now().plus(Duration.ofDays(89))))
    }

    @Test
    fun `ensureClientCa is idempotent and keeps the CA in the truststore`() {
        val first = certService.ensureClientCa()
        certService.removeFromTrustStore(CertificateService.CLIENT_CA_ALIAS)
        val second = certService.ensureClientCa()
        assertEquals(first, second)
        assertEquals(first, certService.getTrustStore()!!.getCertificate(CertificateService.CLIENT_CA_ALIAS))
        assertTrue(first.basicConstraints >= 0, "CA bit")
    }
}
