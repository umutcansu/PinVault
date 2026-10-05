package com.example.pinvault.server

import com.example.pinvault.server.plugin.DeviceRefusalLimit
import com.example.pinvault.server.route.PolicyEnrollment
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.RateLimiter
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
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X962Parameters
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.util.Base64
import kotlin.test.*

/**
 * What a CSR costs before the caller is known (O3): the key is checked for
 * type and size before any signature work, the identity or request a CSR is
 * for is looked up before its signature is verified, refusals are counted per
 * source address whatever client id the caller names, and nothing a caller
 * can send turns into a 500.
 */
class CsrAbuseTest {

    private val scope = "csr-api"
    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private lateinit var identityStore: ClientIdentityStore
    private lateinit var clientCertStore: ClientCertStore
    private lateinit var tokenStore: EnrollmentTokenStore
    private lateinit var policyStore: EnrollmentPolicyStore
    private lateinit var audit: AuditLog

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-csr-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-csr-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        policyStore = EnrollmentPolicyStore(db)
        audit = AuditLog(AuditLogStore(db), null)
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); certsDir.deleteRecursively() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun ecKey(curve: String = "secp256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    private fun csrDer(key: KeyPair, algorithm: String = "SHA256withECDSA"): ByteArray =
        JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
            .build(JcaContentSignerBuilder(algorithm).build(key.private)).encoded

    private fun csr(key: KeyPair): String = Base64.getEncoder().encodeToString(csrDer(key))

    /** A PKCS#10 request over [spki] with a signature that is just bytes: nobody holds a key for it. */
    private fun craftedCsr(spki: SubjectPublicKeyInfo): ByteArray = CertificationRequest(
        CertificationRequestInfo(X500Name("CN=device"), spki, DERSet()),
        AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE),
        DERBitString(ByteArray(256) { 7 })
    ).encoded

    /** An RSA "key" of [bits] bits made of random numbers: no key generation, no private key. */
    private fun rsaSpki(bits: Int, exponent: BigInteger = BigInteger.valueOf(65537)): SubjectPublicKeyInfo =
        SubjectPublicKeyInfo(
            AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            org.bouncycastle.asn1.pkcs.RSAPublicKey(BigInteger(bits, SecureRandom()).setBit(bits - 1).setBit(0), exponent)
        )

    /** Set by a test that watches the truststore hook of P12 enrollments. */
    private var onEnrolled: (() -> Unit)? = null

    private fun Route.mountRoutes(renewLimiter: RateLimiter? = null) {
        certificateConfigRoutes(
            scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
            ConfigSigningService(File(certsDir, "signing.pem")), ClientDeviceStore(db), certService, tokenStore, clientCertStore,
            onClientCertEnrolled = onEnrolled,
            audit = audit, clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) },
            renewLimiter = renewLimiter,
            policyEnrollment = PolicyEnrollment(scope, policyStore, certService, identityStore, clientCertStore, audit, null,
                ttlFor = { Duration.ofDays(90) })
        )
        enrollmentPolicyRoutes(policyStore, clientCertStore, audit, Duration.ofHours(24), 50)
    }

    private fun ApplicationTestBuilder.configureApp(renewLimiter: RateLimiter? = null, refusalLimiter: RateLimiter? = null) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        if (refusalLimiter != null) install(DeviceRefusalLimit) { limiter = refusalLimiter }
        routing { mountRoutes(renewLimiter) }
    }

    private suspend fun ApplicationTestBuilder.enroll(body: String): HttpResponse = client.post("/api/v1/client-certs/enroll") {
        header("X-PinVault-Features", "p12password,csr")
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun ApplicationTestBuilder.enrolled(clientId: String, key: KeyPair) {
        val response = enroll("""{"token":"${tokenStore.create(clientId)}","csr":"${csr(key)}"}""")
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
    }

    private suspend fun ApplicationTestBuilder.renew(clientId: String, csrBase64: String): HttpResponse =
        client.post("/api/v1/client-certs/renew") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("clientId", clientId); put("csr", csrBase64) }.toString())
        }

    private suspend fun HttpResponse.error(): String? =
        (Json.parseToJsonElement(bodyAsText()).jsonObject["error"] as? JsonPrimitive)?.content

    // ── the key is checked before the signature ──────────────────────────

    @Test
    fun `an RSA key outside 2048 to 4096 bits or with another exponent is refused without touching the verifier`() {
        val refused = mapOf(
            "1024 bits" to rsaSpki(1024),
            "4097 bits" to rsaSpki(4097),
            "8192 bits" to rsaSpki(8192),
            "16000 bits" to rsaSpki(16000),
            "exponent 3" to rsaSpki(2048, BigInteger.valueOf(3)),
            "exponent 65539" to rsaSpki(2048, BigInteger.valueOf(65539)),
            "an exponent as long as the modulus" to rsaSpki(4096, BigInteger(4095, SecureRandom()).setBit(0))
        )
        for ((what, spki) in refused) {
            val der = craftedCsr(spki)
            assertTrue(der.size <= CertificateService.MAX_CSR_BYTES, "$what must not be refused for its size alone")
            assertFailsWith<IllegalArgumentException>(what) { certService.parseCsr(der) }
        }
        assertEquals(0, certService.csrSignatureChecks, "no signature was verified for a key that is refused anyway")

        // A real key of the right shape reaches the verifier — and its made-up signature fails there.
        val real = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(craftedCsr(SubjectPublicKeyInfo.getInstance(real.encoded))) }
        assertEquals(1, certService.csrSignatureChecks)
    }

    @Test
    fun `only P-256 and P-384 named curves are accepted for EC`() {
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(csrDer(ecKey("secp521r1"), "SHA512withECDSA")) }
        // A curve the JDK no longer has: key and signature from Bouncy Castle.
        val k1 = KeyPairGenerator.getInstance("EC", "BC").apply { initialize(ECGenParameterSpec("secp256k1")) }.generateKeyPair()
        val k1Csr = JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), k1.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(k1.private)).encoded
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(k1Csr) }
        // The same P-256 point, its curve spelled out as explicit parameters instead of named.
        val named = SubjectPublicKeyInfo.getInstance(ecKey().public.encoded)
        val explicit = SubjectPublicKeyInfo(
            AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, X962Parameters(org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("P-256"))),
            named.publicKeyData.bytes
        )
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(craftedCsr(explicit)) }
        // Another algorithm altogether.
        val ed25519 = SubjectPublicKeyInfo.getInstance(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded)
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(craftedCsr(ed25519)) }
        assertEquals(0, certService.csrSignatureChecks)

        val p256 = ecKey()
        assertEquals(certService.spkiSha256(p256.public), certService.parseCsr(csrDer(p256)).spkiSha256)
        val p384 = ecKey("secp384r1")
        assertEquals(certService.spkiSha256(p384.public), certService.parseCsr(csrDer(p384, "SHA384withECDSA")).spkiSha256)
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertEquals(certService.spkiSha256(rsa.public), certService.parseCsr(csrDer(rsa, "SHA256withRSA")).spkiSha256)
        assertEquals(3, certService.csrSignatureChecks)
    }

    @Test
    fun `an over-long request is refused before it is decoded or parsed`() {
        assertFailsWith<IllegalArgumentException> { certService.parseCsr(ByteArray(CertificateService.MAX_CSR_BYTES + 1)) }
        assertFailsWith<IllegalArgumentException> { certService.parseCsr("A".repeat(CertificateService.MAX_CSR_BYTES * 2)) }
        assertFailsWith<IllegalArgumentException> { certService.parseCsr("not base64 !!") }
        assertEquals(0, certService.csrSignatureChecks)
    }

    @Test
    fun `whatever bytes arrive, parsing ends in a result or an IllegalArgumentException`() {
        val valid = csrDer(ecKey())
        val random = java.util.Random(20261005)
        repeat(400) { round ->
            val mutated = valid.copyOf(if (round % 4 == 0) 1 + random.nextInt(valid.size) else valid.size)
            repeat(1 + random.nextInt(3)) { mutated[random.nextInt(mutated.size)] = random.nextInt(256).toByte() }
            try {
                certService.parseCsr(mutated)
            } catch (_: IllegalArgumentException) {
                // the only refusal the routes turn into a 400
            }
        }
    }

    // ── enrollment ───────────────────────────────────────────────────────

    @Test
    fun `enrollment with an oversized key is a 400 that costs no signature check and no token`() = testApplication {
        configureApp()
        val token = tokenStore.create("dev-big")
        val oversized = Base64.getEncoder().encodeToString(craftedCsr(rsaSpki(16000)))
        val response = enroll("""{"token":"$token","csr":"$oversized"}""")
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("invalid_csr", response.error())
        assertEquals(0, certService.csrSignatureChecks)
        assertNull(identityStore.get("dev-big"))
        assertTrue(tokenStore.getAll().any { it.clientId == "dev-big" && !it.used }, "the token was not spent")
    }

    @Test
    fun `bodies of the wrong shape are a 400 or a 401, never a 500`() = testApplication {
        configureApp()
        val token = tokenStore.create("dev-shape")
        val bodies = listOf(
            """{"token":{"a":1},"csr":["x"]}""",
            """{"token":["$token"]}""",
            """{"requestId":{"x":1},"csr":{}}""",
            """{"requestId":"r","csr":{"nested":true}}""",
            """{"token":"$token","csr":"@@@@"}""",
            """[1,2,3]""",
            """"just a string"""",
            """{"deviceId":{"x":1}}"""
        )
        for (body in bodies) {
            val status = enroll(body).status.value
            assertTrue(status in setOf(400, 401, 404), "$body → $status")
        }
        for (body in listOf("""{"clientId":{"x":1},"csr":"AAAA"}""", """{"clientId":"dev","csr":{"x":1}}""", """{"clientId":"dev","csr":"@@@@"}""", "[]")) {
            val response = client.post("/api/v1/client-certs/renew") { contentType(ContentType.Application.Json); setBody(body) }
            assertEquals(HttpStatusCode.BadRequest, response.status, body)
        }
        assertEquals(0, certService.csrSignatureChecks)
    }

    @Test
    fun `an address that keeps being refused at enrollment is cut off before its CSR is parsed`() = testApplication {
        configureApp(refusalLimiter = RateLimiter(maxAttempts = 3, windowMs = 60_000))
        val statuses = (1..5).map { enroll("""{"token":"guess-$it","csr":"${csr(ecKey())}"}""").status }
        assertEquals(List(3) { HttpStatusCode.Unauthorized } + List(2) { HttpStatusCode.TooManyRequests }, statuses)
        // Whatever it sends now — a real token, a pickup — is not looked at.
        val real = enroll("""{"token":"${tokenStore.create("dev-late")}","csr":"${csr(ecKey())}"}""")
        assertEquals(HttpStatusCode.TooManyRequests, real.status)
        assertEquals("rate_limited", real.error())
        assertEquals(HttpStatusCode.TooManyRequests, enroll("""{"requestId":"r-1","csr":"${csr(ecKey())}"}""").status)
        assertEquals(0, certService.csrSignatureChecks)
    }

    @Test
    fun `P12 enrollments come from the client CA and restart no listener`() = testApplication {
        var now = 0L
        val due = mutableListOf<() -> Unit>()
        val restarts = mutableListOf<String>()
        val coalesced = com.example.pinvault.server.service.CoalescedRestart(
            minIntervalMs = 5_000, clock = { now }, schedule = { _, task -> due += task }, restart = { restarts += it }
        )
        // As Main wires it: the enrollment route asks, the coalescer decides when.
        onEnrolled = { coalesced.request("new truststore") }
        configureApp()
        val trustedBefore = certService.getTrustStore()!!.aliases().toList().sorted()
        repeat(6) {
            // No CSR: a server-made P12. It used to be a self-signed anchor added to the
            // truststore, and every one restarted the mTLS listeners.
            val response = client.post("/api/v1/client-certs/enroll") {
                header("X-PinVault-Features", "p12password")
                contentType(ContentType.Application.Json)
                setBody("""{"token":"${tokenStore.create("p12-dev-$it")}"}""")
            }
            assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        }
        assertEquals(trustedBefore, certService.getTrustStore()!!.aliases().toList().sorted(), "the truststore is untouched")
        assertTrue(restarts.isEmpty(), "nothing to restart for")
        assertTrue(due.isEmpty())

        // A CSR enrollment changes no truststore either.
        enrolled("csr-dev", ecKey())
        assertTrue(restarts.isEmpty())
        assertTrue(due.isEmpty())
    }

    // ── renewal ──────────────────────────────────────────────────────────

    @Test
    fun `renewal verifies a signature only for the registered key of an identity that may renew`() = testApplication {
        configureApp()
        val key = ecKey()
        enrolled("dev-1", key)
        enrolled("dev-revoked", ecKey())
        identityStore.revoke("dev-revoked")
        val before = certService.csrSignatureChecks

        assertEquals(HttpStatusCode.Forbidden, renew("nobody", csr(ecKey())).status)
        assertEquals(HttpStatusCode.Forbidden, renew("dev-revoked", csr(ecKey())).status)
        assertEquals(HttpStatusCode.Forbidden, renew("dev-1", csr(ecKey())).status, "another key")
        assertEquals(HttpStatusCode.Forbidden, renew("<script>", csr(ecKey())).status)
        assertEquals(HttpStatusCode.Forbidden, renew("x".repeat(5_000), csr(ecKey())).status)
        assertEquals(before, certService.csrSignatureChecks, "none of these reached the verifier")

        // A malformed CSR is the same 400 for an id that exists and one that does not.
        val oversized = Base64.getEncoder().encodeToString(craftedCsr(rsaSpki(16000)))
        for (id in listOf("dev-1", "nobody")) {
            val response = renew(id, oversized)
            assertEquals(HttpStatusCode.BadRequest, response.status, id)
            assertEquals("invalid_csr", response.error())
        }
        assertEquals(before, certService.csrSignatureChecks)

        // The registered key with a broken signature: verified (once), refused.
        val tampered = csrDer(key).also { it[it.size - 5] = (it[it.size - 5] + 1).toByte() }
        assertEquals(HttpStatusCode.BadRequest, renew("dev-1", Base64.getEncoder().encodeToString(tampered)).status)
        assertEquals(before + 1, certService.csrSignatureChecks)
        assertEquals(HttpStatusCode.OK, renew("dev-1", csr(key)).status)
        assertEquals(1, identityStore.get("dev-1")!!.renewCount)
    }

    @Test
    fun `rotating the client id does not escape the renewal limiter`() = testApplication {
        configureApp(renewLimiter = RateLimiter(maxAttempts = 3, windowMs = 60_000))
        val key = ecKey()
        enrolled("dev-1", key)

        val statuses = (1..6).map { renew("made-up-$it", csr(ecKey())).status }
        assertEquals(List(3) { HttpStatusCode.Forbidden } + List(3) { HttpStatusCode.TooManyRequests }, statuses)
        // The address is cut off before the body is read: a real identity's renewal waits too.
        val real = renew("dev-1", csr(key))
        assertEquals(HttpStatusCode.TooManyRequests, real.status)
        assertEquals("rate_limited", real.error())
        assertEquals(0, identityStore.get("dev-1")!!.renewCount)
    }

    @Test
    fun `renewals that succeed are counted per identity, not against the shared address`() = testApplication {
        configureApp(renewLimiter = RateLimiter(maxAttempts = 2, windowMs = 60_000))
        val keys = (1..4).associate { "dev-$it" to ecKey() }
        keys.forEach { (id, key) -> enrolled(id, key) }
        // Four devices behind one address renew: more than the quota of refusals, none refused.
        keys.forEach { (id, key) -> assertEquals(HttpStatusCode.OK, renew(id, csr(key)).status, id) }
        // One identity renewing in a loop is stopped; the others are not.
        assertEquals(HttpStatusCode.OK, renew("dev-1", csr(keys.getValue("dev-1"))).status)
        assertEquals(HttpStatusCode.TooManyRequests, renew("dev-1", csr(keys.getValue("dev-1"))).status)
        assertEquals(HttpStatusCode.OK, renew("dev-2", csr(keys.getValue("dev-2"))).status)
        assertEquals(2, identityStore.get("dev-1")!!.renewCount)
    }

    // ── policy pickup ────────────────────────────────────────────────────

    private suspend fun ApplicationTestBuilder.pendingRequest(key: KeyPair): String {
        val created = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json)
            setBody("""{"name":"field","maxDevices":5,"validDays":7,"requireApproval":true}""")
        }
        assertEquals(HttpStatusCode.OK, created.status, created.bodyAsText())
        val code = Json.parseToJsonElement(created.bodyAsText()).jsonObject["code"]!!.jsonPrimitive.content
        val waiting = enroll("""{"token":"$code","csr":"${csr(key)}"}""")
        assertEquals(HttpStatusCode.Accepted, waiting.status, waiting.bodyAsText())
        return Json.parseToJsonElement(waiting.bodyAsText()).jsonObject["requestId"]!!.jsonPrimitive.content
    }

    @Test
    fun `a pickup with an unknown request id does not parse the CSR`() = testApplication {
        configureApp()
        val before = certService.csrSignatureChecks
        // A valid CSR, a CSR that is not one, an oversized key: the id is unknown, nothing else is looked at.
        val oversized = Base64.getEncoder().encodeToString(craftedCsr(rsaSpki(16000)))
        for (csrField in listOf(csr(ecKey()), "@@@@ not a CSR", oversized)) {
            val response = enroll(buildJsonObject { put("requestId", "no-such-request"); put("csr", csrField) }.toString())
            assertEquals(HttpStatusCode.NotFound, response.status)
            assertEquals("enrollment_request_not_found", response.error())
        }
        assertEquals(before, certService.csrSignatureChecks)
    }

    @Test
    fun `a pickup with another key is refused without verifying its signature`() = testApplication {
        configureApp()
        val key = ecKey()
        val requestId = pendingRequest(key)
        val before = certService.csrSignatureChecks

        val other = enroll(buildJsonObject { put("requestId", requestId); put("csr", csr(ecKey())) }.toString())
        assertEquals(HttpStatusCode.Forbidden, other.status)
        assertEquals("enrollment_request_mismatch", other.error())
        assertEquals(before, certService.csrSignatureChecks)

        // The request's own key is verified and told to keep waiting.
        val own = enroll(buildJsonObject { put("requestId", requestId); put("csr", csr(key)) }.toString())
        assertEquals(HttpStatusCode.Accepted, own.status)
        assertEquals(before + 1, certService.csrSignatureChecks)
    }
}
