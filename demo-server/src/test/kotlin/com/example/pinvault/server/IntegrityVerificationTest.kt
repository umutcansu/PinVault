package com.example.pinvault.server

import com.example.pinvault.server.route.PolicyEnrollment
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.CommandIntegrityVerifier
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.EnrollmentIntegrity
import com.example.pinvault.server.service.IntegrityRequestHash
import com.example.pinvault.server.service.IntegrityVerdict
import com.example.pinvault.server.service.IntegrityVerificationMode
import com.example.pinvault.server.service.IntegrityVerifier
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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.util.Base64
import kotlin.test.*

/**
 * INTEGRITY_VERIFICATION on the CSR enrollment paths (one-time token,
 * enrollment code): the request's integrity token is verified against a
 * request hash the server recomputes from the request's own CSR and device
 * id, BEFORE a token or a policy slot is spent.
 *
 * The fake verifier plays Google: a token "verdict:<hash>:<ok|rooted>" is
 * one Google issued for that request hash, with that device verdict.
 */
class IntegrityVerificationTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private lateinit var identityStore: ClientIdentityStore
    private lateinit var clientCertStore: ClientCertStore
    private lateinit var tokenStore: EnrollmentTokenStore
    private lateinit var policyStore: EnrollmentPolicyStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var audit: AuditLog
    private val scope = "int-tls"

    private var mode = IntegrityVerificationMode.ENFORCE
    private val verified = mutableListOf<String>()

    private val fakeGoogle = IntegrityVerifier { token, requestHash, _ ->
        verified += requestHash
        val parts = token.split(':')
        when {
            parts.size != 3 || parts[0] != "verdict" -> IntegrityVerdict(false, "token_malformed")
            parts[1] != requestHash -> IntegrityVerdict(false, "request_hash_mismatch")
            parts[2] != "ok" -> IntegrityVerdict(false, "device_integrity")
            else -> IntegrityVerdict(true, summary = "MEETS_DEVICE_INTEGRITY")
        }
    }

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-integrity-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-integrity-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        policyStore = EnrollmentPolicyStore(db)
        auditStore = AuditLogStore(db)
        audit = AuditLog(auditStore, null)
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); certsDir.deleteRecursively() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.configureApp(verifier: IntegrityVerifier? = fakeGoogle) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        val integrity = EnrollmentIntegrity({ mode }, verifier)
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(certsDir, "signing.pem")), ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                enrollmentMode = "token", audit = audit, clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) },
                policyEnrollment = PolicyEnrollment(
                    scope, policyStore, certService, identityStore, clientCertStore, audit,
                    AuthFailureRecorder(audit, action = "client_cert_enroll_refused", what = "Enrollment with an enrollment code refused"),
                    ttlFor = { Duration.ofDays(90) }, integrity = integrity
                ),
                enrollmentIntegrity = integrity
            )
            enrollmentPolicyRoutes(policyStore, clientCertStore, audit, Duration.ofHours(24), 50)
        }
    }

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csrDer(key: KeyPair): ByteArray =
        JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded

    /** What a device with [verdict] gets from Google for this CSR and device id. */
    private fun tokenFor(csr: ByteArray, deviceId: String?, verdict: String = "ok") =
        "verdict:${IntegrityRequestHash.of(deviceId, csr)}:$verdict"

    private fun body(csr: ByteArray?, token: String? = null, deviceUid: String? = null, integrityToken: String? = null) = buildJsonObject {
        token?.let { put("token", it) }
        deviceUid?.let { put("deviceUid", it) }
        put("deviceAlias", "Pixel")
        csr?.let { put("csr", Base64.getEncoder().encodeToString(it)) }
        integrityToken?.let { put("integrityToken", it) }
    }.toString()

    private suspend fun ApplicationTestBuilder.enroll(json: String, csr: Boolean = true): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", if (csr) "p12password,csr" else "p12password")
            contentType(ContentType.Application.Json)
            setBody(json)
        }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject
    private suspend fun HttpResponse.error(): String? = json()["error"]?.jsonPrimitive?.content
    private suspend fun HttpResponse.reason(): String? = json()["reason"]?.jsonPrimitive?.content

    private suspend fun ApplicationTestBuilder.createPolicy(approval: Boolean): Pair<String, String> {
        val response = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json)
            setBody("""{"name":"field","maxDevices":5,"validDays":7,"requireApproval":$approval}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val json = response.json()
        return json["policy"]!!.jsonObject["id"]!!.jsonPrimitive.content to json["code"]!!.jsonPrimitive.content
    }

    // ── the request hash ─────────────────────────────────────────────────

    @Test
    fun `the request hash matches the library's test vectors`() {
        val csr = ByteArray(10) { it.toByte() }
        assertEquals("rFm1yo7zjKdHsevPadQ1stM-oQ8aG4umNk-CIGhG0ds", IntegrityRequestHash.of("a1b2c3d4e5f60718", csr))
        assertEquals("rYKab7GF91mo9M4VRpmjjOj4gPuKNrCVklCusNHMdno", IntegrityRequestHash.of(null, csr))
    }

    // ── one-time token ───────────────────────────────────────────────────

    @Test
    fun `enforce refuses a missing or failing verdict before the token is spent`() = testApplication {
        configureApp()
        val csr = csrDer(deviceKey())
        val token = tokenStore.create("dev-1")

        val missing = enroll(body(csr, token, deviceUid = "uid-1"))
        assertEquals(HttpStatusCode.Forbidden, missing.status)
        assertEquals("integrity_required", missing.error())

        val rooted = enroll(body(csr, token, deviceUid = "uid-1", integrityToken = tokenFor(csr, "uid-1", "rooted")))
        assertEquals(HttpStatusCode.Forbidden, rooted.status)
        assertEquals("integrity_invalid", rooted.error())
        assertEquals("device_integrity", rooted.reason())

        assertNull(identityStore.get("dev-1"))
        assertEquals("dev-1", tokenStore.validate(token), "the token is still good")

        val ok = enroll(body(csr, token, deviceUid = "uid-1", integrityToken = tokenFor(csr, "uid-1")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertNotNull(identityStore.get("dev-1"))
        assertTrue(auditStore.page(50, 0).any { it.action == "client_cert_issued" && it.summary.contains("integrity passed (MEETS_DEVICE_INTEGRITY)") })
    }

    @Test
    fun `a token made for another CSR or another device id does not pass`() = testApplication {
        configureApp()
        val token = tokenStore.create("dev-2")
        val stolen = csrDer(deviceKey())
        val mine = csrDer(deviceKey())
        // A good verdict from a real phone, replayed with another key.
        val replayed = enroll(body(mine, token, deviceUid = "uid-2", integrityToken = tokenFor(stolen, "uid-2")))
        assertEquals("request_hash_mismatch", replayed.reason())
        // ... or for another device id.
        val otherDevice = enroll(body(mine, token, deviceUid = "uid-2", integrityToken = tokenFor(mine, "uid-9")))
        assertEquals("request_hash_mismatch", otherDevice.reason())
        // The server recomputed the hash from the body, not from anything the device claimed.
        assertEquals(IntegrityRequestHash.of("uid-2", mine), verified.last())
    }

    @Test
    fun `enforce issues no server-made key`() = testApplication {
        configureApp()
        val refused = enroll(body(csr = null, token = tokenStore.create("dev-p12"), deviceUid = "uid-p12"), csr = false)
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("csr_required", refused.error())
    }

    @Test
    fun `warn enrolls either way and notes the verdict`() = testApplication {
        mode = IntegrityVerificationMode.WARN
        configureApp()
        val csr = csrDer(deviceKey())
        val ok = enroll(body(csr, tokenStore.create("dev-w"), deviceUid = "uid-w", integrityToken = tokenFor(csr, "uid-w", "rooted")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertTrue(auditStore.page(50, 0).any { it.summary.contains("integrity not verified: device_integrity") })

        val csr2 = csrDer(deviceKey())
        assertEquals(HttpStatusCode.OK, enroll(body(csr2, tokenStore.create("dev-w2"), deviceUid = "uid-w2")).status)
        assertTrue(auditStore.page(50, 0).any { it.summary.contains("integrity not verified: token_missing") })
    }

    @Test
    fun `off never reads the token`() = testApplication {
        mode = IntegrityVerificationMode.OFF
        configureApp()
        val csr = csrDer(deviceKey())
        assertEquals(HttpStatusCode.OK, enroll(body(csr, tokenStore.create("dev-off"), deviceUid = "uid-off", integrityToken = "garbage")).status)
        assertTrue(verified.isEmpty())
    }

    @Test
    fun `a verifier that throws is a failed verdict, never a pass`() = testApplication {
        configureApp(verifier = IntegrityVerifier { _, _, _ -> error("Google unreachable") })
        val csr = csrDer(deviceKey())
        val refused = enroll(body(csr, tokenStore.create("dev-e"), deviceUid = "uid-e", integrityToken = tokenFor(csr, "uid-e")))
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("verifier_error", refused.reason())
    }

    // ── enrollment codes ─────────────────────────────────────────────────

    @Test
    fun `an enrollment code takes no slot and records no request without a passing verdict`() = testApplication {
        configureApp()
        val (directPolicy, directCode) = createPolicy(approval = false)
        val (approvalPolicy, approvalCode) = createPolicy(approval = true)
        val csr = csrDer(deviceKey())

        assertEquals("integrity_required", enroll(body(csr, directCode, deviceUid = "uid-c")).error())
        assertEquals("integrity_invalid", enroll(body(csr, approvalCode, deviceUid = "uid-c",
            integrityToken = tokenFor(csr, "uid-c", "rooted"))).error())
        assertTrue(policyStore.requests().isEmpty(), "nothing recorded")
        assertEquals(0, policyStore.get(directPolicy)!!.usedCount, "no slot taken")
        assertEquals(0, policyStore.get(approvalPolicy)!!.usedCount)

        val ok = enroll(body(csr, directCode, deviceUid = "uid-c", integrityToken = tokenFor(csr, "uid-c")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertEquals(1, policyStore.get(directPolicy)!!.usedCount)
        assertTrue(auditStore.page(50, 0).any { it.action == "client_cert_issued" && it.summary.contains("integrity passed") })
    }

    // ── start-up and the command verifier ────────────────────────────────

    @Test
    fun `enforce without a verifier does not start, warn warns`() {
        assertFailsWith<IllegalStateException> { IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.ENFORCE, null) }
        assertNotNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.WARN, null))
        assertNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.OFF, null))
        assertNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.ENFORCE, fakeGoogle))
        assertEquals(IntegrityVerificationMode.OFF, IntegrityVerificationMode.parse(null))
        assertFailsWith<IllegalArgumentException> { IntegrityVerificationMode.parse("strict") }
    }

    @Test
    fun `the command verifier gets the request on stdin and its JSON answer decides`() {
        // Passes only when stdin carries this request hash.
        val passing = CommandIntegrityVerifier(
            """grep -q '"requestHash":"h-123"' && echo '{"passed":true,"summary":"MEETS_DEVICE_INTEGRITY"}' || echo '{"passed":false,"reason":"request_hash_mismatch"}'"""
        )
        assertEquals(IntegrityVerdict(true, null, "MEETS_DEVICE_INTEGRITY"), passing.verify("tok", "h-123", "uid"))
        assertEquals(IntegrityVerdict(false, "request_hash_mismatch", null), passing.verify("tok", "h-999", "uid"))

        // A failure without a reason still fails, with a generic one.
        assertEquals("verdict_failed", CommandIntegrityVerifier("""cat >/dev/null; echo '{"passed":false}'""").verify("t", "h", null).reason)
        // Not JSON, no boolean, a non-zero exit, a timeout: errors (the route turns them into verifier_error).
        assertFails { CommandIntegrityVerifier("cat >/dev/null; echo ok").verify("t", "h", null) }
        assertFails { CommandIntegrityVerifier("""cat >/dev/null; echo '{"passed":"yes"}'""").verify("t", "h", null) }
        assertFails { CommandIntegrityVerifier("cat >/dev/null; exit 3").verify("t", "h", null) }
        assertFails { CommandIntegrityVerifier("sleep 5", timeoutMs = 200).verify("t", "h", null) }
    }

    @Test
    fun `the command gets no server secret`() {
        assertTrue(CommandIntegrityVerifier.passes("PATH"))
        assertTrue(CommandIntegrityVerifier.passes("INTEGRITY_SERVICE_ACCOUNT_FILE"))
        assertTrue(CommandIntegrityVerifier.passes("GOOGLE_CLOUD_PROJECT", setOf("GOOGLE_CLOUD_PROJECT")))
        assertFalse(CommandIntegrityVerifier.passes("API_KEY", setOf("API_KEY")))
        assertFalse(CommandIntegrityVerifier.passes("KEYSTORE_PASSWORD"))
        assertFalse(CommandIntegrityVerifier.passes("SIGNER_TOKEN"))
    }

    @Test
    fun `the verifier is configured from the environment`() {
        assertNull(CommandIntegrityVerifier.fromEnv { null })
        assertNotNull(CommandIntegrityVerifier.fromEnv { if (it == "INTEGRITY_VERIFIER_COMMAND") "/bin/true" else null })
        assertFailsWith<IllegalArgumentException> {
            CommandIntegrityVerifier.fromEnv { mapOf("INTEGRITY_VERIFIER_COMMAND" to "/bin/true", "INTEGRITY_VERIFIER_TIMEOUT_MS" to "5").get(it) }
        }
    }
}
