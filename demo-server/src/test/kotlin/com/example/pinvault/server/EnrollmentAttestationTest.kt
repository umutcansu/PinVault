package com.example.pinvault.server

import com.example.pinvault.server.route.PolicyEnrollment
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.EnrollmentAttestation
import com.example.pinvault.server.service.EnrollmentAttestationMode
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.identityDescription
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
 * ENROLLMENT_ATTESTATION on every CSR enrollment path (one-time token,
 * enrollment code with and without approval, code-less application, open
 * mode): the device key's attestation chain is checked against the CSR's key
 * with the identity challenge of the request's deviceUid (or deviceId) BEFORE
 * a token or a policy slot is spent; the verdict goes with the request and
 * the identity. And ENROLLMENT_P12=off: no server-made key, `csr_required`.
 */
class EnrollmentAttestationTest {

    private val pki = Pki()
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
    private val scope = "att-tls"

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-enroll-att-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-enroll-att-${System.nanoTime()}").also { it.mkdirs() }
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

    /** The mode is read per request, so a test can switch it as an operator would between restarts. */
    private var mode = EnrollmentAttestationMode.WARN

    private fun ApplicationTestBuilder.configureApp(enrollmentMode: String = "token", p12: Boolean = true) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        // What Main builds from ENROLLMENT_ATTESTATION; here it follows [mode].
        val attestation = EnrollmentAttestation({ mode }) { pki.verifier() }
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                ConfigSigningService(File(certsDir, "signing.pem")), ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                enrollmentMode = enrollmentMode, audit = audit, clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) },
                policyEnrollment = PolicyEnrollment(
                    scope, policyStore, certService, identityStore, clientCertStore, audit,
                    AuthFailureRecorder(audit, action = "client_cert_enroll_refused", what = "Enrollment with an enrollment code refused"),
                    ttlFor = { Duration.ofDays(90) }, attestation = attestation
                ),
                enrollmentAttestation = attestation, p12Enrollment = p12
            )
            enrollmentPolicyRoutes(policyStore, clientCertStore, audit, Duration.ofHours(24), 50)
        }
    }

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csr(key: KeyPair): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
        return Base64.getEncoder().encodeToString(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded)
    }

    /** The chain the library sends for [key] made with the identity challenge of [uid]. */
    private fun chainFor(key: KeyPair, uid: String) = TestAttestationChains.chain(pki, key.public, identityDescription(uid))

    private fun body(
        key: KeyPair?,
        token: String? = null,
        deviceUid: String? = null,
        deviceId: String? = null,
        chain: List<String>? = null,
        requestId: String? = null
    ) = buildJsonObject {
        token?.let { put("token", it) }
        deviceId?.let { put("deviceId", it) }
        deviceUid?.let { put("deviceUid", it) }
        put("deviceAlias", "Pixel")
        key?.let { put("csr", csr(it)) }
        requestId?.let { put("requestId", it) }
        chain?.let { put("attestationChain", JsonArray(it.map(::JsonPrimitive))) }
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

    // ── one-time token ───────────────────────────────────────────────────

    @Test
    fun `warn enrolls with or without a chain and records which it was`() = testApplication {
        configureApp()
        val plain = deviceKey()
        assertEquals(HttpStatusCode.OK, enroll(body(plain, tokenStore.create("dev-plain"), deviceUid = "uid-plain")).status)
        assertEquals(KeyAttestation(false, null, "chain_missing"), identityStore.get("dev-plain")!!.attestation)

        val attested = deviceKey()
        val ok = enroll(body(attested, tokenStore.create("dev-hw"), deviceUid = "uid-hw", chain = chainFor(attested, "uid-hw")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertEquals(KeyAttestation(true, "tee", "ok"), identityStore.get("dev-hw")!!.attestation)
        // The client certificate list carries it (the dashboard shows it there).
        assertEquals(true, clientCertStore.get("dev-hw")!!.attestation?.attested)
        assertEquals(false, clientCertStore.get("dev-plain")!!.attestation?.attested)

        // A chain made for another device id: accepted under warn, recorded as failed.
        val other = deviceKey()
        assertEquals(HttpStatusCode.OK, enroll(body(other, tokenStore.create("dev-other"), deviceUid = "uid-x", chain = chainFor(other, "uid-y"))).status)
        assertEquals(KeyAttestation(false, "tee", "challenge_mismatch"), identityStore.get("dev-other")!!.attestation)
        assertTrue(auditStore.page(50, 0).any { it.action == "client_cert_issued" && it.summary.contains("hardware-attested") })
    }

    @Test
    fun `enforce refuses a missing or failing chain before the token is spent`() = testApplication {
        mode = EnrollmentAttestationMode.ENFORCE
        configureApp()
        val key = deviceKey()
        val token = tokenStore.create("dev-1")

        val missing = enroll(body(key, token, deviceUid = "uid-1"))
        assertEquals(HttpStatusCode.Forbidden, missing.status)
        assertEquals("attestation_required", missing.error())

        val wrongDevice = enroll(body(key, token, deviceUid = "uid-1", chain = chainFor(key, "uid-2")))
        assertEquals(HttpStatusCode.Forbidden, wrongDevice.status)
        assertEquals("attestation_invalid", wrongDevice.error())
        assertEquals("challenge_mismatch", wrongDevice.reason())

        // Another key's chain: the CSR's key must be the attested one.
        val foreign = deviceKey()
        assertEquals("key_mismatch", enroll(body(key, token, deviceUid = "uid-1", chain = chainFor(foreign, "uid-1"))).reason())
        assertEquals("chain_malformed", enroll(body(key, token, deviceUid = "uid-1", chain = listOf("bm90"))).reason())

        assertNull(identityStore.get("dev-1"))
        assertEquals("dev-1", tokenStore.validate(token), "the token is still good")

        val good = enroll(body(key, token, deviceUid = "uid-1", chain = chainFor(key, "uid-1")))
        assertEquals(HttpStatusCode.OK, good.status, good.bodyAsText())
        assertEquals(KeyAttestation(true, "tee", "ok"), identityStore.get("dev-1")!!.attestation)
        assertNull(tokenStore.validate(token), "spent now")
    }

    @Test
    fun `the challenge is the request's deviceUid, or its deviceId without one`() = testApplication {
        mode = EnrollmentAttestationMode.ENFORCE
        configureApp(enrollmentMode = "open")
        // Open mode: the body carries only the device id.
        val key = deviceKey()
        val open = enroll(body(key, deviceId = "android-1", chain = chainFor(key, "android-1")))
        assertEquals(HttpStatusCode.OK, open.status, open.bodyAsText())
        assertEquals(true, identityStore.get("android-1")!!.attestation?.attested)

        // deviceUid wins over deviceId when both are sent.
        val both = deviceKey()
        val byUid = enroll(body(both, tokenStore.create("dev-both"), deviceUid = "uid-both", deviceId = "id-both", chain = chainFor(both, "uid-both")))
        assertEquals(HttpStatusCode.OK, byUid.status, byUid.bodyAsText())
        val again = deviceKey()
        val byId = enroll(body(again, tokenStore.create("dev-both-2"), deviceUid = "uid-both-2", deviceId = "id-both-2", chain = chainFor(again, "id-both-2")))
        assertEquals("challenge_mismatch", byId.reason())

        // Neither: nothing to check the challenge against.
        val none = deviceKey()
        assertEquals("attestation_required", enroll(body(none, tokenStore.create("dev-none"), chain = chainFor(none, "x"))).error())
    }

    @Test
    fun `off never reads the chain`() = testApplication {
        mode = EnrollmentAttestationMode.OFF
        configureApp()
        val key = deviceKey()
        assertEquals(HttpStatusCode.OK, enroll(body(key, tokenStore.create("dev-off"), deviceUid = "uid-off", chain = listOf("garbage"))).status)
        assertNull(identityStore.get("dev-off")!!.attestation)
    }

    // ── server-made keys ────────────────────────────────────────────────

    @Test
    fun `ENROLLMENT_P12 off and enforce refuse a server-made key with csr_required, token unspent`() = testApplication {
        configureApp(p12 = false)
        val token = tokenStore.create("dev-p12")
        val refused = enroll(body(null, token, deviceUid = "uid-p12"), csr = false)
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("csr_required", refused.error())
        assertNull(clientCertStore.get("dev-p12"))
        assertEquals("dev-p12", tokenStore.validate(token))
        // The same token over a CSR still enrolls.
        assertEquals(HttpStatusCode.OK, enroll(body(deviceKey(), token, deviceUid = "uid-p12")).status)
    }

    @Test
    fun `enforce refuses a server-made key even with ENROLLMENT_P12 on`() = testApplication {
        mode = EnrollmentAttestationMode.ENFORCE
        configureApp(p12 = true)
        val token = tokenStore.create("dev-p12e")
        val refused = enroll(body(null, token), csr = false)
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("csr_required", refused.error())
        assertEquals("dev-p12e", tokenStore.validate(token))
        // warn and P12 on: still issued (older apps).
        mode = EnrollmentAttestationMode.WARN
        assertEquals(HttpStatusCode.OK, enroll(body(null, token), csr = false).status)
    }

    // ── enrollment codes ─────────────────────────────────────────────────

    @Test
    fun `a waiting request shows the approver whether the key is hardware-attested`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val attested = deviceKey()
        val plain = deviceKey()
        assertEquals(HttpStatusCode.Accepted, enroll(body(attested, code, deviceUid = "uid-a", chain = chainFor(attested, "uid-a"))).status)
        assertEquals(HttpStatusCode.Accepted, enroll(body(plain, code, deviceUid = "uid-b")).status)

        val listed = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray
            .associate { it.jsonObject["deviceUid"]!!.jsonPrimitive.content to it.jsonObject["attestation"]!!.jsonObject }
        assertEquals(true, listed["uid-a"]!!["attested"]!!.jsonPrimitive.boolean)
        assertEquals("tee", listed["uid-a"]!!["securityLevel"]!!.jsonPrimitive.content)
        assertEquals(false, listed["uid-b"]!!["attested"]!!.jsonPrimitive.boolean)
        assertEquals("chain_missing", listed["uid-b"]!!["reason"]!!.jsonPrimitive.content)
        assertTrue(auditStore.page(50, 0).any { it.action == "enrollment_request_pending" && it.summary.contains("hardware-attested") })

        // Approved and picked up: the identity keeps the verdict.
        val request = policyStore.requests().first { it.deviceUid == "uid-a" }
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/enrollment-requests/${request.id}/approve").status)
        val picked = enroll(body(attested, requestId = request.id, chain = chainFor(attested, "uid-a")))
        assertEquals(HttpStatusCode.OK, picked.status, picked.bodyAsText())
        assertEquals(true, identityStore.get(request.clientId)!!.attestation?.attested)
    }

    @Test
    fun `under enforce a device without a passing chain never waits and takes no slot`() = testApplication {
        mode = EnrollmentAttestationMode.ENFORCE
        configureApp()
        val (approvalPolicy, approvalCode) = createPolicy(approval = true)
        val (directPolicy, directCode) = createPolicy(approval = false)
        val key = deviceKey()
        assertEquals("attestation_required", enroll(body(key, approvalCode, deviceUid = "uid-1")).error())
        assertEquals("attestation_invalid", enroll(body(key, directCode, deviceUid = "uid-1", chain = chainFor(key, "uid-9"))).error())
        assertTrue(policyStore.requests().isEmpty(), "nothing recorded")
        assertEquals(0, policyStore.get(directPolicy)!!.usedCount, "no slot taken")
        assertEquals(0, policyStore.get(approvalPolicy)!!.usedCount)

        val direct = enroll(body(key, directCode, deviceUid = "uid-1", chain = chainFor(key, "uid-1")))
        assertEquals(HttpStatusCode.OK, direct.status, direct.bodyAsText())
        assertEquals(1, policyStore.get(directPolicy)!!.usedCount)
    }

    @Test
    fun `a request recorded under warn is issued under enforce only with a passing chain`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val key = deviceKey()
        val asked = enroll(body(key, code, deviceUid = "uid-late"))
        assertEquals(HttpStatusCode.Accepted, asked.status)
        val requestId = asked.json()["requestId"]!!.jsonPrimitive.content
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/enrollment-requests/$requestId/approve").status)

        mode = EnrollmentAttestationMode.ENFORCE
        val refused = enroll(body(key, requestId = requestId))
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("attestation_required", refused.error())
        // The pickup carries the request's body: deviceUid as at the first ask.
        val ok = enroll(body(key, requestId = requestId, deviceUid = "uid-late", chain = chainFor(key, "uid-late")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertEquals(true, identityStore.get(policyStore.getRequest(requestId)!!.clientId)!!.attestation?.attested)
    }
}

