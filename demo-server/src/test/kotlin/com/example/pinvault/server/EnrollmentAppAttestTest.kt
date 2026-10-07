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
import com.example.pinvault.server.service.IntegrityRequestHash
import com.example.pinvault.server.service.TestAttestationChains
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.identityDescription
import com.example.pinvault.server.service.UserAuthAttestationMode
import com.example.pinvault.server.service.attestation.AppAttestAdmission
import com.example.pinvault.server.service.attestation.AppAttestFixtures
import com.example.pinvault.server.service.attestation.AppAttestVerifier
import com.example.pinvault.server.service.attestation.AttestationKeyPolicy
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
 * An iPhone's CSR enrollment under ENROLLMENT_ATTESTATION (PORTING.md §6):
 * with App Attest configured, a request without `attestationChain` that
 * carries `appAttestation` — a fresh App Attest key's attestation whose
 * client data hash is SHA-256 of the request's integrity hash (CSR + device
 * id) — stands in for the chain on every path, before the token or a slot is
 * spent; the identity is stored as admitted by App Attest. Without App Attest
 * the field is not read; Android enrollments are judged by their chain.
 */
class EnrollmentAppAttestTest {

    private val pki = Pki()
    private val apple = AppAttestFixtures.Pki()
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
    private val scope = "aa-tls"

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-enroll-aa-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-enroll-aa-${System.nanoTime()}").also { it.mkdirs() }
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

    private var mode = EnrollmentAttestationMode.ENFORCE

    private fun ApplicationTestBuilder.configureApp(appAttest: AppAttestVerifier? = apple.verifier(), enrollmentMode: String = "token") {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        val attestation = EnrollmentAttestation({ mode }, appAttest) { pki.verifier() }
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
                enrollmentAttestation = attestation, p12Enrollment = false
            )
            enrollmentPolicyRoutes(policyStore, clientCertStore, audit, Duration.ofHours(24), 50)
        }
    }

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csrDer(key: KeyPair): ByteArray =
        JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public).build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded

    /**
     * The token the iOS library sends: a fresh App Attest key attested with
     * SHA-256 of the integrity hash of [csr] and [uid] (unless [clientDataHash] says otherwise).
     */
    private fun appAttestation(
        csr: ByteArray,
        uid: String?,
        pki: AppAttestFixtures.Pki = apple,
        appId: String = AppAttestFixtures.APP_ID,
        clientDataHash: ByteArray = AppAttestVerifier.enrollmentClientDataHash(IntegrityRequestHash.of(uid, csr))
    ): String {
        val aaKey = AppAttestFixtures.Key()
        return AppAttestFixtures.token(aaKey.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, aaKey, clientDataHash, appId = appId))
    }

    private fun body(
        csr: ByteArray?,
        token: String? = null,
        deviceUid: String? = null,
        deviceId: String? = null,
        appAttestation: String? = null,
        chain: List<String>? = null,
        requestId: String? = null
    ) = buildJsonObject {
        token?.let { put("token", it) }
        deviceId?.let { put("deviceId", it) }
        deviceUid?.let { put("deviceUid", it) }
        put("deviceAlias", "iPhone")
        csr?.let { put("csr", Base64.getEncoder().encodeToString(it)) }
        requestId?.let { put("requestId", it) }
        chain?.let { put("attestationChain", JsonArray(it.map(::JsonPrimitive))) }
        appAttestation?.let { put("appAttestation", it) }
    }.toString()

    private suspend fun ApplicationTestBuilder.enroll(json: String): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(json)
        }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject
    private suspend fun HttpResponse.error(): String? = json()["error"]?.jsonPrimitive?.content
    private suspend fun HttpResponse.reason(): String? = json()["reason"]?.jsonPrimitive?.content

    // ── enforce ─────────────────────────────────────────────────────────

    @Test
    fun `under enforce an iPhone enrolls with an App Attest attestation bound to its request`() = testApplication {
        configureApp()
        val csr = csrDer(deviceKey())
        val token = tokenStore.create("iphone-1")
        val response = enroll(body(csr, token, deviceUid = "uid-1", appAttestation = appAttestation(csr, "uid-1")))
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val identity = identityStore.get("iphone-1")!!
        assertTrue(AppAttestAdmission.admitted(identity.attestation))
        assertEquals(KeyAttestation(true, null, "app_attest"), identity.attestation, "stored as admitted by App Attest, no key level")
        // In place of the chain: the device id it was bound to is proven, as with a passing chain.
        assertTrue(clientCertStore.get("iphone-1")!!.deviceUidProven)
        assertEquals("app_attest", clientCertStore.get("iphone-1")!!.attestation?.reason)
        val issued = auditStore.page(50, 0).first { it.action == "client_cert_issued" }
        assertTrue(issued.summary.contains("admitted by App Attest"), issued.summary)
        assertNull(tokenStore.validate(token), "spent")
    }

    @Test
    fun `under enforce an App Attest attestation for another request, device, app or root is refused before the token is spent`() = testApplication {
        configureApp()
        val csr = csrDer(deviceKey())
        val token = tokenStore.create("iphone-1")
        for ((attestation, reason) in listOf(
            appAttestation(csrDer(deviceKey()), "uid-1") to "app_attest_nonce_mismatch",   // another CSR
            appAttestation(csr, "uid-2") to "app_attest_nonce_mismatch",                  // another device id
            appAttestation(csr, "uid-1", appId = "ZZZZZ99999.com.evil") to "app_attest_app_id_mismatch",
            appAttestation(csr, "uid-1", pki = AppAttestFixtures.Pki("CN=Not Apple")) to "app_attest_chain_invalid",
            "garbage" to "app_attest_malformed",
            // Each place needs its own: a screen-lock key's or an attestation round's attestation is not an enrollment's.
            appAttestation(csr, "uid-1", clientDataHash = AppAttestAdmission.userAuthClientDataHash("uid-1", csr)) to "app_attest_nonce_mismatch",
            appAttestation(csr, "uid-1", clientDataHash = AppAttestVerifier.roundClientDataHash("nonce", "uid-1")) to "app_attest_nonce_mismatch"
        )) {
            val refused = enroll(body(csr, token, deviceUid = "uid-1", appAttestation = attestation))
            assertEquals(HttpStatusCode.Forbidden, refused.status, reason)
            assertEquals("attestation_invalid", refused.error(), reason)
            assertEquals(reason, refused.reason())
        }
        // An assertion is no enrollment token: a fresh key's attestation is.
        val aaKey = AppAttestFixtures.Key()
        val assertion = AppAttestFixtures.token(aaKey.keyIdBase64, assertion = AppAttestFixtures.assertion(aaKey, ByteArray(32), 1))
        assertEquals("app_attest_attestation_required", enroll(body(csr, token, deviceUid = "uid-1", appAttestation = assertion)).reason())
        // Nothing at all: attestation_required, as before; the message names both ways in.
        val missing = enroll(body(csr, token, deviceUid = "uid-1"))
        assertEquals("attestation_required", missing.error())
        assertTrue(missing.json()["message"]!!.jsonPrimitive.content.contains("appAttestation"))
        // No device id to bind it to.
        assertEquals("attestation_required", enroll(body(csr, token, appAttestation = appAttestation(csr, null))).error())

        assertNull(identityStore.get("iphone-1"))
        assertEquals("iphone-1", tokenStore.validate(token), "the token is still good")
        assertEquals(HttpStatusCode.OK, enroll(body(csr, token, deviceUid = "uid-1", appAttestation = appAttestation(csr, "uid-1"))).status)
    }

    @Test
    fun `the device id is the request's deviceUid, or its deviceId without one, as for the chain`() = testApplication {
        configureApp(enrollmentMode = "open")
        // Open mode: the body carries only the device id.
        val csr = csrDer(deviceKey())
        val open = enroll(body(csr, deviceId = "ios-open", appAttestation = appAttestation(csr, "ios-open")))
        assertEquals(HttpStatusCode.OK, open.status, open.bodyAsText())
        assertTrue(AppAttestAdmission.admitted(identityStore.get("ios-open")!!.attestation))
    }

    @Test
    fun `an enrollment code waits for approval with the App Attest verdict and is issued at pickup`() = testApplication {
        configureApp()
        val created = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json)
            setBody("""{"name":"field","maxDevices":5,"validDays":7,"requireApproval":true}""")
        }.json()
        val code = created["code"]!!.jsonPrimitive.content
        val key = deviceKey()
        val csr = csrDer(key)
        // Without App Attest: refused, nothing recorded, no slot taken.
        assertEquals("attestation_required", enroll(body(csr, code, deviceUid = "uid-a")).error())
        assertTrue(policyStore.requests().isEmpty())

        val asked = enroll(body(csr, code, deviceUid = "uid-a", appAttestation = appAttestation(csr, "uid-a")))
        assertEquals(HttpStatusCode.Accepted, asked.status, asked.bodyAsText())
        val listed = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray.single().jsonObject
        assertEquals(true, listed["attestation"]!!.jsonObject["attested"]!!.jsonPrimitive.boolean)
        assertEquals("app_attest", listed["attestation"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertTrue(auditStore.page(50, 0).any { it.action == "enrollment_request_pending" && it.summary.contains("admitted by App Attest") })

        // Approved and picked up (the pickup carries no new attestation): issued, the verdict kept.
        val requestId = asked.json()["requestId"]!!.jsonPrimitive.content
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/enrollment-requests/$requestId/approve").status)
        val picked = enroll(body(csrDer(key), requestId = requestId))
        assertEquals(HttpStatusCode.OK, picked.status, picked.bodyAsText())
        assertTrue(AppAttestAdmission.admitted(identityStore.get(policyStore.getRequest(requestId)!!.clientId)!!.attestation))
    }

    // ── warn ────────────────────────────────────────────────────────────

    @Test
    fun `warn enrolls either way and records what App Attest said`() = testApplication {
        mode = EnrollmentAttestationMode.WARN
        configureApp()
        val csr = csrDer(deviceKey())
        assertEquals(HttpStatusCode.OK, enroll(body(csr, tokenStore.create("ios-ok"), deviceUid = "uid-ok", appAttestation = appAttestation(csr, "uid-ok"))).status)
        assertTrue(AppAttestAdmission.admitted(identityStore.get("ios-ok")!!.attestation))
        val other = csrDer(deviceKey())
        assertEquals(HttpStatusCode.OK, enroll(body(other, tokenStore.create("ios-bad"), deviceUid = "uid-bad", appAttestation = appAttestation(csr, "uid-bad"))).status)
        assertEquals(KeyAttestation(false, null, "app_attest_nonce_mismatch"), identityStore.get("ios-bad")!!.attestation)
        assertFalse(clientCertStore.get("ios-bad")!!.deviceUidProven)
    }

    // ── what does not change ────────────────────────────────────────────

    @Test
    fun `without App Attest configured the field is not read`() = testApplication {
        configureApp(appAttest = null)
        val csr = csrDer(deviceKey())
        val token = tokenStore.create("iphone-1")
        val refused = enroll(body(csr, token, deviceUid = "uid-1", appAttestation = appAttestation(csr, "uid-1")))
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("attestation_required", refused.error())
        assertFalse(refused.json()["message"]!!.jsonPrimitive.content.contains("App Attest"), "the message is the old one")
        mode = EnrollmentAttestationMode.WARN
        assertEquals(HttpStatusCode.OK, enroll(body(csr, token, deviceUid = "uid-1", appAttestation = appAttestation(csr, "uid-1"))).status)
        assertEquals(KeyAttestation(false, null, "chain_missing"), identityStore.get("iphone-1")!!.attestation)
    }

    @Test
    fun `Android enrollments are judged by their chain, with App Attest configured`() = testApplication {
        configureApp()
        val key = deviceKey()
        val csr = csrDer(key)
        val token = tokenStore.create("android-1")
        // A chain decides when there is one: a failing chain is not rescued by an App Attest attestation next to it.
        val wrong = TestAttestationChains.chain(pki, key.public, identityDescription("uid-other"))
        val refused = enroll(body(csr, token, deviceUid = "uid-1", chain = wrong, appAttestation = appAttestation(csr, "uid-1")))
        assertEquals("challenge_mismatch", refused.reason())
        val good = TestAttestationChains.chain(pki, key.public, identityDescription("uid-1"))
        assertEquals(HttpStatusCode.OK, enroll(body(csr, token, deviceUid = "uid-1", chain = good)).status)
        assertEquals(KeyAttestation(true, "tee", "ok"), identityStore.get("android-1")!!.attestation)
    }

    @Test
    fun `the start-up warning names every enforce setting that would refuse iPhones`() {
        val all = assertNotNull(AppAttestAdmission.iosRefusedWarning(
            EnrollmentAttestationMode.ENFORCE, UserAuthAttestationMode.ENFORCE, AttestationKeyPolicy.ENFORCE, appAttestConfigured = false))
        assertTrue(all.contains("iOS devices will be refused"), all)
        for (name in listOf("ENROLLMENT_ATTESTATION", "USER_AUTH_ATTESTATION", "ATTESTATION_KEY_POLICY", "APP_ATTEST_APP_IDS")) assertTrue(all.contains(name), name)
        val one = assertNotNull(AppAttestAdmission.iosRefusedWarning(
            EnrollmentAttestationMode.WARN, UserAuthAttestationMode.ENFORCE, AttestationKeyPolicy.WARN, appAttestConfigured = false))
        assertFalse(one.contains("ENROLLMENT_ATTESTATION"), one)
        assertNull(AppAttestAdmission.iosRefusedWarning(
            EnrollmentAttestationMode.ENFORCE, UserAuthAttestationMode.ENFORCE, AttestationKeyPolicy.ENFORCE, appAttestConfigured = true))
        assertNull(AppAttestAdmission.iosRefusedWarning(
            EnrollmentAttestationMode.WARN, UserAuthAttestationMode.WARN, AttestationKeyPolicy.OFF, appAttestConfigured = false))
    }
}
