package com.example.pinvault.server

import com.example.pinvault.server.route.PolicyEnrollment
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.enrollmentPolicyRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.AuthFailureRecorder
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.util.Base64
import kotlin.test.*

/**
 * Enrollment policies: one code many devices enroll with, within a device
 * limit and an end date, each device optionally approved by an administrator
 * first. Devices are told apart by their keys, never by a secret of their own.
 */
class EnrollmentPolicyTest {

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
    private lateinit var signingService: ConfigSigningService
    private val scope = "test-tls"

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-policy-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-policy-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        policyStore = EnrollmentPolicyStore(db)
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

    private fun csr(key: KeyPair): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
        return Base64.getEncoder().encodeToString(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded)
    }

    private fun Route.mountRoutes(
        pendingTtl: Duration = Duration.ofHours(24),
        openMaxPending: Int = 50,
        openLimiter: com.example.pinvault.server.service.RateLimiter? = null,
        limits: com.example.pinvault.server.service.EnrollmentLimits = com.example.pinvault.server.service.EnrollmentLimits()
    ) {
        certificateConfigRoutes(
            scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
            signingService, ClientDeviceStore(db), certService, tokenStore, clientCertStore,
            audit = audit, clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) },
            policyEnrollment = PolicyEnrollment(
                scope, policyStore, certService, identityStore, clientCertStore, audit,
                AuthFailureRecorder(audit, action = "client_cert_enroll_refused", what = "Enrollment with an enrollment code refused"),
                ttlFor = { Duration.ofDays(90) },
                pendingTtl = pendingTtl, openMaxPending = openMaxPending, openLimiter = openLimiter, limits = limits
            )
        )
        enrollmentPolicyRoutes(policyStore, clientCertStore, audit, pendingTtl, openMaxPending)
    }

    private fun ApplicationTestBuilder.configureApp(
        pendingTtl: Duration = Duration.ofHours(24),
        openMaxPending: Int = 50,
        openLimiter: com.example.pinvault.server.service.RateLimiter? = null,
        limits: com.example.pinvault.server.service.EnrollmentLimits = com.example.pinvault.server.service.EnrollmentLimits()
    ) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing { mountRoutes(pendingTtl, openMaxPending, openLimiter, limits) }
    }

    /** Creates a policy over the management API: (policy id, code). */
    private suspend fun ApplicationTestBuilder.createPolicy(
        name: String = "field",
        maxDevices: Int = 10,
        approval: Boolean = false,
        validDays: Int = 7
    ): Pair<String, String> {
        val response = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json)
            setBody("""{"name":"$name","maxDevices":$maxDevices,"validDays":$validDays,"requireApproval":$approval}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        val body = response.json()
        return body["policy"]!!.jsonObject["id"]!!.jsonPrimitive.content to body["code"]!!.jsonPrimitive.content
    }

    private suspend fun ApplicationTestBuilder.submit(
        code: String,
        key: KeyPair,
        uid: String? = null,
        withCsr: Boolean = true
    ): HttpResponse = client.post("/api/v1/client-certs/enroll") {
        header("X-PinVault-Features", if (withCsr) "p12password,csr" else "p12password")
        contentType(ContentType.Application.Json)
        setBody(buildJsonObject {
            put("token", code)
            put("deviceAlias", "Pixel")
            if (uid != null) put("deviceUid", uid)
            if (withCsr) put("csr", csr(key))
        }.toString())
    }

    private suspend fun ApplicationTestBuilder.pickup(requestId: String, key: KeyPair): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("requestId", requestId); put("csr", csr(key)) }.toString())
        }

    private suspend fun ApplicationTestBuilder.decide(requestId: String, decision: String): HttpResponse =
        client.post("/api/v1/enrollment-requests/$requestId/$decision")

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    private suspend fun HttpResponse.leaf(): X509Certificate {
        val pem = json()["chain"]!!.jsonArray[0].jsonPrimitive.content
        return CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()) as X509Certificate
    }

    private suspend fun HttpResponse.clientId(): String = json()["clientId"]!!.jsonPrimitive.content

    private fun actions() = auditStore.page(200, 0).map { it.action }

    // ── without approval ─────────────────────────────────────────────────

    @Test
    fun `one code enrolls several devices, each under its own id, up to the limit`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(name = "field", maxDevices = 2)
        val keyA = deviceKey()
        val keyB = deviceKey()

        val a = submit(code, keyA, uid = "uid-a")
        assertEquals(HttpStatusCode.OK, a.status, a.bodyAsText())
        assertEquals("pem-chain", a.headers["X-PinVault-Cert-Format"])
        val idA = a.clientId()
        assertTrue(idA.matches(Regex("field-[0-9a-z]{6}")), idA)
        assertEquals(keyA.public, a.leaf().publicKey)
        assertTrue(a.leaf().subjectX500Principal.name.contains("CN=PinVault Client: $idA"))
        assertEquals("field", a.json()["policy"]!!.jsonPrimitive.content)

        val b = submit(code, keyB, uid = "uid-b")
        assertEquals(HttpStatusCode.OK, b.status, b.bodyAsText())
        val idB = b.clientId()
        assertNotEquals(idA, idB)

        // Each device is its own identity, bound to its own device id.
        assertEquals("uid-a", assertNotNull(identityStore.get(idA)).deviceUid)
        assertEquals("uid-b", assertNotNull(clientCertStore.get(idB)).deviceUid)
        assertEquals("csr", clientCertStore.get(idB)!!.keyType)

        val c = submit(code, deviceKey(), uid = "uid-c")
        assertEquals(HttpStatusCode.Forbidden, c.status)
        assertEquals("enrollment_limit_reached", c.json()["error"]!!.jsonPrimitive.content)

        val policy = assertNotNull(policyStore.get(policyId))
        assertEquals(2, policy.usedCount)
        assertEquals("full", policy.status)
        assertEquals(2, actions().count { it == "client_cert_issued" })
        assertTrue(actions().contains("client_cert_enroll_refused"))
    }

    @Test
    fun `the same device asking again does not take a second slot`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(maxDevices = 1)
        val key = deviceKey()
        val first = submit(code, key, uid = "uid-1")
        assertEquals(HttpStatusCode.OK, first.status, first.bodyAsText())

        // An answer that got lost: the same key asks again and gets the same id.
        val again = submit(code, key, uid = "uid-1")
        assertEquals(HttpStatusCode.OK, again.status, again.bodyAsText())
        assertEquals(first.clientId(), again.clientId())
        assertEquals(1, policyStore.get(policyId)!!.usedCount)

        assertEquals(HttpStatusCode.Forbidden, submit(code, deviceKey(), uid = "uid-2").status)
    }

    @Test
    fun `the code is forgiving about case, dashes, spaces and look-alike letters`() = testApplication {
        configureApp()
        val (_, code) = createPolicy()
        assertTrue(code.matches(Regex("[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){4}")), code)
        val typed = code.lowercase().replace("-", " ").replace('0', 'o').replace('1', 'l')
        val response = submit(typed, deviceKey())
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
    }

    @Test
    fun `the code is stored only as a hash`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy()
        val stored = db.connection().use { conn ->
            conn.prepareStatement("SELECT code_hash, code_prefix FROM enrollment_policies WHERE id = ?").use { stmt ->
                stmt.setString(1, policyId)
                stmt.executeQuery().let { rs -> rs.next(); rs.getString(1) to rs.getString(2) }
            }
        }
        assertFalse(stored.first.contains(code.replace("-", "")))
        assertEquals(code.substringBefore('-'), stored.second)

        val listing = client.get("/api/v1/enrollment-policies").bodyAsText()
        assertFalse(listing.contains(code), "the listing never carries the code")
        assertFalse(listing.contains(code.replace("-", "")))
        assertTrue(actions().contains("enrollment_policy_created"))
    }

    @Test
    fun `a stopped or expired code is refused like a used token`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy()
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/enrollment-policies/$policyId/stop").status)
        val stopped = submit(code, deviceKey())
        assertEquals(HttpStatusCode.Unauthorized, stopped.status)
        assertEquals(HttpStatusCode.Conflict, client.post("/api/v1/enrollment-policies/$policyId/stop").status)
        assertTrue(actions().contains("enrollment_policy_stopped"))

        val expired = policyStore.create("old", 5, Duration.ZERO, requireApproval = false, createdBy = "test")
        assertEquals("expired", expired.policy.status)
        assertEquals(HttpStatusCode.Unauthorized, submit(expired.code, deviceKey()).status)
    }

    @Test
    fun `a code needs a CSR and takes no slot without one`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy()
        val response = submit(code, deviceKey(), withCsr = false)
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("csr_required", response.json()["error"]!!.jsonPrimitive.content)
        assertEquals(0, policyStore.get(policyId)!!.usedCount)
    }

    @Test
    fun `one active identity per device holds for codes too`() = testApplication {
        configureApp()
        val (_, code) = createPolicy()
        assertEquals(HttpStatusCode.OK, submit(code, deviceKey(), uid = "android-1").status)
        val second = submit(code, deviceKey(), uid = "android-1")
        assertEquals(HttpStatusCode.Conflict, second.status)
        assertEquals("device_already_enrolled", second.json()["error"]!!.jsonPrimitive.content)
    }

    @Test
    fun `approval is on unless turned off`() = testApplication {
        configureApp()
        val response = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json)
            setBody("""{"name":"defaults","maxDevices":2,"validDays":1}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.json()["policy"]!!.jsonObject["requireApproval"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `management input is checked`() = testApplication {
        configureApp()
        suspend fun create(body: String) = client.post("/api/v1/enrollment-policies") {
            contentType(ContentType.Application.Json); setBody(body)
        }
        assertEquals(HttpStatusCode.BadRequest, create("""{"name":"has space","maxDevices":5,"validDays":7}""").status)
        assertEquals(HttpStatusCode.BadRequest, create("""{"name":"${"x".repeat(41)}","maxDevices":5,"validDays":7}""").status)
        assertEquals(HttpStatusCode.BadRequest, create("""{"name":"ok","maxDevices":0,"validDays":7}""").status)
        assertEquals(HttpStatusCode.BadRequest, create("""{"name":"ok","maxDevices":5,"validDays":400}""").status)
        assertEquals(HttpStatusCode.BadRequest, create("not json").status)
        assertEquals(HttpStatusCode.NotFound, client.post("/api/v1/enrollment-policies/nope/stop").status)
        assertEquals(HttpStatusCode.NotFound, decide("nope", "approve").status)
    }

    // ── with approval ────────────────────────────────────────────────────

    @Test
    fun `with approval the device waits and gets its certificate once approved`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(name = "tablets", maxDevices = 5, approval = true)
        val key = deviceKey()

        val asked = submit(code, key, uid = "uid-t1")
        assertEquals(HttpStatusCode.Accepted, asked.status, asked.bodyAsText())
        assertEquals("15", asked.headers[HttpHeaders.RetryAfter])
        val body = asked.json()
        assertEquals("pending", body["status"]!!.jsonPrimitive.content)
        val requestId = body["requestId"]!!.jsonPrimitive.content
        val clientId = body["clientId"]!!.jsonPrimitive.content
        assertTrue(clientId.startsWith("tablets-"))
        assertNull(identityStore.get(clientId), "nothing issued before approval")
        assertEquals(0, policyStore.get(policyId)!!.usedCount)
        assertEquals(1, policyStore.get(policyId)!!.pendingCount)

        // Still waiting: asking again (by id, or with the code) changes nothing.
        assertEquals(HttpStatusCode.Accepted, pickup(requestId, key).status)
        assertEquals(requestId, submit(code, key, uid = "uid-t1").json()["requestId"]!!.jsonPrimitive.content)
        assertEquals(1, policyStore.requests(EnrollmentRequest.PENDING).size)

        // The administrator sees the device and lets it in.
        val waiting = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray
        assertEquals(1, waiting.size)
        assertEquals(clientId, waiting[0].jsonObject["clientId"]!!.jsonPrimitive.content)
        assertEquals("Pixel", waiting[0].jsonObject["deviceAlias"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.OK, decide(requestId, "approve").status)
        assertEquals(1, policyStore.get(policyId)!!.usedCount)

        val picked = pickup(requestId, key)
        assertEquals(HttpStatusCode.OK, picked.status, picked.bodyAsText())
        assertEquals(clientId, picked.clientId())
        assertEquals(key.public, picked.leaf().publicKey)
        assertEquals("uid-t1", identityStore.get(clientId)!!.deviceUid)
        assertEquals(EnrollmentRequest.ISSUED, policyStore.getRequest(requestId)!!.status)

        val log = actions()
        assertTrue(log.containsAll(listOf("enrollment_request_pending", "enrollment_request_approved", "client_cert_issued")), log.toString())
        assertEquals(HttpStatusCode.Conflict, decide(requestId, "approve").status, "decided once")
    }

    @Test
    fun `a rejected device is told so and frees nothing it did not take`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(approval = true)
        val key = deviceKey()
        val requestId = submit(code, key).json()["requestId"]!!.jsonPrimitive.content
        assertEquals(HttpStatusCode.OK, decide(requestId, "reject").status)

        val refused = pickup(requestId, key)
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("enrollment_rejected", refused.json()["error"]!!.jsonPrimitive.content)
        // The same key with the code: still the rejected request.
        assertEquals(HttpStatusCode.Forbidden, submit(code, key).status)
        assertEquals(0, policyStore.get(policyId)!!.usedCount)
        assertTrue(actions().contains("enrollment_request_rejected"))
    }

    @Test
    fun `an approved device turned away gives its slot back`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(approval = true)
        val requestId = submit(code, deviceKey()).json()["requestId"]!!.jsonPrimitive.content
        decide(requestId, "approve")
        assertEquals(1, policyStore.get(policyId)!!.usedCount)
        assertEquals(HttpStatusCode.OK, decide(requestId, "reject").status)
        assertEquals(0, policyStore.get(policyId)!!.usedCount)
    }

    @Test
    fun `a request picks up nothing without its key`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val requestId = submit(code, deviceKey()).json()["requestId"]!!.jsonPrimitive.content
        decide(requestId, "approve")

        val stranger = pickup(requestId, deviceKey())
        assertEquals(HttpStatusCode.Forbidden, stranger.status)
        assertEquals("enrollment_request_mismatch", stranger.json()["error"]!!.jsonPrimitive.content)
        assertEquals(EnrollmentRequest.APPROVED, policyStore.getRequest(requestId)!!.status)

        val unknown = pickup("0".repeat(32), deviceKey())
        assertEquals(HttpStatusCode.NotFound, unknown.status)
        assertEquals("enrollment_request_not_found", unknown.json()["error"]!!.jsonPrimitive.content)

        // A pickup needs a CSR like everything else on this path.
        val noCsr = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"requestId":"$requestId"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, noCsr.status)
    }

    @Test
    fun `approving a device that has another identity needs that one revoked first`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val old = submitToken("tablet-07", "android-1")
        assertEquals(HttpStatusCode.OK, old.status, old.bodyAsText())

        // A reinstall: the device comes back with the code. It may ask...
        val key = deviceKey()
        val asked = submit(code, key, uid = "android-1")
        assertEquals(HttpStatusCode.Accepted, asked.status, asked.bodyAsText())
        val requestId = asked.json()["requestId"]!!.jsonPrimitive.content

        // ...the administrator sees the clash...
        val waiting = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray
        assertEquals("tablet-07", waiting.single().jsonObject["heldBy"]!!.jsonPrimitive.content)
        val clash = decide(requestId, "approve")
        assertEquals(HttpStatusCode.Conflict, clash.status)
        assertEquals("tablet-07", clash.json()["heldBy"]!!.jsonPrimitive.content)

        // ...and approves once the old identity is revoked.
        clientCertStore.revoke("tablet-07")
        identityStore.revoke("tablet-07")
        assertEquals(HttpStatusCode.OK, decide(requestId, "approve").status)
        assertEquals(HttpStatusCode.OK, pickup(requestId, key).status)
    }

    private suspend fun ApplicationTestBuilder.submitToken(clientId: String, uid: String): HttpResponse {
        val token = tokenStore.create(clientId)
        return client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("token", token); put("deviceUid", uid); put("csr", csr(deviceKey())) }.toString())
        }
    }

    @Test
    fun `stopping a code turns waiting devices away but lets approved ones in`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(approval = true)
        val keyA = deviceKey()
        val keyB = deviceKey()
        val a = submit(code, keyA).json()["requestId"]!!.jsonPrimitive.content
        val b = submit(code, keyB).json()["requestId"]!!.jsonPrimitive.content
        decide(a, "approve")
        client.post("/api/v1/enrollment-policies/$policyId/stop")

        assertEquals(HttpStatusCode.OK, pickup(a, keyA).status)
        assertEquals("enrollment_rejected", pickup(b, keyB).json()["error"]!!.jsonPrimitive.content)
        assertEquals(HttpStatusCode.Unauthorized, submit(code, deviceKey()).status)
        assertEquals(HttpStatusCode.Conflict, decide(b, "approve").status)
    }

    @Test
    fun `waiting devices are capped and approvals never exceed the limit`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(maxDevices = 2, approval = true)
        val keyA = deviceKey()
        val a = submit(code, keyA).json()["requestId"]!!.jsonPrimitive.content
        val b = submit(code, deviceKey()).json()["requestId"]!!.jsonPrimitive.content
        val third = submit(code, deviceKey())
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertEquals("too_many_pending_requests", third.json()["error"]!!.jsonPrimitive.content)

        // A frees a waiting place by being approved; C may then ask, but only two get in.
        decide(a, "approve")
        pickup(a, keyA)
        val c = submit(code, deviceKey()).json()["requestId"]!!.jsonPrimitive.content
        assertEquals(HttpStatusCode.OK, decide(b, "approve").status)
        val over = decide(c, "approve")
        assertEquals(HttpStatusCode.Conflict, over.status)
        assertEquals("enrollment_limit_reached", over.json()["error"]!!.jsonPrimitive.content)
        assertEquals(2, policyStore.get(policyId)!!.usedCount)
        assertEquals(EnrollmentRequest.PENDING, policyStore.getRequest(c)!!.status)
    }

    @Test
    fun `the device name an approver reads is one printable line`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val response = client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("token", code)
                put("deviceAlias", "Pixel 8\n2026 approved <script>x</script> " + "y".repeat(100))
                put("csr", csr(deviceKey()))
            }.toString())
        }
        assertEquals(HttpStatusCode.Accepted, response.status, response.bodyAsText())
        val alias = assertNotNull(policyStore.requests().single().deviceAlias)
        assertFalse(alias.contains('\n'))
        assertFalse(alias.contains('<'))
        assertTrue(alias.length <= 64, alias)
        assertTrue(alias.startsWith("Pixel 82026 approved scriptx"), alias)
        val summary = auditStore.page(10, 0).first { it.action == "enrollment_request_pending" }.summary
        assertFalse(summary.contains('\n'), summary)
        assertNull(com.example.pinvault.server.route.displayAlias(" \n\t "))
    }

    // ── code-less applications (the dashboard's switch) ──────────────────

    private suspend fun ApplicationTestBuilder.setOpen(enabled: Boolean): JsonObject {
        val response = client.put("/api/v1/enrollment-open") {
            contentType(ContentType.Application.Json)
            setBody("""{"enabled":$enabled}""")
        }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return response.json()
    }

    /** What autoEnroll sends: no token, the device id, a CSR. */
    private suspend fun ApplicationTestBuilder.applyWithoutCode(key: KeyPair, deviceId: String = "android-1"): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("deviceId", deviceId)
                put("deviceUid", deviceId)
                put("deviceAlias", "Pixel")
                put("csr", csr(key))
            }.toString())
        }

    private fun codeOf(key: KeyPair): String =
        com.example.pinvault.server.service.VerificationCode.ofDigest(
            java.security.MessageDigest.getInstance("SHA-256").digest(key.public.encoded)
        )

    @Test
    fun `the verification code is the first 80 bits of the key hash in base32`() {
        val vc = com.example.pinvault.server.service.VerificationCode
        // Same vectors as the library's VerificationCodeTest: both sides must agree.
        val pinvault = java.security.MessageDigest.getInstance("SHA-256").digest("pinvault".toByteArray())
        assertEquals("0XMH-GCGP-BW6Z-10F6", vc.ofDigest(pinvault))
        assertEquals("0XMH-GCGP-BW6Z-10F6", vc.ofSpkiSha256("B2kYMhZfDfCB5iZLbIoeW2GaszFr1dWvNKg4Kz97ayY="))
        assertEquals("B2kYMhZfDfCB5iZLbIoeW2GaszFr1dWvNKg4Kz97ayY=", Base64.getEncoder().encodeToString(pinvault))
        assertEquals("0000-0000-0000-0000", vc.ofDigest(ByteArray(32)))
        assertEquals("ZZZZ-ZZZZ-ZZZZ-ZZZZ", vc.ofDigest(ByteArray(32) { -1 }))
        // Only the first 10 bytes count; the old 40-bit code is its first half.
        assertEquals(vc.ofDigest(pinvault), vc.ofDigest(pinvault.copyOf(10)))
        assertTrue(vc.ofDigest(pinvault).startsWith("0XMH-GCGP-"))
        assertFailsWith<IllegalArgumentException> { vc.ofDigest(ByteArray(9)) }
    }

    @Test
    fun `a key retired with a forgotten identity asks neither with a code nor without one`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(approval = true)
        val key = deviceKey()
        val now = java.time.Instant.now().toString()
        assertTrue(identityStore.register("old-id", scope, certService.spkiSha256(key.public), "01", now, now, null, null, now))
        identityStore.revoke("old-id")
        assertEquals(ClientIdentityStore.Forget.FORGOTTEN, identityStore.forget("old-id", now))

        val withCode = submit(code, key)
        assertEquals(HttpStatusCode.Forbidden, withCode.status, withCode.bodyAsText())
        assertTrue(withCode.bodyAsText().contains("revoked"))
        setOpen(true)
        assertEquals(HttpStatusCode.Forbidden, applyWithoutCode(key, "android-retired").status)
        assertTrue(policyStore.requests().isEmpty(), "nothing waits for an administrator")
    }

    @Test
    fun `without the switch a device asking without a token is told one is required`() = testApplication {
        configureApp()
        val response = applyWithoutCode(deviceKey())
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("Token required"))
        assertFalse(setOpen(false)["enabled"]!!.jsonPrimitive.boolean)
        assertTrue(policyStore.requests().isEmpty())
    }

    @Test
    fun `with the switch on a device asks without a code, waits, and is let in once approved`() = testApplication {
        configureApp()
        assertTrue(setOpen(true)["enabled"]!!.jsonPrimitive.boolean)
        val key = deviceKey()

        val asked = applyWithoutCode(key, "android-open-1")
        assertEquals(HttpStatusCode.Accepted, asked.status, asked.bodyAsText())
        val body = asked.json()
        val requestId = body["requestId"]!!.jsonPrimitive.content
        val clientId = body["clientId"]!!.jsonPrimitive.content
        assertTrue(clientId.matches(Regex("device-[0-9a-z]{6}")), clientId)
        assertEquals(codeOf(key), body["verificationCode"]!!.jsonPrimitive.content)
        assertTrue(body["openApplication"]!!.jsonPrimitive.boolean)

        // The administrator sees the same code the device shows.
        val waiting = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray.single().jsonObject
        assertEquals(codeOf(key), waiting["verificationCode"]!!.jsonPrimitive.content)
        assertTrue(waiting["openApplication"]!!.jsonPrimitive.boolean)
        assertEquals("android-open-1", waiting["deviceUid"]!!.jsonPrimitive.content)

        assertEquals(HttpStatusCode.OK, decide(requestId, "approve").status)
        val picked = pickup(requestId, key)
        assertEquals(HttpStatusCode.OK, picked.status, picked.bodyAsText())
        assertEquals(key.public, picked.leaf().publicKey)
        assertEquals("android-open-1", identityStore.get(clientId)!!.deviceUid)

        val log = auditStore.page(50, 0)
        assertTrue(log.any { it.action == "enrollment_open_changed" })
        val pending = log.first { it.action == "enrollment_request_pending" }.summary
        assertTrue(pending.contains("without a code") && pending.contains(codeOf(key)), pending)
        assertTrue(log.any { it.action == "client_cert_issued" && it.target == clientId })
    }

    @Test
    fun `turning the switch off turns new devices away but keeps the waiting ones decidable`() = testApplication {
        configureApp()
        setOpen(true)
        val key = deviceKey()
        val requestId = applyWithoutCode(key, "android-a").json()["requestId"]!!.jsonPrimitive.content
        assertFalse(setOpen(false)["enabled"]!!.jsonPrimitive.boolean)

        assertEquals(HttpStatusCode.Forbidden, applyWithoutCode(deviceKey(), "android-b").status)
        assertEquals(HttpStatusCode.OK, decide(requestId, "approve").status)
        assertEquals(HttpStatusCode.OK, pickup(requestId, key).status)

        // On again: the same policy, its history kept.
        val again = setOpen(true)
        assertEquals(1, again["policy"]!!.jsonObject["usedCount"]!!.jsonPrimitive.int)
        assertTrue(policyStore.getAll().count { it.openApplications } == 1)
    }

    @Test
    fun `a source address may make only a few code-less applications, retries are free`() = testApplication {
        configureApp(openLimiter = com.example.pinvault.server.service.RateLimiter(maxAttempts = 2, windowMs = 60_000))
        setOpen(true)
        val key = deviceKey()
        val first = applyWithoutCode(key, "android-1").json()["requestId"]!!.jsonPrimitive.content
        // The same key asking again is the same request, and costs nothing.
        repeat(3) { assertEquals(first, applyWithoutCode(key, "android-1").json()["requestId"]!!.jsonPrimitive.content) }
        assertEquals(HttpStatusCode.Accepted, applyWithoutCode(deviceKey(), "android-2").status)
        val third = applyWithoutCode(deviceKey(), "android-3")
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertEquals("too_many_applications", third.json()["error"]!!.jsonPrimitive.content)
    }

    @Test
    fun `waiting code-less applications are capped`() = testApplication {
        configureApp(openMaxPending = 2)
        setOpen(true)
        assertEquals(HttpStatusCode.Accepted, applyWithoutCode(deviceKey(), "android-1").status)
        assertEquals(HttpStatusCode.Accepted, applyWithoutCode(deviceKey(), "android-2").status)
        val third = applyWithoutCode(deviceKey(), "android-3")
        assertEquals(HttpStatusCode.TooManyRequests, third.status)
        assertEquals("too_many_pending_requests", third.json()["error"]!!.jsonPrimitive.content)
    }

    @Test
    fun `a request nobody decides on lapses, and the device is told so`() = testApplication {
        configureApp(pendingTtl = Duration.ofMillis(200))
        setOpen(true)
        val key = deviceKey()
        val requestId = applyWithoutCode(key).json()["requestId"]!!.jsonPrimitive.content
        Thread.sleep(400)

        val lapsed = pickup(requestId, key)
        assertEquals(HttpStatusCode.Gone, lapsed.status)
        assertEquals("enrollment_request_expired", lapsed.json()["error"]!!.jsonPrimitive.content)
        assertEquals(EnrollmentRequest.EXPIRED, policyStore.getRequest(requestId)!!.status)
        assertEquals("[]", client.get("/api/v1/enrollment-requests?status=pending").bodyAsText().replace(Regex("\\s"), ""))
        assertEquals(HttpStatusCode.Conflict, decide(requestId, "approve").status)
        // A new key asks afresh.
        assertEquals(HttpStatusCode.Accepted, applyWithoutCode(deviceKey()).status)
    }

    @Test
    fun `the same device asking twice is flagged on both requests`() = testApplication {
        configureApp()
        setOpen(true)
        applyWithoutCode(deviceKey(), "android-dup")
        applyWithoutCode(deviceKey(), "android-dup")   // reinstalled before anyone decided
        applyWithoutCode(deviceKey(), "android-other")
        val rows = Json.parseToJsonElement(client.get("/api/v1/enrollment-requests?status=pending").bodyAsText()).jsonArray.map { it.jsonObject }
        val dup = rows.filter { it["deviceUid"]!!.jsonPrimitive.content == "android-dup" }
        assertEquals(2, dup.size)
        assertTrue(dup.all { it["sameDevicePending"]!!.jsonPrimitive.int == 1 })
        assertEquals(0, rows.single { it["deviceUid"]!!.jsonPrimitive.content == "android-other" }["sameDevicePending"]!!.jsonPrimitive.int)
    }

    @Test
    fun `the switch outranks ENROLLMENT_MODE=open`() = testApplication {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signingService, ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                enrollmentMode = "open", audit = audit, clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) },
                policyEnrollment = PolicyEnrollment(scope, policyStore, certService, identityStore, clientCertStore, audit, null,
                    ttlFor = { Duration.ofDays(90) })
            )
            enrollmentPolicyRoutes(policyStore, clientCertStore, audit)
        }
        setOpen(true)
        assertEquals(HttpStatusCode.Accepted, applyWithoutCode(deviceKey(), "android-open-mode").status)
        setOpen(false)
        // Off again, open mode hands out certificates as before (demo only).
        assertEquals(HttpStatusCode.OK, applyWithoutCode(deviceKey(), "android-open-mode-2").status)
    }

    @Test
    fun `an approved request never replaces the key of an identity enrolled under its id since`() = testApplication {
        configureApp()
        val (_, code) = createPolicy(name = "late", maxDevices = 5, approval = true)
        val key = deviceKey()
        val asked = submit(code, key, uid = "uid-late").json()
        val requestId = asked["requestId"]!!.jsonPrimitive.content
        val clientId = asked["clientId"]!!.jsonPrimitive.content
        assertEquals(HttpStatusCode.OK, decide(requestId, "approve").status)

        // Meanwhile an administrator's token enrolled another device under that id.
        val other = deviceKey()
        val token = tokenStore.create(clientId)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("token", token); put("csr", csr(other)) }.toString())
        }.status)

        val picked = pickup(requestId, key)
        assertEquals(HttpStatusCode.Conflict, picked.status, picked.bodyAsText())
        assertEquals("identity_already_enrolled", picked.json()["error"]!!.jsonPrimitive.content)
        assertEquals(certService.spkiSha256(other.public), identityStore.get(clientId)!!.spkiSha256, "the enrolled key stays")
    }

    // ── races ────────────────────────────────────────────────────────────

    @Test
    fun `devices racing for the last slots get exactly the limit`() {
        val port = java.net.ServerSocket(0).use { it.localPort }
        val server = io.ktor.server.engine.embeddedServer(io.ktor.server.netty.Netty, port = port, host = "127.0.0.1") {
            install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
            routing { mountRoutes() }
        }.start(wait = false)
        try {
            val created = policyStore.create("race", 3, Duration.ofDays(1), requireApproval = false, createdBy = "test")
            val bodies = (1..12).map { """{"token":"${created.code}","csr":"${csr(deviceKey())}"}""" }
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
            assertEquals(3, statuses.count { it == 200 }, "statuses: $statuses")
            assertEquals(9, statuses.count { it == 403 }, "statuses: $statuses")
            assertEquals(3, policyStore.get(created.policy.id)!!.usedCount)
            assertEquals(3, identityStore.getAll().size)
        } finally {
            server.stop(100, 1000)
        }
    }
    // ── D-A2 / D-A6: work a device can make the server do, bounded ───────

    @Test
    fun `the same key asking again with a code gets its certificate back, also after the code was stopped`() = testApplication {
        configureApp()
        val (policyId, code) = createPolicy(approval = false)
        val key = deviceKey()
        val first = submit(code, key, uid = "android-again")
        assertEquals(HttpStatusCode.OK, first.status)
        val serial = first.json()["serial"]!!.jsonPrimitive.content
        assertEquals(serial, submit(code, key, uid = "android-again").json()["serial"]!!.jsonPrimitive.content, "no new signature")
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/enrollment-policies/$policyId/stop").status)
        val afterStop = submit(code, key, uid = "android-again")
        assertEquals(HttpStatusCode.OK, afterStop.status)
        assertEquals(serial, afterStop.json()["serial"]!!.jsonPrimitive.content)
        assertEquals(1, auditStore.page(100, 0).count { it.action == "client_cert_issued" })
    }

    @Test
    fun `a waiting device asking in a loop is told to slow down`() = testApplication {
        val limits = com.example.pinvault.server.service.EnrollmentLimits(
            issuance = null, keyReplacements = null, pickupsPerSource = null,
            pickupsPerRequest = com.example.pinvault.server.service.RateLimiter(maxAttempts = 3, windowMs = 60_000))
        configureApp(limits = limits)
        val (_, code) = createPolicy(approval = true)
        val key = deviceKey()
        val requestId = submit(code, key, uid = "android-loop").json()["requestId"]!!.jsonPrimitive.content
        repeat(3) { assertEquals(HttpStatusCode.Accepted, pickup(requestId, key).status) }
        val limited = pickup(requestId, key)
        assertEquals(HttpStatusCode.TooManyRequests, limited.status)
        assertEquals("15", limited.headers[HttpHeaders.RetryAfter])
    }
}
