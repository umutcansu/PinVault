package com.example.pinvault.server

import com.example.pinvault.server.plugin.RevocationGate
import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.clientCertRevocationRoutes
import com.example.pinvault.server.route.vaultRoutes
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.respondText
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
import java.security.cert.CertificateFactory
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
 * Revoking a device cuts it off everywhere (Y4), and open enrollment never
 * takes over an enrolled identity (Y5):
 *  - open mode binds the device id, issues only over a CSR and refuses an
 *    enrolled id another key;
 *  - a key replaced by re-enrollment is retired;
 *  - revoke / forget revoke the device's vault tokens and delete its keys;
 *  - a revoked device gets no token file on a TLS listener, and an unauthenticated
 *    caller no answer that tells a revoked device id from any other;
 *  - the mock mTLS hosts refuse a revoked or retired certificate.
 */
class DeviceRevocationTest {

    private val scope = "api-a"
    private val otherScope = "api-b"

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var certsDir: File
    private lateinit var certService: CertificateService
    private lateinit var identityStore: ClientIdentityStore
    private lateinit var clientCertStore: ClientCertStore
    private lateinit var tokenStore: EnrollmentTokenStore
    private lateinit var auditStore: AuditLogStore
    private lateinit var audit: AuditLog
    private lateinit var signingService: ConfigSigningService
    private lateinit var files: VaultFileStore
    private lateinit var vaultTokens: VaultFileTokenStore
    private lateinit var keys: DevicePublicKeyStore
    private lateinit var tokenService: VaultAccessTokenService
    private var presented: X509Certificate? = null
    private val trustRefreshes = mutableListOf<String>()

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-revocation-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-revocation-certs-${System.nanoTime()}").also { it.mkdirs() }
        certService = CertificateService(certsDir)
        certService.ensureClientCa()
        identityStore = ClientIdentityStore(db)
        clientCertStore = ClientCertStore(db)
        tokenStore = EnrollmentTokenStore(db)
        auditStore = AuditLogStore(db)
        audit = AuditLog(auditStore, null)
        signingService = ConfigSigningService(File(certsDir, "signing.pem"))
        files = VaultFileStore(db)
        vaultTokens = VaultFileTokenStore(db)
        keys = DevicePublicKeyStore(db)
        tokenService = VaultAccessTokenService(vaultTokens)
        PinConfigStore(db).ensureConfigExists(scope)
    }

    @AfterTest
    fun tearDown() { dbFile.delete(); certsDir.deleteRecursively() }

    // ── helpers ──────────────────────────────────────────────────────────

    private fun ApplicationTestBuilder.configureApp(enrollmentMode: String = "token") {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        install(createApplicationPlugin("FakePeerCert") {
            onCall { call -> presented?.let { call.attributes.put(TLS_PEER_CERTIFICATE, it) } }
        })
        // As Main wires it on every listener that trusts the client CA.
        install(RevocationGate) {
            isRevoked = { id -> clientCertStore.get(id)?.revoked == true || identityStore.get(id)?.revoked == true }
            isRetiredKey = { cert -> identityStore.isRetired(certService.spkiSha256(cert.publicKey)) }
        }
        routing {
            certificateConfigRoutes(
                scope, PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signingService, ClientDeviceStore(db), certService, tokenStore, clientCertStore,
                enrollmentMode = enrollmentMode, audit = audit,
                clientIdentityStore = identityStore, clientCertTtl = { Duration.ofDays(90) }
            )
            clientCertRevocationRoutes(clientCertStore, identityStore, certService, audit) { reason, _ -> trustRefreshes += reason }
            vaultRoutes(scope, files, VaultDistributionStore(db), vaultTokens, keys, tokenService, VaultEncryptionService(),
                clientCertStore = clientCertStore, audit = audit,
                deviceRevoked = { identityStore.isDeviceRevoked(it) },
                deviceProven = { clientId, deviceId, proof -> identityStore.recordDeviceProof(clientId, deviceId, proof) })
            get("/probe") { call.respondText("ok") }
        }
    }

    private fun deviceKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun csr(key: KeyPair): String {
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
        return Base64.getEncoder().encodeToString(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded)
    }

    private fun rsaPem(): String {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public
        val body = Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    private suspend fun ApplicationTestBuilder.openEnroll(deviceId: String, key: KeyPair?, bodyDeviceUid: String? = null): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            if (key != null) header("X-PinVault-Features", "p12password,csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("deviceId", deviceId)
                bodyDeviceUid?.let { put("deviceUid", it) }
                key?.let { put("csr", csr(it)) }
            }.toString())
        }

    /** [boundTo]: the device id the administrator bound the token to (V20), which makes the binding proven. */
    private suspend fun ApplicationTestBuilder.tokenEnroll(clientId: String, key: KeyPair?, deviceUid: String? = null, boundTo: String? = null): HttpResponse =
        client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", if (key != null) "p12password,csr" else "p12password")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("token", tokenStore.create(clientId, boundTo))
                deviceUid?.let { put("deviceUid", it) }
                key?.let { put("csr", csr(it)) }
            }.toString())
        }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    private suspend fun HttpResponse.leaf(): X509Certificate {
        val pem = json()["chain"]!!.jsonArray[0].jsonPrimitive.content
        return CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()) as X509Certificate
    }

    private suspend fun ApplicationTestBuilder.download(key: String, deviceId: String?, token: String? = null): HttpResponse =
        client.get("/api/v1/vault/$key") {
            deviceId?.let { header("X-Device-Id", it) }
            token?.let { header("X-Vault-Token", it) }
        }

    private fun spki(key: KeyPair) = certService.spkiSha256(key.public)

    private fun actions() = auditStore.page(200, 0).map { it.action }

    // ── Y5: open enrollment never takes over an enrolled identity ────────

    @Test
    fun `open mode binds the device id and refuses an enrolled id another key`() = testApplication {
        configureApp(enrollmentMode = "open")
        val key = deviceKey()
        // The body naming another device is not this device's request (it used to
        // be overwritten silently while the attestation read the body's value).
        val other = openEnroll("android-a", key, bodyDeviceUid = "someone-else")
        assertEquals(HttpStatusCode.BadRequest, other.status)
        assertTrue(other.bodyAsText().contains("device_uid_mismatch"), other.bodyAsText())
        assertNull(clientCertStore.get("android-a"))
        // An open-mode id is bound to itself.
        assertEquals(HttpStatusCode.OK, openEnroll("android-a", key).status)
        assertTrue(clientCertStore.get("android-a")!!.deviceUidProven, "the device id is the client id")
        assertEquals("android-a", clientCertStore.get("android-a")!!.deviceUid)
        assertEquals("android-a", identityStore.get("android-a")!!.deviceUid)

        // The same key asking again (a lost answer) is served.
        assertEquals(HttpStatusCode.OK, openEnroll("android-a", key).status)

        // Anyone else naming the id is refused; the identity keeps its key.
        val takeover = openEnroll("android-a", deviceKey())
        assertEquals(HttpStatusCode.Conflict, takeover.status)
        assertEquals("identity_already_enrolled", takeover.json()["error"]!!.jsonPrimitive.content)
        assertEquals(spki(key), identityStore.get("android-a")!!.spkiSha256)
        assertFalse(identityStore.isRetired(spki(key)))
        assertTrue(actions().contains("client_cert_enroll_refused"))

        // Another id claiming this device in its body is refused (400), not bound to android-a.
        assertEquals(HttpStatusCode.BadRequest, openEnroll("android-b", deviceKey(), bodyDeviceUid = "android-a").status)
        assertNull(clientCertStore.get("android-b"))
    }

    @Test
    fun `open mode issues no P12, to a new id or an enrolled one`() = testApplication {
        configureApp(enrollmentMode = "open")
        val fresh = openEnroll("android-p12", key = null)
        assertEquals(HttpStatusCode.Forbidden, fresh.status)
        assertEquals("csr_required", fresh.json()["error"]!!.jsonPrimitive.content)
        assertNull(clientCertStore.get("android-p12"))
        assertNull(certService.getTrustStore()?.getCertificate("android-p12"), "no truststore entry")

        val key = deviceKey()
        assertEquals(HttpStatusCode.OK, openEnroll("android-c", key).status)
        assertEquals(HttpStatusCode.Forbidden, openEnroll("android-c", key = null).status)
        assertEquals(spki(key), identityStore.get("android-c")!!.spkiSha256)
        assertTrue(actions().count { it == "client_cert_enroll_refused" } >= 2)
    }

    @Test
    fun `an open-mode device enrolls again only after an administrator revoked and forgot it`() = testApplication {
        configureApp(enrollmentMode = "open")
        val old = deviceKey()
        assertEquals(HttpStatusCode.OK, openEnroll("android-d", old).status)
        assertEquals(HttpStatusCode.Conflict, openEnroll("android-d", deviceKey()).status)

        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/client-certs/android-d").status)
        assertEquals(HttpStatusCode.Forbidden, openEnroll("android-d", deviceKey()).status, "revoked stays revoked")
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/android-d/forget").status)

        val fresh = deviceKey()
        assertEquals(HttpStatusCode.OK, openEnroll("android-d", fresh).status)
        assertEquals(spki(fresh), identityStore.get("android-d")!!.spkiSha256)
        assertTrue(identityStore.isRetired(spki(old)))
    }

    @Test
    fun `the open-mode write itself refuses another key, so a racing request cannot replace it`() {
        val now = Instant.now().toString()
        assertTrue(identityStore.register("race", scope, "spki-1", "01", now, now, null, "race", now, replaceKey = false))
        assertFalse(identityStore.register("race", scope, "spki-2", "02", now, now, null, "race", now, replaceKey = false))
        assertEquals("spki-1", identityStore.get("race")!!.spkiSha256)
        assertFalse(identityStore.isRetired("spki-1"), "a refused write retires nothing")
        assertTrue(identityStore.register("race", scope, "spki-1", "03", now, now, null, "race", now, replaceKey = false),
            "the same key again")
    }

    // ── Y4.4: a replaced key is retired ──────────────────────────────────

    @Test
    fun `token re-enrollment of the same id retires the replaced key and its certificate is refused`() = testApplication {
        configureApp()
        val first = deviceKey()
        val second = deviceKey()
        val oldLeaf = tokenEnroll("tablet-r", first, deviceUid = "android-r").leaf()
        val newResponse = tokenEnroll("tablet-r", second, deviceUid = "android-r")
        assertEquals(HttpStatusCode.OK, newResponse.status)
        val newLeaf = newResponse.leaf()

        assertTrue(identityStore.isRetired(spki(first)))
        assertFalse(identityStore.isRetired(spki(second)))
        val issued = auditStore.page(50, 0).first { it.action == "client_cert_issued" }
        assertTrue(issued.detail.toString().contains(spki(first)), "the audit entry names the retired key")

        presented = oldLeaf
        val refused = client.get("/probe")
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertTrue(refused.bodyAsText().contains("reenroll_required"))
        presented = newLeaf
        assertEquals(HttpStatusCode.OK, client.get("/probe").status)
        presented = null

        // The retired key never enrolls again, under any id.
        assertEquals(HttpStatusCode.Forbidden, tokenEnroll("tablet-elsewhere", first).status)
    }

    @Test
    fun `a P12 re-enrollment of a CSR id retires the identity it replaces`() = testApplication {
        configureApp()
        val key = deviceKey()
        assertEquals(HttpStatusCode.OK, tokenEnroll("dual", key).status)
        assertEquals(HttpStatusCode.OK, tokenEnroll("dual", key = null).status)
        assertNull(identityStore.get("dual"), "the P12 replaced the CSR identity")
        assertTrue(identityStore.isRetired(spki(key)))
        assertEquals("p12", clientCertStore.get("dual")!!.keyType)
        assertTrue(actions().contains("client_cert_key_replaced"))
    }

    // ── Y4.1: revoke and forget cut the device off the vault ─────────────

    @Test
    fun `revoking cuts the device off the vault in every scope, and no other device`() = testApplication {
        configureApp()
        // The device's E2E key, on file before the identity was enrolled.
        val deviceE2eKey = rsaPem()
        keys.register("android-r", scope, deviceE2eKey, timestamp = Instant.now().minusSeconds(60).toString())
        val enrolled = tokenEnroll("tablet-1", deviceKey(), deviceUid = "android-r")
        assertEquals(HttpStatusCode.OK, enrolled.status)
        val leaf = enrolled.leaf()
        val now = Instant.now().toString()
        files.put(scope, "f1", "a".toByteArray(), "token", "plain")
        files.put(otherScope, "f2", "b".toByteArray(), "token", "plain")
        val t1 = tokenService.generate(scope, "f1", "android-r")
        val t2 = tokenService.generate(otherScope, "f2", "android-r")
        val bystander = tokenService.generate(scope, "f1", "android-other")
        keys.register("android-r", otherScope, rsaPem(), timestamp = now)
        keys.userAuthKeys().register("android-r", scope, rsaPem(), timestamp = now)
        keys.register("android-other", scope, rsaPem(), timestamp = now)
        keys.userAuthKeys().register("android-other", scope, rsaPem(), timestamp = now)

        // The key the device had on file, sent again over the certificate, proves
        // nothing any more: it is a public key.
        presented = leaf
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/vault/devices/android-r/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", deviceE2eKey) }.toString())
        }.status)
        assertEquals(emptyList<String>(), identityStore.provenDevices("tablet-1"))
        // The device's own token used over the certificate does.
        assertEquals(HttpStatusCode.OK, download("f1", "android-r", t1.plaintext).status)
        presented = null
        assertEquals(listOf("android-r"), identityStore.provenDevices("tablet-1"))

        val response = client.delete("/api/v1/client-certs/tablet-1")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.json()
        assertTrue(body["unverifiedDeviceIds"]!!.jsonArray.isEmpty())
        assertEquals(2, body["vaultTokensRevoked"]!!.jsonPrimitive.int)
        assertEquals(2, body["e2eKeysDeleted"]!!.jsonPrimitive.int)
        assertEquals(1, body["userAuthKeysDeleted"]!!.jsonPrimitive.int)

        assertTrue(clientCertStore.get("tablet-1")!!.revoked)
        assertTrue(identityStore.get("tablet-1")!!.revoked)
        assertFalse(vaultTokens.validate(scope, "f1", "android-r", t1.plaintext))
        assertFalse(vaultTokens.validate(otherScope, "f2", "android-r", t2.plaintext))
        assertNull(keys.get("android-r", scope))
        assertNull(keys.get("android-r", otherScope))
        assertNull(keys.userAuthKeys().get("android-r", scope))
        // Nobody else lost anything.
        assertTrue(vaultTokens.validate(scope, "f1", "android-other", bystander.plaintext))
        assertNotNull(keys.get("android-other", scope))
        assertNotNull(keys.userAuthKeys().get("android-other", scope))

        val entry = auditStore.page(50, 0).first { it.action == "client_cert_revoked" }
        assertTrue(entry.summary.contains("android-r"))
        assertTrue(trustRefreshes.isEmpty(), "a CSR identity has no truststore entry: no listener restart")
    }

    @Test
    fun `a revoked device gets no token file, even with the token it still holds`() = testApplication {
        configureApp()
        val leaf2 = tokenEnroll("tablet-2", deviceKey(), deviceUid = "android-s").leaf()
        files.put(scope, "tok", "token-file".toByteArray(), "token", "plain")
        files.put(scope, "e2e", "e2e-file".toByteArray(), "public", "end_to_end")
        files.put(scope, "open", "public-file".toByteArray(), "public", "plain")
        val token = tokenService.generate(scope, "tok", "android-s").plaintext
        keys.register("android-s", scope, rsaPem(), timestamp = Instant.now().toString())
        // The device's token used over the identity's certificate: proof it is that identity's device.
        presented = leaf2
        assertEquals(HttpStatusCode.OK, download("tok", "android-s", token).status)
        presented = null
        assertEquals(listOf("android-s"), identityStore.provenDevices("tablet-2"))
        assertEquals(HttpStatusCode.OK, download("e2e", "android-s").status)

        // Revoked in the identity tables only: as if the token revocation had not reached it.
        clientCertStore.revoke("tablet-2")
        identityStore.revoke("tablet-2")
        // With the token it still holds: told to enroll again.
        val refused = download("tok", "android-s", token)
        assertEquals(HttpStatusCode.Forbidden, refused.status)
        assertEquals("reenroll_required", refused.json()["error"]!!.jsonPrimitive.content)
        // A file nobody authenticates for: revocation plays no part, the answer is the
        // one any device id with a key on file gets (a real revocation deletes the keys:
        // see the end of this test).
        val e2e = download("e2e", "android-s")
        assertEquals(HttpStatusCode.OK, e2e.status)
        assertEquals(HttpStatusCode.OK, download("open", "android-s").status, "a public plain file is nobody's")
        // A key change without proof: the answer any device id with a key gets.
        val keyRefused = client.post("/api/v1/vault/devices/android-s/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", rsaPem()) }.toString())
        }
        assertEquals(HttpStatusCode.Conflict, keyRefused.status)
        assertFalse(keyRefused.bodyAsText().contains("reenroll_required"))
        // With the device's token as proof: told to enroll again.
        val e2eToken = tokenService.generate(scope, "e2e", "android-s").plaintext
        val keyWithProof = client.post("/api/v1/vault/devices/android-s/public-key") {
            contentType(ContentType.Application.Json)
            header("X-Vault-Key", "e2e"); header("X-Vault-Token", e2eToken)
            setBody(buildJsonObject { put("publicKeyPem", rsaPem()) }.toString())
        }
        assertEquals(HttpStatusCode.Forbidden, keyWithProof.status)
        assertTrue(keyWithProof.bodyAsText().contains("reenroll_required"))

        // Enrolled again under a new id that only CLAIMS the device: still revoked —
        // any token holder naming the device id used to lift the block.
        assertEquals(HttpStatusCode.OK, tokenEnroll("tablet-claim", deviceKey(), deviceUid = "android-s").status)
        assertTrue(identityStore.isDeviceRevoked("android-s"))
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/client-certs/tablet-claim").status)
        // Enrolled again with a token bound to the device: proven, served again.
        val leaf3 = tokenEnroll("tablet-3", deviceKey(), deviceUid = "android-s", boundTo = "android-s").leaf()
        presented = leaf3
        assertEquals(HttpStatusCode.OK, download("tok", "android-s", token).status)
        presented = null
        // Forgetting the old id leaves what the active identity's device holds.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/tablet-2/forget").status)
        assertEquals(HttpStatusCode.OK, download("e2e", "android-s").status)

        // Revoking the new one (which proved the device over its certificate)
        // takes the tokens and keys; once forgotten, the device is no longer
        // "revoked" — and has nothing left to download with.
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/client-certs/tablet-3").status)
        assertEquals(HttpStatusCode.Unauthorized, download("tok", "android-s", token).status, "its token was revoked")
        assertTrue(identityStore.isDeviceRevoked("android-s"))
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/tablet-3/forget").status)
        assertFalse(identityStore.isDeviceRevoked("android-s"))
        assertEquals(HttpStatusCode.Unauthorized, download("tok", "android-s", token).status)
        assertEquals(HttpStatusCode.PreconditionFailed, download("e2e", "android-s").status)
    }

    @Test
    fun `revocation leaves a device id the identity only claimed alone, unless an administrator cascades`() = testApplication {
        configureApp()
        // Someone enrolls naming a victim's device id, never proving it.
        assertEquals(HttpStatusCode.OK, tokenEnroll("intruder", deviceKey(), deviceUid = "victim").status)
        files.put(scope, "tok", "x".toByteArray(), "token", "plain")
        val victimToken = tokenService.generate(scope, "tok", "victim").plaintext
        keys.register("victim", scope, rsaPem(), timestamp = Instant.now().toString())
        keys.userAuthKeys().register("victim", scope, rsaPem(), timestamp = Instant.now().toString())

        val revoked = client.delete("/api/v1/client-certs/intruder").json()
        assertEquals(listOf("victim"), revoked["unverifiedDeviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("intruder"), revoked["deviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(0, revoked["vaultTokensRevoked"]!!.jsonPrimitive.int)
        assertTrue(vaultTokens.validate(scope, "tok", "victim", victimToken))
        assertNotNull(keys.get("victim", scope))
        assertNotNull(keys.userAuthKeys().get("victim", scope))
        assertFalse(identityStore.isDeviceRevoked("victim"))
        assertEquals(HttpStatusCode.OK, download("tok", "victim", victimToken).status, "the victim is not blocked")
        assertTrue(auditStore.page(20, 0).first { it.action == "client_cert_revoked" }.summary.contains("only claimed left alone: victim"))

        // The administrator decides the claimed id really is that identity's device.
        val cascaded = client.delete("/api/v1/client-certs/intruder?cascadeUnverified=true").json()
        assertTrue(cascaded["unverifiedDeviceIds"]!!.jsonArray.isEmpty())
        assertEquals(1, cascaded["vaultTokensRevoked"]!!.jsonPrimitive.int)
        assertEquals(1, cascaded["e2eKeysDeleted"]!!.jsonPrimitive.int)
        assertEquals(1, cascaded["userAuthKeysDeleted"]!!.jsonPrimitive.int)
        assertTrue(identityStore.isDeviceRevoked("victim"))
        val fresh = tokenService.generate(scope, "tok", "victim").plaintext
        assertEquals(HttpStatusCode.Forbidden, download("tok", "victim", fresh).status)
    }

    @Test
    fun `a key registered over a certificate that only claims a device proves nothing`() = testApplication {
        configureApp()
        // The victim's own E2E key and token, on file before the intruder came.
        val victimKey = rsaPem()
        keys.register("victim", scope, victimKey, timestamp = Instant.now().minusSeconds(60).toString())
        files.put(scope, "tok", "x".toByteArray(), "token", "plain")
        val victimToken = tokenService.generate(scope, "tok", "victim").plaintext
        // Someone enrolls naming the victim's device id, then registers keys "for" it over that certificate.
        val leaf = tokenEnroll("intruder", deviceKey(), deviceUid = "victim").leaf()
        val intruderKey = rsaPem()
        presented = leaf
        for (attempt in 1..2) {
            // A new key: the certificate only CLAIMS the device (V20), so it replaces
            // nothing — it used to, and every file sealed for the victim was the intruder's.
            assertEquals(HttpStatusCode.Conflict, client.post("/api/v1/vault/devices/victim/public-key") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("publicKeyPem", intruderKey) }.toString())
            }.status, "attempt $attempt")
        }
        assertTrue(keys.get("victim", scope)!!.publicKeyPem.contains(victimKey.lines()[1].take(20)), "the victim keeps its key")
        // The victim's key sent back (it is public): a no-op, and no proof either.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/vault/devices/victim/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", victimKey) }.toString())
        }.status)
        // A user-auth key too, first registration and again.
        repeat(2) {
            client.post("/api/v1/vault/devices/victim/public-key") {
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("publicKeyPem", intruderKey); put("purpose", "user_auth") }.toString())
            }
        }
        presented = null
        assertEquals(emptyList<String>(), identityStore.provenDevices("intruder"), "registering its own keys proves nothing")

        // Revoking the intruder leaves the victim alone.
        val revoked = client.delete("/api/v1/client-certs/intruder").json()
        assertEquals(listOf("victim"), revoked["unverifiedDeviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertFalse(identityStore.isDeviceRevoked("victim"))
        assertTrue(vaultTokens.validate(scope, "tok", "victim", victimToken))
        assertEquals(HttpStatusCode.OK, download("tok", "victim", victimToken).status)
    }

    @Test
    fun `a key registered over a certificate together with the device's token proves the device`() = testApplication {
        configureApp()
        val leaf = tokenEnroll("tablet-t", deviceKey(), deviceUid = "android-t").leaf()
        files.put(scope, "e2e", "x".toByteArray(), "token", "end_to_end")
        val token = tokenService.generate(scope, "e2e", "android-t").plaintext
        presented = leaf
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/vault/devices/android-t/public-key") {
            contentType(ContentType.Application.Json)
            header("X-Vault-Key", "e2e"); header("X-Vault-Token", token)
            setBody(buildJsonObject { put("publicKeyPem", rsaPem()) }.toString())
        }.status)
        presented = null
        assertEquals(listOf("android-t"), identityStore.provenDevices("tablet-t"))
    }

    @Test
    fun `forget reports the device ids an identity only claimed and leaves them alone`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, tokenEnroll("claimer", deviceKey(), deviceUid = "android-c2").status)
        files.put(scope, "tok", "x".toByteArray(), "token", "plain")
        val token = tokenService.generate(scope, "tok", "android-c2").plaintext
        identityStore.revoke("claimer")
        clientCertStore.revoke("claimer")
        // What the dashboard asks before forgetting (read only).
        val devices = client.get("/api/v1/client-certs/claimer/devices").json()
        assertEquals(listOf("claimer"), devices["deviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("android-c2"), devices["unverifiedDeviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertTrue(vaultTokens.validate(scope, "tok", "android-c2", token), "asking changed nothing")
        assertEquals(HttpStatusCode.NotFound, client.get("/api/v1/client-certs/nobody/devices").status)
        val forgotten = client.post("/api/v1/client-certs/claimer/forget").json()
        assertEquals(listOf("android-c2"), forgotten["unverifiedDeviceIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertTrue(vaultTokens.validate(scope, "tok", "android-c2", token))
    }

    @Test
    fun `nobody without a credential learns whether a device id was revoked`() = testApplication {
        configureApp()
        val leaf = tokenEnroll("tablet-x", deviceKey(), deviceUid = "android-x").leaf()
        files.put(scope, "tok", "x".toByteArray(), "token", "plain")
        files.put(scope, "e2e", "y".toByteArray(), "public", "end_to_end")
        presented = leaf
        assertEquals(HttpStatusCode.OK, download("tok", "android-x", tokenService.generate(scope, "tok", "android-x").plaintext).status)
        presented = null
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/client-certs/tablet-x").status)
        assertTrue(identityStore.isDeviceRevoked("android-x"))

        // A revoked id and one never seen get the same answers — to every request
        // of the sequence, not only the first: a second key, and the file afterwards.
        suspend fun register(device: String, purpose: String? = null) = client.post("/api/v1/vault/devices/$device/public-key") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("publicKeyPem", rsaPem()); purpose?.let { put("purpose", it) } }.toString())
        }
        val answers = listOf("android-x", "android-never-seen").map { device ->
            buildList {
                add(download("tok", device).status)
                add(download("tok", device, "not-a-token").status)
                add(download("e2e", device).status)
                val first = register(device)
                add(first.status)
                add(first.json()["registered"]?.jsonPrimitive?.content)
                // Another key without proof: the first one stays.
                val second = register(device)
                add(second.status)
                add(second.json()["error"]?.jsonPrimitive?.content)
                // The public end_to_end file, now that a key is on file.
                add(download("e2e", device).status)
                add(register(device, "user_auth").status)
                add(register(device, "user_auth").status)
            }
        }
        assertEquals(listOf<Any?>(
            HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.PreconditionFailed,
            HttpStatusCode.OK, "true", HttpStatusCode.Conflict, "key_change_requires_proof",
            HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.Conflict
        ), answers[1], "an id never seen")
        assertEquals(answers[1], answers[0], "a revoked id answers exactly like one never seen")
        // What an administrator reads says which registration was for a revoked id.
        assertTrue(auditStore.page(50, 0).any { it.action == "device_key_registered" && it.summary.contains("identity was revoked") })
        // A caller with the device's (newly issued) token is told to enroll again.
        val issued = tokenService.generate(scope, "tok", "android-x").plaintext
        assertEquals("reenroll_required", download("tok", "android-x", issued).json()["error"]!!.jsonPrimitive.content)
    }

    // ── Enrollment vs revocation ─────────────────────────────────────────

    @Test
    fun `an enrollment never writes over a revoked certificate row`() {
        val now = Instant.now().toString()
        // The identity and its client_certs row go in one transaction.
        assertTrue(identityStore.register("racer", scope, "spki-r1", "01", now, now, null, "android-race", now,
            certRecord = ClientIdentityStore.CertRecord("PinVault Client: racer", "fp-1")))
        assertEquals("fp-1", clientCertStore.get("racer")!!.fingerprint)
        assertFalse(clientCertStore.get("racer")!!.revoked)

        // Revoked (both tables) between an enrollment's checks and its writes:
        identityStore.revokeWithDevices("racer")
        // the CSR path's single transaction refuses and writes nothing,
        assertFalse(identityStore.register("racer", scope, "spki-r2", "02", now, now, null, "android-race", now,
            certRecord = ClientIdentityStore.CertRecord("PinVault Client: racer", "fp-2")))
        // the P12 path's upsert leaves the row revoked.
        assertFalse(clientCertStore.addUnlessRevoked("racer", "PinVault Client: racer", "fp-3", now))
        assertTrue(clientCertStore.get("racer")!!.revoked)
        assertEquals("fp-1", clientCertStore.get("racer")!!.fingerprint)
        assertTrue(identityStore.get("racer")!!.revoked)

        // A client_certs row revoked on its own (a legacy P12 revoked) also stops a CSR registration of that id.
        clientCertStore.add("legacy", "PinVault Client: legacy", "fp-l", now)
        clientCertStore.revoke("legacy")
        assertFalse(identityStore.register("legacy", scope, "spki-l", "03", now, now, null, null, now,
            certRecord = ClientIdentityStore.CertRecord("PinVault Client: legacy", "fp-l2")))
        assertNull(identityStore.get("legacy"), "rolled back")
        assertTrue(clientCertStore.get("legacy")!!.revoked)
        // A fresh id is written as before.
        assertTrue(clientCertStore.addUnlessRevoked("fresh", "PinVault Client: fresh", "fp-f", now))
        assertFalse(clientCertStore.get("fresh")!!.revoked)
    }

    @Test
    fun `forgetting an identity revoked before revocation cut devices off does it then`() = testApplication {
        configureApp()
        assertEquals(HttpStatusCode.OK, tokenEnroll("tablet-old", deviceKey(), deviceUid = "android-o").status)
        files.put(scope, "tok", "x".toByteArray(), "token", "plain")
        val token = tokenService.generate(scope, "tok", "android-o").plaintext
        keys.userAuthKeys().register("android-o", scope, rsaPem(), timestamp = Instant.now().toString())
        clientCertStore.revoke("tablet-old")
        identityStore.revoke("tablet-old")

        // It only claimed the device id: the administrator cascades deliberately.
        val forgotten = client.post("/api/v1/client-certs/tablet-old/forget?cascadeUnverified=true")
        assertEquals(HttpStatusCode.OK, forgotten.status)
        assertEquals(1, forgotten.json()["vaultTokensRevoked"]!!.jsonPrimitive.int)
        assertEquals(1, forgotten.json()["userAuthKeysDeleted"]!!.jsonPrimitive.int)
        assertFalse(vaultTokens.validate(scope, "tok", "android-o", token))
        assertNull(keys.userAuthKeys().get("android-o", scope))
        assertTrue(actions().contains("client_identity_forgotten"))
    }

    // ── Y4.2: the mock mTLS hosts refuse revoked and retired identities ──

    private fun chainFor(clientId: String, key: KeyPair, register: Boolean = true): List<X509Certificate> {
        val parsed = certService.parseCsr(Base64.getDecoder().decode(csr(key)))
        val issued = certService.issueClientCertificate(clientId, parsed, Duration.ofDays(1))
        if (register) {
            val now = Instant.now().toString()
            assertTrue(identityStore.register(clientId, scope, issued.spkiSha256, issued.serialHex,
                issued.notBefore.toString(), issued.notAfter.toString(), null, null, now))
            clientCertStore.add(clientId, issued.commonName, issued.fingerprint, now)
        }
        return listOf(issued.leaf, issued.issuer)
    }

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
        return http.send(
            HttpRequest.newBuilder(URI("https://127.0.0.1:$port/health")).timeout(Duration.ofSeconds(5)).GET().build(),
            JdkResponse.BodyHandlers.ofString()
        ).statusCode()
    }

    @Test
    fun `a mock mTLS host refuses a revoked identity and a retired key on every request`() {
        val mocks = MockServerManager()
        mocks.revocationGate = {
            isRevoked = { id -> clientCertStore.get(id)?.revoked == true || identityStore.get(id)?.revoked == true }
            isRetiredKey = { cert -> identityStore.isRetired(certService.spkiSha256(cert.publicKey)) }
        }
        val keystore = certService.generateCertificate("mockhost", "localhost").keystorePath
        val port = java.net.ServerSocket(0).use { it.localPort }
        mocks.start("mock.test", port, keystore, certService.getTrustStoreFile().absolutePath)
        try {
            val key = deviceKey()
            val chain = chainFor("mock-dev", key)
            assertEquals(200, health(port, key, chain))
            identityStore.revoke("mock-dev")
            assertEquals(403, health(port, key, chain), "revoked: refused although the handshake still succeeds")

            // Re-enrolled over a new key: the old one is retired, its certificate refused.
            val oldKey = deviceKey()
            val oldChain = chainFor("mock-dev2", oldKey)
            val newKey = deviceKey()
            val newChain = chainFor("mock-dev2", newKey)
            assertEquals(403, health(port, oldKey, oldChain))
            assertEquals(200, health(port, newKey, newChain))
        } finally {
            mocks.stopAll()
        }
    }

    // ── D-A1: a device id is proven, not claimed ─────────────────────────

    @Test
    fun `a token bound to a device enrolls that device only, and its binding is proven`() = testApplication {
        configureApp()
        // Another device id than the one the administrator bound the token to: refused, token unspent.
        val token = tokenStore.create("bound-tablet", "android-bound")
        val wrong = client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("token", token); put("deviceUid", "victim"); put("csr", csr(deviceKey())) }.toString())
        }
        assertEquals(HttpStatusCode.Forbidden, wrong.status)
        assertEquals("device_uid_mismatch", wrong.json()["error"]!!.jsonPrimitive.content)
        assertEquals("bound-tablet", tokenStore.validate(token), "not spent by the refusal")
        // The bound device: issued, and the binding counts for its keys and files.
        val right = client.post("/api/v1/client-certs/enroll") {
            header("X-PinVault-Features", "csr")
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("token", token); put("deviceUid", "android-bound"); put("csr", csr(deviceKey())) }.toString())
        }
        assertEquals(HttpStatusCode.OK, right.status)
        assertTrue(clientCertStore.get("bound-tablet")!!.deviceUidProven)
        assertTrue(com.example.pinvault.server.route.certificateProvenFor("bound-tablet", "android-bound", clientCertStore))
        // A token without a binding: the device id is a claim.
        assertEquals(HttpStatusCode.OK, tokenEnroll("claim-tablet", deviceKey(), deviceUid = "android-claim").status)
        assertFalse(clientCertStore.get("claim-tablet")!!.deviceUidProven)
        assertTrue(com.example.pinvault.server.route.certificateBoundTo("claim-tablet", "android-claim", clientCertStore), "bound for reports")
        assertFalse(com.example.pinvault.server.route.certificateProvenFor("claim-tablet", "android-claim", clientCertStore), "not for its keys")
    }

    // ── D-A8: one active identity per device, decided in the write ───────

    @Test
    fun `two identities cannot both hold one device id, whatever was checked before`() {
        assertTrue(clientCertStore.addUnlessRevoked("first", "cn", "fp1", Instant.now().toString(), deviceUid = "android-race"))
        // The second write lost the race the route's check could not see.
        assertFalse(clientCertStore.addUnlessRevoked("second", "cn", "fp2", Instant.now().toString(), deviceUid = "android-race"))
        assertNull(clientCertStore.get("second"))
        // An open-mode row from before device_uid was written holds its own id as the device.
        assertTrue(clientCertStore.addUnlessRevoked("android-legacy", "cn", "fp3", Instant.now().toString()))
        assertEquals("android-legacy", clientCertStore.activeHolderOf("android-legacy", exceptId = "other"))
        assertFalse(clientCertStore.addUnlessRevoked("third", "cn", "fp4", Instant.now().toString(), deviceUid = "android-legacy"))
        // The holder itself enrolls again: fine.
        assertTrue(clientCertStore.addUnlessRevoked("first", "cn", "fp5", Instant.now().toString(), deviceUid = "android-race"))
    }

    // ── D-A2: a device asking again gets what it has ─────────────────────

    @Test
    fun `open mode answers the same key asking again with the certificate it was given`() = testApplication {
        configureApp(enrollmentMode = "open")
        val key = deviceKey()
        val first = openEnroll("android-again", key).json()["serial"]!!.jsonPrimitive.content
        repeat(3) {
            val again = openEnroll("android-again", key)
            assertEquals(HttpStatusCode.OK, again.status)
            assertEquals(first, again.json()["serial"]!!.jsonPrimitive.content, "no new signature")
        }
        assertEquals(1, actions().count { it == "client_cert_issued" }, "one issuance, one audit entry")
    }

    // ── D-A9: a renewal is not replayed ───────────────────────────────────

    @Test
    fun `the same renewal request sent twice renews once`() = testApplication {
        configureApp()
        val key = deviceKey()
        assertEquals(HttpStatusCode.OK, tokenEnroll("renewer", key, deviceUid = "android-renew").status)
        val body = buildJsonObject { put("clientId", "renewer"); put("csr", csr(key)) }.toString()
        suspend fun renew() = client.post("/api/v1/client-certs/renew") {
            contentType(ContentType.Application.Json); setBody(body)
        }
        assertEquals(HttpStatusCode.OK, renew().status)
        // A copy of the request (the recovery door asks for no certificate: the signed CSR is the proof).
        val replay = renew()
        assertEquals(HttpStatusCode.Forbidden, replay.status)
        assertEquals("reenroll_required", replay.json()["error"]!!.jsonPrimitive.content)
        assertEquals(1, identityStore.get("renewer")!!.renewCount)
        // A fresh CSR over the same key (ECDSA: a new signature) renews.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/renew") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject { put("clientId", "renewer"); put("csr", csr(key)) }.toString())
        }.status)
    }

    // ── K04: issuing puts the client CA back into a missing truststore ───

    @Test
    fun `issuing a client certificate recreates a missing client truststore`() = testApplication {
        configureApp()
        assertTrue(certService.getTrustStoreFile().delete(), "an operator moved it away")
        assertNull(certService.getTrustStore())
        assertEquals(HttpStatusCode.OK, tokenEnroll("after-move", deviceKey(), deviceUid = "android-move").status)
        assertTrue(certService.getTrustStoreFile().exists())
        assertNotNull(certService.getTrustStore()!!.getCertificate(CertificateService.CLIENT_CA_ALIAS))
        // The server-made P12 path too.
        assertTrue(certService.getTrustStoreFile().delete())
        certService.generateClientCertificate("p12-after-move", "pw")
        assertNotNull(certService.getTrustStore()!!.getCertificate(CertificateService.CLIENT_CA_ALIAS))
    }
}
