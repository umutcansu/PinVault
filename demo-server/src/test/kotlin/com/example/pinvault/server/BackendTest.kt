package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.*

/**
 * C.16-24: Backend E2E testleri
 * Host CRUD, mTLS toggle, client cert upload/download, config API
 */
class BackendTest {

    private lateinit var db: DatabaseManager
    private lateinit var pinConfigStore: PinConfigStore
    private lateinit var historyStore: PinConfigHistoryStore
    private lateinit var connectionStore: ConnectionHistoryStore
    private lateinit var clientDeviceStore: ClientDeviceStore
    private lateinit var hostStore: HostStore
    private lateinit var certService: CertificateService
    private lateinit var mockServerManager: MockServerManager
    private lateinit var hostClientCertStore: HostClientCertStore
    private lateinit var signingService: ConfigSigningService

    private val configApiId = "test-tls"
    private val testPin1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val testPin2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    private lateinit var dbFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-test-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        pinConfigStore = PinConfigStore(db)
        historyStore = PinConfigHistoryStore(db)
        connectionStore = ConnectionHistoryStore(db)
        clientDeviceStore = ClientDeviceStore(db)
        hostStore = HostStore(db)
        hostClientCertStore = HostClientCertStore(db)
        mockServerManager = MockServerManager()

        clientCertStore = ClientCertStore(db)
        enrollmentTokenStore = EnrollmentTokenStore(db)

        val certsDir = File(System.getProperty("java.io.tmpdir"), "pinvault-test-certs-${System.nanoTime()}")
        certsDir.mkdirs()
        certService = CertificateService(certsDir)

        val signingKeyFile = File(System.getProperty("java.io.tmpdir"), "test-signing-key-${System.nanoTime()}.pem")
        signingService = ConfigSigningService(signingKeyFile)

        pinConfigStore.ensureConfigExists(configApiId)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
    }

    private lateinit var clientCertStore: ClientCertStore
    private lateinit var enrollmentTokenStore: EnrollmentTokenStore

    private fun ApplicationTestBuilder.configureApp(
        enrollmentMode: String = "token",
        configApiMode: String = "tls"
    ) {
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(
                configApiId, pinConfigStore, historyStore, connectionStore,
                signingService, clientDeviceStore, certService, enrollmentTokenStore,
                clientCertStore, mockServerManager, hostClientCertStore,
                enrollmentMode = enrollmentMode, configApiMode = configApiMode
            )
            hostRoutes(
                configApiId, pinConfigStore, hostStore, historyStore,
                certService, mockServerManager, hostClientCertStore
            )
        }
    }

    // ── C.16: Host CRUD ─────────────────────────────────

    @Test
    fun `C16 — host generate-cert creates host and pins`() = testApplication {
        configureApp()
        val response = client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"test.example.com"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("test.example.com", body["hostname"]?.jsonPrimitive?.content)
        assertTrue(body["sha256Pins"]?.jsonArray?.isNotEmpty() == true)
    }

    @Test
    fun `C16 — duplicate hostname rejected`() = testApplication {
        configureApp()
        // Create first
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"dup.test"}""")
        }
        // Duplicate
        val response = client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"dup.test"}""")
        }
        assertEquals(HttpStatusCode.Conflict, response.status)
    }

    // ── C.17: mTLS Toggle ───────────────────────────────

    @Test
    fun `C17 — toggle mtls on and off`() = testApplication {
        configureApp()

        // Create host first
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"mtls-toggle.test"}""")
        }

        // Toggle ON
        val onResp = client.post("/api/v1/hosts/mtls-toggle.test/toggle-mtls") {
            contentType(ContentType.Application.Json)
            setBody("""{"mtls":true}""")
        }
        assertEquals(HttpStatusCode.OK, onResp.status)
        val onBody = Json.parseToJsonElement(onResp.bodyAsText()).jsonObject
        assertTrue(onBody["mtls"]?.jsonPrimitive?.boolean == true)

        // Verify config
        val config = pinConfigStore.load(configApiId)
        val pin = config.pins.find { it.hostname == "mtls-toggle.test" }
        assertNotNull(pin)
        assertTrue(pin!!.mtls)

        // Toggle OFF
        val offResp = client.post("/api/v1/hosts/mtls-toggle.test/toggle-mtls") {
            contentType(ContentType.Application.Json)
            setBody("""{"mtls":false}""")
        }
        assertEquals(HttpStatusCode.OK, offResp.status)
        val updatedConfig = pinConfigStore.load(configApiId)
        assertFalse(updatedConfig.pins.find { it.hostname == "mtls-toggle.test" }!!.mtls)
    }

    // ── C.19: Client cert download ──────────────────────

    @Test
    fun `C19 — client cert download returns 404 when no cert`() = testApplication {
        configureApp(configApiMode = "mtls")
        val response = client.get("/api/v1/client-certs/nonexistent.host/download")
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `C19 — client cert download via hosts endpoint`() = testApplication {
        configureApp()
        // Create host
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"dl.test"}""")
        }

        // No cert yet
        val noResp = client.get("/api/v1/hosts/dl.test/client-cert/download")
        assertEquals(HttpStatusCode.NotFound, noResp.status)
    }

    // ── C.20: Config API ────────────────────────────────

    @Test
    fun `C20 — GET certificate-config returns signed config`() = testApplication {
        configureApp()
        // Add a host so config is not empty
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"config.test"}""")
        }

        val response = client.get("/api/v1/certificate-config")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        // Signed response has payload + signature
        assertNotNull(body["payload"])
        assertNotNull(body["signature"])
    }

    @Test
    fun `C20 — PUT certificate-config updates pins`() = testApplication {
        configureApp()
        val newConfig = PinConfig(
            version = 1,
            pins = listOf(HostPin("new.host", listOf(testPin1, testPin2), version = 1))
        )
        val response = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(PinConfig.serializer(), newConfig))
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val stored = pinConfigStore.load(configApiId)
        assertEquals(1, stored.pins.size)
        assertEquals("new.host", stored.pins[0].hostname)
    }

    @Test
    fun `C20 — PUT with duplicate hostname rejected`() = testApplication {
        configureApp()
        val badConfig = PinConfig(
            version = 1,
            pins = listOf(
                HostPin("same.host", listOf(testPin1, testPin2)),
                HostPin("same.host", listOf(testPin1, testPin2))
            )
        )
        val response = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(PinConfig.serializer(), badConfig))
        }
        assertEquals(HttpStatusCode.Conflict, response.status)
    }

    @Test
    fun `C20 — PUT with less than 2 pins rejected`() = testApplication {
        configureApp()
        val badConfig = PinConfig(
            version = 1,
            pins = listOf(HostPin("bad.host", listOf(testPin1)))
        )
        val response = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json)
            setBody(Json.encodeToString(PinConfig.serializer(), badConfig))
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    // ── C.22: Bağlantı Geçmişi ─────────────────────────

    @Test
    fun `C23 — connection history — client report saved`() = testApplication {
        configureApp()
        val reportJson = """
            {
                "hostname":"api.test",
                "status":"healthy",
                "responseTimeMs":42,
                "pinMatched":true,
                "pinVersion":3,
                "deviceManufacturer":"Google",
                "deviceModel":"Pixel 7"
            }
        """.trimIndent()
        val response = client.post("/api/v1/connection-history/client-report") {
            contentType(ContentType.Application.Json)
            setBody(reportJson)
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val history = connectionStore.getAll()
        assertTrue(history.isNotEmpty())
        assertEquals("android", history[0].source)
        assertEquals("healthy", history[0].status)
    }

    // ── C.24: Cert rotation ─────────────────────────────

    @Test
    fun `C24 — regenerate cert changes pins and increments version`() = testApplication {
        configureApp()
        // Create host
        val createResp = client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"rotate.test"}""")
        }
        val v1 = Json.parseToJsonElement(createResp.bodyAsText()).jsonObject
        val v1Pins = v1["sha256Pins"]?.jsonArray?.map { it.jsonPrimitive.content }
        assertEquals(1, v1["version"]?.jsonPrimitive?.int)

        // Regenerate
        val regenResp = client.post("/api/v1/hosts/rotate.test/regenerate-cert") {
            contentType(ContentType.Application.Json)
        }
        val v2 = Json.parseToJsonElement(regenResp.bodyAsText()).jsonObject
        val v2Pins = v2["sha256Pins"]?.jsonArray?.map { it.jsonPrimitive.content }
        assertEquals(2, v2["version"]?.jsonPrimitive?.int)

        // Pins should be different (new key pair)
        assertNotEquals(v1Pins, v2Pins)
    }

    // ── Force update ────────────────────────────────────

    @Test
    fun `force update per host`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"force.test"}""")
        }

        val response = client.post("/api/v1/certificate-config/force-update/force.test")
        assertEquals(HttpStatusCode.OK, response.status)

        val config = pinConfigStore.load(configApiId)
        assertTrue(config.pins.find { it.hostname == "force.test" }!!.forceUpdate)
    }

    @Test
    fun `clear force update per host`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"clearforce.test"}""")
        }
        client.post("/api/v1/certificate-config/force-update/clearforce.test")
        client.post("/api/v1/certificate-config/clear-force/clearforce.test")

        val config = pinConfigStore.load(configApiId)
        assertFalse(config.pins.find { it.hostname == "clearforce.test" }!!.forceUpdate)
    }

    // ── Store Tests ─────────────────────────────────────

    @Test
    fun `HostClientCertStore — save and retrieve P12`() {
        val p12 = byteArrayOf(1, 2, 3, 4, 5)
        hostClientCertStore.save("test.host", configApiId, p12, 1, "CN=test", "fingerprint123")

        val retrieved = hostClientCertStore.getP12("test.host", configApiId)
        assertNotNull(retrieved)
        assertContentEquals(p12, retrieved!!)
    }

    @Test
    fun `HostClientCertStore — get info`() {
        hostClientCertStore.save("info.host", configApiId, byteArrayOf(9, 8, 7), 3, "CN=info", "fp456")
        val record = hostClientCertStore.get("info.host", configApiId)
        assertNotNull(record)
        assertEquals(3, record!!.version)
        assertEquals("CN=info", record.commonName)
    }

    @Test
    fun `HostClientCertStore — not found returns null`() {
        assertNull(hostClientCertStore.getP12("ghost.host", configApiId))
        assertNull(hostClientCertStore.get("ghost.host", configApiId))
    }

    @Test
    fun `HostClientCertStore — delete removes cert`() {
        hostClientCertStore.save("del.host", configApiId, byteArrayOf(1), 1, null, null)
        assertNotNull(hostClientCertStore.getP12("del.host", configApiId))

        hostClientCertStore.delete("del.host", configApiId)
        assertNull(hostClientCertStore.getP12("del.host", configApiId))
    }

    @Test
    fun `PinConfigStore — mtls and clientCertVersion round-trip`() {
        val config = PinConfig(
            version = 1,
            pins = listOf(
                HostPin("mtls.host", listOf(testPin1, testPin2), version = 1, mtls = true, clientCertVersion = 5),
                HostPin("tls.host", listOf(testPin1, testPin2), version = 2, mtls = false)
            )
        )
        pinConfigStore.save(configApiId, config)
        val loaded = pinConfigStore.load(configApiId)

        val mtlsPin = loaded.pins.find { it.hostname == "mtls.host" }
        assertNotNull(mtlsPin)
        assertTrue(mtlsPin!!.mtls)
        assertEquals(5, mtlsPin.clientCertVersion)

        val tlsPin = loaded.pins.find { it.hostname == "tls.host" }
        assertNotNull(tlsPin)
        assertFalse(tlsPin!!.mtls)
        assertNull(tlsPin.clientCertVersion)
    }

    // ── History ─────────────────────────────────────────

    @Test
    fun `history records events`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"history.test"}""")
        }

        val response = client.get("/api/v1/certificate-config/history/history.test")
        assertEquals(HttpStatusCode.OK, response.status)
        val entries = Json.parseToJsonElement(response.bodyAsText()).jsonArray
        assertTrue(entries.isNotEmpty())
        assertEquals("cert_generated", entries[0].jsonObject["event"]?.jsonPrimitive?.content)
    }

    // ── Health check ────────────────────────────────────

    @Test
    fun `signing key endpoint returns key`() = testApplication {
        configureApp()
        val response = client.get("/api/v1/signing-key")
        assertEquals(HttpStatusCode.OK, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(body["publicKey"])
    }

    // ── C.18: Client cert upload E2E ────────────────────

    @Test
    fun `C18 — client cert upload via host endpoint increments version`() = testApplication {
        configureApp()
        // Create host
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"upload.test"}""")
        }

        // Verify initial state: no client cert
        val infoResp1 = client.get("/api/v1/hosts/upload.test/client-cert/info")
        assertEquals(HttpStatusCode.NotFound, infoResp1.status)

        // Upload a P12 (create a minimal one in-memory)
        val p12 = createTestP12()
        val boundary = "----TestBoundary${System.nanoTime()}"
        val body = buildMultipartBody(boundary, p12, "changeit")

        val uploadResp = client.post("/api/v1/hosts/upload.test/upload-client-cert") {
            header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
            setBody(body)
        }
        assertEquals(HttpStatusCode.OK, uploadResp.status)
        val uploadBody = Json.parseToJsonElement(uploadResp.bodyAsText()).jsonObject
        assertEquals(1, uploadBody["clientCertVersion"]?.jsonPrimitive?.int)

        // Config should now have mtls:true and clientCertVersion:1
        val config = pinConfigStore.load(configApiId)
        val pin = config.pins.find { it.hostname == "upload.test" }
        assertNotNull(pin)
        assertTrue(pin!!.mtls)
        assertEquals(1, pin.clientCertVersion)

        // Download works
        val dlResp = client.get("/api/v1/hosts/upload.test/client-cert/download")
        assertEquals(HttpStatusCode.OK, dlResp.status)

        // Upload again — version increments
        val uploadResp2 = client.post("/api/v1/hosts/upload.test/upload-client-cert") {
            header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
            setBody(body)
        }
        val uploadBody2 = Json.parseToJsonElement(uploadResp2.bodyAsText()).jsonObject
        assertEquals(2, uploadBody2["clientCertVersion"]?.jsonPrimitive?.int)
    }

    // ── C.21: Mock server ───────────────────────────────

    @Test
    fun `C21 — host status endpoint returns mock info`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"mock.test"}""")
        }

        val statusResp = client.get("/api/v1/hosts/mock.test/status")
        assertEquals(HttpStatusCode.OK, statusResp.status)
        val status = Json.parseToJsonElement(statusResp.bodyAsText()).jsonObject
        assertEquals("mock.test", status["hostname"]?.jsonPrimitive?.content)
        assertFalse(status["mockServerRunning"]?.jsonPrimitive?.boolean ?: true)
    }

    // ── E.28: Aynı host'a iki cert yükle ────────────────

    @Test
    fun `E28 — double cert upload increments version`() {
        val p12a = byteArrayOf(1, 2, 3)
        val p12b = byteArrayOf(4, 5, 6)

        hostClientCertStore.save("dbl.host", configApiId, p12a, 1, "CN=v1", "fp1")
        hostClientCertStore.save("dbl.host", configApiId, p12b, 2, "CN=v2", "fp2")

        val record = hostClientCertStore.get("dbl.host", configApiId)
        assertNotNull(record)
        assertEquals(2, record!!.version)
        assertEquals("CN=v2", record.commonName)
        assertContentEquals(p12b, hostClientCertStore.getP12("dbl.host", configApiId)!!)
    }

    // ── E.29: Host sil → cert temizlenmeli ──────────────

    @Test
    fun `E29 — host delete cleans up client cert`() {
        hostClientCertStore.save("cleanup.host", configApiId, byteArrayOf(9), 1, "CN", "fp")
        assertNotNull(hostClientCertStore.getP12("cleanup.host", configApiId))

        hostClientCertStore.delete("cleanup.host", configApiId)
        assertNull(hostClientCertStore.getP12("cleanup.host", configApiId))
    }

    // ── History events for mTLS ─────────────────────────

    @Test
    fun `mTLS toggle records history event`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"hist-mtls.test"}""")
        }

        client.post("/api/v1/hosts/hist-mtls.test/toggle-mtls") {
            contentType(ContentType.Application.Json)
            setBody("""{"mtls":true}""")
        }

        val histResp = client.get("/api/v1/certificate-config/history/hist-mtls.test")
        val entries = Json.parseToJsonElement(histResp.bodyAsText()).jsonArray
        val events = entries.map { it.jsonObject["event"]?.jsonPrimitive?.content }
        assertTrue(events.contains("mtls_enabled"), "mtls_enabled event should exist")
    }

    // ── Client cert download via config API path ────────

    @Test
    fun `config API client cert download path works on mTLS`() = testApplication {
        configureApp(configApiMode = "mtls")
        // Store a cert directly
        hostClientCertStore.save("dl-api.host", configApiId, byteArrayOf(11, 22, 33), 1, "CN=dl", "fp")

        val resp = client.get("/api/v1/client-certs/dl-api.host/download")
        assertEquals(HttpStatusCode.OK, resp.status)
    }

    // ── C.22: Enrollment tracking ─────────────────────

    @Test
    fun `C22 — ClientCertStore tracks enrolled certs`() {
        val clientCertStore = ClientCertStore(db)

        // Boş
        assertEquals(0, clientCertStore.getAll().size)

        // Cert ekle
        clientCertStore.add("device-1", "CN=device-1", "fp-abc", java.time.Instant.now().toString())
        clientCertStore.add("device-2", "CN=device-2", "fp-def", java.time.Instant.now().toString())

        val all = clientCertStore.getAll()
        assertEquals(2, all.size)
        assertEquals("device-2", all[0].id) // DESC sıralı
        assertEquals("device-1", all[1].id)
        assertFalse(all[0].revoked)

        // Revoke
        clientCertStore.revoke("device-1")
        val afterRevoke = clientCertStore.getAll()
        assertTrue(afterRevoke.find { it.id == "device-1" }!!.revoked)
        assertFalse(afterRevoke.find { it.id == "device-2" }!!.revoked)
    }

    @Test
    fun `C22 — EnrollmentTokenStore tracks tokens`() {
        val tokenStore = EnrollmentTokenStore(db)

        // Token üret
        val token = tokenStore.create("android-device")
        assertTrue(token.isNotEmpty())

        // Validate
        val clientId = tokenStore.validate(token)
        assertEquals("android-device", clientId)

        // Kullanılmamış token listede
        val all = tokenStore.getAll()
        assertTrue(all.any { it.token == token && !it.used })

        // Kullan
        tokenStore.markUsed(token)
        assertNull(tokenStore.validate(token)) // artık geçersiz

        val afterUse = tokenStore.getAll()
        assertTrue(afterUse.find { it.token == token }!!.used)
    }

    // ── Enrollment Security Modes ─────────────────────────

    @Test
    fun `enrollment — token mode rejects deviceId-only`() = testApplication {
        configureApp(enrollmentMode = "token")
        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"deviceId":"test-device-123"}""")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("Token required"))
    }

    @Test
    fun `enrollment — token mode accepts valid token`() = testApplication {
        configureApp(enrollmentMode = "token")
        val token = enrollmentTokenStore.create("token-client")

        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        // Response is P12 bytes
        assertTrue(response.bodyAsText().isNotEmpty())
        // Token should be marked used
        assertNull(enrollmentTokenStore.validate(token))
    }

    @Test
    fun `enrollment — token mode rejects used token`() = testApplication {
        configureApp(enrollmentMode = "token")
        val token = enrollmentTokenStore.create("reuse-client")
        enrollmentTokenStore.markUsed(token)

        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token"}""")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("Gecersiz token"))
    }

    @Test
    fun `enrollment — open mode allows deviceId`() = testApplication {
        configureApp(enrollmentMode = "open")
        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"deviceId":"open-device-456"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `enrollment — open mode also accepts token`() = testApplication {
        configureApp(enrollmentMode = "open")
        val token = enrollmentTokenStore.create("open-token-client")
        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"token":"$token"}""")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `enrollment — missing both token and deviceId returns 400`() = testApplication {
        configureApp(enrollmentMode = "token")
        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{}""")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `enrollment — invalid token returns 401`() = testApplication {
        configureApp(enrollmentMode = "token")
        val response = client.post("/api/v1/client-certs/enroll") {
            contentType(ContentType.Application.Json)
            setBody("""{"token":"totally-invalid-token"}""")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    // ── Host Cert Download — TLS vs mTLS restriction ────

    @Test
    fun `host cert download — TLS mode returns 403`() = testApplication {
        configureApp(configApiMode = "tls")
        hostClientCertStore.save("restricted.host", configApiId, byteArrayOf(1, 2, 3), 1, "CN=test", "fp")

        val response = client.get("/api/v1/client-certs/restricted.host/download")
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("mTLS Config API"))
    }

    @Test
    fun `host cert download — mTLS mode returns cert`() = testApplication {
        configureApp(configApiMode = "mtls")
        val certBytes = byteArrayOf(11, 22, 33, 44)
        hostClientCertStore.save("mtls-dl.host", configApiId, certBytes, 1, "CN=mtls", "fp")

        val response = client.get("/api/v1/client-certs/mtls-dl.host/download")
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `host cert download — mTLS mode 404 when no cert`() = testApplication {
        configureApp(configApiMode = "mtls")
        val response = client.get("/api/v1/client-certs/ghost.host/download")
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    // ── Host Client Cert Info via API ───────────────────

    @Test
    fun `host client cert info — returns data after upload`() = testApplication {
        configureApp()
        // Create host + upload cert
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"info-api.test"}""")
        }

        val p12 = createTestP12()
        val boundary = "----TestBoundary${System.nanoTime()}"
        val body = buildMultipartBody(boundary, p12, "changeit")
        client.post("/api/v1/hosts/info-api.test/upload-client-cert") {
            header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
            setBody(body)
        }

        // Now info endpoint should return data
        val infoResp = client.get("/api/v1/hosts/info-api.test/client-cert/info")
        assertEquals(HttpStatusCode.OK, infoResp.status)
        val info = Json.parseToJsonElement(infoResp.bodyAsText()).jsonObject
        assertNotNull(info["version"])
        assertNotNull(info["commonName"])
        assertNotNull(info["fingerprint"])
    }

    @Test
    fun `host client cert upload — sets mtls true and increments certVersion`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/generate-cert") {
            contentType(ContentType.Application.Json)
            setBody("""{"hostname":"auto-mtls.test"}""")
        }

        // Before upload: mtls should be false
        var config = pinConfigStore.load(configApiId)
        assertFalse(config.pins.find { it.hostname == "auto-mtls.test" }!!.mtls)

        val p12 = createTestP12()
        val boundary = "----TestBoundary${System.nanoTime()}"
        val body = buildMultipartBody(boundary, p12, "changeit")
        client.post("/api/v1/hosts/auto-mtls.test/upload-client-cert") {
            header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
            setBody(body)
        }

        // After upload: mtls=true, clientCertVersion=1
        config = pinConfigStore.load(configApiId)
        val pin = config.pins.find { it.hostname == "auto-mtls.test" }!!
        assertTrue(pin.mtls)
        assertEquals(1, pin.clientCertVersion)

        // Second upload: clientCertVersion=2
        client.post("/api/v1/hosts/auto-mtls.test/upload-client-cert") {
            header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
            setBody(body)
        }
        config = pinConfigStore.load(configApiId)
        assertEquals(2, config.pins.find { it.hostname == "auto-mtls.test" }!!.clientCertVersion)
    }

    // ── Helpers ─────────────────────────────────────────

    private fun createTestP12(): ByteArray {
        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        // Self-signed cert
        val provider = org.bouncycastle.jce.provider.BouncyCastleProvider()
        java.security.Security.addProvider(provider)
        val issuer = org.bouncycastle.asn1.x500.X500Name("CN=test-upload")
        val builder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            issuer, java.math.BigInteger.ONE,
            java.util.Date(), java.util.Date(System.currentTimeMillis() + 86400_000 * 365),
            issuer, kp.public
        )
        val signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(kp.private)
        val cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer))

        ks.setKeyEntry("client", kp.private, "changeit".toCharArray(), arrayOf(cert))
        val baos = java.io.ByteArrayOutputStream()
        ks.store(baos, "changeit".toCharArray())
        return baos.toByteArray()
    }

    private fun buildMultipartBody(boundary: String, p12: ByteArray, password: String): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        fun line(s: String) { baos.write("$s\r\n".toByteArray()) }

        line("--$boundary")
        line("Content-Disposition: form-data; name=\"password\"")
        line("")
        line(password)
        line("--$boundary")
        line("Content-Disposition: form-data; name=\"file\"; filename=\"client.p12\"")
        line("Content-Type: application/octet-stream")
        line("")
        baos.write(p12)
        line("")
        line("--$boundary--")
        return baos.toByteArray()
    }
}
