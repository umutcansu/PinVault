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
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * `mtls` and `clientCertVersion` are part of the config a device caches, but
 * the client's change detection is per-host *version* based
 * (`SSLCertificateUpdater.updateNow`). Flipping either flag without moving the
 * version meant a device that already held the config answered
 * "AlreadyCurrent" and never downloaded the host-specific certificate — only a
 * device whose data had been wiped ever saw the change.
 *
 * Also pins the scope parameter on `PUT /api/v1/certificate-config`: the
 * management server mounts these routes under a fixed scope, so the admin UI
 * needs `?configApiId=` to write the Config API the operator actually has open.
 */
class HostMtlsVersionBumpTest {

    private val api = "mtls-bump-test"
    private val otherApi = "mtls-bump-other"
    private val host = "mock-mtls.example.com"

    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val pinsB = listOf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=")

    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File
    private lateinit var certsDir: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var hostStore: HostStore
    private lateinit var historyStore: PinConfigHistoryStore
    private lateinit var hostClientCertStore: HostClientCertStore
    private lateinit var certService: CertificateService

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-mtls-bump-", ".db").also { it.deleteOnExit() }
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        certsDir = File.createTempFile("pinvault-certs-", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        store = PinConfigStore(db)
        hostStore = HostStore(db)
        historyStore = PinConfigHistoryStore(db)
        hostClientCertStore = HostClientCertStore(db)
        certService = CertificateService(certsDir)

        store.save(api, PinConfig(pins = listOf(HostPin(host, pinsA, version = 4)), forceUpdate = false))
        hostStore.save(HostRecord(host, api, null, null, null, Instant.now().toString()))
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
        certsDir.deleteRecursively()
    }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                api, store, historyStore, ConnectionHistoryStore(db),
                ConfigSigningService(signingKeyFile), ClientDeviceStore(db)
            )
            hostRoutes(api, store, hostStore, historyStore, certService, MockServerManager(), hostClientCertStore)
        }
    }

    private fun storedPin(scope: String = api) = store.load(scope).pins.first { it.hostname == host }

    // ── toggle-mtls ─────────────────────────────────────────────────────

    @Test
    fun `enabling mTLS bumps the host pin version`() = testApplication {
        configureApp()
        val before = storedPin().version

        val res = client.post("/api/v1/hosts/$host/toggle-mtls") {
            contentType(ContentType.Application.Json)
            setBody("""{"mtls":true}""")
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())

        val after = storedPin()
        assertTrue(after.mtls, "flag must be stored")
        assertEquals(before + 1, after.version, "a device holding the old config must see a change")

        val body = Json.parseToJsonElement(res.bodyAsText()).jsonObject
        assertEquals(after.version, body["version"]!!.jsonPrimitive.int, "response reports the stored version")
    }

    @Test
    fun `disabling mTLS also bumps the version`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/$host/toggle-mtls") {
            contentType(ContentType.Application.Json); setBody("""{"mtls":true}""")
        }
        val afterEnable = storedPin().version

        client.post("/api/v1/hosts/$host/toggle-mtls") {
            contentType(ContentType.Application.Json); setBody("""{"mtls":false}""")
        }

        val after = storedPin()
        assertFalse(after.mtls)
        assertEquals(afterEnable + 1, after.version, "turning mTLS off must reach devices too")
    }

    @Test
    fun `toggle-mtls records the new version in pin history`() = testApplication {
        configureApp()
        client.post("/api/v1/hosts/$host/toggle-mtls") {
            contentType(ContentType.Application.Json); setBody("""{"mtls":true}""")
        }

        val latest = historyStore.getByHostname(host).first()
        assertEquals("mtls_enabled", latest.event)
        assertEquals(storedPin().version, latest.version, "history must record the version devices will fetch")
    }

    // ── upload-client-cert ──────────────────────────────────────────────

    @Test
    fun `uploading a host client cert bumps both the cert version and the pin version`() = testApplication {
        configureApp()
        val before = storedPin().version
        val p12 = certService.generateClientCertificate("host-cert-1").p12Bytes

        val res = client.submitFormWithBinaryData(
            url = "/api/v1/hosts/$host/upload-client-cert",
            formData = formData {
                append("password", CertificateService.KEYSTORE_PASSWORD)
                append("file", p12, Headers.build {
                    append(HttpHeaders.ContentType, "application/octet-stream")
                    append(HttpHeaders.ContentDisposition, "filename=\"client.p12\"")
                })
            }
        )
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())

        val after = storedPin()
        assertTrue(after.mtls, "upload implies mTLS")
        assertEquals(1, after.clientCertVersion)
        assertEquals(before + 1, after.version, "syncHostClientCerts only runs when the config reports a change")

        val body = Json.parseToJsonElement(res.bodyAsText()).jsonObject
        assertEquals(after.version, body["version"]!!.jsonPrimitive.int)
        assertEquals(1, body["clientCertVersion"]!!.jsonPrimitive.int)

        val latest = historyStore.getByHostname(host).first()
        assertEquals("client_cert_uploaded", latest.event)
        assertEquals(after.version, latest.version)
    }

    @Test
    fun `a second upload keeps both counters moving forward`() = testApplication {
        configureApp()

        suspend fun upload(alias: String) {
            val p12 = certService.generateClientCertificate(alias).p12Bytes
            val res = client.submitFormWithBinaryData(
                url = "/api/v1/hosts/$host/upload-client-cert",
                formData = formData {
                    append("password", CertificateService.KEYSTORE_PASSWORD)
                    append("file", p12, Headers.build {
                        append(HttpHeaders.ContentType, "application/octet-stream")
                        append(HttpHeaders.ContentDisposition, "filename=\"client.p12\"")
                    })
                }
            )
            assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        }

        val before = storedPin().version
        upload("host-cert-1")
        upload("host-cert-2")

        val after = storedPin()
        assertEquals(2, after.clientCertVersion)
        assertEquals(before + 2, after.version, "a cert rotation must be visible to already-provisioned devices")
    }

    // ── PUT scope parameter ─────────────────────────────────────────────

    @Test
    fun `PUT writes the scope named by configApiId, not the mounted one`() = testApplication {
        configureApp()
        store.save(otherApi, PinConfig(pins = listOf(HostPin("other.example.com", pinsA, version = 1)), forceUpdate = false))

        val body = buildJsonObject {
            put("version", 0)
            put("forceUpdate", false)
            putJsonArray("pins") {
                addJsonObject {
                    put("hostname", "other.example.com")
                    putJsonArray("sha256") { pinsB.forEach { add(it) } }
                }
            }
        }
        val res = client.put("/api/v1/certificate-config?configApiId=$otherApi") {
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())

        assertEquals(pinsB, store.load(otherApi).pins.single().sha256, "the named scope was written")
        assertEquals(
            listOf(host), store.load(api).pins.map { it.hostname },
            "the mounted scope must be untouched"
        )
        assertEquals(pinsA, storedPin().sha256)
    }

    @Test
    fun `PUT without configApiId still writes the mounted scope`() = testApplication {
        configureApp()
        val body = buildJsonObject {
            put("version", 0)
            put("forceUpdate", false)
            putJsonArray("pins") {
                addJsonObject {
                    put("hostname", host)
                    putJsonArray("sha256") { pinsB.forEach { add(it) } }
                }
            }
        }
        val res = client.put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        assertEquals(pinsB, storedPin().sha256)
    }
}
