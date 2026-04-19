package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.*

/**
 * Route-level pin ACL enforcement on GET /api/v1/certificate-config.
 *
 * Verifies the intersection logic that [CertificateConfigRoute.kt] applies
 * when `?hosts=…` is provided or `X-Device-Id` is set:
 *
 *   response.pins = configured.pins ∩ (device-ACL ∪ default-ACL)
 *
 * The pinConfigStore, historyStore, and signingService dependencies are
 * real instances against a temp SQLite DB — no mocks, so the test catches
 * SQL-level regressions too.
 */
class CertificateConfigRoutesScopingTest {

    private val testApi = "acl-route-test"

    private lateinit var db: DatabaseManager
    private lateinit var pinConfigStore: PinConfigStore
    private lateinit var historyStore: PinConfigHistoryStore
    private lateinit var connectionStore: ConnectionHistoryStore
    private lateinit var clientDeviceStore: ClientDeviceStore
    private lateinit var aclStore: DeviceHostAclStore
    private lateinit var signingService: ConfigSigningService
    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-acl-route-", ".db")
        dbFile.deleteOnExit()
        // Point to a non-existing file so ConfigSigningService generates a
        // fresh key. createTempFile + delete guarantees a unique path that
        // doesn't exist.
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete() }
        signingKeyFile.deleteOnExit()

        db = DatabaseManager(dbFile.absolutePath)
        pinConfigStore = PinConfigStore(db)
        historyStore = PinConfigHistoryStore(db)
        connectionStore = ConnectionHistoryStore(db)
        clientDeviceStore = ClientDeviceStore(db)
        aclStore = DeviceHostAclStore(db)
        signingService = ConfigSigningService(signingKeyFile)

        // Seed a config with three hosts. Device ACL will authorize only a subset.
        pinConfigStore.save(testApi, PinConfig(
            pins = listOf(
                HostPin("cdn.example.com", listOf("p1", "p2"), version = 1),
                HostPin("api.example.com", listOf("p3", "p4"), version = 1),
                HostPin("internal.acme.com", listOf("p5", "p6"), version = 1)
            ),
            forceUpdate = false
        ))
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
    }

    private fun ApplicationTestBuilder.configureApp(withAcl: Boolean = true) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(
                testApi, pinConfigStore, historyStore, connectionStore,
                signingService, clientDeviceStore,
                deviceHostAclStore = if (withAcl) aclStore else null
            )
        }
    }

    @Test
    fun `without ACL store, all pins returned (legacy behavior)`() = testApplication {
        configureApp(withAcl = false)
        val res = client.get("/api/v1/certificate-config?signed=false&hosts=cdn.example.com")
        val body = res.bodyAsText()
        // No filter applied — all three hosts present
        assertTrue(body.contains("cdn.example.com"))
        assertTrue(body.contains("api.example.com"))
        assertTrue(body.contains("internal.acme.com"))
    }

    @Test
    fun `hosts filter intersects with device ACL`() = testApplication {
        configureApp()
        aclStore.grant(testApi, "dev-a", "cdn.example.com", java.time.Instant.now().toString())
        aclStore.grant(testApi, "dev-a", "api.example.com", java.time.Instant.now().toString())

        val res = client.get("/api/v1/certificate-config?signed=false&hosts=cdn.example.com,internal.acme.com") {
            header("X-Device-Id", "dev-a")
        }
        val body = res.bodyAsText()
        // cdn is requested AND in ACL → returned
        assertTrue(body.contains("cdn.example.com"), "cdn.example.com must be in the response")
        // internal is requested but NOT in ACL → filtered out
        assertFalse(body.contains("internal.acme.com"), "internal.acme.com must NOT be in the response")
        // api is in ACL but not requested → not in response
        assertFalse(body.contains("api.example.com"), "api.example.com was not requested")
    }

    @Test
    fun `hosts filter with empty ACL returns empty pins`() = testApplication {
        configureApp()
        // No ACL grants for this device
        val res = client.get("/api/v1/certificate-config?signed=false&hosts=cdn.example.com") {
            header("X-Device-Id", "unauthorized-device")
        }
        val body = res.bodyAsText()
        assertFalse(body.contains("cdn.example.com"), "No hostname should be returned")
        assertFalse(body.contains("api.example.com"))
        assertFalse(body.contains("internal.acme.com"))
    }

    @Test
    fun `default ACL unions with device ACL`() = testApplication {
        configureApp()
        aclStore.addDefault(testApi, "cdn.example.com")
        aclStore.grant(testApi, "dev-a", "internal.acme.com", java.time.Instant.now().toString())

        val res = client.get("/api/v1/certificate-config?signed=false&hosts=cdn.example.com,internal.acme.com") {
            header("X-Device-Id", "dev-a")
        }
        val body = res.bodyAsText()
        // Both should resolve — cdn via default ACL, internal via device ACL
        assertTrue(body.contains("cdn.example.com"))
        assertTrue(body.contains("internal.acme.com"))
    }

    @Test
    fun `X-Device-Id without hosts filter applies ACL anyway`() = testApplication {
        configureApp()
        aclStore.grant(testApi, "dev-a", "cdn.example.com", java.time.Instant.now().toString())

        val res = client.get("/api/v1/certificate-config?signed=false") {
            header("X-Device-Id", "dev-a")
        }
        val body = res.bodyAsText()
        assertTrue(body.contains("cdn.example.com"))
        assertFalse(body.contains("api.example.com"))
        assertFalse(body.contains("internal.acme.com"))
    }

    @Test
    fun `request without hosts or deviceId returns all pins unscoped`() = testApplication {
        configureApp()
        // Some prior grants exist but no identifying info on this request
        aclStore.grant(testApi, "someone-else", "cdn.example.com", java.time.Instant.now().toString())

        val res = client.get("/api/v1/certificate-config?signed=false")
        val body = res.bodyAsText()
        // No filter context → full config (legacy behavior)
        assertTrue(body.contains("cdn.example.com"))
        assertTrue(body.contains("api.example.com"))
        assertTrue(body.contains("internal.acme.com"))
    }
}
