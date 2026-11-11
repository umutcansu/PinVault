package com.example.pinvault.server

import com.example.pinvault.server.model.ConfigView
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
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
 * M6: a SIGNED narrowed view names the request it answers (`view` inside the
 * payload: canonical requested hosts, claimed device id), a full view names
 * nothing, and the signature cache never serves one request's envelope for
 * another. See SERVER_IMPLEMENTATION_GUIDE.md §3, `view`.
 */
class SignedConfigViewBindingTest {

    private val scope = "view-binding-test"

    private lateinit var db: DatabaseManager
    private lateinit var pinConfigStore: PinConfigStore
    private lateinit var aclStore: DeviceHostAclStore
    private lateinit var signingService: ConfigSigningService
    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-view-binding-", ".db").also { it.deleteOnExit() }
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        pinConfigStore = PinConfigStore(db)
        aclStore = DeviceHostAclStore(db)
        signingService = ConfigSigningService(signingKeyFile)
        pinConfigStore.save(scope, PinConfig(
            pins = listOf(
                HostPin("cdn.example.com", listOf("p1", "p2"), version = 1),
                HostPin("api.example.com", listOf("p3", "p4"), version = 1)
            )
        ))
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
    }

    private fun ApplicationTestBuilder.app(envelopes: SignedConfigService? = null, withAcl: Boolean = true) {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(
                scope, pinConfigStore, PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signingService, ClientDeviceStore(db),
                deviceHostAclStore = if (withAcl) aclStore else null,
                signedConfigService = envelopes
            )
        }
    }

    private suspend fun ApplicationTestBuilder.envelope(query: String = "", deviceId: String? = null): JsonObject {
        val res = client.get("/api/v1/certificate-config$query") {
            deviceId?.let { header("X-Device-Id", it) }
            header("X-PinVault-Features", "redelivery")
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        return Json.parseToJsonElement(res.bodyAsText()).jsonObject
    }

    private fun JsonObject.payloadText(): String = this["payload"]!!.jsonPrimitive.content
    private fun JsonObject.payload(): JsonObject = Json.parseToJsonElement(payloadText()).jsonObject
    private fun JsonObject.hosts(): List<String> = payload()["pins"]!!.jsonArray.map { it.jsonObject["hostname"]!!.jsonPrimitive.content }

    private fun grantAll(device: String) {
        val at = java.time.Instant.now().toString()
        aclStore.grant(scope, device, "cdn.example.com", at)
        aclStore.grant(scope, device, "api.example.com", at)
    }

    @Test
    fun `a full GET carries no view - the payload is what it was`() = testApplication {
        app()
        val payload = envelope().payloadText()
        assertFalse(payload.contains("\"view\""), payload)
        // The exact field order of a full payload, unchanged by the new field.
        assertTrue(Regex("""^\{"version":1,"pins":\[.*],"forceUpdate":false,"issuedAt":\d+,"expiresAt":\d+,"configApiId":"$scope"}$""").matches(payload), payload)
    }

    @Test
    fun `a narrowed GET carries the canonical requested set and the claimed device id`() = testApplication {
        app()
        grantAll("dev-a")
        val env = envelope("?hosts=cdn.example.com,api.example.com", deviceId = "dev-a")
        assertEquals(
            """{"hosts":["api.example.com","cdn.example.com"],"deviceId":"dev-a"}""",
            env.payload()["view"].toString()
        )
        // The view sits last in the payload, after configApiId.
        assertTrue(env.payloadText().endsWith(""","configApiId":"$scope","view":{"hosts":["api.example.com","cdn.example.com"],"deviceId":"dev-a"}}"""), env.payloadText())
    }

    @Test
    fun `hosts naming the whole scope still carry the view - it records the request, not the outcome`() = testApplication {
        app(withAcl = false)
        val env = envelope("?hosts=api.example.com,cdn.example.com")
        assertEquals(setOf("api.example.com", "cdn.example.com"), env.hosts().toSet())
        assertEquals("""{"hosts":["api.example.com","cdn.example.com"]}""", env.payload()["view"].toString())
    }

    @Test
    fun `a device id alone narrows - the view names only the device`() = testApplication {
        app()
        aclStore.grant(scope, "dev-a", "cdn.example.com", java.time.Instant.now().toString())
        val env = envelope(deviceId = "dev-a")
        assertEquals(listOf("cdn.example.com"), env.hosts())
        assertEquals("""{"deviceId":"dev-a"}""", env.payload()["view"].toString())
    }

    @Test
    fun `odd spellings of hosts canonicalise identically and get the same pins`() = testApplication {
        app()
        grantAll("dev-a")
        val spellings = listOf(
            "?hosts=api.example.com,cdn.example.com",
            "?hosts=CDN.Example.COM,api.example.com",
            "?hosts=cdn.example.com,cdn.example.com,api.example.com",
            "?hosts=%20cdn.example.com%20,,api.example.com,"
        )
        val first = envelope(spellings[0], "dev-a")
        for (q in spellings.drop(1)) {
            val env = envelope(q, "dev-a")
            assertEquals(first.payload()["view"], env.payload()["view"], q)
            assertEquals(first.payload()["pins"], env.payload()["pins"], q)
        }
        // A host outside the scope is recorded as requested (it is part of the request) and gets no pins.
        val outside = envelope("?hosts=cdn.example.com,Other.Example.net", "dev-a")
        assertEquals("""{"hosts":["cdn.example.com","other.example.net"],"deviceId":"dev-a"}""", outside.payload()["view"].toString())
        assertEquals(listOf("cdn.example.com"), outside.hosts())
        // `?hosts=` with no names is a request for no host: an empty set, not the full config.
        val empty = envelope("?hosts=", "dev-a")
        assertEquals("""{"hosts":[],"deviceId":"dev-a"}""", empty.payload()["view"].toString())
        assertTrue(empty.hosts().isEmpty())
    }

    @Test
    fun `canonical form - split, trim, ASCII lower case, de-duplicated, sorted by code point`() {
        assertEquals(listOf("a.example.com", "b.example.com"), ConfigView.canonicalHosts(listOf(" B.example.com", "a.example.com,b.example.com", "", ",")))
        // Only A-Z is folded: a non-ASCII letter stays (no locale rules), and sorting is by code point.
        assertEquals(listOf("a", "z", "É"), ConfigView.canonicalHosts(listOf("É", "Z", "A")))
        assertEquals(listOf("a.com", "a.com:8443"), ConfigView.canonicalHosts(listOf("a.com:8443", "A.com")))
        assertNull(ConfigView.of(null, null))
        assertEquals(ConfigView(hosts = emptyList()), ConfigView.of(emptyList(), null))
    }

    @Test
    fun `the unsigned answer stays as it was`() = testApplication {
        app()
        grantAll("dev-a")
        val res = client.get("/api/v1/certificate-config?signed=false&hosts=cdn.example.com") { header("X-Device-Id", "dev-a") }
        assertFalse(res.bodyAsText().contains("\"view\""), res.bodyAsText())
    }

    @Test
    fun `the signature cache never crosses views`() = testApplication {
        val envelopes = SignedConfigService(signingService, cacheEnabled = true)
        app(envelopes)
        grantAll("dev-a")
        grantAll("dev-b")

        val full = envelope()
        // Same pins as the full config (both hosts granted), but a narrowed request.
        val narrowed = envelope("?hosts=api.example.com,cdn.example.com", "dev-a")
        assertEquals(full.payload()["pins"], narrowed.payload()["pins"])
        assertNotEquals(full.payloadText(), narrowed.payloadText())
        assertNull(full.payload()["view"])
        assertNotNull(narrowed.payload()["view"])

        // Another device, same hosts, same pins: its own envelope.
        val other = envelope("?hosts=api.example.com,cdn.example.com", "dev-b")
        assertEquals(narrowed.payload()["pins"], other.payload()["pins"])
        assertEquals("dev-b", other.payload()["view"]!!.jsonObject["deviceId"]!!.jsonPrimitive.content)

        // A spelling of the same request IS the same request: the cached envelope comes back.
        val hits = envelopes.cacheHits.get()
        val again = envelope("?hosts=CDN.example.com,api.example.com", "dev-a")
        assertEquals(narrowed.payloadText(), again.payloadText())
        assertEquals(hits + 1, envelopes.cacheHits.get())
        // And the full one is still its own.
        assertEquals(full.payloadText(), envelope().payloadText())
    }
}
