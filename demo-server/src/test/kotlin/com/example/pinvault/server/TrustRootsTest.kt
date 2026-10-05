package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.PinConfigRules
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
import java.util.Base64
import kotlin.test.*

/**
 * Managed trust roots (ATTESTATION.md §10): stored with the pin config,
 * validated like pins, part of the signed payload only when set, and kept
 * by a write that does not mention them.
 */
class TrustRootsTest {

    private val api = "trust-roots-test"
    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val rootX = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXA="
    private val rootY = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYA="

    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var historyStore: PinConfigHistoryStore
    private lateinit var signingService: ConfigSigningService

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-trust-roots-", ".db").also { it.deleteOnExit() }
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        store = PinConfigStore(db)
        historyStore = PinConfigHistoryStore(db)
        signingService = ConfigSigningService(signingKeyFile)
        store.save(api, PinConfig(pins = listOf(HostPin("a.example.com", pinsA, version = 1))))
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
    }

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes(api, store, historyStore, ConnectionHistoryStore(db), signingService, ClientDeviceStore(db))
        }
    }

    private fun body(roots: List<String>?, pins: List<HostPin> = listOf(HostPin("a.example.com", pinsA))): String = buildJsonObject {
        put("version", 0)
        put("forceUpdate", false)
        putJsonArray("pins") {
            pins.forEach { p ->
                add(buildJsonObject { put("hostname", p.hostname); putJsonArray("sha256") { p.sha256.forEach { add(it) } } })
            }
        }
        if (roots != null) putJsonArray("trustRoots") { roots.forEach { add(it) } }
    }.toString()

    // ── Store ───────────────────────────────────────────────────────────

    @Test
    fun `the store keeps the roots with the config and reads them back in order`() {
        val saved = store.save(api, store.load(api).copy(trustRoots = listOf(rootX, rootY)))
        assertEquals(listOf(rootX, rootY), saved.trustRoots)
        assertEquals(listOf(rootX, rootY), store.load(api).trustRoots)
        assertEquals(emptyList(), store.load("another-scope").trustRoots, "a scope without a row has none")
        store.save(api, store.load(api).copy(trustRoots = emptyList()))
        assertEquals(emptyList(), store.load(api).trustRoots)
    }

    @Test
    fun `the rules refuse a root that is not a pin, a duplicate, and more than 64`() {
        assertEquals(emptyList(), PinConfigRules.trustRootErrors(listOf(rootX, rootY)))
        assertTrue(PinConfigRules.trustRootErrors(listOf("not-a-pin")).single().startsWith("trustRoots[0]"))
        assertTrue(PinConfigRules.trustRootErrors(listOf(rootX, rootX)).single().contains("birden fazla"))
        val many = (0 until 65).map { i ->
            Base64.getEncoder().encodeToString(ByteArray(32) { b -> if (b == 0) i.toByte() else 1 })
        }
        assertTrue(PinConfigRules.trustRootErrors(many).any { it.contains("en fazla ${PinConfigRules.MAX_TRUST_ROOTS}") })
    }

    // ── Route ───────────────────────────────────────────────────────────

    @Test
    fun `a PUT with trustRoots stores them, writes history and serves them signed and unsigned`() = testApplication {
        configureApp()
        val put = client.put("/api/v1/certificate-config?configApiId=$api") {
            contentType(ContentType.Application.Json)
            setBody(body(listOf(" $rootX ", rootY)))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())
        assertEquals(listOf(rootX, rootY), store.load(api).trustRoots, "trimmed, in the order sent")
        assertEquals(1, store.load(api).pins.single().version, "unchanged pins keep their version")
        val entry = historyStore.getByHostname("*").first { it.event == "trust_roots_updated" }
        assertEquals("*", entry.hostname)

        val unsigned = Json.parseToJsonElement(client.get("/api/v1/certificate-config?signed=false").bodyAsText()).jsonObject
        assertEquals(listOf(rootX, rootY), unsigned["trustRoots"]!!.jsonArray.map { it.jsonPrimitive.content })

        val signed = Json.parseToJsonElement(client.get("/api/v1/certificate-config").bodyAsText()).jsonObject
        val payload = Json.parseToJsonElement(signed["payload"]!!.jsonPrimitive.content).jsonObject
        assertEquals(listOf(rootX, rootY), payload["trustRoots"]!!.jsonArray.map { it.jsonPrimitive.content }, "part of what is signed")
    }

    @Test
    fun `a config without roots does not carry the field, so older clients see nothing new`() = testApplication {
        configureApp()
        val signed = Json.parseToJsonElement(client.get("/api/v1/certificate-config").bodyAsText()).jsonObject
        val payload = Json.parseToJsonElement(signed["payload"]!!.jsonPrimitive.content).jsonObject
        assertFalse(payload.containsKey("trustRoots"), payload.toString())
    }

    @Test
    fun `a PUT that does not mention trustRoots keeps them, an empty list clears them`() = testApplication {
        configureApp()
        store.save(api, store.load(api).copy(trustRoots = listOf(rootX)))

        val pinEdit = client.put("/api/v1/certificate-config?configApiId=$api") {
            contentType(ContentType.Application.Json)
            setBody(body(roots = null, pins = listOf(HostPin("a.example.com", pinsA), HostPin("b.example.com", pinsA))))
        }
        assertEquals(HttpStatusCode.OK, pinEdit.status, pinEdit.bodyAsText())
        assertEquals(listOf(rootX), store.load(api).trustRoots, "an older writer cannot drop the roots")
        assertEquals(2, store.load(api).pins.size)
        assertEquals(0, historyStore.getByHostname("*").count { it.event == "trust_roots_updated" })

        val clear = client.put("/api/v1/certificate-config?configApiId=$api") {
            contentType(ContentType.Application.Json)
            setBody(body(roots = emptyList(), pins = listOf(HostPin("a.example.com", pinsA), HostPin("b.example.com", pinsA))))
        }
        assertEquals(HttpStatusCode.OK, clear.status, clear.bodyAsText())
        assertEquals(emptyList(), store.load(api).trustRoots)
        assertEquals(1, historyStore.getByHostname("*").count { it.event == "trust_roots_updated" })
    }

    @Test
    fun `a PUT with a bad root is refused and nothing changes`() = testApplication {
        configureApp()
        for (roots in listOf(listOf("not-a-pin"), listOf(rootX, rootX))) {
            val res = client.put("/api/v1/certificate-config?configApiId=$api") {
                contentType(ContentType.Application.Json)
                setBody(body(roots))
            }
            assertEquals(HttpStatusCode.BadRequest, res.status, res.bodyAsText())
            assertTrue(res.bodyAsText().contains("trustRoots"), res.bodyAsText())
        }
        assertEquals(emptyList(), store.load(api).trustRoots)
    }
}
