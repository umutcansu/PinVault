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
import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.*

/**
 * Per-host versions must never move backwards, including when a host is
 * deleted and later re-added. The Android client rejects a per-host version
 * downgrade, so a re-added host that restarted at v1 was silently ignored by
 * every device that had seen the old versions — it kept using the stale pins
 * until the server counter caught up.
 */
class PinVersionContinuityTest {

    private val api = "continuity-test"
    private val otherApi = "continuity-other"

    // Two valid-looking 32-byte Base64 pins per state.
    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val pinsB = listOf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=")

    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var historyStore: PinConfigHistoryStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-continuity-", ".db").also { it.deleteOnExit() }
        signingKeyFile = File.createTempFile("signing-", ".pem").also { it.delete(); it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        store = PinConfigStore(db)
        historyStore = PinConfigHistoryStore(db)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
        signingKeyFile.delete()
    }

    private fun config(vararg pins: HostPin) = PinConfig(pins = pins.toList(), forceUpdate = false)

    // ── Store level ─────────────────────────────────────────────────────

    @Test
    fun `a brand-new host keeps the version it was given`() {
        val saved = store.save(api, config(HostPin("a.example.com", pinsA, version = 1)))
        assertEquals(1, saved.pins.single().version)
        assertEquals(1, store.load(api).pins.single().version)
    }

    @Test
    fun `a re-added host continues above its old version`() {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 7)))
        store.save(api, config())                                    // deleted
        val saved = store.save(api, config(HostPin("a.example.com", pinsB, version = 1)))

        assertEquals(8, saved.pins.single().version, "returned config reports the stored version")
        assertEquals(8, store.load(api).pins.single().version)
        assertEquals(8, store.versionWatermark(api, "a.example.com"))
    }

    @Test
    fun `hosts that stay in the config keep the version the caller chose`() {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 5)))
        val saved = store.save(api, config(HostPin("a.example.com", pinsB, version = 6)))
        assertEquals(6, saved.pins.single().version)
    }

    @Test
    fun `watermarks are per Config API scope`() {
        store.save(api, config(HostPin("a.example.com", pinsA, version = 9)))
        val saved = store.save(otherApi, config(HostPin("a.example.com", pinsA, version = 1)))
        assertEquals(1, saved.pins.single().version, "another scope has its own sequence")
    }

    // ── Route level: the dashboard's PUT /api/v1/certificate-config ─────

    private fun ApplicationTestBuilder.configureApp() {
        // Same JSON settings as the real servers (defaults such as version = 1 are written).
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                api, store, historyStore, ConnectionHistoryStore(db),
                ConfigSigningService(signingKeyFile), ClientDeviceStore(db)
            )
        }
    }

    private suspend fun io.ktor.client.HttpClient.putPins(vararg hosts: Pair<String, List<String>>): JsonObject {
        val body = buildJsonObject {
            put("version", 0)
            put("forceUpdate", false)
            putJsonArray("pins") {
                hosts.forEach { (host, pins) ->
                    addJsonObject {
                        put("hostname", host)
                        putJsonArray("sha256") { pins.forEach { add(it) } }
                    }
                }
            }
        }
        val res = put("/api/v1/certificate-config") {
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        assertEquals(HttpStatusCode.OK, res.status, res.bodyAsText())
        return Json.parseToJsonElement(res.bodyAsText()).jsonObject
    }

    private fun JsonObject.versionOf(host: String): Int =
        this["pins"]!!.jsonArray.map { it.jsonObject }
            .first { it["hostname"]!!.jsonPrimitive.content == host }["version"]!!.jsonPrimitive.int

    @Test
    fun `dashboard delete and re-add continues the version sequence`() = testApplication {
        configureApp()
        assertEquals(1, client.putPins("a.example.com" to pinsA).versionOf("a.example.com"))
        assertEquals(2, client.putPins("a.example.com" to pinsB).versionOf("a.example.com"))

        client.putPins("b.example.com" to pinsA)                    // a.example.com deleted
        val readded = client.putPins("b.example.com" to pinsA, "a.example.com" to pinsA)

        assertEquals(3, readded.versionOf("a.example.com"), "PUT response reports the stored version")
        assertEquals(3, store.load(api).pins.first { it.hostname == "a.example.com" }.version)
        val latest = historyStore.getByHostname("a.example.com").first()
        assertEquals("host_added", latest.event)
        assertEquals(3, latest.version, "history records the stored version, not 1")
    }
}
