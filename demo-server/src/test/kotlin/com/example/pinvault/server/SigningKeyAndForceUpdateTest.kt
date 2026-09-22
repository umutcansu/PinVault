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
 * Two admin-visible switches that did not reach the client.
 *
 * 1. Regenerating the signing key replaced only the local variable in the admin
 *    handler; every route kept the service instance captured at startup, so the
 *    server went on signing with the old key while the dashboard reported
 *    success — until the next restart silently invalidated every fielded APK.
 * 2. The dashboard writes per-host `forceUpdate` flags, but the library's
 *    "force update or refuse to start" gate reads the config-level flag. Served
 *    configs now carry `forceUpdate = hasAnyForceUpdate()`.
 */
class SigningKeyAndForceUpdateTest {

    private val api = "signing-force-test"
    private val pins = listOf(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
    )

    private lateinit var dbFile: File
    private lateinit var signingKeyFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: PinConfigStore
    private lateinit var historyStore: PinConfigHistoryStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-signforce-", ".db").also { it.deleteOnExit() }
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

    // ── Signing key rotation ────────────────────────────────────────────

    @Test
    fun `regenerate swaps the key for every holder of the service`() {
        val service = ConfigSigningService(signingKeyFile)
        val oldPublicKey = service.publicKeyBase64
        val payloadSignedWithOldKey = service.sign("payload")
        assertTrue(service.verify("payload", payloadSignedWithOldKey))

        val newPublicKey = service.regenerate()

        assertNotEquals(oldPublicKey, newPublicKey, "a fresh key pair is generated")
        assertEquals(newPublicKey, service.publicKeyBase64, "the same instance reports the new key")
        assertFalse(
            service.verify("payload", payloadSignedWithOldKey),
            "signatures made with the previous key no longer verify",
        )
        assertTrue(service.verify("payload", service.sign("payload")), "the new key signs and verifies")
    }

    @Test
    fun `a regenerated key is the one the config route signs with`() = testApplication {
        val service = ConfigSigningService(signingKeyFile)
        store.save(api, PinConfig(pins = listOf(HostPin("a.example.com", pins, version = 1))))
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(api, store, historyStore, ConnectionHistoryStore(db), service, ClientDeviceStore(db))
        }

        val before = signedConfig(client)
        assertTrue(service.verify(before.first, before.second))

        service.regenerate()

        val after = signedConfig(client)
        assertTrue(service.verify(after.first, after.second), "served config is signed with the current key")
        assertFalse(
            service.verify(before.first, before.second),
            "the earlier signature is no longer valid — clients must be rebuilt with the new public key",
        )
    }

    private suspend fun signedConfig(client: io.ktor.client.HttpClient): Pair<String, String> {
        val body = Json.parseToJsonElement(client.get("/api/v1/certificate-config").bodyAsText()).jsonObject
        return body["payload"]!!.jsonPrimitive.content to body["signature"]!!.jsonPrimitive.content
    }

    // ── Force update ────────────────────────────────────────────────────

    @Test
    fun `a per-host force flag is stamped onto the served config`() = testApplication {
        store.save(api, PinConfig(pins = listOf(HostPin("a.example.com", pins, version = 1))))
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        routing {
            certificateConfigRoutes(
                api, store, historyStore, ConnectionHistoryStore(db),
                ConfigSigningService(signingKeyFile), ClientDeviceStore(db),
            )
        }

        assertFalse(servedConfig(client)["forceUpdate"]!!.jsonPrimitive.boolean, "nothing forced yet")

        client.post("/api/v1/certificate-config/force-update/a.example.com")

        val forced = servedConfig(client)
        assertTrue(
            forced["forceUpdate"]!!.jsonPrimitive.boolean,
            "the config-level flag the library reads follows the per-host switch",
        )
        assertTrue(forced["pins"]!!.jsonArray.single().jsonObject["forceUpdate"]!!.jsonPrimitive.boolean)

        client.post("/api/v1/certificate-config/clear-force/a.example.com")
        assertFalse(servedConfig(client)["forceUpdate"]!!.jsonPrimitive.boolean, "clearing the host clears it again")
    }

    private suspend fun servedConfig(client: io.ktor.client.HttpClient): JsonObject =
        Json.parseToJsonElement(client.get("/api/v1/certificate-config?signed=false").bodyAsText()).jsonObject
}
