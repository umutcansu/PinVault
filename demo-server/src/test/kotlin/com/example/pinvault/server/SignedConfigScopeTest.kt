package com.example.pinvault.server

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
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.*

/**
 * The audience of a signed config: every signed payload names the Config API
 * it was signed for (`configApiId`), which a library block with
 * `serverScope(id)` requires — one signing key often serves several Config
 * APIs, and without it an envelope of one is accepted by another.
 */
class SignedConfigScopeTest {

    private lateinit var dir: File
    private lateinit var signing: ConfigSigningService

    @BeforeTest
    fun setUp() {
        dir = File(System.getProperty("java.io.tmpdir"), "pinvault-scope-${System.nanoTime()}").also { it.mkdirs() }
        signing = ConfigSigningService(File(dir, "signing.pem"))
    }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun config() = PinConfig(pins = listOf(HostPin("api.example.com", listOf("A".repeat(43) + "=", "B".repeat(43) + "="))))

    private fun payloadOf(envelopeJson: String): JsonObject =
        Json.parseToJsonElement(Json.parseToJsonElement(envelopeJson).jsonObject["payload"]!!.jsonPrimitive.content).jsonObject

    @Test
    fun `every signed payload names its Config API, cached or not`() {
        for (cache in listOf(false, true)) {
            val envelopes = SignedConfigService(signing, cacheEnabled = cache)
            val a = envelopes.envelope("tls-a", config())
            val b = envelopes.envelope("mtls-b", config())
            assertEquals("tls-a", Json.parseToJsonElement(a.payload).jsonObject["configApiId"]!!.jsonPrimitive.content)
            assertEquals("mtls-b", Json.parseToJsonElement(b.payload).jsonObject["configApiId"]!!.jsonPrimitive.content)
            // Inside the signed bytes: swapping it breaks the signature.
            assertTrue(signing.verify(a.payload, a.signature))
            assertFalse(signing.verify(a.payload.replace("\"tls-a\"", "\"mtls-b\""), a.signature))
        }
        // An unsigned view carries no audience at all.
        assertFalse("configApiId" in Json { encodeDefaults = true }.encodeToString(PinConfig.serializer(), config()))
    }

    @Test
    fun `the config endpoint signs for the scope it serves`() = testApplication {
        val db = DatabaseManager(File(dir, "scope.db").absolutePath)
        PinConfigStore(db).ensureConfigExists("scope-x")
        install(ContentNegotiation) { json(Json { encodeDefaults = true; ignoreUnknownKeys = true }) }
        routing {
            certificateConfigRoutes("scope-x", PinConfigStore(db), PinConfigHistoryStore(db), ConnectionHistoryStore(db),
                signing, ClientDeviceStore(db))
        }
        val signed = client.get("/api/v1/certificate-config")
        assertEquals(HttpStatusCode.OK, signed.status, signed.bodyAsText())
        assertEquals("scope-x", payloadOf(signed.bodyAsText())["configApiId"]!!.jsonPrimitive.content)
        val unsigned = Json.parseToJsonElement(client.get("/api/v1/certificate-config?signed=false").bodyAsText()).jsonObject
        assertNull(unsigned["configApiId"])
    }
}
