package com.example.pinvault.server

import io.ktor.serialization.kotlinx.json.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * `GET /api/v1/health` built its response from nested `mapOf(...)` whose values
 * mixed `String`, `Int` and `Map`. kotlinx.serialization refuses that —
 * "Serializing collections of different element types is not yet supported" —
 * so the endpoint answered **500 on every call**. Nothing exercised it (the
 * container probe uses the bare `/health`, and the dashboard did not call it),
 * so it stayed broken.
 *
 * These tests pin the shape down through the actual serializer, so a future
 * "just use a map again" edit fails here instead of in production.
 */
class ServerHealthSerializationTest {

    private val sample = ServerHealth(
        status = "degraded",
        database = "connected",
        configApis = ConfigApiHealth(running = 2, stopped = 1),
        certs = CertHealth(status = "degraded", nearExpiry = 1, total = 4)
    )

    @Test
    fun `health response serializes to the documented shape`() {
        val json = Json.encodeToJsonElement(ServerHealth.serializer(), sample).jsonObject

        assertEquals("degraded", json["status"]!!.jsonPrimitive.content)
        assertEquals("connected", json["database"]!!.jsonPrimitive.content)
        assertEquals(2, json["configApis"]!!.jsonObject["running"]!!.jsonPrimitive.int)
        assertEquals(1, json["configApis"]!!.jsonObject["stopped"]!!.jsonPrimitive.int)
        assertEquals("degraded", json["certs"]!!.jsonObject["status"]!!.jsonPrimitive.content)
        assertEquals(1, json["certs"]!!.jsonObject["nearExpiry"]!!.jsonPrimitive.int)
        assertEquals(4, json["certs"]!!.jsonObject["total"]!!.jsonPrimitive.int)
    }

    @Test
    fun `responding with the health payload returns 200, not a serializer error`() = testApplication {
        install(ContentNegotiation) { json() }
        routing {
            get("/api/v1/health") { call.respond(sample) }
        }

        val response = client.get("/api/v1/health")
        assertEquals(HttpStatusCode.OK, response.status)

        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals("degraded", body["status"]!!.jsonPrimitive.content)
        assertEquals(4, body["certs"]!!.jsonObject["total"]!!.jsonPrimitive.int)
    }

    @Test
    fun `mixed-type map - the original construction - still fails, proving the regression is real`() {
        // Kept as executable documentation of *why* the typed classes exist.
        val legacy: Map<String, Any> = mapOf(
            "status" to "ok",
            "certs" to mapOf("nearExpiry" to 0, "total" to 2)
        )
        assertFailsWith<Exception> {
            @Suppress("UNCHECKED_CAST")
            Json.encodeToString(
                kotlinx.serialization.serializer(),
                legacy as Map<String, String>
            )
        }
    }
}
