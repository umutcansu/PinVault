package com.example.pinvault.server.plugin

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlin.test.*

/**
 * On a listener that asks for a client certificate, Apple's URL loading system
 * turns a 403 into a TLS error and drops the body. The iOS library asks for a
 * 409 instead (`X-PinVault-Features: forbidden-as-409`); everyone else keeps
 * the 403.
 */
class ForbiddenAsConflictTest {

    private val reenroll = """{"error":"reenroll_required","message":"This identity was revoked. Enroll again."}"""

    private fun ApplicationTestBuilder.configureApp() {
        install(ContentNegotiation) { json() }
        install(ForbiddenAsConflict)
        routing {
            get("/text") { call.respondText(reenroll, ContentType.Application.Json, HttpStatusCode.Forbidden) }
            get("/json") { call.respond(HttpStatusCode.Forbidden, mapOf("error" to "device_identity_mismatch")) }
            get("/bare") { call.respond(HttpStatusCode.Forbidden) }
            get("/ok") { call.respondText("fine") }
            get("/unauthorized") { call.respondText("no", status = HttpStatusCode.Unauthorized) }
        }
    }

    @Test
    fun `a client that asks gets 409 with the original status and the same body`() = testApplication {
        configureApp()
        for ((path, body) in listOf("/text" to reenroll, "/json" to """{"error":"device_identity_mismatch"}""")) {
            val response = client.get(path) { header(FEATURES_HEADER, "redelivery, forbidden-as-409") }
            assertEquals(HttpStatusCode.Conflict, response.status, path)
            assertEquals("403", response.headers[ORIGINAL_STATUS_HEADER], path)
            assertEquals(body, response.bodyAsText(), path)
            assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters(), path)
        }
        val bare = client.get("/bare") { header(FEATURES_HEADER, "FORBIDDEN-AS-409") }
        assertEquals(HttpStatusCode.Conflict, bare.status)
        assertEquals("403", bare.headers[ORIGINAL_STATUS_HEADER])
    }

    @Test
    fun `everyone else keeps the 403`() = testApplication {
        configureApp()
        for (features in listOf(null, "", "csr,redelivery", "forbidden-as-4090")) {
            val response = client.get("/text") { features?.let { header(FEATURES_HEADER, it) } }
            assertEquals(HttpStatusCode.Forbidden, response.status, "features=$features")
            assertNull(response.headers[ORIGINAL_STATUS_HEADER])
            assertEquals(reenroll, response.bodyAsText())
        }
    }

    @Test
    fun `only a 403 is remapped`() = testApplication {
        configureApp()
        val ok = client.get("/ok") { header(FEATURES_HEADER, "forbidden-as-409") }
        assertEquals(HttpStatusCode.OK, ok.status)
        assertNull(ok.headers[ORIGINAL_STATUS_HEADER])
        val unauthorized = client.get("/unauthorized") { header(FEATURES_HEADER, "forbidden-as-409") }
        assertEquals(HttpStatusCode.Unauthorized, unauthorized.status)
        assertNull(unauthorized.headers[ORIGINAL_STATUS_HEADER])
    }

    @Test
    fun `the revocation gate's answer reaches an iPhone as 409`() = testApplication {
        install(ForbiddenAsConflict)
        // No client certificate in the test engine: the gate is exercised through its response shape only.
        routing { get("/api/v1/certificate-config") { call.respondText(reenroll, ContentType.Application.Json, HttpStatusCode.Forbidden) } }
        val response = client.get("/api/v1/certificate-config") { header(FEATURES_HEADER, "redelivery,multisig,keyset,forbidden-as-409") }
        assertEquals(HttpStatusCode.Conflict, response.status)
        assertTrue(response.bodyAsText().contains("reenroll_required"))
    }
}
