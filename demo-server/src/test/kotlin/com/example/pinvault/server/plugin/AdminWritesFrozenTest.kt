package com.example.pinvault.server.plugin

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** `ADMIN_WRITES_FROZEN`: admin changes refused, admin reads and every device call served. */
class AdminWritesFrozenTest {

    /** Stands in for ApiKeyAuth: a request with `X-API-Key: k` is an admin. */
    private val FakeAuth = createApplicationPlugin("FakeAuth") {
        onCall { call ->
            if (call.request.headers["X-API-Key"] == "k") call.attributes.put(AdminPrincipalKey, AdminPrincipal("alice"))
        }
    }

    private fun ApplicationTestBuilder.app(frozen: Boolean) {
        install(FakeAuth)
        install(AdminWritesFrozen) { this.frozen = frozen }
        routing {
            put("/api/v1/certificate-config") { call.respondText("written") }
            get("/api/v1/certificate-config/history") { call.respondText("history") }
            get("/api/v1/certificate-config") { call.respondText("config") }
            post("/api/v1/attest") { call.respondText("attested") }
            post("/api/v1/client-certs/renew") { call.respondText("renewed") }
        }
    }

    @Test
    fun `frozen - an admin write is refused, an admin read and every device call go on`() = testApplication {
        app(frozen = true)
        val write = client.put("/api/v1/certificate-config") {
            header("X-API-Key", "k"); contentType(ContentType.Application.Json); setBody("{}")
        }
        assertEquals(HttpStatusCode.Locked, write.status)
        assertTrue(write.bodyAsText().contains("admin_writes_frozen"))

        assertEquals("history", client.get("/api/v1/certificate-config/history") { header("X-API-Key", "k") }.bodyAsText())
        assertEquals("config", client.get("/api/v1/certificate-config").bodyAsText())
        assertEquals("attested", client.post("/api/v1/attest") { setBody("{}") }.bodyAsText())
        assertEquals("renewed", client.post("/api/v1/client-certs/renew") { setBody("x") }.bodyAsText())
    }

    @Test
    fun `not frozen - nothing changes`() = testApplication {
        app(frozen = false)
        assertEquals("written", client.put("/api/v1/certificate-config") { header("X-API-Key", "k"); setBody("{}") }.bodyAsText())
    }

    @Test
    fun `the setting reads true or false in any case and refuses anything else`() {
        assertFalse(adminWritesFrozenFromEnv(emptyMap()))
        assertFalse(adminWritesFrozenFromEnv(mapOf("ADMIN_WRITES_FROZEN" to "False")))
        assertTrue(adminWritesFrozenFromEnv(mapOf("ADMIN_WRITES_FROZEN" to " TRUE ")))
        assertFailsWith<IllegalStateException> { adminWritesFrozenFromEnv(mapOf("ADMIN_WRITES_FROZEN" to "yes")) }
    }
}
