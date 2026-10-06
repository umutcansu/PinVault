package com.example.pinvault.server.plugin

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlin.test.*

/**
 * `CONFIG_API_ADMIN_ROUTES=off`: a Config API listener answers the device
 * endpoints and nothing else — with or without an admin key.
 */
class DeviceOnlyRoutesTest {

    private fun ApplicationTestBuilder.configure() {
        install(DeviceOnlyRoutes)
        routing {
            get("/api/v1/certificate-config") { call.respondText("pins") }
            post("/api/v1/client-certs/enroll") { call.respondText("enrolled") }
            get("/api/v1/vault/{key}") { call.respondText("file") }
            put("/api/v1/certificate-config") { call.respondText("written") }
            get("/api/v1/certificate-config/history/{host}") { call.respondText("history") }
            post("/api/v1/hosts/{host}/fetch-from-url") { call.respondText("fetched") }
            get("/api/v1/vault/distributions") { call.respondText("inventory") }
            get("/health") { call.respondText("ok") }
        }
    }

    @Test
    fun `device endpoints are answered`() = testApplication {
        configure()
        assertEquals("pins", client.get("/api/v1/certificate-config").bodyAsText())
        assertEquals("enrolled", client.post("/api/v1/client-certs/enroll").bodyAsText())
        assertEquals("file", client.get("/api/v1/vault/model.bin").bodyAsText())
        assertEquals("ok", client.get("/health").bodyAsText())
    }

    @Test
    fun `admin routes are refused, key or no key, and the handler never runs`() = testApplication {
        configure()
        for ((method, path) in listOf(
            HttpMethod.Put to "/api/v1/certificate-config",
            HttpMethod.Get to "/api/v1/certificate-config/history/api.example.com",
            HttpMethod.Post to "/api/v1/hosts/api.example.com/fetch-from-url",
            HttpMethod.Get to "/api/v1/vault/distributions"
        )) {
            for (key in listOf(null, "a-valid-looking-admin-key")) {
                val response = client.request(path) {
                    this.method = method
                    if (key != null) header("X-API-Key", key)
                }
                assertEquals(HttpStatusCode.Forbidden, response.status, "$method $path key=$key")
                val body = response.bodyAsText()
                assertTrue(body.contains("admin_routes_disabled"), body)
                assertFalse(body.contains("written") || body.contains("history") || body.contains("fetched") || body.contains("inventory"))
            }
        }
    }
}
