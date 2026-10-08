package com.example.pinvault.server.plugin

import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Other pages in an administrator's browser cannot drive the admin API:
 * cross-site writes, form posts, and — without admin keys — DNS rebinding.
 */
class AdminBrowserGuardTest {

    private val writes = CopyOnWriteArrayList<String>()

    @AfterTest
    fun tearDown() {
        BrowserGuardRefusals.listener = null
    }

    private fun ApplicationTestBuilder.app(configure: AdminBrowserGuardConfig.() -> Unit = {}) {
        install(AdminBrowserGuard, configure)
        routing {
            post("/api/v1/hosts/generate-cert") { writes += call.receiveText(); call.respondText("done") }
            put("/api/v1/enrollment-open") { writes += call.receiveText(); call.respondText("done") }
            delete("/api/v1/client-certs/dev-1") { writes += "revoked"; call.respondText("done") }
            post("/api/v1/certificate-config/force-update") { writes += "forced"; call.respondText("done") }
            get("/api/v1/audit-log") { call.respondText("[]") }
            // Device endpoints: never touched by the guard.
            post("/api/v1/client-certs/enroll") { call.respondText("enrolled") }
            post("/api/v1/connection-history/client-report") { call.respondText("saved") }
            get("/health") { call.respondText("ok") }
        }
    }

    private suspend fun ApplicationTestBuilder.write(
        vararg headers: Pair<String, String>, path: String = "/api/v1/hosts/generate-cert", body: String = """{"hostname":"x"}"""
    ) = client.post(path) {
        headers.forEach { (name, value) -> header(name, value) }
        setBody(body)
    }

    @Test
    fun `a write from another origin is refused, the dashboard's own is not`() = testApplication {
        app()
        val json = HttpHeaders.ContentType to "application/json"

        for (origin in listOf("https://evil.example", "http://localhost:9999", "http://localhost.evil.example", "null")) {
            val response = write(json, HttpHeaders.Origin to origin)
            assertEquals(HttpStatusCode.Forbidden, response.status, origin)
            assertTrue(response.bodyAsText().contains("cross_origin_request"), response.bodyAsText())
        }
        for (site in listOf("cross-site", "same-site", "Cross-Site")) {
            val response = write(json, "Sec-Fetch-Site" to site)
            assertEquals(HttpStatusCode.Forbidden, response.status, site)
            assertTrue(response.bodyAsText().contains("cross_site_request"), response.bodyAsText())
        }
        assertTrue(writes.isEmpty(), "no handler ran: $writes")

        // The dashboard (same origin), a script (no Origin at all), a browser bar (none).
        assertEquals(HttpStatusCode.OK, write(json, HttpHeaders.Origin to "http://localhost", "Sec-Fetch-Site" to "same-origin").status)
        assertEquals(HttpStatusCode.OK, write(json).status)
        assertEquals(HttpStatusCode.OK, write(json, "Sec-Fetch-Site" to "none").status)
        assertEquals(3, writes.size)
    }

    @Test
    fun `the origin is compared with the Host the request was sent to`() {
        assertTrue(sameOrigin("http://localhost:8090", "localhost:8090", "http"))
        assertTrue(sameOrigin("http://admin.example.com", "admin.example.com", "http"))
        // Behind a TLS-terminating proxy the scheme differs, host and port do not.
        assertTrue(sameOrigin("https://admin.example.com", "admin.example.com", "http"))
        assertTrue(sameOrigin("http://[::1]:8090", "[::1]:8090", "http"))
        assertFalse(sameOrigin("http://localhost:8091", "localhost:8090", "http"))
        assertFalse(sameOrigin("http://evil.example:8090", "localhost:8090", "http"))
        assertFalse(sameOrigin("https://admin.example.com", "admin.example.com:8443", "https"))
        assertFalse(sameOrigin("http://localhost:8090", null, "http"))
        assertFalse(sameOrigin("null", "localhost:8090", "http"))
        assertFalse(sameOrigin("http://localhost:8090/path", "localhost:8090", "http"))
    }

    @Test
    fun `a proxy's origin can be allowed by name`() = testApplication {
        app { allowedOrigins = setOf("https://admin.example.com/") }
        val json = HttpHeaders.ContentType to "application/json"
        assertEquals(HttpStatusCode.OK, write(json, HttpHeaders.Origin to "https://admin.example.com").status)
        assertEquals(HttpStatusCode.Forbidden, write(json, HttpHeaders.Origin to "https://admin.example.com.evil.example").status)
    }

    @Test
    fun `a write a plain form could send is refused - JSON or a custom header is required`() = testApplication {
        app()
        // What a cross-site <form> can send without a preflight, on a browser that sends no Origin.
        for (type in listOf("text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x")) {
            val response = write(HttpHeaders.ContentType to type)
            assertEquals(HttpStatusCode.UnsupportedMediaType, response.status, type)
            assertTrue(response.bodyAsText().contains("admin_write_needs_json"), response.bodyAsText())
        }
        // No body at all (a form with no fields), on the routes that take none.
        assertEquals(HttpStatusCode.UnsupportedMediaType, client.post("/api/v1/certificate-config/force-update").status)
        assertEquals(HttpStatusCode.UnsupportedMediaType, client.delete("/api/v1/client-certs/dev-1").status)
        assertTrue(writes.isEmpty(), "no handler ran: $writes")

        // JSON, or a header no form can add (the admin key, the dashboard's marker): accepted.
        assertEquals(HttpStatusCode.OK, write(HttpHeaders.ContentType to "application/json; charset=utf-8").status)
        assertEquals(HttpStatusCode.OK, write(HttpHeaders.ContentType to "multipart/form-data; boundary=x", "X-API-Key" to "k").status)
        assertEquals(HttpStatusCode.OK, write(HttpHeaders.ContentType to "application/octet-stream", "X-PinVault-Admin" to "1").status)
        assertEquals(HttpStatusCode.OK, client.delete("/api/v1/client-certs/dev-1") { header("X-API-Key", "k") }.status)
        assertEquals(HttpStatusCode.OK, client.put("/api/v1/enrollment-open") { header(HttpHeaders.ContentType, "application/json"); setBody("{}") }.status)

        // Reads and device endpoints are not concerned.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/audit-log") { header(HttpHeaders.Origin, "https://evil.example") }.status)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/enroll") { header(HttpHeaders.Origin, "https://evil.example"); setBody("x") }.status)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/connection-history/client-report") { setBody("x") }.status)
    }

    @Test
    fun `without admin keys every admin request must be addressed to this machine`() = testApplication {
        app { requireLocalHost = true; listenerPorts = setOf(8090, 8490); allowedHosts = setOf("pinvault.lan:6650") }
        val json = HttpHeaders.ContentType to "application/json"

        // DNS rebinding: the page's own name, pointed at 127.0.0.1. Same-origin as far as the browser can tell.
        for (host in listOf("attacker.example:8090", "attacker.example", "localhost:9999", "127.0.0.1", "localhost.attacker.example:8090", "192.168.1.10:8090")) {
            val read = client.get("/api/v1/audit-log") { header(HttpHeaders.Host, host) }
            assertEquals(HttpStatusCode.Forbidden, read.status, "GET with Host $host")
            assertTrue(read.bodyAsText().contains("host_not_allowed"), read.bodyAsText())
            assertEquals(HttpStatusCode.Forbidden,
                write(json, HttpHeaders.Host to host, HttpHeaders.Origin to "http://$host").status, "POST with Host $host")
        }
        assertTrue(writes.isEmpty())

        for (host in listOf("localhost:8090", "127.0.0.1:8090", "[::1]:8090", "LOCALHOST:8490", "pinvault.lan:6650")) {
            assertEquals(HttpStatusCode.OK, client.get("/api/v1/audit-log") { header(HttpHeaders.Host, host) }.status, host)
            assertEquals(HttpStatusCode.OK, write(json, HttpHeaders.Host to host, HttpHeaders.Origin to "http://${host.lowercase()}").status, host)
        }
        // Devices and the health probe reach their endpoints under any name.
        assertEquals(HttpStatusCode.OK, client.get("/health") { header(HttpHeaders.Host, "192.168.1.10:8090") }.status)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/enroll") { header(HttpHeaders.Host, "192.168.1.10:8090"); setBody("x") }.status)
    }

    @Test
    fun `with admin keys the Host is not restricted, and refusals are reported`() = testApplication {
        app()
        val seen = CopyOnWriteArrayList<String>()
        BrowserGuardRefusals.listener = { _, method, path, reason -> seen += "$method $path $reason" }
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/audit-log") { header(HttpHeaders.Host, "pinvault.example.com") }.status)
        write(HttpHeaders.ContentType to "application/json", HttpHeaders.Origin to "https://evil.example")
        assertEquals(listOf("POST /api/v1/hosts/generate-cert cross_origin_request"), seen.toList())
    }
}
