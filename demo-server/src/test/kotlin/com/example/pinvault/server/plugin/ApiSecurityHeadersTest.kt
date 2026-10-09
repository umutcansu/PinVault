package com.example.pinvault.server.plugin

import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ApiSecurityHeadersTest {

    @Test
    fun `nosniff on every answer, HSTS over TLS only, no HTML headers`() = testApplication {
        install(ApiSecurityHeaders)
        routing { get("/health") { call.respondText("ok") } }

        val plain = client.get("http://localhost/health")
        assertEquals(HttpStatusCode.OK, plain.status)
        assertEquals("nosniff", plain.headers["X-Content-Type-Options"])
        assertNull(plain.headers[HttpHeaders.StrictTransportSecurity], "never on the plain-HTTP port")
        // JSON listeners, not HTML: the admin-UI headers do not belong here.
        assertNull(plain.headers["X-Frame-Options"])
        assertNull(plain.headers["Content-Security-Policy"])

        val tls = client.get("https://localhost/health")
        assertEquals("max-age=31536000", tls.headers[HttpHeaders.StrictTransportSecurity])
        assertEquals("nosniff", tls.headers["X-Content-Type-Options"])

        // A 404 (no route) carries nosniff too.
        val missing = client.get("http://localhost/nothing")
        assertEquals(HttpStatusCode.NotFound, missing.status)
        assertEquals("nosniff", missing.headers["X-Content-Type-Options"])
    }

    @Test
    fun `a route that set its own value is not overwritten`() = testApplication {
        install(ApiSecurityHeaders)
        routing {
            get("/own") {
                call.response.header("X-Content-Type-Options", "custom")
                call.respondText("ok")
            }
        }
        assertEquals("custom", client.get("http://localhost/own").headers["X-Content-Type-Options"])
    }
}
