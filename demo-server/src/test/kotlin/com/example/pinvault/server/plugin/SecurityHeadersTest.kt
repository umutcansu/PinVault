package com.example.pinvault.server.plugin

import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecurityHeadersTest {

    @Test
    fun `no Server header, the security headers on every answer, HSTS over TLS only`() = testApplication {
        install(SecurityHeaders)
        routing { get("/health") { call.respondText("ok") } }

        val plain = client.get("http://localhost/health")
        assertEquals(HttpStatusCode.OK, plain.status)
        assertNull(plain.headers[HttpHeaders.Server], "the framework and its version are nobody's business")
        assertEquals("nosniff", plain.headers["X-Content-Type-Options"])
        assertEquals("DENY", plain.headers["X-Frame-Options"])
        assertEquals("no-referrer", plain.headers["Referrer-Policy"])
        assertTrue(plain.headers["Content-Security-Policy"]!!.contains("frame-ancestors 'none'"))
        assertTrue(plain.headers[HttpHeaders.Date]!!.endsWith("GMT"))
        assertNull(plain.headers[HttpHeaders.StrictTransportSecurity], "never on the plain-HTTP port")

        val tls = client.get("https://localhost/health")
        assertEquals("max-age=31536000", tls.headers[HttpHeaders.StrictTransportSecurity])
        assertNull(tls.headers[HttpHeaders.Server])

        // A 404 (no route) carries them too.
        val missing = client.get("http://localhost/nothing")
        assertEquals(HttpStatusCode.NotFound, missing.status)
        assertEquals("DENY", missing.headers["X-Frame-Options"])
        assertNull(missing.headers[HttpHeaders.Server])
    }
}
