package com.example.pinvault.server.plugin

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Without admin keys (`ALLOW_ANONYMOUS_ADMIN=true`) the admin API is open to
 * whoever reaches it, so where it is reached decides everything (A1, A7), and
 * with keys a source address that keeps guessing is cut off (A8).
 */
class AnonymousAdminTest {

    private val writes = CopyOnWriteArrayList<String>()

    private fun ApplicationTestBuilder.app(configure: ApiKeyAuthConfig.() -> Unit) {
        install(io.ktor.server.plugins.contentnegotiation.ContentNegotiation) { json() }
        install(ApiKeyAuth, configure)
        routing {
            put("/api/v1/certificate-config") { writes += "pins"; call.respondText("saved") }
            get("/api/v1/audit-log") { call.respondText("[]") }
            get("/api/v1/certificate-config") { call.respondText("{\"pins\":[]}") }
            post("/api/v1/client-certs/enroll") { call.respondText("enrolled") }
        }
    }

    @Test
    fun `a Config API listener without admin keys serves device endpoints and refuses every admin route`() = testApplication {
        app { registry = AdminRegistry(null, emptyMap()); allowAnonymous = true; anonymousAdminListener = false }

        val write = client.put("/api/v1/certificate-config") {
            header(HttpHeaders.ContentType, "application/json"); setBody("""{"pins":[]}""")
        }
        assertEquals(HttpStatusCode.Forbidden, write.status)
        assertTrue(write.bodyAsText().contains("admin_key_required"), write.bodyAsText())
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/audit-log").status, "reads too")
        assertTrue(writes.isEmpty(), "no pin write ran: $writes")

        // The device side is untouched.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/certificate-config").status)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/enroll").status)
    }

    @Test
    fun `the management listener without admin keys still serves this machine`() = testApplication {
        app { registry = AdminRegistry(null, emptyMap()); allowAnonymous = true }
        val write = client.put("/api/v1/certificate-config") {
            header(HttpHeaders.ContentType, "application/json"); setBody("""{"pins":[]}""")
        }
        assertEquals(HttpStatusCode.OK, write.status, write.bodyAsText())
        assertEquals(listOf("pins"), writes)
    }

    @Test
    fun `anonymous admin is limited to loopback peers and ANONYMOUS_ADMIN_PEERS`() {
        for (local in listOf("127.0.0.1", "127.8.9.10", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "localhost")) {
            assertTrue(PeerRules.allowed(local, emptyList()), local)
        }
        // A program on the LAN sending `Host: localhost:8090` arrives from its own address.
        for (remote in listOf("192.168.1.50", "10.0.0.7", "172.17.0.1", "fe80::1", "2001:db8::1", "evil.example", "")) {
            assertFalse(PeerRules.allowed(remote, emptyList()), remote)
        }
        // A container's gateway, named on purpose.
        assertTrue(PeerRules.allowed("172.17.0.1", listOf("172.17.0.1")))
        assertTrue(PeerRules.allowed("172.18.3.4", listOf("172.16.0.0/12")))
        assertFalse(PeerRules.allowed("172.32.0.1", listOf("172.16.0.0/12")))
        assertTrue(PeerRules.allowed("fd00::5", listOf("fd00::/8")))
        assertFalse(PeerRules.allowed("192.168.1.50", listOf("fd00::/8")), "families never match each other")

        assertTrue(PeerRules.valid("10.0.0.0/8"))
        assertTrue(PeerRules.valid("172.17.0.1"))
        assertFalse(PeerRules.valid("10.0.0.0/33"))
        assertFalse(PeerRules.valid("gateway.docker.internal"), "names are never resolved")
        assertFalse(PeerRules.valid("10.0.0.0/x"))
    }

    @Test
    fun `invalid admin keys from one address are cut off with 429, a correct key is never counted`() = testApplication {
        val alice = "alice-key-0123456789"
        val hash = MessageDigest.getInstance("SHA-256").digest(alice.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        app { registry = AdminRegistry.fromEnv(mapOf("ADMIN_KEYS" to "alice:$hash")); allowAnonymous = false; failureLimit = 5 }

        // Any number of correct requests: nothing is counted.
        repeat(20) { assertEquals(HttpStatusCode.OK, client.get("/api/v1/audit-log") { header("X-API-Key", alice) }.status) }

        repeat(5) { assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/audit-log") { header("X-API-Key", "guess-$it") }.status) }
        val cutOff = client.get("/api/v1/audit-log") { header("X-API-Key", "guess-6") }
        assertEquals(HttpStatusCode.TooManyRequests, cutOff.status)
        assertEquals("600", cutOff.headers[HttpHeaders.RetryAfter])
        // ...the right key included: a guess that hit would otherwise still be told apart.
        assertEquals(HttpStatusCode.TooManyRequests, client.get("/api/v1/audit-log") { header("X-API-Key", alice) }.status)
        // Devices are not admins: their endpoints stay open.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/certificate-config").status)
    }

    @Test
    fun `ADMIN_AUTH_FAILURE_LIMIT=0 turns the limit off`() = testApplication {
        app { registry = AdminRegistry("shared-key-0123456789", emptyMap()); allowAnonymous = false; failureLimit = 0 }
        repeat(40) { assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/audit-log") { header("X-API-Key", "guess-$it") }.status) }
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/audit-log") { header("X-API-Key", "shared-key-0123456789") }.status)
    }
}
