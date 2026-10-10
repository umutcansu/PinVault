package com.example.pinvault.server.plugin

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.origin
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import org.slf4j.LoggerFactory
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `TRUSTED_PROXIES`: behind Cloudflare / a tunnel every device came from the
 * proxy's address, so per-address limits counted the whole fleet as one
 * caller. The forwarded address is believed only from a listed proxy.
 */
class ClientAddressTest {

    private val savedRules = TrustedProxies.rules
    private val savedHeader = TrustedProxies.header

    @AfterTest
    fun restore() {
        TrustedProxies.rules = savedRules
        TrustedProxies.header = savedHeader
    }

    private fun trust(vararg rules: String, header: String = "X-Forwarded-For") {
        TrustedProxies.rules = rules.toList()
        TrustedProxies.header = header
    }

    @Test
    fun `without TRUSTED_PROXIES the socket's peer is the client whatever the header says`() {
        trust()
        assertEquals("198.51.100.4", TrustedProxies.clientAddress("198.51.100.4", listOf("203.0.113.7")))
    }

    @Test
    fun `a forwarding header from a peer that is not a trusted proxy is ignored`() {
        trust("10.0.0.0/8")
        assertEquals("198.51.100.4", TrustedProxies.clientAddress("198.51.100.4", listOf("203.0.113.7")))
    }

    @Test
    fun `X-Forwarded-For is read from the right, skipping our proxies - a spoofed left entry does not count`() {
        trust("10.0.0.0/8", "172.16.0.0/12")
        // The device wrote "127.0.0.1" itself; Cloudflare appended the real address, the tunnel its own.
        assertEquals("203.0.113.7",
            TrustedProxies.clientAddress("10.0.0.5", listOf("127.0.0.1, 203.0.113.7, 172.18.0.3")))
        // Two header lines are one list.
        assertEquals("203.0.113.7", TrustedProxies.clientAddress("10.0.0.5", listOf("1.2.3.4", "203.0.113.7")))
    }

    @Test
    fun `when every hop is a proxy of ours the leftmost is the client, and garbage leaves the peer`() {
        trust("10.0.0.0/8")
        assertEquals("10.1.1.1", TrustedProxies.clientAddress("10.0.0.5", listOf("10.1.1.1, 10.2.2.2")))
        assertEquals("10.0.0.5", TrustedProxies.clientAddress("10.0.0.5", listOf("203.0.113.7, evil.example.com")))
        assertEquals("10.0.0.5", TrustedProxies.clientAddress("10.0.0.5", listOf("unknown")))
        assertEquals("10.0.0.5", TrustedProxies.clientAddress("10.0.0.5", emptyList()))
    }

    @Test
    fun `addresses with ports and IPv6 are normalized`() {
        trust("10.0.0.0/8")
        assertEquals("203.0.113.7", TrustedProxies.clientAddress("10.0.0.5", listOf("203.0.113.7:51234")))
        assertEquals("2001:db8:0:0:0:0:0:1", TrustedProxies.clientAddress("10.0.0.5", listOf("[2001:db8::1]:443")))
        assertEquals("2001:db8:0:0:0:0:0:1", TrustedProxies.clientAddress("10.0.0.5", listOf("2001:db8::1")))
    }

    @Test
    fun `a single-address header such as CF-Connecting-IP is taken as it is`() {
        trust("127.0.0.1", header = "CF-Connecting-IP")
        assertEquals("203.0.113.7", TrustedProxies.clientAddress("127.0.0.1", listOf("203.0.113.7")))
        assertEquals("127.0.0.1", TrustedProxies.clientAddress("127.0.0.1", listOf("not-an-ip")))
        assertEquals("198.51.100.4", TrustedProxies.clientAddress("198.51.100.4", listOf("203.0.113.7")))
    }

    @Test
    fun `a malformed TRUSTED_PROXIES or header name stops the start`() {
        trust("10.0.0.0/33")
        assertFailsWith<IllegalArgumentException> { TrustedProxies.validate() }
        trust("cloudflare")
        assertFailsWith<IllegalArgumentException> { TrustedProxies.validate() }
        trust("10.0.0.0/8", header = "X-Forwarded-For: x")
        assertFailsWith<IllegalArgumentException> { TrustedProxies.validate() }
        trust("10.0.0.0/8", "2001:db8::/32", header = "CF-Connecting-IP")
        TrustedProxies.validate()
    }

    // ── Real sockets: the test engine has no peer address ──────────────────

    private val http = HttpClient.newHttpClient()

    /** (status, body) of a request to this test's server; [headers] as name/value pairs. */
    private fun call(port: Int, method: String, path: String, vararg headers: Pair<String, String>): Pair<Int, String> {
        val builder = HttpRequest.newBuilder(URI("http://127.0.0.1:$port$path"))
            .method(method, HttpRequest.BodyPublishers.noBody())
        headers.forEach { (name, value) -> builder.header(name, value) }
        val response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        return response.statusCode() to response.body()
    }

    private fun serve(module: Application.() -> Unit, block: (Int) -> Unit) {
        val port = ServerSocket(0).use { it.localPort }
        val server = embeddedServer(Netty, port = port, host = "127.0.0.1", module = module).start(wait = false)
        try {
            block(port)
        } finally {
            server.stop(100, 500)
        }
    }

    @Test
    fun `origin carries the forwarded address only when the socket peer is a trusted proxy`() {
        val module: Application.() -> Unit = {
            install(ClientAddress)
            routing { get("/who") { call.respondText(call.request.origin.remoteAddress) } }
        }
        trust()
        serve(module) { port ->
            assertEquals("127.0.0.1", call(port, "GET", "/who", "X-Forwarded-For" to "203.0.113.7").second,
                "no proxy trusted: the header is the caller's word")
        }
        trust("127.0.0.1")
        serve(module) { port ->
            assertEquals("203.0.113.7", call(port, "GET", "/who", "X-Forwarded-For" to "203.0.113.7").second)
            assertEquals("127.0.0.1", call(port, "GET", "/who").second, "no header: the proxy itself")
        }
    }

    @Test
    fun `anonymous admin is refused through a trusted proxy on this machine`() {
        val module: Application.() -> Unit = {
            install(ContentNegotiation) { json() }
            install(ClientAddress)
            install(ApiKeyAuth) { registry = AdminRegistry(null, emptyMap()); allowAnonymous = true; anonymousAdminListener = true }
            routing { put("/api/v1/certificate-config") { call.respondText("saved") } }
        }
        trust()
        serve(module) { port ->
            assertEquals(200, call(port, "PUT", "/api/v1/certificate-config").first,
                "loopback without a proxy: the dev mode as before")
        }
        // A tunnel on this machine forwards the internet from 127.0.0.1.
        trust("127.0.0.1")
        serve(module) { port ->
            val (status, body) = call(port, "PUT", "/api/v1/certificate-config", "X-Forwarded-For" to "203.0.113.7")
            assertEquals(403, status, body)
            assertEquals(403, call(port, "PUT", "/api/v1/certificate-config").first, "a proxy peer is never \"this machine\"")
        }
    }

    @Test
    fun `the request log has the client address, the path without its query and only a well-formed device id`() {
        val logger = LoggerFactory.getLogger("ConfigApiAccess") as Logger
        val appender = ListAppender<ILoggingEvent>().apply { start() }
        logger.addAppender(appender)
        try {
            trust("127.0.0.1")
            serve({
                install(ClientAddress)
                installRequestLog("default-tls :8091")
                routing {
                    get("/api/v1/certificate-config") { call.respondText("{}") }
                    get("/health") { call.respondText("ok") }
                }
            }) { port ->
                call(port, "GET", "/api/v1/certificate-config?signed=true&token=secret",
                    "X-Forwarded-For" to "203.0.113.7", "X-Device-Id" to "6f1c2b6a-0e2f")
                call(port, "GET", "/api/v1/certificate-config", "X-Device-Id" to "bad id INJECTED")
                call(port, "GET", "/health")
            }
            // CallLogging also writes the listener's start/stop lines to this logger.
            val lines = appender.list.map { it.formattedMessage }.filter { it.startsWith("[") }
            assertEquals(2, lines.size, "health checks are not logged: $lines")
            assertTrue(lines[0].startsWith("[default-tls :8091] 200 OK GET /api/v1/certificate-config from 203.0.113.7 device=6f1c2b6a-0e2f in "), lines[0])
            assertFalse(lines.any { "secret" in it || "token=" in it }, "no query string: $lines")
            assertTrue(lines[1].contains("from 127.0.0.1 in "), lines[1])
            assertFalse(lines[1].contains("INJECTED") || lines[1].contains("device="), lines[1])
        } finally {
            logger.detachAppender(appender)
        }
    }
}
