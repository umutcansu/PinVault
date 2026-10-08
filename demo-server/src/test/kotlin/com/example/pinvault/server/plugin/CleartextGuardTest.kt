package com.example.pinvault.server.plugin

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.install
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlin.test.*

/**
 * Enrollment — a token in, a private key and its password out — is not served
 * over plain HTTP to another machine (D2). The management server listens on
 * HTTP; its copy of the enrollment endpoint answered there like anywhere else.
 */
class CleartextGuardTest {

    private var handled = 0

    private fun ApplicationTestBuilder.configureApp(loopback: Boolean) {
        install(CleartextGuard) { isLoopback = { loopback } }
        routing {
            post("/api/v1/client-certs/enroll") { handled++; call.respondText("enrolled with ${call.receiveText().length} bytes") }
            get("/api/v1/client-certs/{hostname}/download") { handled++; call.respondText("p12") }
            get("/api/v1/vault/{key}") { handled++; call.respondText("file") }
            get("/api/v1/certificate-config") { call.respondText("pins") }
            get("/api/v1/client-certs") { call.respondText("admin list") }
            post("/api/v1/connection-history/client-report") { call.respondText("saved") }
        }
    }

    @Test
    fun `enrollment over cleartext from another machine is refused before the token is read`() = testApplication {
        configureApp(loopback = false)
        val response = client.post("/api/v1/client-certs/enroll") { setBody("""{"token":"one-time-token"}""") }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("tls_required"))
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/client-certs/bank.example/download").status)
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/vault/ml-model") { header("X-Vault-Token", "t") }.status)
        assertEquals(0, handled, "no handler ran")
    }

    @Test
    fun `what carries no credential or key stays reachable over cleartext`() = testApplication {
        configureApp(loopback = false)
        assertEquals("pins", client.get("/api/v1/certificate-config").bodyAsText())
        assertEquals("admin list", client.get("/api/v1/client-certs").bodyAsText())
        assertEquals("saved", client.post("/api/v1/connection-history/client-report") { setBody("{}") }.bodyAsText())
    }

    @Test
    fun `the same request is served to this machine and over TLS`() {
        testApplication {
            // Loopback: local tooling, the tests, a TLS-terminating proxy on the same host.
            configureApp(loopback = true)
            assertEquals(HttpStatusCode.OK, client.post("/api/v1/client-certs/enroll") { setBody("{}") }.status)
        }
        testApplication {
            configureApp(loopback = false)
            val overTls = client.post("https://localhost/api/v1/client-certs/enroll") { setBody("{}") }
            assertEquals(HttpStatusCode.OK, overTls.status, overTls.bodyAsText())
            assertEquals(HttpStatusCode.OK, client.get("https://localhost/api/v1/vault/ml-model").status)
        }
        assertEquals(3, handled)
    }

    @Test
    fun `loopback is decided from the socket's literal address, never by resolving a name`() {
        for (address in listOf("127.0.0.1", "127.8.9.10", "::1", "0:0:0:0:0:0:0:1", "localhost")) {
            assertTrue(isLoopbackAddress(address), address)
        }
        for (address in listOf("192.168.1.10", "10.0.2.2", "172.17.0.1", "0.0.0.0", "2001:db8::1", "fe80::1%en0",
            "localhost.attacker.example", "127.0.0.1.attacker.example", "", "not an address")) {
            assertFalse(isLoopbackAddress(address), address)
        }
    }

    @Test
    fun `the guarded endpoints are the ones that take a token or return a key`() {
        assertTrue(carriesDeviceSecrets("/api/v1/client-certs/enroll", HttpMethod.Post))
        assertTrue(carriesDeviceSecrets("/api/v1/client-certs/renew", HttpMethod.Post))
        assertTrue(carriesDeviceSecrets("/api/v1/client-certs/192.168.1.20/download", HttpMethod.Get))
        assertTrue(carriesDeviceSecrets("/api/v1/vault/ml-model", HttpMethod.Get))
        assertTrue(carriesDeviceSecrets("/api/v1/vault/devices/android-1/public-key", HttpMethod.Post))
        assertFalse(carriesDeviceSecrets("/api/v1/vault/distributions", HttpMethod.Get), "an admin route, not a file")
        assertFalse(carriesDeviceSecrets("/api/v1/certificate-config", HttpMethod.Get))
        assertFalse(carriesDeviceSecrets("/api/v1/vault/report", HttpMethod.Post))
        assertFalse(carriesDeviceSecrets("/health", HttpMethod.Get))
        assertFalse(carriesDeviceSecrets("/", HttpMethod.Get))
    }
}
