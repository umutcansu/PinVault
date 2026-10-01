package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.TLS_PEER_CERTIFICATE
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.application.install
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.test.*

/** The request-size cap on device endpoints and the per-request revocation check on mTLS listeners. */
class ClientEdgePluginsTest {

    private fun ApplicationTestBuilder.echoRoutes() = routing {
        post("/api/v1/client-certs/enroll") { call.respondText("read ${call.receiveText().length}") }
        put("/api/v1/vault/model") { call.respondText("read ${call.receiveText().length}") }
        get("/api/v1/certificate-config") { call.respondText("config") }
        post("/api/v1/client-certs/renew") { call.respondText("renewed") }
    }

    // ── ClientBodyLimit ──────────────────────────────────────────────────

    @Test
    fun `a device endpoint refuses a body above the cap before reading it`() = testApplication {
        install(ClientBodyLimit)
        echoRoutes()

        val big = client.post("/api/v1/client-certs/enroll") { setBody("x".repeat(70 * 1024)) }
        assertEquals(HttpStatusCode.PayloadTooLarge, big.status)
        assertTrue(big.bodyAsText().contains("body_too_large"))

        val small = client.post("/api/v1/client-certs/enroll") { setBody("x".repeat(2_000)) }
        assertEquals(HttpStatusCode.OK, small.status)
        assertEquals("read 2000", small.bodyAsText())
    }

    @Test
    fun `a device endpoint refuses a body without a declared length`() {
        // Real socket: the test host never produces a chunked request.
        val port = java.net.ServerSocket(0).use { it.localPort }
        val server = io.ktor.server.engine.embeddedServer(io.ktor.server.netty.Netty, port = port, host = "127.0.0.1") {
            install(ClientBodyLimit)
            routing { post("/api/v1/client-certs/enroll") { call.respondText("read ${call.receiveText().length}") } }
        }.start(wait = false)
        try {
            val http = java.net.http.HttpClient.newBuilder().version(java.net.http.HttpClient.Version.HTTP_1_1).build()
            val uri = java.net.URI("http://127.0.0.1:$port/api/v1/client-certs/enroll")
            val chunked = java.net.http.HttpRequest.newBuilder(uri)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofInputStream { "x".repeat(100).byteInputStream() })
                .build()
            assertEquals(411, http.send(chunked, java.net.http.HttpResponse.BodyHandlers.ofString()).statusCode())

            val declared = java.net.http.HttpRequest.newBuilder(uri)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("x".repeat(100)))
                .build()
            val ok = http.send(declared, java.net.http.HttpResponse.BodyHandlers.ofString())
            assertEquals(200, ok.statusCode())
            assertEquals("read 100", ok.body())
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun `admin uploads are not capped`() = testApplication {
        install(ClientBodyLimit)
        echoRoutes()

        val upload = client.put("/api/v1/vault/model") { setBody("x".repeat(200 * 1024)) }
        assertEquals(HttpStatusCode.OK, upload.status)
        assertEquals("read ${200 * 1024}", upload.bodyAsText())
    }

    // ── RevocationGate ───────────────────────────────────────────────────

    private fun clientCert(clientId: String): X509Certificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=PinVault Client: $clientId, O=PinVault Client, C=TR")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000), name, pair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private fun ApplicationTestBuilder.gated(presented: X509Certificate?) {
        if (presented != null) {
            install(createApplicationPlugin("FakePeerCert") {
                onCall { call -> call.attributes.put(TLS_PEER_CERTIFICATE, presented) }
            })
        }
        install(RevocationGate) { isRevoked = { it == "tablet-08" } }
        echoRoutes()
    }

    @Test
    fun `a revoked identity is refused on every request, with the renewal answer`() = testApplication {
        gated(clientCert("tablet-08"))

        val config = client.get("/api/v1/certificate-config")
        assertEquals(HttpStatusCode.Forbidden, config.status)
        assertTrue(config.bodyAsText().contains("reenroll_required"))
        assertEquals(HttpStatusCode.Forbidden, client.post("/api/v1/client-certs/renew") { setBody("{}") }.status)
    }

    @Test
    fun `an active identity passes`() = testApplication {
        gated(clientCert("tablet-07"))
        assertEquals("config", client.get("/api/v1/certificate-config").bodyAsText())
    }

    @Test
    fun `a request without a client certificate is not the gate's business`() = testApplication {
        gated(null)
        assertEquals("config", client.get("/api/v1/certificate-config").bodyAsText())
    }
}
