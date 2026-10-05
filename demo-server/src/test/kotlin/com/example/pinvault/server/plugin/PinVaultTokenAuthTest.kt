package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.attestation.PinVaultToken
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The reference PinVault-Token verifier: what the mock hosts run with MOCK_HOST_REQUIRE_TOKEN=true. */
class PinVaultTokenAuthTest {

    private val secret = ByteArray(32) { 7 }
    private val now = 1_759_660_800L

    private fun ApplicationTestBuilder.app(audience: String? = "api", required: Set<String>? = null) {
        install(PinVaultTokenAuth) {
            secrets = { mapOf("k1" to secret) }
            this.audience = audience
            requireAnnotations = required
            clock = { now }
        }
        routing {
            get("/health") { call.respondText("ok") }
            get("/data") { call.respondText("device " + call.pinVaultToken()!!.deviceId + " " + call.pinVaultToken()!!.annotations) }
        }
    }

    private fun token(kid: String = "k1", key: ByteArray = secret, aud: String = "api", at: Long = now, anno: List<String> = emptyList()) =
        PinVaultToken.issue(kid, key, "dev-1", aud, "00000000", 1, 300, anno, at)

    @Test
    fun `a valid token passes and the claims reach the handler`() = testApplication {
        app()
        val response = client.get("/data") { header(PinVaultToken.HEADER, token(anno = listOf("staff"))) }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertEquals("device dev-1 [staff]", response.bodyAsText())
        assertEquals("ok", client.get("/health").bodyAsText(), "health needs no token")
    }

    @Test
    fun `every refusal is 401 with the header and reason the library looks for`() = testApplication {
        app()
        suspend fun refused(reason: String, vararg headers: Pair<String, String>) {
            val response = client.get("/data") { headers.forEach { (n, v) -> header(n, v) } }
            assertEquals(HttpStatusCode.Unauthorized, response.status, reason)
            val challenge = response.headers[HttpHeaders.WWWAuthenticate] ?: ""
            assertTrue(challenge.startsWith("PinVault-Token error=\"invalid_token\""), challenge)
            assertEquals("""{"error":"invalid_token","reason":"$reason"}""", response.bodyAsText())
        }
        refused("missing")
        refused("malformed", PinVaultToken.HEADER to "not-a-jwt")
        refused("unknown_kid", PinVaultToken.HEADER to token(kid = "k9"))
        refused("signature", PinVaultToken.HEADER to token(key = ByteArray(32) { 8 }))
        refused("expired", PinVaultToken.HEADER to token(at = now - 400))
        refused("audience", PinVaultToken.HEADER to token(aud = "other"))
        // Bearer is not the contract: the header is PinVault-Token.
        refused("missing", HttpHeaders.Authorization to "Bearer ${token()}")
    }

    @Test
    fun `required annotations`() = testApplication {
        app(required = setOf("staff"))
        val without = client.get("/data") { header(PinVaultToken.HEADER, token()) }
        assertEquals(HttpStatusCode.Unauthorized, without.status)
        assertTrue(without.bodyAsText().contains("\"annotations\""), without.bodyAsText())
        val with = client.get("/data") { header(PinVaultToken.HEADER, token(anno = listOf("canary", "staff"))) }
        assertEquals(HttpStatusCode.OK, with.status)
    }

    @Test
    fun `without an audience any Config API's token is accepted`() = testApplication {
        app(audience = null)
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, token(aud = "whatever")) }.status)
    }
}
