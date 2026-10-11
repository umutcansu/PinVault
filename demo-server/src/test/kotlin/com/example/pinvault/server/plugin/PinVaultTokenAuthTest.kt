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

    private fun ApplicationTestBuilder.app(
        audience: String? = "api", required: Set<String>? = null,
        certBinding: Boolean = false, certificate: java.security.cert.X509Certificate? = null
    ) {
        install(PinVaultTokenAuth) {
            secrets = { mapOf("k1" to secret) }
            this.audience = audience
            requireAnnotations = required
            clock = { now }
            requireCertBinding = certBinding
            // The test host has no TLS: the connection's verified client certificate is given here.
            clientCertificate = { certificate }
        }
        routing {
            get("/health") { call.respondText("ok") }
            get("/data") { call.respondText("device " + call.pinVaultToken()!!.deviceId + " " + call.pinVaultToken()!!.annotations) }
        }
    }

    private fun token(
        kid: String = "k1", key: ByteArray = secret, aud: String = "api", at: Long = now, anno: List<String> = emptyList(),
        certThumbprint: String? = null
    ) = PinVaultToken.issue(kid, key, "dev-1", aud, "00000000", 1, 300, anno, at, keyThumbprint = "jkt-of-the-device-key", certThumbprint = certThumbprint)

    private fun certificate(cn: String): java.security.cert.X509Certificate {
        val key = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val name = org.bouncycastle.asn1.x500.X500Name("CN=$cn")
        val builder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, java.math.BigInteger.ONE,
            java.util.Date(now * 1000 - 86_400_000), java.util.Date(now * 1000 + 86_400_000), name, key.public)
        return org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
            .getCertificate(builder.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(key.private)))
    }

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
    fun `the audience is required - without one no token is accepted`() = testApplication {
        app(audience = null)
        val refused = client.get("/data") { header(PinVaultToken.HEADER, token(aud = "whatever")) }
        assertEquals(HttpStatusCode.Unauthorized, refused.status)
        assertEquals("""{"error":"invalid_token","reason":"audience"}""", refused.bodyAsText())
    }

    @Test
    fun `a request that names its device must name the token's`() = testApplication {
        app()
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, token()); header("X-Device-Id", "dev-1") }.status)
        val other = client.get("/data") { header(PinVaultToken.HEADER, token()); header("X-Device-Id", "dev-2") }
        assertEquals(HttpStatusCode.Unauthorized, other.status)
        assertEquals("""{"error":"invalid_token","reason":"device_mismatch"}""", other.bodyAsText())
        // No X-Device-Id: nothing to compare (a backend that does not send it).
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, token()) }.status)
    }

    @Test
    fun `cnf claims are read, and ignored unless cert binding is on`() = testApplication {
        val cert = certificate("device")
        val bound = token(certThumbprint = PinVaultToken.certThumbprint(cert.encoded))
        val claims = (PinVaultToken.verify(bound, mapOf("k1" to secret), "api", now) as PinVaultToken.Result.Valid).claims
        assertEquals("jkt-of-the-device-key", claims.keyThumbprint)
        assertEquals(PinVaultToken.certThumbprint(cert.encoded), claims.certThumbprint)
        assertEquals(43, claims.certThumbprint!!.length, "base64url SHA-256, no padding (RFC 8705)")
        // An old token without cnf, and a bound one over a connection without the certificate: both fine while binding is off.
        app(certificate = null)
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, PinVaultToken.issue("k1", secret, "dev-1", "api", "0", 1, 300, nowSeconds = now)) }.status)
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, bound) }.status)
    }

    @Test
    fun `PINVAULT_TOKEN_REQUIRE_CERT_BINDING - only over mTLS with the certificate the token names`() = testApplication {
        val device = certificate("device")
        val stranger = certificate("stranger")
        app(certBinding = true, certificate = device)
        assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, token(certThumbprint = PinVaultToken.certThumbprint(device.encoded))) }.status)
        // Lifted from the device and replayed with another certificate, or attested over plain TLS (no x5t#S256), or issued before cnf.
        for (refused in listOf(token(certThumbprint = PinVaultToken.certThumbprint(stranger.encoded)), token(),
            PinVaultToken.issue("k1", secret, "dev-1", "api", "0", 1, 300, nowSeconds = now))) {
            val response = client.get("/data") { header(PinVaultToken.HEADER, refused) }
            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals("""{"error":"invalid_token","reason":"cert_binding"}""", response.bodyAsText())
        }
    }

    @Test
    fun `cert binding refuses a request without a client certificate`() = testApplication {
        val device = certificate("device")
        app(certBinding = true, certificate = null)
        val response = client.get("/data") { header(PinVaultToken.HEADER, token(certThumbprint = PinVaultToken.certThumbprint(device.encoded))) }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("cert_binding"))
    }
}

/** PINVAULT_TOKEN_REQUIRE_PROOF: the token plus a PinVault-Proof per request (§5.1). */
class PinVaultTokenAuthProofTest {
    private val secret = ByteArray(32) { 7 }
    private val now = 1_759_660_800L
    private val device = java.security.KeyPairGenerator.getInstance("EC")
        .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val token = PinVaultToken.issue("k1", secret, "dev-1", "api", "00000000", 1, 300, nowSeconds = now,
        keyThumbprint = PinVaultToken.jwkThumbprint(device.public as java.security.interfaces.ECPublicKey))

    private fun ApplicationTestBuilder.app(origin: String? = null) {
        install(PinVaultTokenAuth) {
            secrets = { mapOf("k1" to secret) }
            audience = "api"
            clock = { now }
            requireProof = true
            publicOrigin = origin
        }
        routing { get("/data") { call.respondText("ok") } }
    }

    private suspend fun ApplicationTestBuilder.reason(vararg headers: Pair<String, String>): String {
        val response = client.get("/data?q=1") { headers.forEach { (n, v) -> header(n, v) } }
        if (response.status == HttpStatusCode.OK) return "ok"
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.headers[HttpHeaders.WWWAuthenticate].orEmpty().startsWith("PinVault-Token error=\"invalid_token\""))
        return Regex("\"reason\":\"([a-z_]+)\"").find(response.bodyAsText())!!.groupValues[1]
    }

    @Test
    fun `the token alone is refused, with a proof for this request it passes once`() = testApplication {
        app()
        assertEquals("proof_missing", reason(PinVaultToken.HEADER to token))
        // The test client talks to http://localhost:80.
        val proof = com.example.pinvault.server.service.attestation.Proofs.make(device, "GET", "http://localhost/data", token, now)
        assertEquals("ok", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to proof))
        assertEquals("proof_replay", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to proof))
    }

    @Test
    fun `publicOrigin replaces what the proxy changed`() = testApplication {
        app(origin = "https://api.example.com")
        val local = com.example.pinvault.server.service.attestation.Proofs.make(device, "GET", "http://localhost/data", token, now)
        assertEquals("proof_url", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to local))
        val public = com.example.pinvault.server.service.attestation.Proofs.make(device, "GET", "https://api.example.com/data", token, now)
        assertEquals("ok", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to public))
    }

    @Test
    fun `a proof for another token or by another key is refused`() = testApplication {
        app()
        val other = PinVaultToken.issue("k1", secret, "dev-1", "api", "00000000", 1, 300, nowSeconds = now,
            keyThumbprint = PinVaultToken.jwkThumbprint(device.public as java.security.interfaces.ECPublicKey))
        val forOther = com.example.pinvault.server.service.attestation.Proofs.make(device, "GET", "http://localhost/data", other, now)
        assertEquals("proof_token", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to forOther))
        val stranger = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val byStranger = com.example.pinvault.server.service.attestation.Proofs.make(stranger, "GET", "http://localhost/data", token, now)
        assertEquals("proof_key", reason(PinVaultToken.HEADER to token, "PinVault-Proof" to byStranger))
        // A token issued before cnf (no jkt) cannot be proven at all.
        val bare = PinVaultToken.issue("k1", secret, "dev-1", "api", "00000000", 1, 300, nowSeconds = now)
        val forBare = com.example.pinvault.server.service.attestation.Proofs.make(device, "GET", "http://localhost/data", bare, now)
        assertEquals("proof_key", reason(PinVaultToken.HEADER to bare, "PinVault-Proof" to forBare))
    }
}

/** PINVAULT_TOKEN_ANOMALY: each device's token use counted (§5.2). */
class PinVaultTokenAuthAnomalyTest {
    private val secret = ByteArray(32) { 7 }
    private val now = 1_759_660_800L
    private val reported = mutableListOf<String>()
    private var address = "10.0.0.1"

    private fun ApplicationTestBuilder.app(action: com.example.pinvault.server.service.attestation.TokenAnomalyAction, proof: Boolean = false) {
        install(PinVaultTokenAuth) {
            secrets = { mapOf("k1" to secret) }
            audience = "api"
            clock = { now }
            requireProof = proof
            anomaly = com.example.pinvault.server.service.attestation.TokenAnomalyDetector(maxAddresses = 2, maxRequests = 100, clock = { now })
            anomalyAction = action
            onAnomaly = { claims, found, at -> reported += "${claims.audience}/${claims.deviceId} ${found.kind} $at" }
            remoteAddress = { address }
        }
        routing { get("/data") { call.respondText("ok") } }
    }

    private fun token() = PinVaultToken.issue("k1", secret, "dev-1", "api", "00000000", 1, 300, nowSeconds = now, keyThumbprint = "jkt")

    @Test
    fun `warn reports the device once and keeps serving it`() = testApplication {
        app(com.example.pinvault.server.service.attestation.TokenAnomalyAction.WARN)
        for (a in listOf("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")) {
            address = a
            assertEquals(HttpStatusCode.OK, client.get("/data") { header(PinVaultToken.HEADER, token()) }.status)
        }
        assertEquals(listOf("api/dev-1 addresses 10.0.0.3"), reported)
    }

    @Test
    fun `refuse answers 429 until the window ends, and a lifted token without its proof counts too`() = testApplication {
        app(com.example.pinvault.server.service.attestation.TokenAnomalyAction.REFUSE, proof = true)
        for (a in listOf("10.0.0.1", "10.0.0.2")) {
            address = a
            assertEquals(HttpStatusCode.Unauthorized, client.get("/data") { header(PinVaultToken.HEADER, token()) }.status, "no proof")
        }
        address = "10.0.0.3"
        val refused = client.get("/data") { header(PinVaultToken.HEADER, token()) }
        assertEquals(HttpStatusCode.TooManyRequests, refused.status)
        assertEquals("""{"error":"token_anomaly"}""", refused.bodyAsText())
        assertTrue((refused.headers[HttpHeaders.RetryAfter] ?: "0").toInt() > 0)
        assertEquals(1, reported.size)
    }
}

