package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PinVaultTokenTest {

    private val secret = ByteArray(32) { it.toByte() }
    private val other = ByteArray(32) { (it + 1).toByte() }
    private val secrets = mapOf("2026-10-05-01" to secret, "2026-10-04-01" to other)
    private val now = 1_759_660_800L

    private fun issue(kid: String = "2026-10-05-01", key: ByteArray = secret, anno: List<String> = emptyList(), at: Long = now) =
        PinVaultToken.issue(kid, key, "9774d56d682e549c", "default-tls", "7f3a9c1e", 3, 300, anno, at, jti = "j1")

    @Test
    fun `a token verifies and carries the claims of ATTESTATION md`() {
        val token = issue(anno = listOf("staff", "canary"))
        val parts = token.split('.')
        assertEquals(3, parts.size)
        val header = String(Base64.getUrlDecoder().decode(parts[0]))
        assertTrue(header.contains("\"alg\":\"HS256\"") && header.contains("\"kid\":\"2026-10-05-01\""), header)
        assertTrue(parts.none { it.contains('=') }, "base64url without padding")

        val result = assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(token, secrets, "default-tls", now + 10))
        val c = result.claims
        assertEquals("9774d56d682e549c", c.deviceId)
        assertEquals("default-tls", c.audience)
        assertEquals(now, c.issuedAt)
        assertEquals(now + 300, c.expiresAt)
        assertEquals("7f3a9c1e", c.arc)
        assertEquals(3, c.policyVersion)
        assertEquals(listOf("staff", "canary"), c.annotations)
        assertEquals("pinvault", c.payload["iss"]!!.jsonPrimitive.content)
        assertEquals("9774d56d682e549c", c.payload["sub"]!!.jsonPrimitive.content)
        assertEquals("j1", c.jti)
    }

    @Test
    fun `the issuer is checked, after the signature`() {
        val parts = issue().split('.')
        val payload = String(Base64.getUrlDecoder().decode(parts[1])).replace("\"iss\":\"pinvault\"", "\"iss\":\"other\"")
        val signingInput = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())
        // Re-signed with the right secret: everything but the issuer is in order.
        val mac = javax.crypto.Mac.getInstance("HmacSHA256").apply { init(javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256")) }
        val resigned = signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(signingInput.toByteArray(Charsets.US_ASCII)))
        assertEquals(PinVaultToken.Result.Invalid("issuer"), PinVaultToken.verify(resigned, secrets, "default-tls", now))
        // With the old signature it is the signature that fails, before the issuer is looked at.
        assertEquals(PinVaultToken.Result.Invalid("signature"), PinVaultToken.verify(signingInput + "." + parts[2], secrets, "default-tls", now))
    }

    @Test
    fun `anno is absent without annotations`() {
        val payload = String(Base64.getUrlDecoder().decode(issue().split('.')[1]))
        assertTrue(!payload.contains("anno"), payload)
    }

    @Test
    fun `expiry with leeway`() {
        val token = issue()
        assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(token, secrets, "default-tls", now + 300 + 59))
        assertEquals(PinVaultToken.Result.Invalid("expired"), PinVaultToken.verify(token, secrets, "default-tls", now + 300 + 61))
        assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(token, secrets, "default-tls", now + 300 + 100, leewaySeconds = 120))
        // A token from well in the future is not one issued now.
        assertEquals(PinVaultToken.Result.Invalid("expired"), PinVaultToken.verify(issue(at = now + 1000), secrets, "default-tls", now))
    }

    @Test
    fun `unknown kid, wrong secret, tampering and audience`() {
        assertEquals(PinVaultToken.Result.Invalid("unknown_kid"), PinVaultToken.verify(issue(kid = "nope"), secrets, "default-tls", now))
        // Signed with another secret than the kid names.
        assertEquals(PinVaultToken.Result.Invalid("signature"), PinVaultToken.verify(issue(key = other), secrets, "default-tls", now))
        // The previous secret still verifies under its own kid.
        assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(issue(kid = "2026-10-04-01", key = other), secrets, "default-tls", now))

        val token = issue()
        val parts = token.split('.')
        val payload = String(Base64.getUrlDecoder().decode(parts[1])).replace("\"did\":\"9774d56d682e549c\"", "\"did\":\"other\"")
        val tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray()) + "." + parts[2]
        assertEquals(PinVaultToken.Result.Invalid("signature"), PinVaultToken.verify(tampered, secrets, "default-tls", now))

        assertEquals(PinVaultToken.Result.Invalid("audience"), PinVaultToken.verify(token, secrets, "other-api", now))
        assertIs<PinVaultToken.Result.Valid>(PinVaultToken.verify(token, secrets, null, now), "null audience accepts any")
    }

    @Test
    fun `malformed tokens`() {
        for (bad in listOf("", "abc", "a.b", "a.b.c", "$$$.b.c", issue().replace(".", "..", ignoreCase = false).take(10))) {
            assertEquals(PinVaultToken.Result.Invalid("malformed"), PinVaultToken.verify(bad, secrets, null, now), bad)
        }
        // alg none with a known kid.
        val header = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"alg":"none","kid":"2026-10-05-01"}""".toByteArray())
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"exp":${now + 300},"aud":"default-tls","sub":"x"}""".toByteArray())
        assertEquals(PinVaultToken.Result.Invalid("malformed"), PinVaultToken.verify("$header.$payload.AAAA", secrets, null, now))
    }
}
