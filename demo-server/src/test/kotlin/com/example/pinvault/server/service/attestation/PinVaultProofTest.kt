package com.example.pinvault.server.service.attestation

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/** PinVault-Proof (ATTESTATION.md §5.1): a DPoP proof made with the key the token's cnf.jkt names. */
class PinVaultProofTest {

    private val now = 1_759_660_800L
    private val device = newKey()
    private val token = PinVaultToken.issue("k1", ByteArray(32) { 7 }, "dev-1", "api", "00000000", 1, 300, nowSeconds = now,
        keyThumbprint = PinVaultToken.jwkThumbprint(device.public as ECPublicKey))
    private val jkt = PinVaultToken.jwkThumbprint(device.public as ECPublicKey)
    private val url = "https://api.example.com:8444/v1/me"

    private fun verify(proof: String?, method: String = "GET", at: String = url, cache: PinVaultProof.ReplayCache = PinVaultProof.ReplayCache(),
                       thumbprint: String? = jkt, clock: Long = now) =
        PinVaultProof.verify(proof, method, at, token, thumbprint, cache, clock)

    private fun reason(result: PinVaultProof.Result) = (result as? PinVaultProof.Result.Invalid)?.reason ?: "valid"

    @Test
    fun `a proof made for the request with the token's key passes once`() {
        val cache = PinVaultProof.ReplayCache()
        val proof = Proofs.make(device, "GET", url, token, now)
        assertIs<PinVaultProof.Result.Valid>(verify(proof, cache = cache))
        assertEquals("proof_replay", reason(verify(proof, cache = cache)))
    }

    @Test
    fun `the url is compared without query, fragment, default port or case`() {
        val proof = Proofs.make(device, "GET", "HTTPS://API.example.com:443/v1/me?x=1#f", token, now)
        assertIs<PinVaultProof.Result.Valid>(verify(proof, at = "https://api.example.com/v1/me?y=2"))
        assertEquals("proof_url", reason(verify(Proofs.make(device, "GET", url, token, now), at = "https://api.example.com:8444/v1/other")))
        assertEquals("proof_url", reason(verify(Proofs.make(device, "GET", url, token, now), at = "https://evil.example.com:8444/v1/me")))
        assertEquals("proof_url", reason(verify(Proofs.make(device, "GET", url, token, now), at = "http://api.example.com:8444/v1/me")))
        assertEquals("proof_url", reason(verify(Proofs.make(device, "GET", "ftp://api.example.com/v1/me", token, now))))
    }

    @Test
    fun `every mismatch has its own reason`() {
        assertEquals("proof_missing", reason(verify(null)))
        assertEquals("proof_missing", reason(verify("  ")))
        assertEquals("proof_malformed", reason(verify("a.b")))
        assertEquals("proof_malformed", reason(verify("x".repeat(PinVaultProof.MAX_LENGTH + 1))))
        assertEquals("proof_method", reason(verify(Proofs.make(device, "POST", url, token, now))))
        assertEquals("proof_time", reason(verify(Proofs.make(device, "GET", url, token, now - 61))))
        assertEquals("proof_time", reason(verify(Proofs.make(device, "GET", url, token, now + 61))))
        assertIs<PinVaultProof.Result.Valid>(verify(Proofs.make(device, "GET", url, token, now - 60)))
        assertEquals("proof_token", reason(verify(Proofs.make(device, "GET", url, token + "x", now))))
        assertEquals("proof_token", reason(verify(Proofs.make(device, "GET", url, null, now))))
        assertEquals("proof_malformed", reason(verify(Proofs.make(device, "GET", url, token, now, jti = "short"))))
        assertEquals("proof_malformed", reason(verify(Proofs.make(device, "GET", url, token, now, typ = "JWT"))))
        assertEquals("proof_malformed", reason(verify(Proofs.make(device, "GET", url, token, now, alg = "ES384"))))
    }

    @Test
    fun `another key, or a token without cnf, is proof_key`() {
        val other = newKey()
        assertEquals("proof_key", reason(verify(Proofs.make(other, "GET", url, token, now))))
        assertEquals("proof_key", reason(verify(Proofs.make(device, "GET", url, token, now), thumbprint = null)))
    }

    @Test
    fun `a signature by one key under another key's jwk does not verify`() {
        val other = newKey()
        // The header names the device key, the signature is the other key's.
        val proof = Proofs.make(device, "GET", url, token, now, signer = other)
        assertEquals("proof_signature", reason(verify(proof)))
        // A DER signature (what a Keystore returns before conversion) is not ES256.
        assertEquals("proof_signature", reason(verify(Proofs.make(device, "GET", url, token, now, der = true))))
    }

    @Test
    fun `a jwk with private material or off the curve is refused`() {
        assertEquals("proof_malformed", reason(verify(Proofs.make(device, "GET", url, token, now, extraJwk = ",\"d\":\"AAAA\""))))
        assertEquals("proof_malformed", reason(verify(Proofs.make(device, "GET", url, token, now, offCurve = true))))
    }

    @Test
    fun `a refused proof does not spend its jti`() {
        val cache = PinVaultProof.ReplayCache()
        val proof = Proofs.make(device, "GET", url, token, now)
        assertEquals("proof_url", reason(verify(proof, at = "https://api.example.com:8444/elsewhere", cache = cache)))
        assertIs<PinVaultProof.Result.Valid>(verify(proof, cache = cache))
    }

    @Test
    fun `a full replay cache refuses instead of forgetting live entries, and frees expired ones`() {
        val cache = PinVaultProof.ReplayCache(capacity = 2)
        assertIs<PinVaultProof.Result.Valid>(verify(Proofs.make(device, "GET", url, token, now), cache = cache))
        assertIs<PinVaultProof.Result.Valid>(verify(Proofs.make(device, "GET", url, token, now), cache = cache))
        assertEquals("proof_busy", reason(verify(Proofs.make(device, "GET", url, token, now), cache = cache)))
        // Once the first two could no longer pass the time check, their slots are free again.
        assertIs<PinVaultProof.Result.Valid>(verify(Proofs.make(device, "GET", url, token, now + 61), cache = cache, clock = now + 61))
    }

    @Test
    fun `normalizedUrl follows RFC 9449`() {
        assertEquals("https://a.example/", PinVaultProof.normalizedUrl("https://A.example"))
        assertEquals("https://a.example:8443/p%20q", PinVaultProof.normalizedUrl("https://a.example:8443/p%20q?x#y"))
        assertEquals("http://10.0.0.1:8080/x", PinVaultProof.normalizedUrl("http://10.0.0.1:8080/x"))
        assertEquals("http://a.example/x", PinVaultProof.normalizedUrl("http://a.example:80/x"))
        assertEquals("https://[::1]:8443/x", PinVaultProof.normalizedUrl("https://[::1]:8443/x"))
        assertNull(PinVaultProof.normalizedUrl("/relative"))
        assertNull(PinVaultProof.normalizedUrl("mailto:a@b"))
    }

    @Test
    fun `ath is base64url SHA-256 of the token`() {
        assertEquals("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", PinVaultProof.tokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"))
    }

    private fun newKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
}

/** Makes PinVault-Proofs the way the libraries do (and wrong ones, for the tests). */
object Proofs {
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    fun jwk(key: ECPublicKey, offCurve: Boolean = false): Pair<String, String> {
        fun c(v: BigInteger): String {
            val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return b64.encodeToString(ByteArray(32 - raw.size) + raw)
        }
        val y = if (offCurve) key.w.affineY.add(BigInteger.ONE) else key.w.affineY
        return c(key.w.affineX) to c(y)
    }

    fun make(
        key: KeyPair, method: String, url: String, token: String?, iat: Long,
        jti: String = b64.encodeToString(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }),
        typ: String = "dpop+jwt", alg: String = "ES256", signer: KeyPair = key, der: Boolean = false,
        extraJwk: String = "", offCurve: Boolean = false
    ): String {
        val (x, y) = jwk(key.public as ECPublicKey, offCurve)
        val header = """{"typ":"$typ","alg":"$alg","jwk":{"kty":"EC","crv":"P-256","x":"$x","y":"$y"$extraJwk}}"""
        val ath = token?.let { ",\"ath\":\"${PinVaultProof.tokenHash(it)}\"" } ?: ""
        val payload = """{"jti":"$jti","htm":"$method","htu":"$url","iat":$iat$ath}"""
        val input = b64.encodeToString(header.toByteArray()) + "." + b64.encodeToString(payload.toByteArray())
        val signature = Signature.getInstance(if (der) "SHA256withECDSA" else "SHA256withECDSAinP1363Format").run {
            initSign(signer.private); update(input.toByteArray(Charsets.US_ASCII)); sign()
        }
        return input + "." + b64.encodeToString(signature)
    }
}
