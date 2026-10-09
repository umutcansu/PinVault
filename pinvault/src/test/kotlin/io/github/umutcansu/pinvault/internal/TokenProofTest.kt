package io.github.umutcansu.pinvault.internal

import okhttp3.HttpUrl.Companion.toHttpUrl
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** `PinVault-Proof` (ATTESTATION.md §5.1): the DPoP proof the token interceptor adds. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class TokenProofTest {

    private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val publicKey = keys.public as ECPublicKey
    private fun der(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(data); sign() }
    private val dec = Base64.getUrlDecoder()

    @Test
    fun `the proof is a DPoP JWS signed by the key it names`() {
        val proof = TokenProof.make("GET", "https://API.example.com:8444/v1/me?x=1#f".toHttpUrl(), "the.token.value", publicKey, 1_759_660_800L, ::der)!!
        val parts = proof.split('.')
        assertEquals(3, parts.size)
        assertTrue("base64url without padding", parts.all { Regex("^[A-Za-z0-9_-]+$").matches(it) })

        val header = JSONObject(String(dec.decode(parts[0])))
        assertEquals("dpop+jwt", header.getString("typ"))
        assertEquals("ES256", header.getString("alg"))
        val jwk = header.getJSONObject("jwk")
        assertEquals("EC", jwk.getString("kty"))
        assertEquals("P-256", jwk.getString("crv"))
        assertEquals(32, dec.decode(jwk.getString("x")).size)
        assertEquals(32, dec.decode(jwk.getString("y")).size)
        assertEquals(java.math.BigInteger(1, dec.decode(jwk.getString("x"))), publicKey.w.affineX)

        val payload = JSONObject(String(dec.decode(parts[1])))
        assertEquals("GET", payload.getString("htm"))
        assertEquals("https://api.example.com:8444/v1/me", payload.getString("htu"))
        assertEquals(1_759_660_800L, payload.getLong("iat"))
        assertEquals(22, payload.getString("jti").length)
        val ath = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest("the.token.value".toByteArray()))
        assertEquals(ath, payload.getString("ath"))

        // ES256: raw r‖s over the ASCII of header.payload.
        val signature = dec.decode(parts[2])
        assertEquals(64, signature.size)
        val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(publicKey); update((parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)); verify(signature)
        }
        assertTrue(ok)
    }

    @Test
    fun `every proof has its own jti`() {
        val url = "https://api.example.com/x".toHttpUrl()
        val a = JSONObject(String(dec.decode(TokenProof.make("GET", url, "t", publicKey, 1L, ::der)!!.split('.')[1])))
        val b = JSONObject(String(dec.decode(TokenProof.make("GET", url, "t", publicKey, 1L, ::der)!!.split('.')[1])))
        assertNotEquals(a.getString("jti"), b.getString("jti"))
    }

    @Test
    fun `htu drops query, fragment and the default port, keeps the encoded path`() {
        assertEquals("https://a.example/", TokenProof.htu("https://A.example".toHttpUrl()))
        assertEquals("https://a.example/p%20q", TokenProof.htu("https://a.example:443/p q?x=1".toHttpUrl()))
        assertEquals("http://10.0.0.1:8080/x", TokenProof.htu("http://10.0.0.1:8080/x".toHttpUrl()))
        assertEquals("https://[::1]:8443/x", TokenProof.htu("https://[::1]:8443/x".toHttpUrl()))
    }

    @Test
    fun `an odd method or a key that is not P-256 makes no proof`() {
        val url = "https://a.example/".toHttpUrl()
        assertNull(TokenProof.make("get\"", url, "t", publicKey, 1L, ::der))
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        assertNull(TokenProof.make("GET", url, "t", p384.public as ECPublicKey, 1L, ::der))
    }

    @Test
    fun `derToRaw pads short integers, strips the sign byte and refuses what is not a signature`() {
        repeat(200) {
            val data = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
            val raw = TokenProof.derToRaw(der(data))!!
            assertEquals(64, raw.size)
            val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run { initVerify(publicKey); update(data); verify(raw) }
            assertTrue(ok)
        }
        // SEQUENCE { INTEGER 1, INTEGER 0x80 } → r = 0…01, s = 0…080
        val small = byteArrayOf(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80.toByte())
        assertArrayEquals(ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(0x80.toByte()), TokenProof.derToRaw(small))
        assertNull(TokenProof.derToRaw(byteArrayOf()))
        assertNull("trailing bytes", TokenProof.derToRaw(small + 0))
        assertNull("negative r", TokenProof.derToRaw(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x81.toByte(), 0x02, 0x01, 0x01)))
        assertNull("zero r", TokenProof.derToRaw(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01)))
        assertNull("not a SEQUENCE", TokenProof.derToRaw(byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)))
        assertNull("r over 32 bytes", TokenProof.derToRaw(byteArrayOf(0x30, 0x25, 0x02, 0x21, 0x01) + ByteArray(32) + byteArrayOf(0x02, 0x01, 0x01)))
    }
}
