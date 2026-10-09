package io.github.umutcansu.pinvault.internal

import android.util.Base64
import okhttp3.HttpUrl
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey

/**
 * `PinVault-Proof` (`ATTESTATION.md` §5.1): a DPoP proof (RFC 9449) of one
 * request, signed by the device key the `PinVault-Token`'s `cnf.jkt` names.
 *
 * ```
 * header  {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}
 * payload {"jti":"…","htm":"GET","htu":"https://api.example.com/v1/me","iat":…,"ath":"…"}
 * ```
 *
 * Every value is base64url, a number, an upper-case method or an encoded
 * URL, so the JSON is written by hand: nothing in it needs escaping.
 */
internal object TokenProof {
    const val HEADER = "PinVault-Proof"

    private val random = SecureRandom()
    private val METHOD = Regex("^[A-Z]{1,16}$")

    /**
     * The proof for [method] [url] carrying [token], signed by [sign] (a
     * DER `SHA256withECDSA` signature, as the Keystore makes it) over the
     * key [publicKey]; `iat` is [nowSeconds]. Null when [method] is not a
     * plain HTTP method or the key is not P-256.
     */
    fun make(
        method: String,
        url: HttpUrl,
        token: String,
        publicKey: ECPublicKey,
        nowSeconds: Long,
        sign: (ByteArray) -> ByteArray
    ): String? {
        if (!METHOD.matches(method)) return null
        if (publicKey.params.curve.field.fieldSize != 256) return null
        val x = coordinate(publicKey.w.affineX)
        val y = coordinate(publicKey.w.affineY)
        val header = """{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"$x","y":"$y"}}"""
        val jti = b64(ByteArray(16).also(random::nextBytes))
        val payload = """{"jti":"$jti","htm":"$method","htu":"${htu(url)}","iat":$nowSeconds,"ath":"${tokenHash(token)}"}"""
        val input = b64(header.toByteArray(Charsets.UTF_8)) + "." + b64(payload.toByteArray(Charsets.UTF_8))
        val raw = derToRaw(sign(input.toByteArray(Charsets.US_ASCII))) ?: return null
        return input + "." + b64(raw)
    }

    /** RFC 9449 `htu`: scheme, host, the port when not the default, the encoded path; no query or fragment. */
    fun htu(url: HttpUrl): String {
        val host = if (':' in url.host) "[${url.host}]" else url.host
        val port = if (url.port == HttpUrl.defaultPort(url.scheme)) "" else ":${url.port}"
        return "${url.scheme}://$host$port${url.encodedPath}"
    }

    /** `ath`: base64url SHA-256 of the token. */
    fun tokenHash(token: String): String =
        b64(MessageDigest.getInstance("SHA-256").digest(token.trim().toByteArray(Charsets.US_ASCII)))

    /** A DER ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` as JWS ES256 `r‖s` (32 bytes each); null when it is not one. */
    fun derToRaw(der: ByteArray): ByteArray? {
        var i = 0
        fun byte(): Int? = if (i < der.size) der[i++].toInt() and 0xFF else null
        fun length(): Int? {
            val first = byte() ?: return null
            if (first < 0x80) return first
            if (first != 0x81) return null
            return byte()?.takeIf { it >= 0x80 }
        }
        if (byte() != 0x30) return null
        val total = length() ?: return null
        if (i + total != der.size) return null
        fun integer(): ByteArray? {
            if (byte() != 0x02) return null
            val len = length()?.takeIf { it in 1..33 } ?: return null
            if (i + len > der.size) return null
            val value = der.copyOfRange(i, i + len)
            i += len
            val unsigned = BigInteger(value).takeIf { it.signum() > 0 } ?: return null
            val bytes = unsigned.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it }
            return if (bytes.size > 32) null else ByteArray(32 - bytes.size) + bytes
        }
        val r = integer() ?: return null
        val s = integer() ?: return null
        return if (i == der.size) r + s else null
    }

    private fun coordinate(v: BigInteger): String {
        val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return b64(ByteArray(32 - raw.size) + raw)
    }

    private fun b64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
