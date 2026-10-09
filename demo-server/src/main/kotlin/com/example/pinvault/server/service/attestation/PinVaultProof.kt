package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.math.BigInteger
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * `PinVault-Proof` (ATTESTATION.md §5.1): proof that the request comes from
 * the holder of the device key a `PinVault-Token` was issued to. It is a
 * DPoP proof (RFC 9449) — any DPoP library verifies it:
 *
 * ```
 * header  { "typ": "dpop+jwt", "alg": "ES256",
 *           "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
 * payload { "jti": "…", "htm": "GET", "htu": "https://api.example.com/v1/me",
 *           "iat": 1759660800, "ath": "<base64url SHA-256 of the token>" }
 * ```
 *
 * signed (ES256, raw `r‖s`) by the device key whose RFC 7638 thumbprint is
 * the token's `cnf.jkt`. `htu` is the request URL without query and
 * fragment; `ath` ties the proof to one token, so a proof is good for that
 * token's lifetime at most, and `jti` makes it single use.
 */
object PinVaultProof {
    const val HEADER = "PinVault-Proof"
    const val TYPE = "dpop+jwt"

    /** A proof longer than this is refused unread (a P-256 proof is ~600 characters). */
    const val MAX_LENGTH = 4096

    sealed interface Result {
        /** [jti] has been recorded as spent. */
        data class Valid(val jti: String, val issuedAt: Long) : Result

        /**
         * [reason]: `proof_missing`, `proof_malformed`, `proof_signature`,
         * `proof_key` (not the token's key, or a token without `cnf.jkt`),
         * `proof_method`, `proof_url`, `proof_time`, `proof_token` (`ath`),
         * `proof_replay`, `proof_busy` (the replay cache is full).
         */
        data class Invalid(val reason: String) : Result
    }

    private val json = Json { ignoreUnknownKeys = true }
    private val base64Url = Base64.getUrlEncoder().withoutPadding()

    /**
     * Verifies [proof] for a request [method] [url] carrying [token], whose
     * verified `cnf.jkt` is [keyThumbprint]. [url] is what the client asked
     * for (scheme, host, port, path; query and fragment are ignored).
     * `iat` must lie within [windowSeconds] of [nowSeconds] either way. The
     * signature is checked before any claim is believed; a valid proof's
     * `jti` is spent in [replay].
     */
    fun verify(
        proof: String?,
        method: String,
        url: String,
        token: String,
        keyThumbprint: String?,
        replay: ReplayCache,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
        windowSeconds: Long = 60
    ): Result {
        val value = proof?.trim()?.takeIf { it.isNotEmpty() } ?: return Result.Invalid("proof_missing")
        if (value.length > MAX_LENGTH) return Result.Invalid("proof_malformed")
        val parts = value.split('.')
        if (parts.size != 3 || parts.any { it.isEmpty() }) return Result.Invalid("proof_malformed")
        val header = decodeObject(parts[0]) ?: return Result.Invalid("proof_malformed")
        if (string(header, "typ") != TYPE || string(header, "alg") != "ES256") return Result.Invalid("proof_malformed")
        val key = (header["jwk"] as? JsonObject)?.let(::p256Key) ?: return Result.Invalid("proof_malformed")
        val signature = try { Base64.getUrlDecoder().decode(parts[2]) } catch (_: IllegalArgumentException) { return Result.Invalid("proof_malformed") }
        if (signature.size != 64 || !verifyEs256(key, parts[0] + "." + parts[1], signature)) return Result.Invalid("proof_signature")

        // The token names the key it was issued to; the proof must be made with that one.
        if (keyThumbprint == null || !MessageDigest.isEqual(PinVaultToken.jwkThumbprint(key).toByteArray(), keyThumbprint.toByteArray())) {
            return Result.Invalid("proof_key")
        }
        val payload = decodeObject(parts[1]) ?: return Result.Invalid("proof_malformed")
        val jti = string(payload, "jti")?.takeIf { JTI.matches(it) } ?: return Result.Invalid("proof_malformed")
        val iat = (payload["iat"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: return Result.Invalid("proof_malformed")
        if (string(payload, "htm") != method.uppercase()) return Result.Invalid("proof_method")
        val htu = string(payload, "htu")?.let(::normalizedUrl) ?: return Result.Invalid("proof_url")
        if (htu != normalizedUrl(url)) return Result.Invalid("proof_url")
        if (iat < nowSeconds - windowSeconds || iat > nowSeconds + windowSeconds) return Result.Invalid("proof_time")
        val ath = string(payload, "ath") ?: return Result.Invalid("proof_token")
        if (!MessageDigest.isEqual(ath.toByteArray(), tokenHash(token).toByteArray())) return Result.Invalid("proof_token")
        // Spent last, so a proof refused for another reason does not burn its jti.
        return when (replay.spend(keyThumbprint + ":" + jti, until = iat + windowSeconds, nowSeconds = nowSeconds)) {
            ReplayCache.Spend.Ok -> Result.Valid(jti, iat)
            ReplayCache.Spend.Replayed -> Result.Invalid("proof_replay")
            ReplayCache.Spend.Full -> Result.Invalid("proof_busy")
        }
    }

    /** `ath`: base64url (no padding) SHA-256 of the token's ASCII. */
    fun tokenHash(token: String): String =
        base64Url.encodeToString(MessageDigest.getInstance("SHA-256").digest(token.trim().toByteArray(Charsets.US_ASCII)))

    /**
     * RFC 9449 §4.3 / RFC 3986 §6.2.2–6.2.3: scheme and host lower-cased,
     * the scheme's default port dropped, an empty path as `/`; query and
     * fragment removed. Null for anything but an absolute http(s) URL.
     */
    fun normalizedUrl(url: String): String? {
        val uri = try { URI(url.trim()) } catch (_: Exception) { return null }
        val scheme = uri.scheme?.lowercase()?.takeIf { it == "https" || it == "http" } ?: return null
        val host = uri.host?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        val port = uri.port.takeIf { it != -1 && it != (if (scheme == "https") 443 else 80) }
        val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return scheme + "://" + (if (':' in host && !host.startsWith("[")) "[$host]" else host) + (port?.let { ":$it" } ?: "") + path
    }

    /**
     * Spent `jti`s, each until its proof could no longer pass the time
     * check. Bounded: when full of live entries a proof is refused
     * (`proof_busy`) rather than an entry forgotten early.
     */
    class ReplayCache(private val capacity: Int = 100_000) {
        enum class Spend { Ok, Replayed, Full }

        private val spent = ConcurrentHashMap<String, Long>()

        fun spend(id: String, until: Long, nowSeconds: Long): Spend {
            if (spent.size >= capacity) spent.entries.removeIf { it.value < nowSeconds }
            if (spent.size >= capacity) return Spend.Full
            val previous = spent.putIfAbsent(id, until)
            return when {
                previous == null -> Spend.Ok
                previous < nowSeconds -> if (spent.replace(id, previous, until)) Spend.Ok else Spend.Replayed
                else -> Spend.Replayed
            }
        }

        val size: Int get() = spent.size
    }

    private val JTI = Regex("^[A-Za-z0-9_-]{16,64}$")

    private val p256: ECParameterSpec = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)

    /** The public key of a `{"kty":"EC","crv":"P-256","x","y"}` JWK, or null. */
    private fun p256Key(jwk: JsonObject): ECPublicKey? {
        if (string(jwk, "kty") != "EC" || string(jwk, "crv") != "P-256") return null
        // A JWK with private material is not a public key, whatever else it says.
        if (jwk.containsKey("d")) return null
        fun coordinate(name: String): BigInteger? {
            val text = string(jwk, name) ?: return null
            return try {
                Base64.getUrlDecoder().decode(text).takeIf { it.size == 32 }?.let { BigInteger(1, it) }
            } catch (_: IllegalArgumentException) {
                null
            }
        }
        val x = coordinate("x") ?: return null
        val y = coordinate("y") ?: return null
        // On the curve: y² = x³ + ax + b (mod p); KeyFactory does not check it.
        val field = (p256.curve.field as java.security.spec.ECFieldFp).p
        if (x >= field || y >= field) return null
        if (y.modPow(BigInteger.TWO, field) != x.modPow(BigInteger.valueOf(3), field).add(p256.curve.a.multiply(x)).add(p256.curve.b).mod(field)) return null
        return try {
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256)) as ECPublicKey
        } catch (_: Exception) {
            null
        }
    }

    private fun verifyEs256(key: ECPublicKey, signingInput: String, signature: ByteArray): Boolean = try {
        Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(key)
            update(signingInput.toByteArray(Charsets.US_ASCII))
            verify(signature)
        }
    } catch (_: Exception) {
        false
    }

    private fun decodeObject(segment: String): JsonObject? = try {
        json.parseToJsonElement(Base64.getUrlDecoder().decode(segment).toString(Charsets.UTF_8)).jsonObject
    } catch (_: Exception) {
        null
    }

    private fun string(obj: JsonObject, name: String): String? =
        (obj[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
}
