package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * `PinVault-Token` (ATTESTATION.md §5): an HS256 JWT, hand-rolled — no
 * library — so a backend in any language can verify it with its JWT library
 * of choice, or with twenty lines of HMAC.
 *
 * ```
 * header  { "alg": "HS256", "typ": "JWT", "kid": "<secret id>" }
 * payload { "iss": "pinvault", "sub": "<deviceId>", "aud": "<configApiId>",
 *           "iat": …, "exp": …, "jti": "…", "did": "<deviceId>",
 *           "arc": "7f3a9c1e", "pol": 3, "anno": ["staff"],   // anno only when the device has annotations
 *           "cnf": { "jkt": "…", "x5t#S256": "…" } }          // x5t#S256 only when the attestation came over mTLS
 * ```
 *
 * `cnf` (RFC 7800) names what the token was issued to: `jkt` the device key
 * that signed the report (its RFC 7638 JWK SHA-256 thumbprint, as DPoP
 * names a key), `x5t#S256` the client certificate of the connection the
 * attestation arrived on (RFC 8705: base64url SHA-256 of its DER). A
 * backend that sees the same certificate on its own mTLS connection can
 * require them to match ([com.example.pinvault.server.plugin.PinVaultTokenAuthConfig.requireCertBinding]);
 * a token is otherwise a bearer credential for its lifetime.
 */
object PinVaultToken {
    const val ISSUER = "pinvault"
    const val HEADER = "PinVault-Token"

    /** The verified claims of a token. */
    data class Claims(
        val kid: String,
        val deviceId: String,
        val audience: String,
        val issuedAt: Long,
        val expiresAt: Long,
        val jti: String?,
        val arc: String?,
        val policyVersion: Int?,
        val annotations: List<String>,
        val payload: JsonObject,
        /** `cnf.jkt`: the JWK thumbprint of the device key the token was issued to; null in tokens a server without `cnf` issued. */
        val keyThumbprint: String? = null,
        /** `cnf.x5t#S256`: the client certificate the attestation arrived with; null when it came over plain TLS. */
        val certThumbprint: String? = null
    )

    sealed interface Result {
        data class Valid(val claims: Claims) : Result

        /** [reason]: `malformed`, `unknown_kid`, `signature`, `expired`, `audience`. */
        data class Invalid(val reason: String) : Result
    }

    private val base64 = Base64.getUrlEncoder().withoutPadding()
    private val random = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true }

    /** Signs a token for [deviceId] bound to [configApiId]; [nowSeconds] is `iat`, `exp` = `iat` + [ttlSeconds]. */
    fun issue(
        kid: String,
        secret: ByteArray,
        deviceId: String,
        configApiId: String,
        arc: String,
        policyVersion: Int,
        ttlSeconds: Int,
        annotations: List<String> = emptyList(),
        nowSeconds: Long = System.currentTimeMillis() / 1000,
        jti: String = ByteArray(12).also(random::nextBytes).let { base64.encodeToString(it) },
        /** `cnf.jkt` ([jwkThumbprint] of the device key); null = no `cnf`. */
        keyThumbprint: String? = null,
        /** `cnf.x5t#S256` ([certThumbprint] of the connection's client certificate); null = none. */
        certThumbprint: String? = null
    ): String {
        val header = buildJsonObject { put("alg", "HS256"); put("typ", "JWT"); put("kid", kid) }
        val payload = buildJsonObject {
            put("iss", ISSUER)
            put("sub", deviceId)
            put("aud", configApiId)
            put("iat", nowSeconds)
            put("exp", nowSeconds + ttlSeconds)
            put("jti", jti)
            put("did", deviceId)
            put("arc", arc)
            put("pol", policyVersion)
            if (annotations.isNotEmpty()) put("anno", buildJsonArray { annotations.forEach { add(JsonPrimitive(it)) } })
            if (keyThumbprint != null || certThumbprint != null) put("cnf", buildJsonObject {
                keyThumbprint?.let { put("jkt", it) }
                certThumbprint?.let { put(CNF_X5T, it) }
            })
        }
        val signingInput = base64.encodeToString(header.toString().toByteArray(Charsets.UTF_8)) + "." +
            base64.encodeToString(payload.toString().toByteArray(Charsets.UTF_8))
        return signingInput + "." + base64.encodeToString(hmac(secret, signingInput))
    }

    /**
     * Verifies [token]: three segments, `alg` HS256, a `kid` in [secrets],
     * the signature, `iss`, `exp` (with [leewaySeconds]) and, when [audience]
     * is given, `aud`. Nothing is believed before the signature checks out.
     */
    fun verify(
        token: String,
        secrets: Map<String, ByteArray>,
        audience: String?,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
        leewaySeconds: Long = 60
    ): Result {
        val parts = token.trim().split('.')
        if (parts.size != 3 || parts.any { it.isEmpty() }) return Result.Invalid("malformed")
        val header = decodeObject(parts[0]) ?: return Result.Invalid("malformed")
        if (string(header, "alg") != "HS256") return Result.Invalid("malformed")
        val kid = string(header, "kid") ?: return Result.Invalid("malformed")
        val secret = secrets[kid] ?: return Result.Invalid("unknown_kid")
        val signature = try { Base64.getUrlDecoder().decode(parts[2]) } catch (_: IllegalArgumentException) { return Result.Invalid("malformed") }
        if (!MessageDigest.isEqual(hmac(secret, parts[0] + "." + parts[1]), signature)) return Result.Invalid("signature")
        val payload = decodeObject(parts[1]) ?: return Result.Invalid("malformed")
        // Signed by a secret of ours, but not issued as one of our tokens.
        if (string(payload, "iss") != ISSUER) return Result.Invalid("issuer")
        val exp = (payload["exp"] as? JsonPrimitive)?.longOrNull ?: return Result.Invalid("malformed")
        val iat = (payload["iat"] as? JsonPrimitive)?.longOrNull ?: 0L
        val sub = string(payload, "sub") ?: string(payload, "did") ?: return Result.Invalid("malformed")
        val aud = string(payload, "aud") ?: return Result.Invalid("malformed")
        if (nowSeconds > exp + leewaySeconds) return Result.Invalid("expired")
        // A token from the future beyond the leeway is not one this server issued now.
        if (iat > nowSeconds + leewaySeconds) return Result.Invalid("expired")
        if (audience != null && aud != audience) return Result.Invalid("audience")
        val annotations = (payload["anno"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
        val cnf = payload["cnf"] as? JsonObject
        return Result.Valid(Claims(
            kid = kid, deviceId = string(payload, "did") ?: sub, audience = aud, issuedAt = iat, expiresAt = exp,
            jti = string(payload, "jti"), arc = string(payload, "arc"),
            policyVersion = (payload["pol"] as? JsonPrimitive)?.longOrNull?.toInt(), annotations = annotations, payload = payload,
            keyThumbprint = cnf?.let { string(it, "jkt") }, certThumbprint = cnf?.let { string(it, CNF_X5T) }
        ))
    }

    /** `cnf` member of the certificate thumbprint (RFC 8705). */
    const val CNF_X5T = "x5t#S256"

    /** RFC 8705 `x5t#S256`: base64url (no padding) SHA-256 of the certificate's DER. */
    fun certThumbprint(der: ByteArray): String = base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(der))

    /**
     * RFC 7638 JWK SHA-256 thumbprint of an EC P-256 key — the `jkt` a DPoP
     * library computes: base64url SHA-256 of `{"crv":"P-256","kty":"EC","x":…,"y":…}`
     * (members in that order, coordinates 32 bytes each, base64url without padding).
     */
    fun jwkThumbprint(key: java.security.interfaces.ECPublicKey): String {
        fun coordinate(v: java.math.BigInteger): String {
            val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return base64.encodeToString(ByteArray(32 - raw.size) + raw)
        }
        val jwk = """{"crv":"P-256","kty":"EC","x":"${coordinate(key.w.affineX)}","y":"${coordinate(key.w.affineY)}"}"""
        return base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(jwk.toByteArray(Charsets.UTF_8)))
    }

    private fun hmac(secret: ByteArray, text: String): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }.doFinal(text.toByteArray(Charsets.US_ASCII))

    private fun decodeObject(segment: String): JsonObject? = try {
        json.parseToJsonElement(Base64.getUrlDecoder().decode(segment).toString(Charsets.UTF_8)).jsonObject
    } catch (_: Exception) {
        null
    }

    private fun string(obj: JsonObject, name: String): String? =
        (obj[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
}
