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
 * `PinVault-Token` (ATTESTATION.md §5): a JWT, hand-rolled — no library — so
 * a backend in any language can verify it with its JWT library of choice.
 * ES256 (default since 2.4.2): the server signs with an EC P-256 key that
 * never leaves it, backends verify with the public key (`GET
 * /api/v1/attestation/jwks`). HS256 (`PINVAULT_TOKEN_ALG=HS256`, for
 * backends not moved yet): one shared secret signs and verifies. A key's
 * algorithm is fixed: a token whose header names another one is refused,
 * so an HS256 token can never be made with an ES256 public key as secret.
 *
 * ```
 * header  { "alg": "ES256", "typ": "JWT", "kid": "<key id>" }
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

    /** What signs a token: an HS256 secret or an ES256 private key, under its [kid]. */
    sealed interface SigningKey {
        val kid: String
        class Hs256(override val kid: String, val secret: ByteArray) : SigningKey
        class Es256(override val kid: String, val privateKey: java.security.interfaces.ECPrivateKey) : SigningKey
    }

    /** What verifies a token of one `kid`: the HS256 secret, or the ES256 public key. */
    sealed interface VerificationKey {
        class Hs256(val secret: ByteArray) : VerificationKey
        class Es256(val publicKey: java.security.interfaces.ECPublicKey) : VerificationKey
    }

    sealed interface Result {
        data class Valid(val claims: Claims) : Result

        /** [reason]: `malformed`, `unknown_kid`, `signature`, `issuer`, `expired`, `audience`. */
        data class Invalid(val reason: String) : Result
    }

    private val base64 = Base64.getUrlEncoder().withoutPadding()
    private val random = SecureRandom()
    private val json = Json { ignoreUnknownKeys = true }

    /** [issue] with an HS256 [secret] under [kid]. */
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
        keyThumbprint: String? = null,
        certThumbprint: String? = null
    ): String = issue(SigningKey.Hs256(kid, secret), deviceId, configApiId, arc, policyVersion, ttlSeconds, annotations,
        nowSeconds, jti, keyThumbprint, certThumbprint)

    /** Signs a token for [deviceId] bound to [configApiId] with [key]; [nowSeconds] is `iat`, `exp` = `iat` + [ttlSeconds]. */
    fun issue(
        key: SigningKey,
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
        val header = buildJsonObject { put("alg", algOf(key)); put("typ", "JWT"); put("kid", key.kid) }
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
        val signature = when (key) {
            is SigningKey.Hs256 -> hmac(key.secret, signingInput)
            is SigningKey.Es256 -> java.security.Signature.getInstance(ES256_JCA).run {
                initSign(key.privateKey); update(signingInput.toByteArray(Charsets.US_ASCII)); sign()
            }
        }
        return signingInput + "." + base64.encodeToString(signature)
    }

    /** [verify] with HS256 [secrets] by kid and one [audience]. */
    fun verify(
        token: String,
        secrets: Map<String, ByteArray>,
        audience: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
        leewaySeconds: Long = 60
    ): Result = verify(token, secrets.mapValues { VerificationKey.Hs256(it.value) }, setOf(audience), nowSeconds, leewaySeconds)

    /**
     * Verifies [token]: three segments, a `kid` in [keys] whose algorithm the
     * header names (`alg` ES256 for an EC key, HS256 for a secret — nothing
     * else), the signature, `iss`, `exp` (with [leewaySeconds]) and `aud`,
     * which must be one of [audiences] (an empty set accepts none: the
     * audience is not optional). Nothing is believed before the signature
     * checks out.
     */
    fun verify(
        token: String,
        keys: Map<String, VerificationKey>,
        audiences: Set<String>,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
        leewaySeconds: Long = 60
    ): Result {
        val parts = token.trim().split('.')
        if (parts.size != 3 || parts.any { it.isEmpty() }) return Result.Invalid("malformed")
        val header = decodeObject(parts[0]) ?: return Result.Invalid("malformed")
        val alg = string(header, "alg")
        if (alg != ALG_ES256 && alg != ALG_HS256) return Result.Invalid("malformed")
        val kid = string(header, "kid") ?: return Result.Invalid("malformed")
        val key = keys[kid] ?: return Result.Invalid("unknown_kid")
        // The key decides the algorithm, never the header (no alg confusion).
        if (alg != algOf(key)) return Result.Invalid("malformed")
        val signature = try { Base64.getUrlDecoder().decode(parts[2]) } catch (_: IllegalArgumentException) { return Result.Invalid("malformed") }
        val signingInput = parts[0] + "." + parts[1]
        val signed = when (key) {
            is VerificationKey.Hs256 -> MessageDigest.isEqual(hmac(key.secret, signingInput), signature)
            is VerificationKey.Es256 -> signature.size == 64 && runCatching {
                java.security.Signature.getInstance(ES256_JCA).run {
                    initVerify(key.publicKey); update(signingInput.toByteArray(Charsets.US_ASCII)); verify(signature)
                }
            }.getOrDefault(false)
        }
        if (!signed) return Result.Invalid("signature")
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
        if (aud !in audiences) return Result.Invalid("audience")
        val annotations = (payload["anno"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
        val cnf = payload["cnf"] as? JsonObject
        return Result.Valid(Claims(
            kid = kid, deviceId = string(payload, "did") ?: sub, audience = aud, issuedAt = iat, expiresAt = exp,
            jti = string(payload, "jti"), arc = string(payload, "arc"),
            policyVersion = (payload["pol"] as? JsonPrimitive)?.longOrNull?.toInt(), annotations = annotations, payload = payload,
            keyThumbprint = cnf?.let { string(it, "jkt") }, certThumbprint = cnf?.let { string(it, CNF_X5T) }
        ))
    }

    const val ALG_ES256 = "ES256"
    const val ALG_HS256 = "HS256"

    /** JCA name of ES256 with the JWS signature form (raw `r‖s`, RFC 7518 §3.4). */
    private const val ES256_JCA = "SHA256withECDSAinP1363Format"

    private fun algOf(key: SigningKey) = if (key is SigningKey.Es256) ALG_ES256 else ALG_HS256
    private fun algOf(key: VerificationKey) = if (key is VerificationKey.Es256) ALG_ES256 else ALG_HS256

    /** The RFC 7517 JWK of an ES256 public key, as `GET /api/v1/attestation/jwks` lists it. */
    fun jwk(kid: String, key: java.security.interfaces.ECPublicKey): JsonObject = buildJsonObject {
        fun coordinate(v: java.math.BigInteger): String {
            val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return base64.encodeToString(ByteArray(32 - raw.size) + raw)
        }
        put("kty", "EC"); put("crv", "P-256"); put("kid", kid); put("alg", ALG_ES256); put("use", "sig")
        put("x", coordinate(key.w.affineX)); put("y", coordinate(key.w.affineY))
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
