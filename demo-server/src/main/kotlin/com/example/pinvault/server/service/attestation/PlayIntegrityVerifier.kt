package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Verifies Play Integrity **classic** tokens on this server (ATTESTATION.md
 * §11), with the response keys the Play Console hands out under App
 * integrity → "Manage and download my response encryption keys": the AES-256
 * decryption key and the EC P-256 verification key. Nothing is sent to
 * Google on the request path.
 *
 * A token is a JWE (`A256KW` + `A256GCM`) around a JWS (`ES256`) around the
 * verdict JSON. The checks, in order, each with a fixed reason:
 *
 *  1. `malformed` / `unsupported_alg` / `decrypt_failed` — not a token for
 *     these keys (someone else's app, a copy from another server's keys);
 *  2. `signature_invalid` — the JWS does not verify with the verification key;
 *  3. `payload_invalid` — no `requestDetails`;
 *  4. `nonce_mismatch` — Google saw a different nonce than this round's;
 *  5. `token_stale` — `timestampMillis` older than [tokenMaxAgeSeconds]
 *     (or from the future by more than a minute);
 *  6. `package_mismatch` — `requestPackageName` / `appIntegrity.packageName`
 *     not in [packageNames];
 *  7. `app_unrecognized` — `appRecognitionVerdict` ≠ `PLAY_RECOGNIZED` while
 *     [requireAppRecognized];
 *  8. `device_integrity` — `deviceRecognitionVerdict` does not reach [deviceLevel].
 *
 * The verdict is bound to the attestation round twice: by the nonce inside
 * Google's signed payload, and by the device key's signature over the report
 * that carries the token.
 */
class PlayIntegrityVerifier(
    decryptionKey: ByteArray,
    private val verificationKey: PublicKey,
    /** Package names a token must name; empty = any (not recommended). */
    val packageNames: Set<String>,
    val deviceLevel: DeviceLevel = DeviceLevel.DEVICE,
    val requireAppRecognized: Boolean = true,
    /** A token's `timestampMillis` may be at most this old. */
    val tokenMaxAgeSeconds: Long = DEFAULT_TOKEN_MAX_AGE_SECONDS,
    /** A verified verdict counts for this long before `play_integrity_missing` is raised. */
    val verdictMaxAgeSeconds: Long = DEFAULT_VERDICT_MAX_AGE_SECONDS
) {
    /** `deviceRecognitionVerdict` labels in rising order; a device at a level lists that level and every one below. */
    enum class DeviceLevel(val label: String) {
        BASIC("MEETS_BASIC_INTEGRITY"), DEVICE("MEETS_DEVICE_INTEGRITY"), STRONG("MEETS_STRONG_INTEGRITY");

        /** True when [verdicts] names this level or a higher one. */
        fun metBy(verdicts: Collection<String>): Boolean = entries.filter { it >= this }.any { it.label in verdicts }

        companion object {
            fun parse(value: String?): DeviceLevel = when (value?.trim()?.lowercase()) {
                null, "", "device" -> DEVICE
                "basic" -> BASIC
                "strong" -> STRONG
                else -> throw IllegalArgumentException("PLAY_INTEGRITY_DEVICE_LEVEL must be basic, device or strong (got '$value')")
            }
        }
    }

    /**
     * What a token said. [passed] = every check held. [summary] is what the
     * device record keeps (`play_integrity` column, shown in the dashboard):
     * no token, no nonce, only what an operator needs to read a verdict.
     */
    class Result(val passed: Boolean, val reason: String, val summary: JsonObject) {
        override fun toString() = "PlayIntegrity(${if (passed) "pass" else "fail"}: $reason)"
    }

    private val decryptionKey: SecretKey

    init {
        require(decryptionKey.size == 32) { "PLAY_INTEGRITY_DECRYPTION_KEY must decode to 32 bytes (AES-256), got ${decryptionKey.size}" }
        require(verificationKey is ECPublicKey && verificationKey.params.curve.field.fieldSize == 256) {
            "PLAY_INTEGRITY_VERIFICATION_KEY must be an EC P-256 public key (X.509 SubjectPublicKeyInfo, Base64)"
        }
        this.decryptionKey = SecretKeySpec(decryptionKey, "AES")
    }

    /** Verifies [token] for a round whose attestation nonce is [expectedNonce]. Never throws. */
    fun verify(token: String, expectedNonce: String, now: Instant = Instant.now()): Result {
        val payload = when (val opened = open(token)) {
            is Opened.Failed -> return fail(opened.reason, null, now)
            is Opened.Payload -> opened.json
        }
        val request = payload["requestDetails"] as? JsonObject ?: return fail("payload_invalid", payload, now)
        val app = payload["appIntegrity"] as? JsonObject
        val device = payload["deviceIntegrity"] as? JsonObject

        if (request.string("nonce") != expectedNonce) return fail("nonce_mismatch", payload, now)
        val timestamp = (request["timestampMillis"] as? JsonPrimitive)?.let { it.longOrNull ?: it.content.toLongOrNull() }
            ?: return fail("payload_invalid", payload, now)
        val ageSeconds = (now.toEpochMilli() - timestamp) / 1000
        if (ageSeconds > tokenMaxAgeSeconds || ageSeconds < -MAX_FUTURE_SECONDS) return fail("token_stale", payload, now)

        if (packageNames.isNotEmpty()) {
            val requested = request.string("requestPackageName")
            val attested = app?.string("packageName")
            if (requested !in packageNames || (attested != null && attested !in packageNames)) return fail("package_mismatch", payload, now)
        }
        if (requireAppRecognized && app?.string("appRecognitionVerdict") != PLAY_RECOGNIZED) return fail("app_unrecognized", payload, now)
        val deviceVerdicts = (device?.get("deviceRecognitionVerdict") as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }.orEmpty()
        if (!deviceLevel.metBy(deviceVerdicts)) return fail("device_integrity", payload, now)

        return Result(true, "ok", summary(payload, "ok", now))
    }

    private fun fail(reason: String, payload: JsonObject?, now: Instant) = Result(false, reason, summary(payload, reason, now))

    /** The stored summary: what Google said, never the token or the nonce. */
    private fun summary(payload: JsonObject?, reason: String, now: Instant): JsonObject = buildJsonObject {
        put("reason", reason)
        put("verifiedAt", now.toString())
        val request = payload?.get("requestDetails") as? JsonObject
        val app = payload?.get("appIntegrity") as? JsonObject
        val device = payload?.get("deviceIntegrity") as? JsonObject
        val account = payload?.get("accountDetails") as? JsonObject
        request?.string("requestPackageName")?.let { put("packageName", it) }
        (request?.get("timestampMillis") as? JsonPrimitive)?.let { it.longOrNull ?: it.content.toLongOrNull() }?.let { put("timestampMillis", it) }
        app?.string("appRecognitionVerdict")?.let { put("appVerdict", it) }
        (app?.get("versionCode") as? JsonPrimitive)?.let { it.longOrNull ?: it.content.toLongOrNull() }?.let { put("versionCode", it) }
        (device?.get("deviceRecognitionVerdict") as? JsonArray)?.let { verdicts ->
            put("deviceVerdicts", buildJsonArray { verdicts.forEach { v -> (v as? JsonPrimitive)?.takeIf { it.isString }?.let { add(it) } } })
        }
        account?.string("appLicensingVerdict")?.let { put("licensing", it) }
    }

    // ── JWE / JWS ──────────────────────────────────────────────────────

    private sealed interface Opened {
        class Payload(val json: JsonObject) : Opened
        class Failed(val reason: String) : Opened
    }

    private fun open(token: String): Opened {
        val jwe = token.trim().split('.')
        if (jwe.size != 5 || jwe.any { it.isEmpty() && it !== jwe[1] }) return Opened.Failed("malformed")
        val header = try { Json.parseToJsonElement(String(b64(jwe[0]), Charsets.UTF_8)) as? JsonObject } catch (_: Exception) { null }
            ?: return Opened.Failed("malformed")
        if (header.string("alg") != "A256KW" || header.string("enc") != "A256GCM") return Opened.Failed("unsupported_alg")

        val jws = try {
            val cek = Cipher.getInstance("AESWrap").run {
                init(Cipher.UNWRAP_MODE, decryptionKey)
                unwrap(b64(jwe[1]), "AES", Cipher.SECRET_KEY)
            }
            val iv = b64(jwe[2])
            val ciphertext = b64(jwe[3])
            val tag = b64(jwe[4])
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, cek, GCMParameterSpec(tag.size * 8, iv))
                updateAAD(jwe[0].toByteArray(Charsets.US_ASCII))
                String(doFinal(ciphertext + tag), Charsets.UTF_8)
            }
        } catch (_: Exception) {
            return Opened.Failed("decrypt_failed")
        }

        val parts = jws.trim().split('.')
        if (parts.size != 3) return Opened.Failed("malformed")
        val jwsHeader = try { Json.parseToJsonElement(String(b64(parts[0]), Charsets.UTF_8)) as? JsonObject } catch (_: Exception) { null }
            ?: return Opened.Failed("malformed")
        if (jwsHeader.string("alg") != "ES256") return Opened.Failed("unsupported_alg")
        val signature = try { b64(parts[2]) } catch (_: Exception) { return Opened.Failed("malformed") }
        val verified = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(verificationKey)
                update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
                verify(if (signature.size == 64) rawToDer(signature) else signature)
            }
        } catch (_: Exception) {
            false
        }
        if (!verified) return Opened.Failed("signature_invalid")
        val payload = try { Json.parseToJsonElement(String(b64(parts[1]), Charsets.UTF_8)) as? JsonObject } catch (_: Exception) { null }
            ?: return Opened.Failed("payload_invalid")
        return Opened.Payload(payload)
    }

    companion object {
        const val DEFAULT_TOKEN_MAX_AGE_SECONDS = 600L
        const val DEFAULT_VERDICT_MAX_AGE_SECONDS = 86_400L
        private const val MAX_FUTURE_SECONDS = 60L
        const val PLAY_RECOGNIZED = "PLAY_RECOGNIZED"

        /**
         * From `PLAY_INTEGRITY_DECRYPTION_KEY` and `PLAY_INTEGRITY_VERIFICATION_KEY`
         * (both Base64, as the Play Console shows them); null when neither is
         * set or `PLAY_INTEGRITY_ENABLED=false`. One without the other, or a
         * key of the wrong shape, is a startup error. `PLAY_INTEGRITY_PACKAGE_NAMES`
         * defaults to [fallbackPackageNames] (`ATTESTATION_PACKAGE_NAMES`);
         * `PLAY_INTEGRITY_DEVICE_LEVEL` basic|device|strong (default device);
         * `PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED` (default true);
         * `PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS` (600); `PLAY_INTEGRITY_MAX_AGE_SECONDS` (86400).
         */
        fun fromEnv(env: Map<String, String> = System.getenv(), fallbackPackageNames: Set<String> = emptySet()): PlayIntegrityVerifier? {
            val enabled = when (env["PLAY_INTEGRITY_ENABLED"]?.trim()?.lowercase()) {
                null, "" -> null
                "true", "on" -> true
                "false", "off" -> false
                else -> throw IllegalArgumentException("PLAY_INTEGRITY_ENABLED must be true or false (got '${env["PLAY_INTEGRITY_ENABLED"]}')")
            }
            val decryption = env["PLAY_INTEGRITY_DECRYPTION_KEY"]?.trim()?.takeIf { it.isNotEmpty() }
            val verification = env["PLAY_INTEGRITY_VERIFICATION_KEY"]?.trim()?.takeIf { it.isNotEmpty() }
            if (enabled == false) return null
            if (decryption == null && verification == null) {
                check(enabled != true) { "PLAY_INTEGRITY_ENABLED=true needs PLAY_INTEGRITY_DECRYPTION_KEY and PLAY_INTEGRITY_VERIFICATION_KEY (Play Console → App integrity → response encryption keys)." }
                return null
            }
            checkNotNull(decryption) { "PLAY_INTEGRITY_VERIFICATION_KEY is set but PLAY_INTEGRITY_DECRYPTION_KEY is not: both keys come from the Play Console together." }
            checkNotNull(verification) { "PLAY_INTEGRITY_DECRYPTION_KEY is set but PLAY_INTEGRITY_VERIFICATION_KEY is not: both keys come from the Play Console together." }
            val packages = env["PLAY_INTEGRITY_PACKAGE_NAMES"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
                ?.takeIf { it.isNotEmpty() } ?: fallbackPackageNames
            val tokenMaxAge = env["PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS"]?.trim()?.takeIf { it.isNotEmpty() }?.let {
                it.toLongOrNull()?.takeIf { v -> v in 30..86_400 } ?: throw IllegalArgumentException("PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS must be 30..86400 (got '$it')")
            } ?: DEFAULT_TOKEN_MAX_AGE_SECONDS
            val verdictMaxAge = env["PLAY_INTEGRITY_MAX_AGE_SECONDS"]?.trim()?.takeIf { it.isNotEmpty() }?.let {
                it.toLongOrNull()?.takeIf { v -> v in 60..(30 * 86_400L) } ?: throw IllegalArgumentException("PLAY_INTEGRITY_MAX_AGE_SECONDS must be 60..2592000 (got '$it')")
            } ?: DEFAULT_VERDICT_MAX_AGE_SECONDS
            val requireApp = when (env["PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED"]?.trim()?.lowercase()) {
                null, "", "true", "on" -> true
                "false", "off" -> false
                else -> throw IllegalArgumentException("PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED must be true or false")
            }
            return PlayIntegrityVerifier(
                decryptionKey = decodeKey(decryption, "PLAY_INTEGRITY_DECRYPTION_KEY"),
                verificationKey = parseVerificationKey(verification),
                packageNames = packages,
                deviceLevel = DeviceLevel.parse(env["PLAY_INTEGRITY_DEVICE_LEVEL"]),
                requireAppRecognized = requireApp,
                tokenMaxAgeSeconds = tokenMaxAge,
                verdictMaxAgeSeconds = verdictMaxAge
            )
        }

        fun parseVerificationKey(base64: String): PublicKey = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(decodeKey(base64, "PLAY_INTEGRITY_VERIFICATION_KEY")))
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("PLAY_INTEGRITY_VERIFICATION_KEY is not an X.509 EC public key: ${e.message}")
        }

        private fun decodeKey(value: String, name: String): ByteArray = try {
            val cleaned = value.replace("\\s".toRegex(), "")
            if (cleaned.contains('-') || cleaned.contains('_')) Base64.getUrlDecoder().decode(cleaned) else Base64.getDecoder().decode(cleaned)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("$name is not Base64")
        }

        private fun b64(text: String): ByteArray = Base64.getUrlDecoder().decode(text)

        /** A JWS `r ‖ s` signature (64 bytes) as the DER SEQUENCE the JCA verifies. */
        fun rawToDer(raw: ByteArray): ByteArray {
            require(raw.size == 64)
            val r = BigInteger(1, raw.copyOfRange(0, 32)).toByteArray()
            val s = BigInteger(1, raw.copyOfRange(32, 64)).toByteArray()
            val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
            return byteArrayOf(0x30, body.size.toByte()) + body
        }

        private fun JsonObject.string(name: String): String? =
            (this[name] as? JsonPrimitive)?.takeIf { it !is JsonNull && it.isString }?.content
    }
}
