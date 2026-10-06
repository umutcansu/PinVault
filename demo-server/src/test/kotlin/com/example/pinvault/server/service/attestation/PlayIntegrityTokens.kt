package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Mints Play Integrity classic tokens the way Google does — JWE `A256KW` +
 * `A256GCM` around a JWS `ES256` around the verdict — with keys of the
 * test's own, so [PlayIntegrityVerifier] can be exercised offline.
 */
class PlayIntegrityTokens(
    val decryptionKey: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
    val signingKey: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
) {
    val verificationKeyBase64: String get() = Base64.getEncoder().encodeToString(signingKey.public.encoded)
    val decryptionKeyBase64: String get() = Base64.getEncoder().encodeToString(decryptionKey)

    fun verifier(
        packageNames: Set<String> = setOf(PACKAGE),
        deviceLevel: PlayIntegrityVerifier.DeviceLevel = PlayIntegrityVerifier.DeviceLevel.DEVICE,
        requireAppRecognized: Boolean = true,
        tokenMaxAgeSeconds: Long = PlayIntegrityVerifier.DEFAULT_TOKEN_MAX_AGE_SECONDS,
        verdictMaxAgeSeconds: Long = PlayIntegrityVerifier.DEFAULT_VERDICT_MAX_AGE_SECONDS
    ) = PlayIntegrityVerifier(decryptionKey, signingKey.public, packageNames, deviceLevel, requireAppRecognized, tokenMaxAgeSeconds, verdictMaxAgeSeconds)

    /** A verdict payload as Google shapes it. */
    fun payload(
        nonce: String,
        timestampMillis: Long,
        packageName: String = PACKAGE,
        appVerdict: String = "PLAY_RECOGNIZED",
        deviceVerdicts: List<String> = listOf("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"),
        licensing: String = "LICENSED"
    ): JsonObject = buildJsonObject {
        put("requestDetails", buildJsonObject {
            put("requestPackageName", packageName)
            put("nonce", nonce)
            put("timestampMillis", timestampMillis)
        })
        put("appIntegrity", buildJsonObject {
            put("appRecognitionVerdict", appVerdict)
            put("packageName", packageName)
            put("certificateSha256Digest", buildJsonArray { add(JsonPrimitive("6a6a1474b5cbbb2b1aa57e0bc3")) })
            put("versionCode", 42)
        })
        put("deviceIntegrity", buildJsonObject {
            put("deviceRecognitionVerdict", buildJsonArray { deviceVerdicts.forEach { add(JsonPrimitive(it)) } })
        })
        put("accountDetails", buildJsonObject { put("appLicensingVerdict", licensing) })
    }

    /** The complete token for [payload]; [signer] and [wrapKey] let a test use the wrong keys. */
    fun token(payload: JsonObject, signer: KeyPair = signingKey, wrapKey: ByteArray = decryptionKey, jwsAlg: String = "ES256"): String {
        val jws = sign(payload.toString(), signer, jwsAlg)
        return encrypt(jws, wrapKey)
    }

    fun sign(payloadText: String, signer: KeyPair = signingKey, alg: String = "ES256"): String {
        val header = b64("""{"alg":"$alg"}""".toByteArray())
        val body = b64(payloadText.toByteArray())
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(signer.private)
            update("$header.$body".toByteArray(Charsets.US_ASCII))
            sign()
        }
        return "$header.$body.${b64(derToRaw(der))}"
    }

    fun encrypt(plaintext: String, wrapKey: ByteArray = decryptionKey, alg: String = "A256KW", enc: String = "A256GCM"): String {
        val header = b64("""{"alg":"$alg","enc":"$enc"}""".toByteArray())
        val cek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val wrapped = Cipher.getInstance("AESWrap").run {
            init(Cipher.WRAP_MODE, SecretKeySpec(wrapKey, "AES"))
            wrap(SecretKeySpec(cek, "AES"))
        }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val sealed = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
            updateAAD(header.toByteArray(Charsets.US_ASCII))
            doFinal(plaintext.toByteArray())
        }
        val ciphertext = sealed.copyOfRange(0, sealed.size - 16)
        val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)
        return listOf(header, b64(wrapped), b64(iv), b64(ciphertext), b64(tag)).joinToString(".")
    }

    companion object {
        const val PACKAGE = "com.example.app"

        fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        /** DER ECDSA signature → the 64-byte `r ‖ s` JWS form. */
        fun derToRaw(der: ByteArray): ByteArray {
            var i = 2
            require(der[0] == 0x30.toByte())
            if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
            require(der[i] == 0x02.toByte())
            val rLen = der[i + 1].toInt() and 0xff
            val r = BigInteger(1, der.copyOfRange(i + 2, i + 2 + rLen))
            i += 2 + rLen
            require(der[i] == 0x02.toByte())
            val sLen = der[i + 1].toInt() and 0xff
            val s = BigInteger(1, der.copyOfRange(i + 2, i + 2 + sLen))
            return fixed(r) + fixed(s)
        }

        private fun fixed(value: BigInteger): ByteArray {
            val bytes = value.toByteArray()
            return when {
                bytes.size == 32 -> bytes
                bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
                else -> ByteArray(32 - bytes.size) + bytes
            }
        }
    }
}
