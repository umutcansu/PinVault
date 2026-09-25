package io.github.umutcansu.pinvault.crypto

import android.util.Base64
import timber.log.Timber
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Verifies ECDSA-SHA256 signatures on config payloads.
 *
 * The public key is embedded in the APK at build time via [PinVaultConfig.signaturePublicKey].
 * The corresponding private key lives on the config backend (never in the APK).
 */
internal object ConfigSignatureVerifier {

    /**
     * Verifies that [signature] is a valid ECDSA-SHA256 signature of [payload]
     * using the given [publicKeyBase64] (X.509 encoded, Base64).
     *
     * @return true if signature is valid, false otherwise
     */
    fun verify(payload: String, signature: String, publicKeyBase64: String): Boolean {
        return try {
            val valid = verifyOrThrow(payload, signature, publicKeyBase64)
            if (!valid) {
                Timber.e("Config signature verification FAILED")
            } else {
                Timber.d("Config signature verified ✓")
            }
            valid
        } catch (e: Exception) {
            Timber.e(e, "Config signature verification error")
            false
        }
    }

    /**
     * [verify] without logging. Used when several keys are tried in turn
     * (multi-key trust, m-of-n): a key that does not match is the expected
     * case there, not an error worth an `E` line per attempt.
     */
    fun verifyQuietly(payload: String, signature: String, publicKeyBase64: String): Boolean =
        try {
            verifyOrThrow(payload, signature, publicKeyBase64)
        } catch (_: Exception) {
            false
        }

    private fun verifyOrThrow(payload: String, signature: String, publicKeyBase64: String): Boolean {
        val keyBytes = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(keyBytes))

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(publicKey)
        sig.update(payload.toByteArray(Charsets.UTF_8))

        val signatureBytes = Base64.decode(signature, Base64.NO_WRAP)
        return sig.verify(signatureBytes)
    }

    /**
     * One canonical text form per EC public key: accepts Base64 (line breaks
     * and PEM armour allowed), parses it, and re-encodes the parsed key as
     * single-line Base64 X.509. Two spellings of the same key — a trailing
     * newline, a wrapped PEM body — map to the same string, so key lists can
     * be de-duplicated and compared safely. `null` when it is not an EC key.
     */
    fun canonicalKey(key: String): String? = try {
        val body = key.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
            .filterNot { it.isWhitespace() }
        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.decode(body, Base64.NO_WRAP)))
        Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    } catch (_: Exception) {
        null
    }

    /**
     * Key id of a Base64 X.509 public key: Base64 of SHA-256 over the
     * SubjectPublicKeyInfo bytes — the same shape as a TLS SPKI pin, so an id
     * can be compared with what a backend or `openssl` reports. `null` when
     * [publicKeyBase64] is not Base64.
     */
    fun keyIdOf(publicKeyBase64: String): String? = try {
        val spki = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
        Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(spki), Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
        null
    }

    /**
     * Verifies a vault file's CONTENT signature (integrity). The signed canonical
     * binds key + version + SHA-256(plaintext), mirroring the server's
     * [com.example.pinvault.server.service.ConfigSigningService] `signVaultFile`.
     * The device verifies the PLAINTEXT it ends up with (after any E2E decrypt),
     * so one signature covers every encryption mode.
     *
     * @param version the server-reported (and signature-bound) vault version;
     *                tampering with it makes the canonical — and therefore the
     *                signature — mismatch, so it is implicitly authenticated.
     * @return true if the signature is valid for (key, version, plaintext)
     */
    fun verifyVaultFile(
        key: String,
        version: Int,
        plaintext: ByteArray,
        signature: String,
        publicKeyBase64: String
    ): Boolean = verify(vaultCanonical(key, version, plaintext), signature, publicKeyBase64)

    /** The string a vault file signature covers. */
    fun vaultCanonical(key: String, version: Int, plaintext: ByteArray): String =
        "pinvault-vault-file:v1:$key:$version:${sha256HexLower(plaintext)}"

    private fun sha256HexLower(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
