package io.github.umutcansu.pinvault.crypto

import android.util.Base64
import timber.log.Timber
import java.security.KeyFactory
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
            val keyBytes = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(keyBytes))

            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(publicKey)
            sig.update(payload.toByteArray(Charsets.UTF_8))

            val signatureBytes = Base64.decode(signature, Base64.NO_WRAP)
            val valid = sig.verify(signatureBytes)

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
    ): Boolean {
        val canonical = "pinvault-vault-file:v1:$key:$version:${sha256HexLower(plaintext)}"
        return verify(canonical, signature, publicKeyBase64)
    }

    private fun sha256HexLower(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
