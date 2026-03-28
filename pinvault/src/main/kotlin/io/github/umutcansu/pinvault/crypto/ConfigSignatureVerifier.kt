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
}
