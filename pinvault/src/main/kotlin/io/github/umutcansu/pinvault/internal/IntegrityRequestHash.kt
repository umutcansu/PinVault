package io.github.umutcansu.pinvault.internal

import java.security.MessageDigest

/**
 * The value an integrity token is bound to for one enrollment request (see
 * [io.github.umutcansu.pinvault.model.IntegrityTokenProvider]):
 *
 * ```
 * base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))
 * ```
 *
 * Unpadded Base64url, 43 characters: a valid Play Integrity `requestHash`
 * and classic `nonce` alike. The server recomputes it from the request it
 * receives. Plain JVM code (no `android.util.Base64`), so the library and a
 * JVM server can share test vectors.
 */
internal object IntegrityRequestHash {

    private const val PREFIX = "pinvault-integrity:v1:"

    fun of(deviceId: String?, csrDer: ByteArray): String {
        val csrHash = base64Url(sha256(csrDer))
        return base64Url(sha256("$PREFIX${deviceId.orEmpty()}:$csrHash".toByteArray(Charsets.UTF_8)))
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    /** RFC 4648 §5 without padding. `java.util.Base64` needs API 26; minSdk is 24. */
    internal fun base64Url(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i + 3 <= bytes.size) {
            val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8) or (bytes[i + 2].toInt() and 0xff)
            out.append(ALPHABET[n ushr 18 and 63]).append(ALPHABET[n ushr 12 and 63])
                .append(ALPHABET[n ushr 6 and 63]).append(ALPHABET[n and 63])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = bytes[i].toInt() and 0xff shl 16
                out.append(ALPHABET[n ushr 18 and 63]).append(ALPHABET[n ushr 12 and 63])
            }
            2 -> {
                val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8)
                out.append(ALPHABET[n ushr 18 and 63]).append(ALPHABET[n ushr 12 and 63]).append(ALPHABET[n ushr 6 and 63])
            }
        }
        return out.toString()
    }
}
