package io.github.umutcansu.pinvault.internal

import java.security.MessageDigest
import java.security.PublicKey

/**
 * The short code a device shows while its enrollment waits for approval, so
 * the administrator can match it with the request in the dashboard: the
 * first 40 bits of the SHA-256 of the device key (SubjectPublicKeyInfo) in
 * Crockford's base32, `4F7K-2QXM`. The server computes the same from the key
 * it received (demo-server `VerificationCode`); keep the two in step.
 */
internal object VerificationCode {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    fun of(publicKey: PublicKey): String =
        ofDigest(MessageDigest.getInstance("SHA-256").digest(publicKey.encoded))

    fun ofDigest(digest: ByteArray): String {
        require(digest.size >= 5) { "digest too short" }
        var bits = 0L
        for (i in 0 until 5) bits = (bits shl 8) or (digest[i].toLong() and 0xff)
        val chars = CharArray(8) { i -> ALPHABET[((bits shr (35 - 5 * i)) and 31).toInt()] }
        return String(chars, 0, 4) + "-" + String(chars, 4, 4)
    }
}
