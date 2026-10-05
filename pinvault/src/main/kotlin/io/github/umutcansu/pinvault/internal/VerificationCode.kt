package io.github.umutcansu.pinvault.internal

import java.security.MessageDigest
import java.security.PublicKey

/**
 * The code a device shows while its enrollment waits for approval, so the
 * administrator can match it with the request in the dashboard: the first 80
 * bits (10 bytes) of the SHA-256 of the device key (SubjectPublicKeyInfo, DER)
 * in Crockford's base32, 16 characters in groups of four —
 * `4F7K-2QXM-9D3T-H6WP`. The server computes the same from the key it
 * received (demo-server `VerificationCode`); keep the two in step.
 *
 * It used to be the first 40 bits (`4F7K-2QXM`). Someone who wants the
 * administrator to approve THEIR key under a waiting device's code needs a
 * key whose code matches, and with 40 bits that is a few minutes of key
 * generation; with 80 it is out of reach. The first eight characters are the
 * old code.
 */
internal object VerificationCode {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** Bytes of the digest the code is made of. */
    const val BYTES = 10

    fun of(publicKey: PublicKey): String =
        ofDigest(MessageDigest.getInstance("SHA-256").digest(publicKey.encoded))

    fun ofDigest(digest: ByteArray): String {
        require(digest.size >= BYTES) { "digest too short" }
        val chars = CharArray(16)
        // 5 bytes = 40 bits = 8 characters, twice.
        for (half in 0 until 2) {
            var bits = 0L
            for (i in 0 until 5) bits = (bits shl 8) or (digest[half * 5 + i].toLong() and 0xff)
            for (i in 0 until 8) chars[half * 8 + i] = ALPHABET[((bits shr (35 - 5 * i)) and 31).toInt()]
        }
        return String(chars).chunked(4).joinToString("-")
    }
}
