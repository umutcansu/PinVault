package com.example.pinvault.server.service

import java.util.Base64

/**
 * A short code derived from a device's key, shown on the device and next to
 * its request in the dashboard, so an administrator can tell which device
 * they are letting in — the role a MAC address plays in a router's filter.
 *
 * The first 80 bits (10 bytes) of the key's SHA-256 (over its
 * SubjectPublicKeyInfo) in Crockford's base32, as four groups of four
 * (`4F7K-2QXM-9D3T-H6WP`). The library computes the same from the key it
 * holds (`internal/VerificationCode.kt`); keep the two in step. Vector:
 * SHA-256("pinvault") → `0XMH-GCGP-BW6Z-10F6`.
 *
 * It used to be 40 bits (`4F7K-2QXM`, now the first two groups): someone
 * wanting the administrator to approve their key under a waiting device's
 * code needs a key whose code matches, and 40 bits is minutes of key
 * generation; 80 is out of reach.
 */
object VerificationCode {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** Bytes of the digest the code is made of. */
    const val BYTES = 10

    /** From the key's SHA-256 digest (32 bytes; the first [BYTES] are used). */
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

    /** From the Base64 SHA-256 the server keeps for every device key (`spkiSha256`). */
    fun ofSpkiSha256(spkiSha256Base64: String): String =
        runCatching { ofDigest(Base64.getDecoder().decode(spkiSha256Base64)) }.getOrDefault("")
}
