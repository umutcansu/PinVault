package com.example.pinvault.server.service

import java.util.Base64

/**
 * A short code derived from a device's key, shown on the device and next to
 * its request in the dashboard, so an administrator can tell which device
 * they are letting in — the role a MAC address plays in a router's filter.
 *
 * The first 40 bits of the key's SHA-256 (over its SubjectPublicKeyInfo) in
 * Crockford's base32, as two groups of four (`4F7K-2QXM`). The library
 * computes the same from the key it holds; another device cannot show the
 * same code without that key (or tens of thousands of key pairs per second for
 * days, while the request waits in plain view).
 */
object VerificationCode {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** From the key's SHA-256 digest (32 bytes). */
    fun ofDigest(digest: ByteArray): String {
        require(digest.size >= 5) { "digest too short" }
        var bits = 0L
        for (i in 0 until 5) bits = (bits shl 8) or (digest[i].toLong() and 0xff)
        val chars = CharArray(8) { i -> ALPHABET[((bits shr (35 - 5 * i)) and 31).toInt()] }
        return String(chars, 0, 4) + "-" + String(chars, 4, 4)
    }

    /** From the Base64 SHA-256 the server keeps for every device key (`spkiSha256`). */
    fun ofSpkiSha256(spkiSha256Base64: String): String =
        runCatching { ofDigest(Base64.getDecoder().decode(spkiSha256Base64)) }.getOrDefault("")
}
