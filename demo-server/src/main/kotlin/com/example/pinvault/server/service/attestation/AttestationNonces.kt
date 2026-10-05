package com.example.pinvault.server.service.attestation

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Stateless attestation nonces (ATTESTATION.md §2.1) and the ARC
 * (attestation result code) that shares their key.
 *
 * A nonce is `base64url( ts(8) ‖ rand(16) ‖ HMAC-SHA256(nonceKey, ts ‖ rand)[0..16) )`:
 * the server keeps nothing when it hands one out, verifies the MAC and the
 * age (≤ [ttlSeconds]) when it comes back, and remembers the ones it accepted
 * in a bounded cache ([maxCached]) for as long as they could still be
 * presented, so each is accepted once.
 *
 * The key is random per process start: a restart invalidates the nonces
 * in flight (the library simply asks for a new challenge) and changes the
 * ARC of a given set of reasons — the dashboard resolves an ARC from the
 * device's stored verdict, never by recomputing it, so that is fine.
 */
class AttestationNonces(
    val ttlSeconds: Int = 120,
    key: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
    private val clock: () -> Long = System::currentTimeMillis,
    private val maxCached: Int = 100_000
) {
    private val keySpec = SecretKeySpec(key, "HmacSHA256")
    private val random = SecureRandom()

    /** Accepted nonces → the time they stop being presentable (ms). Oldest first. */
    private val accepted = object : LinkedHashMap<String, Long>(1024, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > maxCached
    }

    sealed interface Check {
        data object Ok : Check
        data object Invalid : Check
        data object Expired : Check
        data object Replayed : Check
    }

    /** A fresh nonce for `GET /api/v1/attest/challenge`. */
    fun issue(): String {
        val ts = clock()
        val rand = ByteArray(RAND_LEN).also(random::nextBytes)
        val body = ByteBuffer.allocate(TS_LEN + RAND_LEN).putLong(ts).put(rand).array()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(body + mac(body).copyOf(MAC_LEN))
    }

    /** Checks [nonce] and, when it is good, marks it used. */
    @Synchronized
    fun consume(nonce: String): Check {
        val bytes = try {
            Base64.getUrlDecoder().decode(nonce)
        } catch (_: IllegalArgumentException) {
            return Check.Invalid
        }
        if (bytes.size != TS_LEN + RAND_LEN + MAC_LEN) return Check.Invalid
        val body = bytes.copyOf(TS_LEN + RAND_LEN)
        if (!MessageDigest.isEqual(mac(body).copyOf(MAC_LEN), bytes.copyOfRange(TS_LEN + RAND_LEN, bytes.size))) return Check.Invalid
        val ts = ByteBuffer.wrap(body).long
        val now = clock()
        val ttlMs = ttlSeconds * 1000L
        // From the future (another process's clock, or a forged timestamp) counts as expired too.
        if (ts > now + MAX_FUTURE_MS || now - ts > ttlMs) return Check.Expired
        val expiresAt = ts + ttlMs
        // Entries that can no longer be presented go first (insertion order ≈ issue order).
        val iterator = accepted.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value <= now) iterator.remove() else break
        }
        if (accepted.containsKey(nonce)) return Check.Replayed
        accepted[nonce] = expiresAt
        return Check.Ok
    }

    /** How many accepted nonces are remembered now (tests). */
    val cached: Int get() = synchronized(this) { accepted.size }

    /**
     * The attestation result code of a verdict: the first 8 hex characters of
     * `HMAC-SHA256(nonceKey, sorted reasons ‖ "|" ‖ sorted warnings)`.
     */
    fun arc(reasons: Collection<String>, warnings: Collection<String>): String {
        val text = reasons.sorted().joinToString(",") + "|" + warnings.sorted().joinToString(",")
        return mac(text.toByteArray(Charsets.UTF_8)).take(4).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private fun mac(data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(keySpec) }.doFinal(data)

    companion object {
        private const val TS_LEN = 8
        private const val RAND_LEN = 16
        private const val MAC_LEN = 16

        /** A nonce stamped further ahead than this is not one of ours (clock skew between restarts aside). */
        private const val MAX_FUTURE_MS = 5_000L
    }
}
