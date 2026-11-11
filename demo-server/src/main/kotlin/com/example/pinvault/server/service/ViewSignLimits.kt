package com.example.pinvault.server.service

/**
 * How many NARROWED signed config views one requester may have signed per
 * window ([WINDOW_MS], 10 minutes). Only signings are counted — a request
 * answered from the signature cache costs nothing and is never refused — and
 * only narrowed ones: the full view is one signing per content, whoever asks.
 *
 * A narrowed view (`?hosts=`, `X-Device-Id`, the attestation body's `hosts`)
 * names the request it answers (`view`, M6), so every distinct host set and
 * device id is its own signed content. On a TLS listener both are the
 * caller's unauthenticated claims: without this, made-up values were a cache
 * miss and a signing each — HSM/KMS calls at will, the cache evicted, the
 * signer's permits and queue full.
 *
 * Keyed by the verified client id on an mTLS listener (one device behind a
 * NAT must not use up the others' budget), else by the source address
 * ([RateLimiter.sourceKey], which honours `TRUSTED_PROXIES`).
 *
 * `CONFIG_VIEW_SIGN_RATE_LIMIT` (per address, default [DEFAULT_PER_SOURCE])
 * and `CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT` (per client id, default
 * [DEFAULT_PER_IDENTITY]); 0 = no limit. A device costs about one signing per
 * half TTL (init, then a re-fetch after the cached envelope ages out or an
 * admin change); pin-mismatch recovery (6 refetches per 5 minutes at most) and
 * attestation every 5 minutes mostly hit the cache. The address budget is
 * larger because devices behind one NAT share it.
 */
class ViewSignLimits(
    private val perSource: RateLimiter?,
    private val perIdentity: RateLimiter?
) {
    /** Who asks for a narrowed view: [clientId] = the verified client certificate's id, if any. */
    data class Requester(val remoteAddress: String, val clientId: String? = null) {
        internal fun key(): String = clientId?.let { "id|$it" } ?: RateLimiter.sourceKey(remoteAddress)
    }

    private fun limiterFor(requester: Requester): RateLimiter? = if (requester.clientId != null) perIdentity else perSource

    /** Counts one signing for [requester]; false once its budget for the window is spent. */
    fun allow(requester: Requester): Boolean = limiterFor(requester)?.allow(requester.key()) != false

    /** Seconds until [requester] may have a narrowed view signed again (`Retry-After`). */
    fun retryAfterSeconds(requester: Requester): Long =
        ((limiterFor(requester)?.retryAfterMs(requester.key()) ?: WINDOW_MS) + 999) / 1000

    companion object {
        const val WINDOW_MS = 10 * 60_000L
        const val DEFAULT_PER_SOURCE = 120
        const val DEFAULT_PER_IDENTITY = 30
        const val MAX_LIMIT = 1_000_000

        fun of(perSource: Int, perIdentity: Int, clock: () -> Long = System::currentTimeMillis): ViewSignLimits? {
            if (perSource == 0 && perIdentity == 0) return null
            return ViewSignLimits(
                perSource = if (perSource > 0) RateLimiter(maxAttempts = perSource, windowMs = WINDOW_MS, clock = clock) else null,
                // Client ids proved themselves in the handshake and are not addresses:
                // a full table lets a new one through; the address limit is not involved.
                perIdentity = if (perIdentity > 0) RateLimiter(maxAttempts = perIdentity, windowMs = WINDOW_MS, clock = clock,
                    overflow = RateLimiter.Overflow.FAIL_OPEN) else null
            )
        }

        /** From the environment; a value that is not a whole number from 0 to [MAX_LIMIT] stops the server. Blank = default. */
        fun fromEnv(env: Map<String, String> = ServerEnv.all()): ViewSignLimits? =
            of(limit(env, "CONFIG_VIEW_SIGN_RATE_LIMIT", DEFAULT_PER_SOURCE), limit(env, "CONFIG_VIEW_SIGN_DEVICE_RATE_LIMIT", DEFAULT_PER_IDENTITY))

        private fun limit(env: Map<String, String>, name: String, default: Int): Int {
            val raw = env[name]?.trim().orEmpty()
            if (raw.isEmpty()) return default
            return raw.toIntOrNull()?.takeIf { it in 0..MAX_LIMIT }
                ?: error("$name must be a whole number from 0 to $MAX_LIMIT (got '$raw')")
        }
    }
}
