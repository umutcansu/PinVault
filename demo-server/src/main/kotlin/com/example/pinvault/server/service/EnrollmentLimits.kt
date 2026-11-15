package com.example.pinvault.server.service

/**
 * How often a device may make the server do enrollment work that succeeds.
 * Refusals are counted elsewhere ([DeviceRefusalLimit][com.example.pinvault.server.plugin.DeviceRefusalLimit]);
 * these are the answers that cost a signature, an audit entry and a webhook
 * each, which anyone holding a shared code — or nothing, in open mode — could
 * repeat without end.
 */
class EnrollmentLimits(
    /**
     * Certificates issued per client id (`ISSUANCE_RATE_LIMIT`, default 10 per
     * 10 minutes): open-mode re-enrollment and policy issuance. Keyed by an id
     * the server assigned or that the key just proved: a full table drops the
     * least recently used id's window (never lets one through uncounted).
     */
    val issuance: RateLimiter? = RateLimiter(maxAttempts = 10, windowMs = 10 * 60_000, maxKeys = IDENTITY_KEYS, overflow = RateLimiter.Overflow.EVICT_LRU),
    /** Pickups (`requestId` asks) per request (`PICKUP_RATE_LIMIT`, default 120 per 10 minutes: one per 5 s). */
    val pickupsPerRequest: RateLimiter? = RateLimiter(maxAttempts = 120, windowMs = 10 * 60_000, maxKeys = IDENTITY_KEYS, overflow = RateLimiter.Overflow.EVICT_LRU),
    /** Pickups per source address (default 600 per 10 minutes). */
    val pickupsPerSource: RateLimiter? = RateLimiter(maxAttempts = 600, windowMs = 10 * 60_000),
    /** Device-initiated E2E / user-auth key replacements per client id over a certificate (`KEY_REPLACEMENT_RATE_LIMIT`, default 10). */
    val keyReplacements: RateLimiter? = RateLimiter(maxAttempts = 10, windowMs = 10 * 60_000, maxKeys = IDENTITY_KEYS, overflow = RateLimiter.Overflow.EVICT_LRU)
) {
    companion object {
        /** Off: nothing limited (tests that are about something else). */
        val NONE = EnrollmentLimits(null, null, null, null)

        /** The identity tables' size without configuration: `DEVICE_KEY_LIMIT`'s default (100 000) + a quarter. */
        private val IDENTITY_KEYS = RateLimiter.identityTableSize(100_000, emptyMap())

        fun fromEnv(env: Map<String, String> = com.example.pinvault.server.service.ServerEnv.all()): EnrollmentLimits {
            fun limit(name: String, default: Int) = (env[name]?.toIntOrNull() ?: default).coerceAtLeast(0)
            // Client ids: at most DEVICE_KEY_LIMIT of them (RATE_LIMIT_IDENTITY_KEYS overrides the size).
            val keys = RateLimiter.identityTableSize((env["DEVICE_KEY_LIMIT"]?.toIntOrNull() ?: 100_000).coerceAtLeast(1), env)
            fun identity(n: Int) = if (n > 0) RateLimiter(maxAttempts = n, windowMs = 10 * 60_000, maxKeys = keys, overflow = RateLimiter.Overflow.EVICT_LRU) else null
            val sources = limit("PICKUP_SOURCE_RATE_LIMIT", 600)
            return EnrollmentLimits(
                issuance = identity(limit("ISSUANCE_RATE_LIMIT", 10)),
                pickupsPerRequest = identity(limit("PICKUP_RATE_LIMIT", 120)),
                pickupsPerSource = if (sources > 0) RateLimiter(maxAttempts = sources, windowMs = 10 * 60_000) else null,
                keyReplacements = identity(limit("KEY_REPLACEMENT_RATE_LIMIT", 10))
            )
        }
    }
}
