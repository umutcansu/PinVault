package com.example.pinvault.server.service

/**
 * A fixed-window counter for device endpoints that ask for no API key, keyed
 * by the caller's source address ([sourceKey]) — never by an id the caller
 * chose, which it could rotate to get a fresh window each time. Used two ways:
 *  - [allow] counts an attempt and says whether it is within the quota (E2E key
 *    writes, code-less applications, reports);
 *  - [exceeded] only looks, so a route can count refusals ([allow] on each one)
 *    and cut the source off before doing any work, without charging devices
 *    that share its address for requests that succeed (renewal, enrollment,
 *    vault downloads).
 *
 * Memory is bounded by [maxKeys]. When full, windows that ran out are dropped;
 * a live window is never dropped: evicting one (it used to be an arbitrary
 * one) let a caller with many keys flush other callers' counters, its own
 * included. What happens to a NEW key while every window is live is
 * [overflow]: refusing it (as this used to do for every limiter) let anyone
 * with ten thousand addresses — or ten thousand identities — shut everyone
 * else out.
 */
class RateLimiter(
    private val maxAttempts: Int = 10,
    private val windowMs: Long = 10 * 60_000,
    private val maxKeys: Int = 10_000,
    private val clock: () -> Long = System::currentTimeMillis,
    private val overflow: Overflow = Overflow.PREFIX
) {
    /** What a new key gets while the table is full of live windows. */
    enum class Overflow {
        /**
         * Source keys ([sourceKey], optionally behind a `label|`) are counted in
         * a bucket of their network — IPv4 /24, IPv6 /48 — so a flood from many
         * addresses limits those networks, not the whole server. A key that is
         * not an address is refused.
         */
        PREFIX,

        /** Allowed and not counted: for keys of authenticated callers (a client id that just proved itself). */
        FAIL_OPEN,

        /** Refused until a window runs out. */
        REFUSE
    }

    private class Window(val start: Long, var count: Int)

    private val windows = HashMap<String, Window>()

    /** [Overflow.PREFIX] buckets, bounded by [maxKeys] too. */
    private val buckets = HashMap<String, Window>()

    /** Counts one attempt for [key] and says whether it may proceed. */
    @Synchronized
    fun allow(key: String): Boolean {
        val now = clock()
        val current = windows[key]
        val window = if (current == null || now - current.start >= windowMs) {
            if (current == null && windows.size >= maxKeys) {
                windows.values.removeIf { now - it.start >= windowMs }
                if (windows.size >= maxKeys) return allowOverflow(key, now)
            }
            Window(now, 0).also { windows[key] = it }
        } else current
        window.count++
        return window.count <= maxAttempts
    }

    /** Whether [key] has used up its quota in the current window; counts nothing. */
    @Synchronized
    fun exceeded(key: String): Boolean {
        val window = windows[key] ?: (if (buckets.isEmpty()) null else bucketOf(key)?.let { buckets[it] }) ?: return false
        return clock() - window.start < windowMs && window.count >= maxAttempts
    }

    private fun allowOverflow(key: String, now: Long): Boolean = when (overflow) {
        Overflow.FAIL_OPEN -> true
        Overflow.REFUSE -> false
        Overflow.PREFIX -> allowBucket(bucketOf(key), now)
    }

    private fun allowBucket(bucket: String?, now: Long): Boolean {
        if (bucket == null) return false
        val current = buckets[bucket]
        val window = if (current == null || now - current.start >= windowMs) {
            if (current == null && buckets.size >= maxKeys) {
                buckets.values.removeIf { now - it.start >= windowMs }
                if (buckets.size >= maxKeys) return false
            }
            Window(now, 0).also { buckets[bucket] = it }
        } else current
        window.count++
        return window.count <= maxAttempts
    }

    companion object {
        private val IPV6_LITERAL = Regex("^[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*(%[0-9A-Za-z._-]+)?$")

        /**
         * What a source address is counted under: an IPv4 address as it is, an
         * IPv6 address by its /64 — one subscriber holds a whole /64 and could
         * otherwise use a new address for every request.
         */
        private val IPV4_LITERAL = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.\\d{1,3}$")
        private val V6_PREFIX_KEY = Regex("^([0-9a-f]{16})::/64$")

        /**
         * The overflow bucket of [key]: the network of the address it names —
         * after an optional `label|` — or null when it names none. A source key
         * of an IPv6 address is already its /64; the bucket is the /48.
         */
        internal fun bucketOf(key: String): String? {
            val label = key.substringBeforeLast('|', "")
            val address = key.substringAfterLast('|')
            val network = IPV4_LITERAL.matchEntire(address)?.let { m -> "${m.groupValues[1]}.${m.groupValues[2]}.${m.groupValues[3]}.0/24" }
                ?: V6_PREFIX_KEY.matchEntire(address)?.let { m -> m.groupValues[1].take(12) + "::/48" }
                ?: sourceKey(address).takeIf { it != address }?.let { v6 -> V6_PREFIX_KEY.matchEntire(v6)?.groupValues?.get(1)?.take(12)?.plus("::/48") }
                ?: return null
            return "net:$label|$network"
        }

        fun sourceKey(remoteAddress: String): String {
            // Only what can be an IPv6 literal is parsed; nothing is ever resolved.
            if (!IPV6_LITERAL.matches(remoteAddress)) return remoteAddress
            val bytes = try {
                (java.net.InetAddress.getByName(remoteAddress) as? java.net.Inet6Address)?.address
            } catch (_: Exception) {
                null
            } ?: return remoteAddress
            return bytes.take(8).joinToString("") { "%02x".format(it) } + "::/64"
        }
    }
}

/**
 * At most [maxPerKey] requests of one key (a [RateLimiter.sourceKey]) at once.
 * Vault downloads need no credential for a `public` file and stream a body
 * that may be megabytes: without this one address could hold every worker.
 */
class ConcurrencyLimiter(private val maxPerKey: Int, private val maxKeys: Int = 10_000) {
    private val running = HashMap<String, Int>()

    /** Takes a slot for [key]; false when it has [maxPerKey] running already (or the table is full). */
    @Synchronized
    fun tryAcquire(key: String): Boolean {
        val current = running[key] ?: 0
        if (current >= maxPerKey || (current == 0 && running.size >= maxKeys)) return false
        running[key] = current + 1
        return true
    }

    @Synchronized
    fun release(key: String) {
        val current = running[key] ?: return
        if (current <= 1) running.remove(key) else running[key] = current - 1
    }
}
