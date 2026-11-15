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
 * Memory is bounded by [maxKeys]. The windows are kept in the order they
 * started, so the ones that ran out are dropped first, from the head, at
 * O(1) each (this used to be a scan of the whole table, under the lock, for
 * every new key once the table was full). What happens to a NEW key while
 * every window is live is [overflow]:
 *  - source keys ([Overflow.PREFIX], [Overflow.REFUSE]) never push a live
 *    window out: evicting one let a caller with many addresses flush other
 *    callers' counters, its own included;
 *  - identity keys ([Overflow.EVICT_LRU]) push out the least recently used
 *    one. Nothing is let through uncounted: the table used to "fail open"
 *    when full, and with more than 10 000 devices the per-device limit then
 *    silently stopped applying to most of them (load test 2026-11-15).
 *    Identity tables are sized above the fleet they count
 *    ([identityTableSize]), so eviction happens only to a table flooded with
 *    new identities; the evicted identity merely starts a new window.
 */
class RateLimiter(
    private val maxAttempts: Int = 10,
    private val windowMs: Long = 10 * 60_000,
    private val maxKeys: Int = 10_000,
    private val clock: () -> Long = System::currentTimeMillis,
    private val overflow: Overflow = Overflow.PREFIX
) {
    init {
        require(maxKeys > 0) { "maxKeys must be positive" }
    }

    /** What a new key gets while the table is full of live windows. */
    enum class Overflow {
        /**
         * Source keys ([sourceKey], optionally behind a `label|`) are counted in
         * a bucket of their network — IPv4 /24, IPv6 /48 — so a flood from many
         * addresses limits those networks, not the whole server. A key that is
         * not an address is refused.
         */
        PREFIX,

        /**
         * For keys of callers that proved who they are (a client id, an
         * attested device): the least recently used key's window is dropped to
         * make room, so a new identity is never shut out by others and is
         * still counted. Never lets a request through uncounted.
         */
        EVICT_LRU,

        /** Refused until a window runs out. */
        REFUSE
    }

    private class Window(val start: Long, var count: Int)

    /** Insertion order = the order the windows started: the head runs out first. */
    private val windows = LinkedHashMap<String, Window>()

    /** [Overflow.EVICT_LRU] only: keys in the order they were last counted (the head is the least recently used). */
    private val used: LinkedHashMap<String, Unit>? =
        if (overflow == Overflow.EVICT_LRU) LinkedHashMap(16, 0.75f, true) else null

    /** [Overflow.PREFIX] buckets, bounded by [maxKeys] too, in the order they started. */
    private val buckets = LinkedHashMap<String, Window>()

    /** How many windows are kept now (tests, metrics). */
    @get:Synchronized
    val size: Int get() = windows.size

    /** Counts one attempt for [key] and says whether it may proceed. */
    @Synchronized
    fun allow(key: String): Boolean {
        val now = clock()
        var window = windows[key]
        if (window != null && now - window.start >= windowMs) {
            // A new window for this key: to the tail, where the youngest windows are.
            windows.remove(key)
            window = null
        }
        if (window == null) {
            if (windows.size >= maxKeys) {
                dropExpired(windows, now)
                if (windows.size >= maxKeys) {
                    if (used == null) return allowOverflow(key, now)
                    evictLeastRecentlyUsed()
                }
            }
            window = Window(now, 0)
            windows[key] = window
        }
        used?.put(key, Unit)
        window.count++
        return window.count <= maxAttempts
    }

    /** Whether [key] has used up its quota in the current window; counts nothing. */
    @Synchronized
    fun exceeded(key: String): Boolean {
        val window = windows[key] ?: (if (buckets.isEmpty()) null else bucketOf(key)?.let { buckets[it] }) ?: return false
        return clock() - window.start < windowMs && window.count >= maxAttempts
    }

    /** Milliseconds until [key]'s window (or its overflow bucket's) runs out; the whole window when it has none. For `Retry-After`. */
    @Synchronized
    fun retryAfterMs(key: String): Long {
        val window = windows[key] ?: (if (buckets.isEmpty()) null else bucketOf(key)?.let { buckets[it] }) ?: return windowMs
        return (window.start + windowMs - clock()).coerceIn(1, windowMs)
    }

    /** Drops the windows that ran out, oldest first; stops at the first live one (the rest are younger). */
    private fun dropExpired(table: LinkedHashMap<String, Window>, now: Long) {
        val it = table.entries.iterator()
        while (it.hasNext()) {
            val entry = it.next()
            if (now - entry.value.start < windowMs) return
            it.remove()
            if (table === windows) used?.remove(entry.key)
        }
    }

    private fun evictLeastRecentlyUsed() {
        val it = used!!.keys.iterator()
        if (!it.hasNext()) return
        val key = it.next()
        it.remove()
        windows.remove(key)
    }

    private fun allowOverflow(key: String, now: Long): Boolean = when (overflow) {
        Overflow.REFUSE -> false
        Overflow.PREFIX -> allowBucket(bucketOf(key), now)
        Overflow.EVICT_LRU -> error("not an overflow mode")
    }

    private fun allowBucket(bucket: String?, now: Long): Boolean {
        if (bucket == null) return false
        var window = buckets[bucket]
        if (window != null && now - window.start >= windowMs) {
            buckets.remove(bucket)
            window = null
        }
        if (window == null) {
            if (buckets.size >= maxKeys) {
                dropExpired(buckets, now)
                if (buckets.size >= maxKeys) return false
            }
            window = Window(now, 0)
            buckets[bucket] = window
        }
        window.count++
        return window.count <= maxAttempts
    }

    companion object {
        /**
         * How many identities an [Overflow.EVICT_LRU] table holds: `RATE_LIMIT_IDENTITY_KEYS`
         * when set (1 000 – 10 000 000), else a quarter above [expected] (the most identities
         * the server holds, e.g. `ATTESTATION_DEVICE_LIMIT` or `DEVICE_KEY_LIMIT`), at least
         * 10 000; [expected] 0 (no cap configured) = 250 000. About 200 bytes per live window.
         */
        fun identityTableSize(expected: Int, env: Map<String, String> = ServerEnv.all(), name: String = "RATE_LIMIT_IDENTITY_KEYS"): Int {
            env[name]?.trim()?.takeIf { it.isNotEmpty() }?.let { raw ->
                return raw.toIntOrNull()?.takeIf { it in 1_000..10_000_000 }
                    ?: error("$name must be a whole number from 1000 to 10000000 (got '$raw')")
            }
            if (expected <= 0) return 250_000
            return maxOf(10_000, (expected.toLong() + expected / 4).coerceAtMost(10_000_000).toInt())
        }

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
