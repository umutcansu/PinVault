package com.example.pinvault.server.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The limiter's memory bound cannot be used to reset anyone's counter, and its key is the source, not the caller's text. */
class RateLimiterTest {

    private var now = 1_000_000L
    private fun limiter(maxAttempts: Int = 2, maxKeys: Int = 3) =
        RateLimiter(maxAttempts = maxAttempts, windowMs = 60_000, maxKeys = maxKeys, clock = { now })

    @Test
    fun `a full limiter refuses new keys instead of dropping a live window`() {
        val limiter = limiter()
        // Three sources, each one attempt into its window.
        listOf("a", "b", "c").forEach { assertTrue(limiter.allow(it)) }

        // It used to drop an arbitrary window here: with enough keys a caller flushed
        // every counter, its own included, and started over.
        repeat(50) { assertFalse(limiter.allow("flood-$it"), "a new key while every window is live") }

        // Nobody's count was lost: each has exactly one attempt left.
        for (key in listOf("a", "b", "c")) {
            assertTrue(limiter.allow(key), key)
            assertFalse(limiter.allow(key), key)
            assertTrue(limiter.exceeded(key), key)
        }
    }

    @Test
    fun `windows that ran out make room`() {
        val limiter = limiter()
        listOf("a", "b", "c").forEach { limiter.allow(it) }
        assertFalse(limiter.allow("d"))
        now += 60_000
        assertTrue(limiter.allow("d"), "expired windows are dropped first")
        assertTrue(limiter.allow("a"), "a starts a new window")
        assertTrue(limiter.allow("e"))
        assertFalse(limiter.allow("f"), "d, a and e are live: full again")
    }

    @Test
    fun `exceeded looks without counting`() {
        val limiter = limiter(maxAttempts = 2, maxKeys = 10)
        repeat(100) { assertFalse(limiter.exceeded("a")) }
        assertTrue(limiter.allow("a"))
        assertFalse(limiter.exceeded("a"))
        assertTrue(limiter.allow("a"))
        assertTrue(limiter.exceeded("a"), "the quota is used up")
        assertFalse(limiter.exceeded("b"))
        now += 60_000
        assertFalse(limiter.exceeded("a"), "a new window")
    }

    @Test
    fun `an IPv6 source is counted by its 64-bit prefix`() {
        assertEquals("203.0.113.7", RateLimiter.sourceKey("203.0.113.7"))
        assertEquals("localhost", RateLimiter.sourceKey("localhost"))
        val one = RateLimiter.sourceKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
        assertEquals(one, RateLimiter.sourceKey("2001:db8:1:2::1"), "the same /64")
        assertEquals(one, RateLimiter.sourceKey("2001:0db8:0001:0002:ffff:ffff:ffff:ffff"))
        assertNotEquals(one, RateLimiter.sourceKey("2001:db8:1:3::1"), "another /64")
        // An IPv4 address written as IPv6 stays one address.
        assertNotEquals(RateLimiter.sourceKey("::ffff:203.0.113.7"), RateLimiter.sourceKey("::ffff:203.0.113.8"))
        // Not an address at all: used as it is, never resolved.
        assertEquals("not:an:address:zz", RateLimiter.sourceKey("not:an:address:zz"))
    }

    @Test
    fun `a full table counts new addresses by their network instead of refusing everyone`() {
        val limiter = RateLimiter(maxAttempts = 2, windowMs = 60_000, maxKeys = 3, clock = { now })
        listOf("10.0.0.1", "10.0.0.2", "10.0.0.3").forEach { assertTrue(limiter.allow(it)) }
        // A flood from one /24: two attempts for the whole network, then refused.
        assertTrue(limiter.allow("198.51.100.1"))
        assertTrue(limiter.allow("198.51.100.2"))
        assertFalse(limiter.allow("198.51.100.3"))
        assertTrue(limiter.exceeded("198.51.100.77"), "the network is cut off, every address in it")
        // Another network is not: a device elsewhere still gets in while the table is full.
        assertTrue(limiter.allow("203.0.113.9"))
        assertFalse(limiter.exceeded("203.0.113.10"))
        // IPv6 /64 source keys share their /48, behind a label too.
        val a = RateLimiter.sourceKey("2001:db8:1:2::1")
        val b = RateLimiter.sourceKey("2001:db8:1:3::1")
        assertEquals(RateLimiter.bucketOf("apply|$a"), RateLimiter.bucketOf("apply|$b"))
        assertEquals(null, RateLimiter.bucketOf("id|some-client"), "not an address: no bucket")
    }

    @Test
    fun `a full identity table makes room by dropping the least recently used identity, and still counts the new one`() {
        val limiter = RateLimiter(maxAttempts = 1, windowMs = 60_000, maxKeys = 2, clock = { now }, overflow = RateLimiter.Overflow.EVICT_LRU)
        assertTrue(limiter.allow("id|a")); assertTrue(limiter.allow("id|b"))
        assertFalse(limiter.allow("id|a"), "a tracked identity is limited (and a is now the most recently used)")
        // An identity that just proved itself is never shut out by others…
        assertTrue(limiter.allow("id|c"), "c gets in: b, the least recently used, makes room")
        // …and it is counted: it used to be let through uncounted, again and again (fail open).
        assertFalse(limiter.allow("id|c"), "c is limited like anyone")
        assertTrue(limiter.exceeded("id|c"))
        assertFalse(limiter.allow("id|a"), "a kept its window: it was used more recently than b")
        assertEquals(2, limiter.size, "bounded")
    }

    @Test
    fun `windows that ran out are dropped before a live identity is pushed out`() {
        val limiter = RateLimiter(maxAttempts = 1, windowMs = 60_000, maxKeys = 3, clock = { now }, overflow = RateLimiter.Overflow.EVICT_LRU)
        assertTrue(limiter.allow("old"))
        now += 30_000
        assertTrue(limiter.allow("live-1")); assertTrue(limiter.allow("live-2"))
        // "old" is used again (the most recently used now), but its window still runs out first.
        assertFalse(limiter.allow("old"))
        now += 30_000 // old's window has run out; live-1 and live-2 have 30 s left
        assertTrue(limiter.allow("new"))
        assertFalse(limiter.allow("live-1"), "not evicted: the expired window made room")
        assertFalse(limiter.allow("live-2"), "not evicted either")
        assertTrue(limiter.allow("old"), "old starts a new window (its old one was dropped)")
    }

    @Test
    fun `50 000 devices are each counted and limited by the per-device attestation table`() {
        // The table as Main sizes it for the default ATTESTATION_DEVICE_LIMIT (100 000).
        val limits = com.example.pinvault.server.route.AttestationLimits.of(perAddress = 0, perDevice = 3,
            deviceKeys = RateLimiter.identityTableSize(100_000, emptyMap()))
        val devices = (0 until 50_000).map { "lt-%05d".format(it) }
        repeat(3) { round -> devices.forEach { assertTrue(limits.allowDevice("default-tls", it), "$it round $round") } }
        // The fourth attempt of every one of them is refused: nobody slipped through uncounted.
        devices.forEach { assertFalse(limits.allowDevice("default-tls", it), it) }
    }

    @Test
    fun `a flood of new identities can only reset the least recently used ones, never skip counting`() {
        val limiter = RateLimiter(maxAttempts = 2, windowMs = 60_000, maxKeys = 1_000, clock = { now }, overflow = RateLimiter.Overflow.EVICT_LRU)
        var allowed = 0
        repeat(50_000) { if (limiter.allow("id|flood-$it")) allowed++ }
        assertEquals(50_000, allowed, "each new identity gets its first attempt")
        assertEquals(1_000, limiter.size, "the table stays bounded")
        // The 1 000 most recent ones are all still counted.
        (49_000 until 50_000).forEach { assertTrue(limiter.allow("id|flood-$it")); assertFalse(limiter.allow("id|flood-$it")) }
    }

    @Test
    fun `identity tables are sized from the configured limit, or by RATE_LIMIT_IDENTITY_KEYS`() {
        assertEquals(125_000, RateLimiter.identityTableSize(100_000, emptyMap()))
        assertEquals(10_000, RateLimiter.identityTableSize(500, emptyMap()), "never below 10 000")
        assertEquals(250_000, RateLimiter.identityTableSize(0, emptyMap()), "no device cap configured")
        assertEquals(40_000, RateLimiter.identityTableSize(100_000, mapOf("RATE_LIMIT_IDENTITY_KEYS" to "40000")))
        assertEquals(300_000, RateLimiter.identityTableSize(100_000, mapOf("ATTESTATION_DEVICE_RATE_KEYS" to "300000"), name = "ATTESTATION_DEVICE_RATE_KEYS"))
        kotlin.test.assertFailsWith<IllegalStateException> { RateLimiter.identityTableSize(1, mapOf("RATE_LIMIT_IDENTITY_KEYS" to "12")) }
    }

    @Test
    fun `a key longer than the cap is kept as its digest, still counted and never merged`() {
        val limiter = RateLimiter(maxAttempts = 1, windowMs = 60_000, maxKeys = 10, clock = { now }, overflow = RateLimiter.Overflow.EVICT_LRU)
        val long = "id|" + "a".repeat(100_000)
        assertTrue(limiter.allow(long))
        assertFalse(limiter.allow(long), "counted")
        assertTrue(limiter.exceeded(long))
        assertTrue(limiter.allow(long + "b"), "another long key is another window")
        assertTrue(RateLimiter.bounded(long).length < 80)
        assertEquals("id|short", RateLimiter.bounded("id|short"))
    }

    @Test
    fun `reports per device are never refused for a device the table has not seen`() {
        // ReportLimits used to build its per-device table with the address default: past
        // 10 000 devices bucketOf gave no network for a client id, and every new device got 429.
        val limits = com.example.pinvault.server.route.ReportLimits.of(perAddress = 0, perDevice = 2, deviceKeys = 10_000)
        repeat(30_000) { assertTrue(limits.allowDevice("default-tls", "client-$it"), "client-$it") }
        (29_000 until 30_000).forEach { assertTrue(limits.allowDevice("default-tls", "client-$it")); assertFalse(limits.allowDevice("default-tls", "client-$it")) }
    }
}
