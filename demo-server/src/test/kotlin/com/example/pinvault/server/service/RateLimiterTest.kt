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
    fun `identity keys fail open when the table is full`() {
        val limiter = RateLimiter(maxAttempts = 1, windowMs = 60_000, maxKeys = 2, clock = { now }, overflow = RateLimiter.Overflow.FAIL_OPEN)
        assertTrue(limiter.allow("id|a")); assertTrue(limiter.allow("id|b"))
        assertFalse(limiter.allow("id|a"), "a tracked identity is still limited")
        repeat(20) { assertTrue(limiter.allow("id|new-$it"), "an identity that just proved itself is never shut out by others") }
    }
}
