package io.github.umutcansu.pinvault.ssl

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The clock config expiry is decided by: the later of the wall clock and the
 * highest time seen, carried forward by the monotonic clock.
 */
class TrustedClockTest {

    private var wall = 1_800_000_000_000L
    private var elapsed = 50_000L
    private var stored = 0L
    private var writes = 0
    private val minute = 60_000L

    private fun clock() = TrustedClock(
        wall = { wall },
        elapsed = { elapsed },
        load = { stored },
        persist = { stored = it; writes++ }
    )

    private fun pass(ms: Long, wallToo: Boolean = true) {
        elapsed += ms
        if (wallToo) wall += ms
    }

    @Test
    fun `follows the wall clock while it moves forward`() {
        val clock = clock()
        assertEquals(wall, clock.now())
        pass(10 * minute)
        assertEquals(wall, clock.now())
    }

    @Test
    fun `a wall clock set back does not take the time back, and time keeps running`() {
        val clock = clock()
        val seen = clock.now()

        wall -= 24 * 60 * minute
        assertEquals(seen, clock.now())

        // Only the monotonic clock moves from here on.
        pass(30 * minute, wallToo = false)
        assertEquals(seen + 30 * minute, clock.now())
    }

    @Test
    fun `the reference survives a restart`() {
        val first = clock()
        first.now()
        pass(10 * minute)
        first.checkpoint()
        val seen = wall

        // New process, monotonic clock restarted (a reboot), wall clock set back.
        wall -= 5 * 60 * minute
        elapsed = 0L
        assertEquals(seen, clock().now())
    }

    @Test
    fun `writes are rare — one per step, not one per call`() {
        val clock = clock()
        clock.now()
        val afterFirst = writes
        repeat(100) { pass(1_000); clock.now() }
        assertEquals("100 seconds: below the step", afterFirst, writes)

        pass(TrustedClock.PERSIST_STEP_MS)
        clock.now()
        assertEquals(afterFirst + 1, writes)
        assertEquals(wall, stored)
    }

    @Test
    fun `resetTo lowers a reference that is ahead, to the later of wall clock and issuedAt`() {
        val clock = clock()
        val real = wall
        wall += 365L * 24 * 60 * minute // set far ahead by mistake …
        clock.checkpoint()
        wall = real                      // … and corrected
        assertTrue(clock.now() > real)

        clock.resetTo(issuedAt = real - 5 * minute)
        assertEquals(real, clock.now())
        assertEquals(real, stored)

        // A wall clock behind the config's issuedAt: the issuedAt is the floor.
        wall = real - 60 * minute
        clock.resetTo(issuedAt = real - 5 * minute)
        assertEquals(real - 5 * minute, clock.now())
    }

    @Test
    fun `resetTo never raises the reference`() {
        val clock = clock()
        val before = clock.now()
        clock.resetTo(issuedAt = before + 60 * minute)
        assertEquals(before, clock.now())
    }

    @Test
    fun `an unreadable reference falls back to the wall clock and is read again later`() {
        stored = wall + 60 * minute
        var readable = false
        val clock = TrustedClock(
            wall = { wall },
            elapsed = { elapsed },
            load = { if (readable) stored else throw IllegalStateException("keystore") },
            persist = { stored = it }
        )
        assertEquals(wall, clock.now())

        readable = true
        pass(minute)
        assertEquals("picked up once the store reads again", stored, clock.now())
    }
}
