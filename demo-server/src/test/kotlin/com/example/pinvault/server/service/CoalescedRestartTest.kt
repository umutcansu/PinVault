package com.example.pinvault.server.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Repeated requests for a listener restart become one restart per interval:
 * a run of P12 enrollments cannot keep the mTLS listeners down.
 */
class CoalescedRestartTest {

    private var now = 1_000_000L
    private val restarts = mutableListOf<String>()
    private val scheduled = mutableListOf<Pair<Long, () -> Unit>>()

    private fun coalescer(minIntervalMs: Long = 5_000, onRestart: (String) -> Unit = {}) = CoalescedRestart(
        minIntervalMs = minIntervalMs,
        clock = { now },
        schedule = { delay, task -> scheduled += (now + delay) to task },
        restart = { reason -> restarts += reason; onRestart(reason) }
    )

    /** Moves the clock and runs what came due, in order. */
    private fun advance(ms: Long) {
        now += ms
        while (true) {
            val due = scheduled.filter { it.first <= now }.minByOrNull { it.first } ?: return
            scheduled.remove(due)
            due.second()
        }
    }

    @Test
    fun `the first request restarts at once, on the caller's thread`() {
        val restart = coalescer()
        assertTrue(restart.request("enrolled dev-1"))
        assertEquals(listOf("enrolled dev-1"), restarts)
        assertTrue(scheduled.isEmpty())
    }

    @Test
    fun `a burst within the interval becomes one more restart, when the interval is over`() {
        val restart = coalescer()
        assertTrue(restart.request("enrolled dev-1"))
        repeat(50) { assertFalse(restart.request("enrolled dev-${it + 2}")) }
        assertEquals(1, restarts.size, "nothing restarted during the burst")
        assertEquals(1, scheduled.size, "one restart is pending, not fifty")

        advance(4_999)
        assertEquals(1, restarts.size, "not before the interval is over")
        advance(1)
        assertEquals(listOf("enrolled dev-1", "enrolled dev-51"), restarts, "one restart covers the whole burst")
        assertTrue(scheduled.isEmpty())
    }

    @Test
    fun `requests keep arriving - listeners are still up for the whole interval between restarts`() {
        val times = mutableListOf<Long>()
        val restart = coalescer { times += now }
        // One enrollment every 100 ms for a minute.
        repeat(600) {
            restart.request("enrolled $it")
            advance(100)
        }
        assertTrue(restarts.size >= 12, "and the truststore is picked up every interval: ${restarts.size}")
        assertTrue(restarts.size <= 13, "at most one restart per 5 s: ${restarts.size}")
        assertTrue(times.zipWithNext().all { (a, b) -> b - a >= 5_000 }, "restarts at $times")
    }

    @Test
    fun `a quiet period later, a request restarts at once again`() {
        val restart = coalescer()
        restart.request("a")
        advance(5_000)
        assertTrue(restart.request("b"))
        assertEquals(listOf("a", "b"), restarts)
        assertTrue(scheduled.isEmpty())
    }

    @Test
    fun `a request during a restart is not lost and does not run a second one alongside`() {
        var inside = 0
        var maxInside = 0
        lateinit var restart: CoalescedRestart
        restart = coalescer { reason ->
            inside++
            maxInside = maxOf(maxInside, inside)
            // The truststore changes again while the listeners are restarting.
            if (reason == "first") assertFalse(restart.request("during"))
            inside--
        }
        assertTrue(restart.request("first"))
        assertEquals(listOf("first"), restarts)
        assertEquals(1, scheduled.size, "the request made during the restart is owed")
        advance(5_000)
        assertEquals(listOf("first", "during"), restarts)
        assertEquals(1, maxInside)
    }

    @Test
    fun `a restart that fails does not block the next one`() {
        var fail = true
        val restart = coalescer { if (fail) throw IllegalStateException("port in use") }
        runCatching { restart.request("a") }
        fail = false
        advance(5_000)
        assertTrue(restart.request("b"))
        assertEquals(listOf("a", "b"), restarts)
    }

    @Test
    fun `an interval of zero restarts every time`() {
        val restart = coalescer(minIntervalMs = 0)
        repeat(3) { assertTrue(restart.request("r$it")) }
        assertEquals(3, restarts.size)
    }
}
