package com.example.pinvault.server.service

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Runs a listener restart at most once per [minIntervalMs], however often it
 * is asked for.
 *
 * Every server-made P12 enrollment adds a certificate to the client
 * truststore, and the mTLS listeners read that file only when they start — so
 * each enrollment restarted every mTLS Config API and every mock mTLS host,
 * inside the request. Whoever held a handful of enrollment tokens could keep
 * those listeners down for every other device by using them one after
 * another.
 *
 * Now: a request that finds nothing running and the interval elapsed runs the
 * restart at once, on the caller's thread, as before (the enrolling device
 * finds its certificate trusted when the answer arrives). Requests during a
 * restart, or within [minIntervalMs] of the last one, are folded into ONE
 * restart that runs when the interval is over — it reads the truststore as it
 * is then, so it covers all of them. Listeners are therefore up for at least
 * [minIntervalMs] between two restarts, and never restarted twice at once.
 */
class CoalescedRestart(
    private val minIntervalMs: Long = 5_000,
    private val clock: () -> Long = System::currentTimeMillis,
    /** Runs [task] after `delayMs`; the default is one daemon thread. */
    private val schedule: (delayMs: Long, task: () -> Unit) -> Unit = defaultSchedule,
    private val restart: (reason: String) -> Unit
) {
    private val lock = Any()
    private var running = false
    private var scheduled = false
    private var lastFinished: Long? = null
    /** Why the restart that is owed was asked for (the latest request's reason). */
    private var pending: String? = null

    /**
     * Asks for a restart because of [reason]. True when it ran before this
     * returned; false when it was folded into one that runs later.
     */
    fun request(reason: String): Boolean {
        synchronized(lock) {
            val last = lastFinished
            val wait = if (last == null) 0 else minIntervalMs - (clock() - last)
            if (running || scheduled || wait > 0) {
                pending = reason
                // During a restart nothing is scheduled here: run() does it when it finishes.
                if (!running && !scheduled) scheduleLocked(wait)
                return false
            }
            running = true
        }
        run(reason)
        return true
    }

    private fun run(reason: String) {
        try {
            restart(reason)
        } finally {
            synchronized(lock) {
                running = false
                lastFinished = clock()
                if (pending != null && !scheduled) scheduleLocked(minIntervalMs)
            }
        }
    }

    private fun scheduleLocked(delayMs: Long) {
        scheduled = true
        schedule(delayMs.coerceAtLeast(0)) {
            val reason = synchronized(lock) {
                scheduled = false
                val owed = pending
                pending = null
                if (owed != null) running = true
                owed
            }
            if (reason != null) run(reason)
        }
    }

    private companion object {
        private val executor by lazy {
            Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "coalesced-restart").apply { isDaemon = true } }
        }
        val defaultSchedule: (Long, () -> Unit) -> Unit = { delayMs, task ->
            executor.schedule({
                try { task() } catch (e: Exception) { System.err.println("Coalesced restart failed: ${e.message}") }
            }, delayMs, TimeUnit.MILLISECONDS)
        }
    }
}
