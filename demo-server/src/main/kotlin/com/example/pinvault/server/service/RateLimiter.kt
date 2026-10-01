package com.example.pinvault.server.service

import java.util.concurrent.ConcurrentHashMap

/**
 * A fixed-window counter for device endpoints that ask for no API key. The
 * certificate renewal endpoint counts per source and client id: a source that
 * keeps sending requests that fail the CSR check is cut off for the rest of
 * the window. E2E key registration over TLS counts the keys a source address
 * writes. Memory is bounded by [maxKeys], after which the oldest window is
 * dropped.
 */
class RateLimiter(
    private val maxAttempts: Int = 10,
    private val windowMs: Long = 10 * 60_000,
    private val maxKeys: Int = 10_000,
    private val clock: () -> Long = System::currentTimeMillis
) {
    private class Window(val start: Long, var count: Int)

    private val windows = ConcurrentHashMap<String, Window>()

    /** Counts one attempt for [key] and says whether it may proceed. */
    @Synchronized
    fun allow(key: String): Boolean {
        val now = clock()
        val current = windows[key]
        val window = if (current == null || now - current.start >= windowMs) {
            if (windows.size >= maxKeys) windows.remove(windows.keys.first())
            Window(now, 0).also { windows[key] = it }
        } else current
        window.count++
        return window.count <= maxAttempts
    }
}
