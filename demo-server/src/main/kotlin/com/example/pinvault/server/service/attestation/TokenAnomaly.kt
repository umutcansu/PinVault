package com.example.pinvault.server.service.attestation

/**
 * How one device's tokens are used (ATTESTATION.md §5.2): per device, in
 * fixed windows of [windowSeconds], the number of requests and of distinct
 * client addresses. A phone makes requests from one address at a time (a
 * handful as it moves between networks) and at a human pace; a token lifted
 * to a fleet of bots, or a rooted phone signing proofs for others, shows up
 * as many addresses or a request rate no person makes.
 *
 * Bounded: at most [capacity] devices are tracked (the least recently seen
 * is dropped) and at most [maxAddresses] + 1 addresses per device.
 */
class TokenAnomalyDetector(
    val windowSeconds: Long = DEFAULT_WINDOW_SECONDS,
    val maxAddresses: Int = DEFAULT_MAX_ADDRESSES,
    val maxRequests: Int = DEFAULT_MAX_REQUESTS,
    private val capacity: Int = 100_000,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 }
) {
    init {
        require(windowSeconds in 60..86_400) { "window must be 60–86400 s" }
        require(maxAddresses in 1..1000) { "maxAddresses must be 1–1000" }
        require(maxRequests in 1..1_000_000) { "maxRequests must be 1–1000000" }
    }

    /** What was seen in the window that crossed a limit: [kind] `addresses` or `requests`. */
    data class Anomaly(val kind: String, val addresses: Int, val requests: Int, val windowSeconds: Long, val windowEndsAt: Long)

    private class Window(val start: Long) {
        val addresses = HashSet<String>()
        var requests = 0
        var reported = false
    }

    private val windows = object : LinkedHashMap<String, Window>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Window>?) = size > capacity
    }

    /**
     * Counts one request of [device] from [address]. Returns the anomaly the
     * first time a limit is crossed in the current window, null otherwise.
     */
    @Synchronized
    fun observe(device: String, address: String): Anomaly? {
        val now = clock()
        val window = windows[device]?.takeIf { now - it.start < windowSeconds } ?: Window(now).also { windows[device] = it }
        if (window.addresses.size <= maxAddresses) window.addresses += address
        window.requests++
        if (window.reported) return null
        val kind = when {
            window.addresses.size > maxAddresses -> "addresses"
            window.requests > maxRequests -> "requests"
            else -> return null
        }
        window.reported = true
        return Anomaly(kind, window.addresses.size, window.requests, windowSeconds, window.start + windowSeconds)
    }

    /** When the window in which [device] crossed a limit ends; null when it has not in the current one. */
    @Synchronized
    fun flaggedUntil(device: String): Long? {
        val window = windows[device] ?: return null
        val end = window.start + windowSeconds
        return end.takeIf { window.reported && clock() < it }
    }

    companion object {
        const val DEFAULT_WINDOW_SECONDS = 600L
        const val DEFAULT_MAX_ADDRESSES = 8
        /** Two requests a second for ten minutes, every second. */
        const val DEFAULT_MAX_REQUESTS = 1200
    }
}

/** What the reference verifier does when a device's tokens cross a limit. */
enum class TokenAnomalyAction {
    /** Report it ([com.example.pinvault.server.plugin.PinVaultTokenAuthConfig.onAnomaly]) and serve the request. */
    WARN,
    /** Report it, and refuse the device's requests (`429 token_anomaly`) until the window ends. */
    REFUSE
}
