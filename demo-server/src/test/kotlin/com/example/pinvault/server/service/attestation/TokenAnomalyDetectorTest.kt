package com.example.pinvault.server.service.attestation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Token anomalies (ATTESTATION.md §5.2): per device, addresses and requests per window. */
class TokenAnomalyDetectorTest {

    private var now = 1_000_000L
    private fun detector(maxAddresses: Int = 3, maxRequests: Int = 10, capacity: Int = 100) =
        TokenAnomalyDetector(windowSeconds = 600, maxAddresses = maxAddresses, maxRequests = maxRequests, capacity = capacity, clock = { now })

    @Test
    fun `too many addresses in a window is reported once`() {
        val d = detector()
        listOf("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.1").forEach { assertNull(d.observe("api:dev-1", it)) }
        val found = assertNotNull(d.observe("api:dev-1", "10.0.0.4"))
        assertEquals("addresses", found.kind)
        assertEquals(4, found.addresses)
        assertEquals(now + 600, found.windowEndsAt)
        assertNull(d.observe("api:dev-1", "10.0.0.5"), "once per window")
        assertEquals(now + 600, d.flaggedUntil("api:dev-1"))
        assertNull(d.flaggedUntil("api:dev-2"))
    }

    @Test
    fun `too many requests in a window is reported, a new window starts over`() {
        val d = detector()
        repeat(10) { assertNull(d.observe("api:dev-1", "10.0.0.1")) }
        assertEquals("requests", d.observe("api:dev-1", "10.0.0.1")!!.kind)
        now += 600
        assertNull(d.flaggedUntil("api:dev-1"), "the window ended")
        repeat(10) { assertNull(d.observe("api:dev-1", "10.0.0.1")) }
        assertNotNull(d.observe("api:dev-1", "10.0.0.1"))
    }

    @Test
    fun `devices are counted apart and the oldest is dropped past the capacity`() {
        val d = detector(maxRequests = 2, capacity = 2)
        d.observe("api:a", "x"); d.observe("api:a", "x")
        d.observe("api:b", "x"); d.observe("api:c", "x")
        // a was dropped: its count starts again.
        assertNull(d.observe("api:a", "x"))
        assertNull(d.observe("api:a", "x"))
        assertNotNull(d.observe("api:a", "x"))
    }
}
