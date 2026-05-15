package io.github.umutcansu.pinvault.ssl

import org.junit.Assert.*
import org.junit.Test

/**
 * H-01 regression coverage. The pre-V2 trust manager merged every host's pin
 * hashes into a single set, silently accepting any pinned hash on any host.
 * These tests lock down the per-host scoping rules so a refactor cannot
 * quietly re-open the cross-host pin-reuse hole.
 */
class PinHostMatcherTest {

    private val bankPins = setOf("BANK_PIN_1", "BANK_PIN_2")
    private val analyticsPins = setOf("ANALYTICS_PIN_1", "ANALYTICS_PIN_2")

    private val pinMap = PinHostMatcher.build(
        listOf(
            "bank.example.com" to bankPins,
            "analytics.example.com" to analyticsPins
        )
    )

    @Test
    fun `exact hostname returns that host's pins`() {
        assertEquals(bankPins, PinHostMatcher.match(pinMap, "bank.example.com"))
        assertEquals(analyticsPins, PinHostMatcher.match(pinMap, "analytics.example.com"))
    }

    @Test
    fun `pins from one host never match a different host (H-01)`() {
        // The bank entry must not accept analytics-only pins, and vice versa.
        val matched = PinHostMatcher.match(pinMap, "bank.example.com")
        assertTrue("bank lookup must not leak analytics pins",
            matched != null && matched.intersect(analyticsPins).isEmpty())
    }

    @Test
    fun `unknown hostname returns null (fail-safe)`() {
        assertNull(PinHostMatcher.match(pinMap, "unknown.example.com"))
        assertNull(PinHostMatcher.match(pinMap, "evil.com"))
    }

    @Test
    fun `hostname matching is case-insensitive`() {
        assertEquals(bankPins, PinHostMatcher.match(pinMap, "BANK.example.com"))
        assertEquals(bankPins, PinHostMatcher.match(pinMap, "Bank.Example.COM"))
    }

    @Test
    fun `wildcard matches single sub-label`() {
        val wildcardMap = PinHostMatcher.build(
            listOf("*.example.com" to setOf("WILD_PIN_1", "WILD_PIN_2"))
        )
        assertEquals(setOf("WILD_PIN_1", "WILD_PIN_2"),
            PinHostMatcher.match(wildcardMap, "api.example.com"))
        assertEquals(setOf("WILD_PIN_1", "WILD_PIN_2"),
            PinHostMatcher.match(wildcardMap, "foo.example.com"))
    }

    @Test
    fun `wildcard does NOT match the bare apex`() {
        // *.example.com must not match example.com — the wildcard requires
        // a single label. This is the RFC 6125 / OkHttp convention.
        val wildcardMap = PinHostMatcher.build(
            listOf("*.example.com" to setOf("WILD"))
        )
        assertNull(PinHostMatcher.match(wildcardMap, "example.com"))
    }

    @Test
    fun `wildcard does NOT match multi-label sub-domain`() {
        // *.example.com matches `api.example.com` but NOT `a.b.example.com`.
        val wildcardMap = PinHostMatcher.build(
            listOf("*.example.com" to setOf("WILD"))
        )
        assertNull(PinHostMatcher.match(wildcardMap, "a.b.example.com"))
    }

    @Test
    fun `exact entry wins over wildcard entry`() {
        val mixedMap = PinHostMatcher.build(
            listOf(
                "*.example.com" to setOf("WILD"),
                "api.example.com" to setOf("EXACT")
            )
        )
        assertEquals(setOf("EXACT"), PinHostMatcher.match(mixedMap, "api.example.com"))
    }

    @Test
    fun `empty map matches nothing`() {
        val empty = PinHostMatcher.build(emptyList())
        assertNull(PinHostMatcher.match(empty, "anything.com"))
    }

    @Test
    fun `TLD-level wildcard is refused — single-label suffix`() {
        // *.com would otherwise authorize every .com host via a single
        // misconfigured pin entry, re-opening H-01 across the entire TLD.
        val tldMap = PinHostMatcher.build(
            listOf("*.com" to setOf("PIN_FOR_STAR_COM"))
        )
        assertNull(
            "*.com must not match any host — defense against TLD-wide pin reuse",
            PinHostMatcher.match(tldMap, "example.com")
        )
        assertNull(PinHostMatcher.match(tldMap, "anything.com"))
    }

    @Test
    fun `narrow wildcard still works — two-label suffix`() {
        // Sanity: the TLD guard must not break legitimate `*.example.com`
        // patterns.
        val narrowMap = PinHostMatcher.build(
            listOf("*.example.com" to setOf("PIN_NARROW"))
        )
        assertEquals(setOf("PIN_NARROW"), PinHostMatcher.match(narrowMap, "api.example.com"))
    }
}
