package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.service.ExactQuery
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Review 2026-11-14 (S1): the approval card and the handler read the query
 * string with different parsers. On a real socket (Netty) — a test
 * application's engine reads both sides with one parser and never showed it —
 * `?ConfigApiId=staging` got a card for scope `staging` and rewrote
 * `default-tls`; a query that began with 1000 `&` did the reverse.
 */
class ApprovalQueryReadingTest {

    private val pinA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val pinB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
    private fun body(host: String) = """{"pins":[{"hostname":"$host","sha256":["$pinA","$pinB"],"version":1}]}"""
    private fun dir(): File = Files.createTempDirectory("approval-query").toFile()

    @Test
    fun `a scope parameter spelled in another case is no scope - for the card and for the write`() {
        GovernanceHarness(dir()).use { h ->
            h.pins.save(h.scope, h.pins.load(h.scope).copy(pins = listOf(HostPin("bank.example.com", listOf(pinA, pinB), version = 1))))

            val pending = h.call("PUT", "/api/v1/certificate-config?ConfigApiId=staging", ALICE, body("other.example.com"))
            assertEquals(202, pending.status, pending.body)
            assertEquals("default-tls", h.changeRequest(pending.changeRequestId).configApiId, "the card names the scope that is written")

            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertEquals(listOf("other.example.com"), h.pins.load("default-tls").pins.map { it.hostname })
            assertNull(h.pinsOf("other.example.com", "staging"))
        }
    }

    @Test
    fun `the scope on the card is the scope that is written`() {
        GovernanceHarness(dir()).use { h ->
            val pending = h.call("PUT", "/api/v1/certificate-config?configApiId=staging", ALICE, body("other.example.com"))
            assertEquals(202, pending.status, pending.body)
            assertEquals("staging", h.changeRequest(pending.changeRequestId).configApiId)
            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertEquals(listOf("other.example.com"), h.pins.load("staging").pins.map { it.hostname })
            assertEquals(emptyList(), h.pins.load("default-tls").pins)
        }
    }

    @Test
    fun `padding and a second spelling hide nothing - the card names the scope that is written`() {
        GovernanceHarness(dir()).use { h ->
            h.pins.save("prod-mtls", h.pins.load("prod-mtls").copy(pins = listOf(HostPin("bank.example.com", listOf(pinA, pinB), version = 1))))
            // Empty parameters in front (past the limit of the parser the card used to
            // use) hide nothing: the card names the scope the handler will write.
            val padded = h.call("PUT", "/api/v1/certificate-config?" + "&".repeat(1000) + "configApiId=prod-mtls", ALICE, body("other.example.com"))
            assertEquals(202, padded.status, padded.body.take(300))
            assertEquals("prod-mtls", h.changeRequest(padded.changeRequestId).configApiId)

            // One name in two spellings: two parameters, and only the exact one counts.
            val twice = h.call("PUT", "/api/v1/certificate-config?configApiId=staging&ConfigApiId=prod-mtls", ALICE, body("other.example.com"))
            assertEquals(202, twice.status, twice.body.take(300))
            assertEquals("staging", h.changeRequest(twice.changeRequestId).configApiId)

            // Neither was approved yet.
            assertEquals(listOf("bank.example.com"), h.pins.load("prod-mtls").pins.map { it.hostname }, "nothing was written")
            assertEquals(emptyList(), h.pins.load("default-tls").pins)
        }
    }

    @Test
    fun `one reading of a query - exact names, first value, empty parts skipped`() {
        val q = ExactQuery.parse("&&a=1&A=2&a=3&b&c=x%20y+z&=lost")
        assertEquals("1", q["a"])
        assertEquals("2", q["A"])
        assertEquals("", q["b"])
        assertEquals("x y z", q["c"])
        assertNull(q["d"])
        assertEquals(setOf("a", "A", "b", "c"), q.entries().keys)
        assertFailsWith<ExactQuery.MalformedQuery> { ExactQuery.parse("a=%zz") }
    }
}
