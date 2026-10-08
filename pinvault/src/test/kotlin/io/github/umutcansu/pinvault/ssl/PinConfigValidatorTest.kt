package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InvalidPinFormatException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * What a pin config may contain: host names that are host names, pins that
 * are SHA-256 hashes. One bad entry refuses the whole config.
 */
class PinConfigValidatorTest {

    private val pinA = "A".repeat(43) + "="
    private val pinB = "B".repeat(43) + "="

    private fun config(vararg hosts: String) =
        CertificateConfig(version = 1, pins = hosts.map { HostPin(it, listOf(pinA, pinB), version = 1) })

    private fun assertRefused(config: CertificateConfig, expected: String) {
        try {
            PinConfigValidator.validate(config)
            fail("the config should have been refused")
        } catch (e: InvalidPinFormatException) {
            assertTrue(e.message, e.message!!.contains(expected))
        }
    }

    @Test
    fun `plain names, wildcards, ports and IPv4 addresses are accepted`() {
        listOf(
            "api.example.com", "API.Example.COM", "localhost", "xn--mnchen-3ya.de", "a-b.example.com",
            "*.example.com", "*.cdn.example.co.uk", "api.example.com:8443", "*.example.com:443",
            "192.168.1.10", "192.168.1.10:8091", "host:1", "host:65535"
        ).forEach { assertNull(it, PinConfigValidator.hostPatternError(it)) }
        PinConfigValidator.validate(config("api.example.com", "*.example.com", "192.168.1.10:8091"))
    }

    @Test
    fun `names that carry the old store's separators are refused`() {
        // Each of these was written to disk as one entry and read back as another.
        listOf(
            "api.bank.com|9|${pinA},${pinB}|false\nx",
            "api.bank.com=2147483647\nx",
            "api.bank.com,evil.com",
            "api.bank.com\n",
            "api.bank.com evil.com"
        ).forEach { assertNotNull(it, PinConfigValidator.hostPatternError(it)) }
        assertRefused(config("ok.example.com", "api.bank.com|9|x"), "not a host name")
    }

    @Test
    fun `malformed names are refused`() {
        listOf(
            "", ".", "example..com", "example.com.", ".example.com", "-a.example.com", "a-.example.com",
            "exa_mple.com", "exam ple.com", "https://example.com", "example.com/path", "a".repeat(64) + ".com",
            (List(64) { "abc" }.joinToString(".")), // 255 characters
            "*", "*example.com", "a.*.example.com", "*.*.example.com", "**.example.com",
            "example.com:0", "example.com:65536", "example.com:", "example.com:80a", "example.com:0443",
            "[::1]", "::1"
        ).forEach { assertNotNull("'$it' should be refused", PinConfigValidator.hostPatternError(it)) }
    }

    @Test
    fun `a wildcard over a public suffix or an address is refused`() {
        listOf("*.com", "*.tr", "*.co.uk", "*.com.tr", "*.github.io", "*.1.80", "*.168.1.80").forEach {
            assertNotNull(it, PinConfigValidator.hostPatternError(it))
        }
        assertRefused(config("*.com"), "public suffix")
    }

    @Test
    fun `the length limit is 253 without the port`() {
        val name = (List(63) { "abc" }.joinToString(".")) + ".a" // 253
        assertEquals(253, name.length)
        assertNull(PinConfigValidator.hostPatternError(name))
        assertNull(PinConfigValidator.hostPatternError("$name:443"))
        assertNotNull(PinConfigValidator.hostPatternError(name + "b"))
    }

    @Test
    fun `pins must be the Base64 of a SHA-256`() {
        assertNull(PinConfigValidator.pinError(pinA))
        assertNull(PinConfigValidator.pinError("ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM="))
        listOf(null, "", " ", "short", "A".repeat(44), "A".repeat(42) + "==", "A".repeat(43) + "\n", "A".repeat(42) + ",=", "A".repeat(42) + "|=")
            .forEach { assertNotNull("'$it'", PinConfigValidator.pinError(it)) }

        assertRefused(CertificateConfig(pins = listOf(HostPin("a.example.com", listOf(pinA, "not-a-pin")))), "Hash at index 1")
    }

    @Test
    fun `the same pin listed twice does not count as a backup`() {
        assertRefused(
            CertificateConfig(version = 1, pins = listOf(HostPin("api.example.com", listOf(pinA, pinA), version = 1))),
            "2 different pins"
        )
        // Two different pins plus a repeat of one of them is fine.
        PinConfigValidator.validate(
            CertificateConfig(version = 1, pins = listOf(HostPin("api.example.com", listOf(pinA, pinB, pinA), version = 1)))
        )
    }

    @Test
    fun `an empty config, a duplicate host and a negative version are refused`() {
        assertRefused(CertificateConfig(pins = emptyList()), "at least one pin entry")
        assertRefused(config("a.example.com", "A.example.com"), "more than once")
        assertRefused(CertificateConfig(pins = listOf(HostPin("a.example.com", listOf(pinA, pinB), version = -1))), "negative version")
    }

    @Test
    fun `what Gson leaves null is refused, not dereferenced`() {
        val gson = com.google.gson.Gson()
        listOf(
            """{"version":1}""",
            """{"pins":[null]}""",
            """{"pins":[{"sha256":["$pinA","$pinB"]}]}""",
            """{"pins":[{"hostname":"a.example.com"}]}""",
            """{"pins":[{"hostname":"a.example.com","sha256":["$pinA",null]}]}""",
            """{"pins":[{"hostname":"a.example.com","sha256":["$pinA"]}]}"""
        ).forEach { json ->
            try {
                PinConfigValidator.validate(gson.fromJson(json, CertificateConfig::class.java))
                fail("should have been refused: $json")
            } catch (e: InvalidPinFormatException) {
                // expected
            }
        }
    }
}
