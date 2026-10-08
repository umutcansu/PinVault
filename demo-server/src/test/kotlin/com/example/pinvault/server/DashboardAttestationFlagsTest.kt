package com.example.pinvault.server

import com.example.pinvault.server.service.attestation.AttestationFlag
import com.example.pinvault.server.service.attestation.AttestationPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The dashboard's policy table must know every flag the server can raise: a
 * flag missing from `ATTEST_FLAGS` cannot be set from the panel (and a PUT
 * from it would keep the server default silently), one without a help text
 * shows its raw name, and a `strict` preset that differs from the server's
 * makes "reset to strict" mean something else in the panel.
 */
class DashboardAttestationFlagsTest {

    private fun script(name: String): String =
        javaClass.classLoader.getResource("static/js/$name")?.readText() ?: fail("static/js/$name is not on the classpath")

    private val attestation by lazy { script("app-attestation.js") }

    @Test
    fun `every server flag is in the policy table, in the server's order`() {
        val list = Regex("const ATTEST_FLAGS = \\[(.*?)\\];", RegexOption.DOT_MATCHES_ALL).find(attestation)?.groupValues?.get(1)
            ?: fail("ATTEST_FLAGS not found")
        val flags = Regex("'([a-z_]+)'").findAll(list).map { it.groupValues[1] }.toList()
        assertEquals(AttestationFlag.names, flags)
    }

    @Test
    fun `the strict preset is the server's strict table`() {
        val block = Regex("strict: \\{(.*?)\\}", RegexOption.DOT_MATCHES_ALL).find(attestation)?.groupValues?.get(1)
            ?: fail("ATTEST_PRESETS.strict not found")
        val preset = Regex("([a-z_]+): '([a-z]+)'").findAll(block).associate { it.groupValues[1] to it.groupValues[2] }
        assertEquals(AttestationPolicy.STRICT_FLAGS, preset)
    }

    @Test
    fun `every flag has a help text in both languages`() {
        val i18n = script("app-i18n.js")
        for (flag in AttestationFlag.names) {
            assertEquals(2, Regex("\\battHelp_$flag:").findAll(i18n).count(), "attHelp_$flag needs a text in both languages")
        }
        for (key in listOf("attKeyBootloader", "attKeyBoot", "attKeyPatch", "attLocked", "attUnlocked", "attFactsHint")) {
            assertTrue(Regex("\\b$key:").findAll(i18n).count() == 2, "$key needs a text in both languages")
        }
    }
}
