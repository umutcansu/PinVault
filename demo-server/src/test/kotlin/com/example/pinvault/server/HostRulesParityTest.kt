package com.example.pinvault.server

import com.example.pinvault.server.service.HostPatternRules
import com.example.pinvault.server.service.PinConfigRules
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The server's intake rules against the vectors the Android and iOS libraries
 * are held to (`pinvault-ios/Tests/PinVaultTests/Fixtures/parity/host-rules.json`):
 * a host name or pin the server stores and a device refuses takes the whole
 * config down on that device; one the server refuses and a device would take
 * is a rule that exists on one side only.
 */
class HostRulesParityTest {

    private val vectors by lazy {
        val file = File("../pinvault-ios/Tests/PinVaultTests/Fixtures/parity/host-rules.json")
        assertTrue(file.isFile, "run from the demo-server directory (${file.absolutePath})")
        Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
    }

    @Test
    fun `host patterns are accepted and refused as the shared vectors say`() {
        val mismatches = vectors["hostPatterns"]!!.jsonArray.mapNotNull { v ->
            val expected = v.jsonObject["valid"]!!.jsonPrimitive.boolean
            val actual = HostPatternRules.error(v.jsonObject["pattern"]!!.jsonPrimitive.content) == null
            if (actual == expected) null else "pattern ${v.jsonObject["pattern"]}: expected valid=$expected, got $actual"
        }
        assertTrue(mismatches.isEmpty(), "differs from host-rules.json:\n" + mismatches.joinToString("\n"))
    }

    @Test
    fun `pins are accepted and refused as the shared vectors say`() {
        val mismatches = vectors["pins"]!!.jsonArray.mapNotNull { v ->
            val expected = v.jsonObject["valid"]!!.jsonPrimitive.boolean
            val actual = PinConfigRules.pinError(v.jsonObject["pin"]!!.jsonPrimitive.content) == null
            if (actual == expected) null else "pin ${v.jsonObject["pin"]}: expected valid=$expected, got $actual"
        }
        assertTrue(mismatches.isEmpty(), "differs from host-rules.json:\n" + mismatches.joinToString("\n"))
    }
}
