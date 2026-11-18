package io.github.umutcansu.pinvault.ssl

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The host-name, pin and host-matching decisions every implementation must
 * share, from ONE file: `pinvault-ios/Tests/PinVaultTests/Fixtures/parity/host-rules.json`.
 * The iOS library (`HostRulesParityTests`) and the server (`HostRulesParityTest`)
 * read the same file. A rule one platform applies and another does not is a
 * config that one fleet accepts and the other refuses — or, worse, a host one
 * of them pins and the other does not (review 2026-11-17).
 */
class HostRulesParityTest {

    private val vectors: JsonObject by lazy {
        val file = File("../pinvault-ios/Tests/PinVaultTests/Fixtures/parity/host-rules.json")
        assertTrue("run from the pinvault module directory (${file.absolutePath})", file.isFile)
        JsonParser.parseString(file.readText(Charsets.UTF_8)).asJsonObject
    }

    private fun check(mismatches: List<String>) =
        assertTrue("differs from host-rules.json:\n" + mismatches.joinToString("\n"), mismatches.isEmpty())

    @Test
    fun `host patterns are accepted and refused as the shared vectors say`() {
        check(vectors.getAsJsonArray("hostPatterns").mapNotNull { v ->
            val pattern = v.asJsonObject["pattern"].asString
            val expected = v.asJsonObject["valid"].asBoolean
            val actual = PinConfigValidator.hostPatternError(pattern) == null
            if (actual == expected) null else "pattern ${JsonParser.parseString(v.toString()).asJsonObject["pattern"]}: expected valid=$expected, got $actual"
        })
    }

    @Test
    fun `pins are accepted and refused as the shared vectors say`() {
        check(vectors.getAsJsonArray("pins").mapNotNull { v ->
            val pin = v.asJsonObject["pin"].asString
            val expected = v.asJsonObject["valid"].asBoolean
            val actual = PinConfigValidator.pinError(pin) == null
            if (actual == expected) null else "pin ${v.asJsonObject["pin"]}: expected valid=$expected, got $actual"
        })
    }

    @Test
    fun `a host is matched to the entry the shared vectors name`() {
        check(vectors.getAsJsonArray("matching").mapNotNull { v ->
            val o = v.asJsonObject
            val entries = o.getAsJsonArray("entries").map { it.asString }
            // Each entry maps to its own (lower-cased) name, so the answer says which entry matched.
            val map = PinHostMatcher.build(entries.map { it to setOf(it.lowercase()) })
            val port = o["port"].takeUnless { it.isJsonNull }?.asInt
            val expected = o["match"].takeUnless { it.isJsonNull }?.asString
            val actual = PinHostMatcher.match(map, o["host"].asString, port)?.single()
            if (actual == expected) null else "$o: got $actual"
        })
    }
}
