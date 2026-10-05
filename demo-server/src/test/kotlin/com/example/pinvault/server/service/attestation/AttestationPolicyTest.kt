package com.example.pinvault.server.service.attestation

import com.example.pinvault.server.store.AttestationPolicyStore
import com.example.pinvault.server.store.DatabaseManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AttestationPolicyTest {

    @Test
    fun `strict and lenient defaults`() {
        val strict = AttestationPolicy.strict()
        assertEquals(0, strict.version)
        assertEquals(AttestationFlag.names.toSet(), strict.flags.keys, "every flag has an action")
        for (flag in listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner")) {
            assertEquals("reject", strict.flags[flag], flag)
        }
        for (flag in listOf("unknown_installer", "software_key", "key_unattested", "old_patch_level")) assertEquals("warn", strict.flags[flag], flag)
        assertEquals("ignore", strict.flags["adb_enabled"])
        assertFalse(strict.revealReasons)
        assertEquals(300, strict.tokenTtlSeconds)
        assertEquals(300, strict.attestIntervalSeconds)

        val lenient = AttestationPolicy.lenient(revealReasons = true, tokenTtlSeconds = 120, attestIntervalSeconds = 600)
        assertTrue(lenient.flags.values.all { it == "warn" })
        assertTrue(lenient.revealReasons)
        assertEquals(120, lenient.tokenTtlSeconds)
        assertEquals(600, lenient.attestIntervalSeconds)

        val env = AttestationPolicyDefaults.fromEnv(mapOf("ATTESTATION_POLICY_DEFAULT" to "lenient", "ATTESTATION_TOKEN_TTL_SECONDS" to "90",
            "ATTESTATION_INTERVAL_SECONDS" to "100000", "ATTESTATION_REVEAL_REASONS" to "true"))
        assertEquals(AttestationPolicy.LENIENT_FLAGS, env.policy.flags)
        assertEquals(90, env.policy.tokenTtlSeconds)
        assertEquals(86_400, env.policy.attestIntervalSeconds, "coerced into range")
        assertTrue(env.policy.revealReasons)
        assertEquals("strict", AttestationPolicyDefaults.fromEnv(emptyMap()).profile)
    }

    @Test
    fun `JSON round trip and partial PUT`() {
        val strict = AttestationPolicy.strict()
        val text = strict.toJson()
        val obj = Json.parseToJsonElement(text).jsonObject
        assertEquals("reject", obj["flags"]!!.jsonObject["rooted"]!!.jsonPrimitive.content)
        assertEquals(strict, AttestationPolicy.fromStored(text, 0, AttestationPolicy.lenient()))

        val put = AttestationPolicy.parse("""{"flags":{"adb_enabled":"warn","rooted":"warn"},"revealReasons":true,"tokenTtlSeconds":120}""", strict).getOrThrow()
        assertEquals("warn", put.flags["adb_enabled"])
        assertEquals("warn", put.flags["rooted"])
        assertEquals("reject", put.flags["emulator"], "untouched flags keep their action")
        assertTrue(put.revealReasons)
        assertEquals(120, put.tokenTtlSeconds)
        assertEquals(300, put.attestIntervalSeconds)

        // A stored row from an older server that knows fewer flags: the defaults fill the rest.
        val older = AttestationPolicy.fromStored("""{"flags":{"rooted":"ignore"},"revealReasons":false}""", 4, strict)
        assertEquals(4, older.version)
        assertEquals("ignore", older.flags["rooted"])
        assertEquals("reject", older.flags["emulator"])
        assertEquals(AttestationFlag.names.toSet(), older.flags.keys)
    }

    @Test
    fun `invalid PUT bodies`() {
        val strict = AttestationPolicy.strict()
        for (bad in listOf(
            """{"flags":{"jailbroken":"reject"}}""", """{"flags":{"rooted":"maybe"}}""", """{"flags":["rooted"]}""",
            """{"revealReasons":"yes"}""", """{"tokenTtlSeconds":5}""", """{"attestIntervalSeconds":10}""", """[1]""", "not json"
        )) assertTrue(AttestationPolicy.parse(bad, strict).isFailure, bad)
    }

    @Test
    fun `the store bumps the version on every PUT and returns defaults when nothing is stored`() {
        val dir = kotlin.io.path.createTempDirectory("pinvault-policy-").toFile()
        try {
            val store = AttestationPolicyStore(DatabaseManager(File(dir, "db.sqlite").absolutePath))
            val defaults = AttestationPolicy.strict()
            assertNull(store.get("default-tls", defaults))
            assertEquals(defaults, store.effective("default-tls", defaults))

            val v1 = store.put("default-tls", defaults.copy(revealReasons = true), "alice")
            assertEquals(1, v1.version)
            val v2 = store.put("default-tls", v1.copy(flags = v1.flags + ("rooted" to "warn")), "alice")
            assertEquals(2, v2.version)
            assertEquals("warn", store.get("default-tls", defaults)!!.flags["rooted"])
            assertTrue(store.get("default-tls", defaults)!!.revealReasons)
            // Another scope is untouched.
            assertEquals(defaults, store.effective("other", defaults))
            assertTrue(store.delete("default-tls"))
            assertNull(store.get("default-tls", defaults))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `key policy parsing and the start-up check`() {
        assertEquals(AttestationKeyPolicy.WARN, AttestationKeyPolicy.parse(null))
        assertEquals(AttestationKeyPolicy.ENFORCE, AttestationKeyPolicy.parse(" Enforce "))
        assertEquals(AttestationKeyPolicy.OFF, AttestationKeyPolicy.parse("off"))
        assertTrue(runCatching { AttestationKeyPolicy.parse("strict") }.isFailure)

        val pki = com.example.pinvault.server.service.TestAttestationChains.Pki()
        assertNull(AttestationKeyPolicy.startupCheck(AttestationKeyPolicy.ENFORCE, pki.verifier()))
        val unbound = pki.verifier(packageNames = emptySet(), signerDigests = emptySet())
        assertNull(AttestationKeyPolicy.startupCheck(AttestationKeyPolicy.OFF, unbound))
        assertTrue(AttestationKeyPolicy.startupCheck(AttestationKeyPolicy.WARN, unbound)!!.contains("ATTESTATION_PACKAGE_NAMES"))
        assertTrue(runCatching { AttestationKeyPolicy.startupCheck(AttestationKeyPolicy.ENFORCE, unbound) }.isFailure, "enforce without the binding does not start")
    }
}
