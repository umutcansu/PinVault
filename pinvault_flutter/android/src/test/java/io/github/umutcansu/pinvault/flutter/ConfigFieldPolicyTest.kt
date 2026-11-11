package io.github.umutcansu.pinvault.flutter

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Review 2026-11-12: a field the parser reads was Dart's to set unless someone
 * remembered to add a release rule for it. Every key `ConfigParser.parse`
 * asks for must now be classified in [ConfigFieldPolicy] — a new key without
 * a decision, or a decision for a key no longer read, fails here.
 */
class ConfigFieldPolicyTest {

    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    private val pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    private val pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="

    @After
    fun tearDown() { Fields.readHook = null }

    /** Every nested object present once, so every key path is asked for. */
    private val everyObject = """
        {"configApis":[{"id":"default","url":"https://h.example:8081/",
            "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],
            "signaturePublicKey":"$key","attestationInterval":{"amount":10,"unit":"MINUTES"}}],
         "vaultFiles":[{"key":"flags","endpoint":"api/v1/vault/flags","maxOfflineAge":{"amount":1,"unit":"DAYS"}}],
         "staticPins":{"pins":[{"hostname":"s.example","sha256":["$pinA","$pinB"]}]},
         "expiredConfigGrace":{"amount":0,"unit":"SECONDS"},
         "vaultFileMaxOfflineAge":{"amount":1,"unit":"DAYS"},
         "environmentGuard":{},
         "android":{},
         "ios":{}}
    """.trimIndent()

    private fun keysRead(): Set<String> {
        val read = sortedSetOf<String>()
        Fields.readHook = { path, key -> read += "${path.replace(Regex("\\[\\d+]"), "[]")}.$key" }
        ConfigParser.parse(everyObject, VaultTokenStore(), { EnvironmentGuard { true } }, null)
        Fields.readHook = null
        return read
    }

    @Test fun `every key the parser reads has a release policy, and every policy names a key it reads`() {
        val read = keysRead()
        val classified = ConfigFieldPolicy.POLICY.keys
        assertEquals("keys read but not classified in ConfigFieldPolicy.POLICY", emptySet<String>(), read - classified)
        assertEquals("ConfigFieldPolicy.POLICY names keys the parser no longer reads", emptySet<String>(), classified - read)
    }
}
