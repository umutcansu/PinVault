package io.github.umutcansu.pinvault.flutter

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * The other half of [ConfigFieldPolicyTest]: a key classified NATIVE must be
 * refused when a release build's Dart sets it to something the native file did
 * not say. Every NATIVE key needs an example here (a new one fails until it
 * has one), and every example must be refused.
 */
class NativeFieldEnforcementTest {

    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    private val key2 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2B2nCnNnOqLbd9HnN0Bzh1n0yA0V1Z2tKm8bq6H1Z0lFv8yP0n0n8y0Ue7c3Hn2c9mQ3M6nYk0fJm5X3Qh9g=="
    private val pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    private val pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    private val evil = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    /** The file: anchors, addresses and one vault file; nothing relaxed, no static pins. */
    private val native = NativeSecurity.parse("""
        {"configApis":[{"id":"default","url":"https://h.example:8081/",
          "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],
          "signaturePublicKeys":["$key"],"requiredSignatures":1,"serverScope":"default-tls",
          "enrollmentUrl":"https://h.example:8081/","renewalUrl":"https://h.example:8093/",
          "tokenHosts":["h.example"],"clientCertHosts":["h.example:8092"],"healthEndpoint":"health"}],
         "require":{"requireUnlockedDevice":true},
         "vaultFiles":[{"key":"doc","signaturePublicKey":"$key","encryption":"END_TO_END","userAuth":"NONE"}]}
    """.trimIndent(), "assets/pinvault_security.json")

    private val otherPins = """[{"hostname":"h.example","sha256":["$evil","$pinB"]}]"""
    private val staticPins = """{"pins":[{"hostname":"s.example","sha256":["$pinA","$pinB"]}]}"""

    /** Where the JS fragment goes. */
    private enum class At { BLOCK, ROOT, VAULT, ANDROID }

    /** One release-build Dart value per NATIVE key that the file did not give. */
    private val examples: Map<String, Pair<At, String>> = buildMap {
        val api = "config.configApis[]"
        put("$api.url", At.BLOCK to """"url":"https://evil.example/"""")
        put("$api.enrollmentUrl", At.BLOCK to """"enrollmentUrl":"https://evil.example/"""")
        put("$api.renewalUrl", At.BLOCK to """"renewalUrl":"https://evil.example/"""")
        put("$api.tokenHosts", At.BLOCK to """"tokenHosts":["evil.example"]""")
        put("$api.clientCertHosts", At.BLOCK to """"clientCertHosts":["evil.example:443"]""")
        listOf("", "[].hostname", "[].sha256", "[].version", "[].forceUpdate", "[].mtls", "[].clientCertVersion").forEach {
            put("$api.bootstrapPins$it", At.BLOCK to """"bootstrapPins":$otherPins""")
        }
        put("$api.signaturePublicKey", At.BLOCK to """"signaturePublicKey":"$key2"""")
        put("$api.signaturePublicKeys", At.BLOCK to """"signaturePublicKeys":["$key2"]""")
        put("$api.requiredSignatures", At.BLOCK to """"requiredSignatures":2,"signaturePublicKeys":["$key"]""")
        put("$api.recoveryPublicKeys", At.BLOCK to """"recoveryPublicKeys":["$key2"]""")
        put("$api.requiredRecoverySignatures", At.BLOCK to """"requiredRecoverySignatures":2""")
        put("$api.serverScope", At.BLOCK to """"serverScope":"other-scope"""")
        put("$api.clientCaPins", At.BLOCK to """"clientCaPins":["$evil"]""")
        put("$api.allowUnsigned", At.BLOCK to """"allowUnsigned":true""")
        put("$api.allowUnpinnedConfigApi", At.BLOCK to """"allowUnpinnedConfigApi":true""")
        put("$api.allowServerGeneratedKey", At.BLOCK to """"allowServerGeneratedKey":true""")
        put("$api.healthEndpoint", At.BLOCK to """"healthEndpoint":"api/v1/certificate-config"""")
        put("config.vaultFiles[].signaturePublicKey", At.VAULT to """"signaturePublicKey":"$key2"""")
        put("config.vaultFiles[].encryption", At.VAULT to """"encryption":"PLAIN"""")
        put("config.vaultFiles[].userAuth", At.VAULT to """"userAuth":"REQUIRED"""")
        listOf("", ".version", ".forceUpdate", ".pins", ".pins[].hostname", ".pins[].sha256", ".pins[].version",
            ".pins[].forceUpdate", ".pins[].mtls", ".pins[].clientCertVersion").forEach {
            put("config.staticPins$it", At.ROOT to """"staticPins":$staticPins""")
        }
        put("config.managedTrustRoots", At.ROOT to """"managedTrustRoots":true""")
        put("config.android.requireUnlockedDeviceAllowFallback", At.ANDROID to """"requireUnlockedDeviceAllowFallback":true""")
    }

    private fun js(at: At, fragment: String): String {
        // The base url is left out when the example gives one: a key twice is refused on its own.
        val baseUrl = if (at == At.BLOCK && fragment.startsWith("\"url\"")) "" else ""","url":"https://h.example:8081/""""
        val block = """{"id":"default"$baseUrl${if (at == At.BLOCK) ",$fragment" else ""}}"""
        val vault = """{"key":"doc","endpoint":"api/v1/vault/doc"${if (at == At.VAULT) ",$fragment" else ""}}"""
        val android = if (at == At.ANDROID) ""","android":{$fragment}""" else ""
        val root = if (at == At.ROOT) ",$fragment" else ""
        return """{"configApis":[$block],"vaultFiles":[$vault]$android$root}"""
    }

    /** The key a sub-key belongs to (`…bootstrapPins[].sha256` → `bootstrapPins`, `config.staticPins.pins[].mtls` → `staticPins`). */
    private fun parentOf(path: String): String =
        if (path.contains("staticPins")) "staticPins" else path.substringBeforeLast("[]").substringAfterLast('.')

    private fun parse(json: String) =
        ConfigParser.parse(json, VaultTokenStore(), { EnvironmentGuard { true } }, null, native, release = true)

    @Test fun `every NATIVE key has an example, and none is left for a key that is not NATIVE`() {
        val nativeKeys = ConfigFieldPolicy.POLICY.filterValues { it == ConfigFieldPolicy.Policy.NATIVE }.keys
        assertEquals("NATIVE keys without an example here", emptySet<String>(), nativeKeys - examples.keys)
        assertEquals("examples for keys that are not NATIVE", emptySet<String>(), examples.keys - nativeKeys)
    }

    @Test fun `the base config itself is accepted`() {
        parse(js(At.ROOT, """"deviceAlias":"x""""))
    }

    @Test fun `a release build refuses every NATIVE key the file did not give`() {
        // A refusal counts only when it names the key: one for another reason proves nothing.
        val accepted = examples.filter { (path, example) ->
            val name = path.substringAfterLast('.').substringBefore('[').ifEmpty { path }
            try {
                parse(js(example.first, example.second))
                true
            } catch (e: IllegalArgumentException) {
                !(e.message ?: "").contains(name.substringBefore("[]").let { if (it in setOf("hostname", "sha256", "version", "forceUpdate", "mtls", "clientCertVersion", "pins")) parentOf(path) else it })
            }
        }.keys
        if (accepted.isNotEmpty()) fail("a release build took these NATIVE keys from Dart: $accepted")
    }
}
