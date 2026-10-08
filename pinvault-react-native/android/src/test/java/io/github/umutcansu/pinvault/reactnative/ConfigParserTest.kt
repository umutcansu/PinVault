package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import io.github.umutcansu.pinvault.model.GuardedOperation
import io.github.umutcansu.pinvault.model.StorageStrategy
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.TimeUnit

class ConfigParserTest {

    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    private val pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    private val pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    private val tokens = VaultTokenStore()
    private val noGuard: (Long) -> EnvironmentGuard = { EnvironmentGuard { true } }

    private fun api(extra: String = "") = """
        {"id":"default","url":"https://h.example:8081/",
         "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],
         "signaturePublicKey":"$key"$extra}
    """.trimIndent()

    private fun parse(json: String) = ConfigParser.parse(json, tokens, noGuard, null)

    private fun refused(json: String, vararg fragments: String) {
        try {
            parse(json)
            fail("accepted: $json")
        } catch (e: IllegalArgumentException) {
            fragments.forEach { assertTrue("'${e.message}' lacks '$it'", e.message!!.contains(it)) }
        }
    }

    @Test fun `a full config goes through the builders`() {
        val parsed = parse("""
            {"configApis":[${api(""","serverScope":"default-tls","clientCertHosts":["https://h.example:8092/"],
                "attestation":true,"attestationInterval":{"amount":10,"unit":"MINUTES"},"requiredSignatures":1""")}],
             "vaultFiles":[
               {"key":"flags","endpoint":"api/v1/vault/flags"},
               {"key":"secret","endpoint":"/api/v1/vault/secret","accessPolicy":"TOKEN_MTLS","encryption":"USER_AUTH",
                "userAuth":"REQUIRED","storage":"ENCRYPTED_FILE","maxOfflineAge":{"amount":7,"unit":"DAYS"}}],
             "requireCaTrust":["www.example.com"],"updateIntervalMinutes":15,"deviceAlias":"RN",
             "wipeVaultFilesOnRevocation":true,"requireUnlockedDevice":true,"requireHardwareBackedKeys":true,
             "expiredConfigGrace":{"amount":1,"unit":"HOURS"},"environmentGuard":{"timeoutMs":2000},
             "android":{"requireUnlockedDeviceAllowFallback":true,"pinGlobalNetworking":false},
             "ios":{"resolve":{"a.sample":"10.0.0.1"}}}
        """.trimIndent())
        val c = parsed.config
        val block = c.configApis.getValue("default")
        assertEquals("https://h.example:8081/", block.configUrl)
        assertEquals(listOf(pinA, pinB), block.bootstrapPins.single().sha256)
        assertTrue(block.attestationEnabled)
        assertEquals(TimeUnit.MINUTES.toMillis(10), block.attestationIntervalMs)
        val secret = c.vaultFiles.getValue("secret")
        assertEquals(VaultFileAccessPolicy.TOKEN_MTLS, secret.accessPolicy)
        assertEquals(VaultFileEncryption.USER_AUTH, secret.encryption)
        assertEquals(UserAuth.REQUIRED, secret.userAuth)
        assertEquals(StorageStrategy.ENCRYPTED_FILE, secret.storageStrategy)
        assertEquals("api/v1/vault/secret", secret.endpoint)
        assertEquals(TimeUnit.DAYS.toMillis(7), secret.maxOfflineAgeMs)
        assertEquals(listOf("www.example.com"), c.caTrustHosts)
        assertEquals(15L, c.updateIntervalMinutes)
        assertTrue(c.requireUnlockedDevice && c.requireUnlockedDeviceFallback && c.requireHardwareBackedKeys)
        assertEquals(TimeUnit.HOURS.toMillis(1), c.expiredConfigGraceMs)
        assertEquals(2000L, parsed.guardTimeoutMs)
        assertNotNull(c.environmentGuard)
        assertFalse(parsed.pinGlobalNetworking)
    }

    @Test fun `token files read their token from native memory on every download`() {
        val c = parse("""{"configApis":[${api()}],"vaultFiles":[{"key":"s","endpoint":"e","accessPolicy":"TOKEN"}]}""").config
        val provider = c.vaultFiles.getValue("s").accessTokenProvider!!
        assertEquals("", provider())
        tokens.put("s", "tok-123456")
        assertEquals("tok-123456", provider())
        tokens.put("s", null)
        assertEquals("", provider())
    }

    @Test fun `public files get no token provider`() {
        val c = parse("""{"configApis":[${api()}],"vaultFiles":[{"key":"p","endpoint":"e"}]}""").config
        assertNull(c.vaultFiles.getValue("p").accessTokenProvider)
    }

    @Test fun `defaults stay the library's`() {
        val p = parse("""{"configApis":[${api()}]}""")
        assertNull(p.guardTimeoutMs)
        assertNull(p.config.environmentGuard)
        assertTrue(p.pinGlobalNetworking)
        assertFalse(p.config.requireUnlockedDevice)
    }

    @Test fun `unknown keys are refused at every level`() {
        refused("""{"configApis":[${api()}],"confgApis":[]}""", "config", "'confgApis'")
        refused("""{"configApis":[${api(""","bootstrapPinz":[]""")}]}""", "config.configApis[0]", "'bootstrapPinz'")
        refused("""{"configApis":[${api()}],"vaultFiles":[{"key":"k","endpoint":"e","acessPolicy":"TOKEN"}]}""", "vaultFiles[0]", "'acessPolicy'")
        refused("""{"configApis":[${api()}],"android":{"pinGlobalFetch":true}}""", "config.android", "'pinGlobalFetch'")
        refused("""{"configApis":[${api()}],"expiredConfigGrace":{"amount":1,"unit":"HOURS","x":1}}""", "'x'")
        refused("""{"configApis":[{"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"],"pinned":true}],"signaturePublicKey":"$key"}]}""", "bootstrapPins[0]", "'pinned'")
    }

    @Test fun `wrong types are refused, never coerced`() {
        refused("""{"configApis":[${api()}],"maxRetryCount":"3"}""", "maxRetryCount", "number")
        refused("""{"configApis":[${api()}],"maxRetryCount":2.5}""", "whole number")
        refused("""{"configApis":[${api()}],"requireUnlockedDevice":"true"}""", "requireUnlockedDevice", "boolean")
        refused("""{"configApis":[${api()}],"requireUnlockedDevice":1}""", "boolean")
        refused("""{"configApis":[${api()}],"requireCaTrust":"www.example.com"}""", "list of strings")
        refused("""{"configApis":[${api()}],"requireCaTrust":[1]}""", "requireCaTrust[0]", "string")
        refused("""{"configApis":{}}""", "configApis", "list of objects")
        refused("""{"configApis":[${api()}],"vaultFiles":[{"key":"k","endpoint":"e","encryption":"user_auth"}]}""", "encryption", "USER_AUTH")
        refused("""[]""", "must be an object")
        refused("""{"configApis":[${api()}],""", "not valid JSON")
    }

    @Test fun `ranges and sizes are bounded`() {
        refused("""{"configApis":[${api()}],"maxRetryCount":11}""", "between 0 and 10")
        refused("""{"configApis":[${api()}],"updateIntervalMinutes":5}""", "between 15")
        refused("""{"configApis":[${api()}],"environmentGuard":{"timeoutMs":60000}}""", "timeoutMs")
        refused("""{"configApis":[${api()}],"deviceAlias":"${"a".repeat(200)}"}""", "longer than 128")
        refused("""{"configApis":[${api()}],"deviceAlias":"a\nb"}""", "control characters")
        val many = (1..17).joinToString(",") { api().replace("\"default\"", "\"api$it\"") }
        refused("""{"configApis":[$many]}""", "more than 16")
        refused("{\"deviceAlias\":\"${"a".repeat(StrictJson.MAX_INPUT_CHARS)}\"}", "larger than")
    }

    @Test fun `only https Config API URLs`() {
        refused("""{"configApis":[{"id":"a","url":"http://h/","signaturePublicKey":"$key","allowUnpinnedConfigApi":true}]}""", "https://")
        refused("""{"configApis":[${api(""","renewalUrl":"http://h:8083/"""")}]}""", "renewalUrl", "https://")
    }

    @Test fun `builder rules still apply`() {
        // A pin entry needs two pins (the HostPin constructor).
        refused("""{"configApis":[{"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA"]}],"signaturePublicKey":"$key"}]}""", "At least 2 pins")
        // A signed Config API needs its key.
        refused("""{"configApis":[{"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}]}]}""", "signaturePublicKey is required")
        // TOKEN files and USER_AUTH encryption keep their builder rules.
        refused("""{"configApis":[${api()}],"vaultFiles":[{"key":"k","endpoint":"e","encryption":"USER_AUTH"}]}""", "needs userAuth")
        refused("""{"configApis":[${api()}],"android":{"requireUnlockedDeviceAllowFallback":true}}""", "needs requireUnlockedDevice")
        refused("""{"configApis":[${api(""","signaturePublicKeys":["$key"]""")}]}""", "not both")
    }

    @Test fun `deep nesting is refused before the parser runs`() {
        val deep = "[".repeat(5000) + "]".repeat(5000)
        refused("""{"configApis":$deep}""", "nested too deeply")
        // Brackets inside strings do not count.
        assertEquals(1, StrictJson.nestingDepth("""{"a":"[[[[[[[[[[{{{{{{"}"""))
        assertEquals(3, StrictJson.nestingDepth("""{"a":[{"b":"\"]"}]}"""))
        // Far beyond what the tokener's recursion survives: still a plain refusal.
        try {
            val open = "{\"a\":".repeat(100_000)
            PinnedFetch.parse("{\"url\":\"https://h/\",\"headers\":" + open + "\"x\"" + "}".repeat(100_001))
            fail()
        } catch (e: BridgeInputException) {
            assertTrue(e.message!!.contains("nested too deeply"))
        }
    }

    @Test fun `the networking options are read`() {
        val p = parse("""{"configApis":[${api()}],"requirePinnedReactNativeNetworking":true,
            "android":{"keepReactNativeHttpCache":true,"keepReactNativeCookies":true}}""")
        assertEquals(NetworkingOptions(requirePinned = true, keepHttpCache = true, keepCookies = true), p.networking)
        assertEquals(NetworkingOptions(), parse("""{"configApis":[${api()}]}""").networking)
        refused("""{"configApis":[${api()}],"requirePinnedReactNativeNetworking":true,"android":{"pinGlobalNetworking":false}}""", "contradicts")
    }

    @Test fun `the JS guard factory gets the timeout`() {
        var timeout = -1L
        ConfigParser.parse("""{"configApis":[${api()}],"environmentGuard":{}}""", tokens, { t -> timeout = t; EnvironmentGuard { false } }, null)
        assertEquals(JsEnvironmentGuard.DEFAULT_TIMEOUT_MS, timeout)
    }

    @Test fun `unlock prompts are parsed strictly`() {
        val (prompt, encoding) = ConfigParser.unlockPrompt("""{"title":"Aç","description":"Kilit","encoding":"base64"}""")
        assertEquals("Aç", prompt.title)
        assertEquals("Cancel", prompt.negativeButtonText)
        assertEquals("base64", encoding)
        try {
            ConfigParser.unlockPrompt("""{"title":"x","encoding":"hex"}""")
            fail()
        } catch (e: BridgeInputException) {
            assertTrue(e.message!!.contains("utf8"))
        }
        try {
            ConfigParser.unlockPrompt("""{"titel":"x"}""")
            fail()
        } catch (e: BridgeInputException) {
            assertTrue(e.message!!.contains("title"))
        }
    }

    @Suppress("unused") private val op = GuardedOperation.INIT
}
