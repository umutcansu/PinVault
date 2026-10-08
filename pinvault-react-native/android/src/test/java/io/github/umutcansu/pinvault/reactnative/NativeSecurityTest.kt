package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The native security file against the JS config (ConfigParser + SecurityPolicy). */
class NativeSecurityTest {

    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    private val key2 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2B2nCnNnOqLbd9HnN0Bzh1n0yA0V1Z2tKm8bq6H1Z0lFv8yP0n0n8y0Ue7c3Hn2c9mQ3M6nYk0fJm5X3Qh9g=="
    private val key3 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp9Vq4Xn1m3Lk2h8Gf5Jd6Sa0Qw7Er1Ty2Ui3Op4As5Df6Gh7Jk8Lz9Xc0Vb1Nm2Qa3Ws4Ed5Rf6Tg7Yh8Uj9Ik0Ol=="
    private val pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    private val pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    private val evil = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    private val tokens = VaultTokenStore()
    private val noGuard: (Long) -> EnvironmentGuard = { EnvironmentGuard { true } }

    private val file = NativeSecurity.parse("""
        {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],
          "signaturePublicKeys":["$key","$key2"],"requiredSignatures":2,"recoveryPublicKeys":["$key3"],
          "serverScope":"default-tls","clientCaPins":["$pinA"]}]}
    """.trimIndent(), "assets/pinvault_security.json")

    private fun parse(json: String, native: NativeSecurity? = file, release: Boolean = true) =
        ConfigParser.parse(json, tokens, noGuard, null, native, release)

    private fun refused(json: String, native: NativeSecurity? = file, release: Boolean = true, vararg fragments: String) {
        try {
            parse(json, native, release)
            fail("accepted: $json")
        } catch (e: IllegalArgumentException) {
            fragments.forEach { assertTrue("'${e.message}' lacks '$it'", e.message!!.contains(it)) }
        }
    }

    @Test fun `the native values apply when JS leaves them out`() {
        val p = parse("""{"configApis":[{"id":"default","url":"https://h.example:8081/"}]}""")
        val block = p.config.configApis.getValue("default")
        assertEquals(listOf(pinA, pinB), block.bootstrapPins.single().sha256)
        assertTrue(p.nativeSecurityApplied)
        assertEquals("default-tls", block.serverScope)
        assertEquals(2, block.requiredSignatures)
        assertEquals(listOf(pinA), block.clientCaPins)
    }

    @Test fun `JS may repeat the native values, in any order`() {
        parse("""{"configApis":[{"id":"default","url":"https://h.example:8081/",
            "bootstrapPins":[{"hostname":"H.example","sha256":["$pinB","$pinA"]}],
            "signaturePublicKeys":["$key2","$key"],"requiredSignatures":2,"serverScope":"default-tls"}]}""")
    }

    @Test fun `a differing trust anchor from JS is refused`() {
        val base = """"id":"default","url":"https://h.example:8081/""""
        refused("""{"configApis":[{$base,"bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$evil"]}]}]}""",
            fragments = arrayOf("config.configApis[0].bootstrapPins", "native security file", "fixed"))
        refused("""{"configApis":[{$base,"signaturePublicKey":"$key"}]}""", fragments = arrayOf("signaturePublicKey", "fixed"))
        refused("""{"configApis":[{$base,"requiredSignatures":1}]}""", fragments = arrayOf("requiredSignatures"))
        refused("""{"configApis":[{$base,"recoveryPublicKeys":["$key"]}]}""", fragments = arrayOf("recoveryPublicKeys"))
        refused("""{"configApis":[{$base,"serverScope":"other"}]}""", fragments = arrayOf("serverScope"))
        refused("""{"configApis":[{$base,"clientCaPins":["$evil"]}]}""", fragments = arrayOf("clientCaPins"))
    }

    @Test fun `a Config API the file does not declare is refused, and so are JS static pins`() {
        refused("""{"configApis":[{"id":"evil","url":"https://e.example/","bootstrapPins":[{"hostname":"e.example","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key"}]}""",
            fragments = arrayOf("'evil' is not declared", "pinvault_security.json"))
        refused("""{"staticPins":{"pins":[{"hostname":"x.example","sha256":["$pinA","$pinB"]}]}}""",
            fragments = arrayOf("config.staticPins", "not declared"))
    }

    @Test fun `the relaxations need the file's consent`() {
        val base = """"id":"default","url":"https://h.example:8081/""""
        refused("""{"configApis":[{$base,"allowUnsigned":true}]}""", fragments = arrayOf("allowUnsigned", "does not allow"))
        refused("""{"configApis":[{$base,"allowUnpinnedConfigApi":true}]}""", fragments = arrayOf("allowUnpinnedConfigApi"))
        refused("""{"configApis":[{$base,"allowServerGeneratedKey":true}]}""", fragments = arrayOf("allowServerGeneratedKey"))
        // Even in a debug build: the file is there, it decides.
        refused("""{"configApis":[{$base,"allowServerGeneratedKey":true}]}""", release = false, fragments = arrayOf("does not allow"))
        val allowing = NativeSecurity.parse("""{"configApis":[{"id":"default","allowServerGeneratedKey":true,"signaturePublicKeys":["$key"],
            "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}]}]}""", "f")
        // Allowed by the file: from JS or not, it applies.
        assertTrue(parse("""{"configApis":[{$base}]}""", allowing).config.configApis.getValue("default").allowServerGeneratedKey)
        assertTrue(parse("""{"configApis":[{$base,"allowServerGeneratedKey":true}]}""", allowing).config.configApis.getValue("default").allowServerGeneratedKey)
    }

    @Test fun `without a file, a release build refuses the relaxations from JS, a debug build takes them`() {
        val api = """"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key""""
        refused("""{"configApis":[{$api,"allowServerGeneratedKey":true}]}""", native = null, release = true,
            fragments = arrayOf("allowServerGeneratedKey: refused from JS", "native security file"))
        refused("""{"configApis":[{"id":"a","url":"https://h/","allowUnsigned":true}]}""", native = null, release = true, fragments = arrayOf("allowUnsigned"))
        refused("""{"configApis":[{$api,"allowUnpinnedConfigApi":true}]}""", native = null, release = true, fragments = arrayOf("allowUnpinnedConfigApi"))
        assertTrue(parse("""{"configApis":[{$api,"allowServerGeneratedKey":true}]}""", native = null, release = false)
            .config.configApis.getValue("a").allowServerGeneratedKey)
        // Nothing else changes without a file.
        assertFalse(parse("""{"configApis":[{$api}]}""", native = null, release = true).nativeSecurityApplied)
    }

    @Test fun `the file itself is parsed strictly`() {
        fun bad(text: String, fragment: String) {
            try {
                NativeSecurity.parse(text, "assets/pinvault_security.json")
                fail("accepted: $text")
            } catch (e: BridgeInputException) {
                assertTrue("'${e.message}' lacks '$fragment'", e.message!!.contains(fragment))
                assertTrue(e.message!!.startsWith("native security file"))
            }
        }
        bad("""{"configApis":[{"id":"a","serverScop":"x"}]}""", "'serverScop'")
        bad("""{"configApis":[{"id":"a"},{"id":"a"}]}""", "declared twice")
        bad("""{}""", "declares neither")
        bad("""{"configApis":[{"id":"a","requiredSignatures":"2"}]}""", "must be a number")
        bad("""{"configApis":""", "not valid JSON")
        bad("""{"configApis":[{"id":"a","bootstrapPins":[{"hostname":"h","sha256":["$pinA"]}]}]}""", "At least 2 pins")
    }

    @Test fun `file static pins apply and must match`() {
        val withPins = NativeSecurity.parse("""{"staticPins":{"version":3,"pins":[{"hostname":"x.example","sha256":["$pinA","$pinB"]}]}}""", "f")
        assertEquals(3, parse("""{}""", withPins).config.staticPins!!.version)
        parse("""{"staticPins":{"version":3,"pins":[{"hostname":"x.example","sha256":["$pinB","$pinA"]}]}}""", withPins)
        refused("""{"staticPins":{"version":4,"pins":[{"hostname":"x.example","sha256":["$pinA","$pinB"]}]}}""", withPins, fragments = arrayOf("staticPins", "fixed"))
    }
}
