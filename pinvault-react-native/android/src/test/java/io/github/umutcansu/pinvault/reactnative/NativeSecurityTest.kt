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

    private fun parse(json: String, native: NativeSecurity? = file, release: Boolean = true, noFileAllowed: Boolean = false) =
        ConfigParser.parse(json, tokens, noGuard, null, native, release, noFileAllowed)

    private fun refused(json: String, native: NativeSecurity? = file, release: Boolean = true, vararg fragments: String, noFileAllowed: Boolean = false) {
        try {
            parse(json, native, release, noFileAllowed)
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

    @Test fun `without a file, a release build refuses JS-only anchors unless the manifest accepts them`() {
        val api = """"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key""""
        refused("""{"configApis":[{$api}]}""", native = null, fragments = arrayOf("none is shipped", NativeSecurity.NO_FILE_META_DATA))
        refused("""{"staticPins":{"pins":[{"hostname":"x","sha256":["$pinA","$pinB"]}]}}""", native = null, fragments = arrayOf("none is shipped"))
        assertFalse(parse("""{"configApis":[{$api}]}""", native = null, noFileAllowed = true).nativeSecurityApplied)
        // A debug build takes it as before.
        assertFalse(parse("""{"configApis":[{$api}]}""", native = null, release = false).nativeSecurityApplied)
    }

    @Test fun `without a file, a release build refuses the relaxations from JS, a debug build takes them`() {
        val api = """"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key""""
        refused("""{"configApis":[{$api,"allowServerGeneratedKey":true}]}""", native = null, release = true,
            fragments = arrayOf("allowServerGeneratedKey: refused from JS", "native security file"), noFileAllowed = true)
        refused("""{"configApis":[{"id":"a","url":"https://h/","allowUnsigned":true}]}""", native = null, release = true,
            fragments = arrayOf("allowUnsigned"), noFileAllowed = true)
        refused("""{"configApis":[{$api,"allowUnpinnedConfigApi":true}]}""", native = null, release = true,
            fragments = arrayOf("allowUnpinnedConfigApi"), noFileAllowed = true)
        assertTrue(parse("""{"configApis":[{$api,"allowServerGeneratedKey":true}]}""", native = null, release = false)
            .config.configApis.getValue("a").allowServerGeneratedKey)
    }

    @Test fun `require only tightens, and the block's url, token hosts and attestation are fixed`() {
        val strict = NativeSecurity.parse("""
            {"configApis":[{"id":"default","url":"https://h.example:8081/","attestation":true,"tokenHosts":["api.example"],
              "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}],
             "require":{"requireUnlockedDevice":true,"requireHardwareBackedKeys":true,"requireCaTrust":["h.example"],
                        "expectedSignerSha256":["${"ab".repeat(32)}"],"expiredConfigGraceSeconds":3600,
                        "expectedBundleIds":["com.example.ios"]}}
        """.trimIndent(), "f")
        val base = """"id":"default","url":"https://h.example:8081/""""
        val p = parse("""{"configApis":[{$base}],"requireUnlockedDevice":false,"requireCaTrust":["other.example"]}""", native = strict)
        assertTrue("JS false does not switch it off", p.config.requireUnlockedDevice)
        assertTrue(p.config.requireHardwareBackedKeys)
        assertEquals(setOf("other.example", "h.example"), p.config.caTrustHosts.toSet())
        assertEquals(listOf("ab".repeat(32)), p.config.expectedSignerSha256)
        assertTrue(p.config.configApis.getValue("default").attestationEnabled)
        refused("""{"configApis":[{$base,"attestation":false}]}""", native = strict, fragments = arrayOf("attestation", "cannot turn it off"))
        refused("""{"configApis":[{$base,"tokenHosts":["evil.example"]}]}""", native = strict, fragments = arrayOf("tokenHosts", "fixed"))
        refused("""{"configApis":[{"id":"default","url":"https://evil.example/"}]}""", native = strict, fragments = arrayOf("url", "fixed"))
        refused("""{"configApis":[{$base}],"expectedSignerSha256":["${"cd".repeat(32)}"]}""", native = strict, fragments = arrayOf("expectedSignerSha256", "fixed"))
        refused("""{"configApis":[{$base}],"expiredConfigGrace":{"amount":2,"unit":"HOURS"}}""", native = strict, fragments = arrayOf("expiredConfigGrace"))
        parse("""{"configApis":[{$base}],"expiredConfigGrace":{"amount":30,"unit":"MINUTES"}}""", native = strict)
    }

    @Test fun `proofOfPossession from the file cannot be turned off, and JS may turn it on`() {
        val proving = NativeSecurity.parse("""
            {"configApis":[{"id":"default","attestation":true,"proofOfPossession":true,
              "bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}]}
        """.trimIndent(), "f")
        val base = """"id":"default","url":"https://h.example:8081/""""
        assertTrue(parse("""{"configApis":[{$base}]}""", native = proving).config.configApis.getValue("default").tokenProof)
        refused("""{"configApis":[{$base,"proofOfPossession":false}]}""", native = proving, fragments = arrayOf("proofOfPossession", "cannot turn it off"))
        val plain = NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}]}
        """.trimIndent(), "f")
        assertTrue(parse("""{"configApis":[{$base,"attestation":true,"proofOfPossession":true}]}""", native = plain)
            .config.configApis.getValue("default").tokenProof)
        assertFalse(parse("""{"configApis":[{$base,"attestation":true}]}""", native = plain).config.configApis.getValue("default").tokenProof)
    }

    @Test fun `offline ages and enrollment urls cannot be loosened from JS`() {
        val strict = NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"],
              "enrollmentUrl":"https://enroll.example/"}],
             "require":{"vaultFileMaxOfflineAgeSeconds":3600,"userAuthStrength":"BIOMETRIC_CURRENT_SET"},
             "vaultFiles":[{"key":"statement","maxOfflineAgeSeconds":600}]}
        """.trimIndent(), "f")
        val base = """"id":"default","url":"https://h.example:8081/""""
        val p = parse("""{"configApis":[{$base}],"vaultFiles":[{"key":"statement","endpoint":"e"}]}""", native = strict)
        assertEquals(3_600_000L, p.config.vaultFileMaxOfflineAgeMs)
        assertEquals(600_000L, p.config.vaultFiles.getValue("statement").maxOfflineAgeMs)
        refused("""{"configApis":[{$base}],"vaultFileMaxOfflineAge":{"amount":2,"unit":"HOURS"}}""", native = strict, fragments = arrayOf("vaultFileMaxOfflineAge"))
        refused("""{"configApis":[{$base}],"vaultFileMaxOfflineAge":{"amount":0,"unit":"SECONDS"}}""", native = strict, fragments = arrayOf("vaultFileMaxOfflineAge"))
        refused("""{"configApis":[{$base}],"vaultFiles":[{"key":"statement","endpoint":"e","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}""",
            native = strict, fragments = arrayOf("maxOfflineAge"))
        refused("""{"configApis":[{$base,"enrollmentUrl":"https://evil.example/"}]}""", native = strict, fragments = arrayOf("enrollmentUrl", "fixed"))
        parse("""{"configApis":[{$base}],"vaultFileMaxOfflineAge":{"amount":30,"unit":"MINUTES"}}""", native = strict)
        // The config-wide cap holds for a file the file does not name a cap for, too.
        val globalOnly = NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}],
             "require":{"vaultFileMaxOfflineAgeSeconds":3600}}
        """.trimIndent(), "f")
        refused("""{"configApis":[{$base}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":0,"unit":"SECONDS"}}]}""",
            native = globalOnly, fragments = arrayOf("maxOfflineAge"))
        refused("""{"configApis":[{$base}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":2,"unit":"HOURS"}}]}""",
            native = globalOnly, fragments = arrayOf("maxOfflineAge"))
        parse("""{"configApis":[{$base}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":10,"unit":"MINUTES"}}]}""", native = globalOnly)
    }

    @Test fun `an empty Config API list in release asks for no native file`() {
        try {
            parse("""{"configApis":[]}""", native = null)
            fail("accepted a config with nothing in it")
        } catch (e: IllegalArgumentException) {
            assertFalse(e.message!!, e.message!!.contains("none is shipped"))
        }
    }

    @Test fun `a release build caps the expired config grace`() {
        val api = """"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key""""
        refused("""{"configApis":[{$api}],"expiredConfigGrace":{"amount":8,"unit":"DAYS"}}""", native = null,
            fragments = arrayOf("at most 7 days"), noFileAllowed = true)
        parse("""{"configApis":[{$api}],"expiredConfigGrace":{"amount":8,"unit":"DAYS"}}""", native = null, release = false)
    }

    @Test fun `declared vault files keep their protection, undeclared ones are refused`() {
        val files = NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}],
             "vaultFiles":[{"key":"statement","signaturePublicKey":"$key","encryption":"USER_AUTH","userAuth":"REQUIRED"}]}
        """.trimIndent(), "f")
        val base = """"id":"default","url":"https://h.example:8081/""""
        val ok = parse("""{"configApis":[{$base}],"vaultFiles":[{"key":"statement","endpoint":"api/v1/vault/statement"}]}""", native = files)
        val file = ok.config.vaultFiles.getValue("statement")
        assertEquals(io.github.umutcansu.pinvault.model.VaultFileEncryption.USER_AUTH, file.encryption)
        assertEquals(io.github.umutcansu.pinvault.model.UserAuth.REQUIRED, file.userAuth)
        refused("""{"configApis":[{$base}],"vaultFiles":[{"key":"statement","endpoint":"e","encryption":"PLAIN"}]}""", native = files,
            fragments = arrayOf("encryption", "fixed"))
        refused("""{"configApis":[{$base}],"vaultFiles":[{"key":"other","endpoint":"e"}]}""", native = files, fragments = arrayOf("'other' is not declared"))
        val signed = """"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["$pinA","$pinB"]}],"signaturePublicKey":"$key""""
        refused("""{"configApis":[{$signed}],"vaultFiles":[{"key":"../x","endpoint":"e"}]}""", native = null, release = false,
            fragments = arrayOf("[A-Za-z0-9._-]"))
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
