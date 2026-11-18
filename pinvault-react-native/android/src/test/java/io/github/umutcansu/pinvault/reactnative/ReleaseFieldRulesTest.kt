package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.model.EnvironmentGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Review 2026-11-12: fields a release build still took from JS although they
 * weaken what the native security file sets up.
 */
class ReleaseFieldRulesTest {

    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    private val pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    private val pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    private val tokens = VaultTokenStore()
    private val noGuard: (Long) -> EnvironmentGuard = { EnvironmentGuard { true } }

    private val block = """"id":"default","url":"https://h.example:8081/","bootstrapPins":[{"hostname":"h.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]"""

    private fun file(extraBlock: String = "", top: String = "") =
        NativeSecurity.parse("""{"configApis":[{$block$extraBlock}]$top}""", "assets/pinvault_security.json")

    private fun parse(js: String, native: NativeSecurity? = file(), release: Boolean = true) =
        ConfigParser.parse(js, tokens, noGuard, null, native, release, noFileAllowed = native == null)

    private fun refused(js: String, native: NativeSecurity? = file(), vararg fragments: String) {
        try {
            parse(js, native)
            fail("accepted: $js")
        } catch (e: IllegalArgumentException) {
            fragments.forEach { assertTrue("'${e.message}' lacks '$it'", e.message!!.contains(it)) }
        }
    }

    private val api = """"configApis":[{"id":"default","url":"https://h.example:8081/""""

    @Test fun `healthEndpoint comes from the file in a release build`() {
        refused("""{$api,"healthEndpoint":"api/v1/certificate-config"}]}""", file(), "healthEndpoint", "native security file")
        val declared = file(""","healthEndpoint":"status"""")
        assertEquals("status", parse("""{$api}]}""", declared).config.configApis.getValue("default").healthEndpoint)
        parse("""{$api,"healthEndpoint":"status"}]}""", declared)
        // A debug build takes it from JS as before.
        parse("""{$api,"healthEndpoint":"elsewhere"}]}""", file(), release = false)
    }

    @Test fun `managed trust roots are a relaxation the file allows`() {
        refused("""{$api}],"managedTrustRoots":true}""", file(), "managedTrustRoots")
        // Without a native file (the manifest allows it) the anchors come from JS, the relaxation still does not.
        refused("""{"configApis":[{$block}],"managedTrustRoots":true}""", null, "managedTrustRoots")
        parse("""{$api}],"managedTrustRoots":true}""", file(top = ""","require":{"managedTrustRoots":true}"""))
    }

    @Test fun `the unlocked-device fallback needs the file's consent when the file requires an unlocked device`() {
        val requires = file(top = ""","require":{"requireUnlockedDevice":true}""")
        refused("""{$api}],"android":{"requireUnlockedDeviceAllowFallback":true}}""", requires, "requireUnlockedDeviceAllowFallback")
        val allows = file(top = ""","require":{"requireUnlockedDevice":true,"requireUnlockedDeviceAllowFallback":true}""")
        parse("""{$api}],"android":{"requireUnlockedDeviceAllowFallback":true}}""", allows)
    }

    @Test fun `React Native networking stays pinned in a release build unless the file allows otherwise`() {
        refused("""{$api}],"android":{"pinGlobalNetworking":false}}""", file(), "pinGlobalNetworking")
        refused("""{$api}],"requirePinnedReactNativeNetworking":false}""", file(), "requirePinnedReactNativeNetworking")
        val allows = file(top = ""","require":{"allowUnpinnedReactNativeNetworking":true}""")
        assertEquals(false, parse("""{$api}],"android":{"pinGlobalNetworking":false}}""", allows).pinGlobalNetworking)
    }

    @Test fun `a release build with a native file takes vault files only from its vaultFiles section`() {
        refused("""{$api}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"NONE"}]}""", file(), "vaultFiles section")
        // A debug build, and a release build with the file's declaration, are fine.
        parse("""{$api}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}""", file(), release = false)
        parse("""{$api}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}""", file(top = ""","vaultFiles":[{"key":"doc"}]"""))
    }

    // Review 2026-11-14 (K1): a bare entry used to leave the three fields to the bundle.
    @Test fun `a vault field the native entry leaves out is the library default in a release build, never JS's`() {
        val bare = file(top = ""","vaultFiles":[{"key":"doc"}]""")
        fun doc(extra: String) = """{$api}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"$extra}]}"""
        refused(doc(""","signaturePublicKey":"$key""""), bare, "vaultFiles[0].signaturePublicKey", "does not give signaturePublicKey", "only from there")
        refused(doc(""","encryption":"PLAIN""""), bare, "vaultFiles[0].encryption", "does not give encryption", "only from there")
        refused(doc(""","userAuth":"NONE""""), bare, "vaultFiles[0].userAuth", "does not give userAuth", "only from there")
        refused(doc(""","encryption":"USER_AUTH","userAuth":"REQUIRED""""), bare, "does not give")
        // Nothing from JS: the library's defaults (the block's signing keys, PLAIN, NONE).
        val vault = parse(doc(""), bare).config.vaultFiles.getValue("doc")
        assertEquals(null, vault.signaturePublicKey)
        assertEquals(io.github.umutcansu.pinvault.model.VaultFileEncryption.PLAIN, vault.encryption)
        assertEquals(io.github.umutcansu.pinvault.model.UserAuth.NONE, vault.userAuth)
        // What the entry gives is the value; JS may repeat it.
        val full = file(top = ""","vaultFiles":[{"key":"doc","signaturePublicKey":"$key","encryption":"USER_AUTH","userAuth":"REQUIRED"}]""")
        val locked = parse(doc(""","encryption":"USER_AUTH""""), full).config.vaultFiles.getValue("doc")
        assertEquals(key, locked.signaturePublicKey)
        assertEquals(io.github.umutcansu.pinvault.model.UserAuth.REQUIRED, locked.userAuth)
        // An entry that gives one field leaves the other two at the default, not to JS.
        val keyOnly = file(top = ""","vaultFiles":[{"key":"doc","signaturePublicKey":"$key"}]""")
        refused(doc(""","userAuth":"IF_SCREEN_LOCK""""), keyOnly, "does not give userAuth")
        // A debug build, and a release build without a native file, take them from JS as before.
        val debug = parse(doc(""","encryption":"USER_AUTH","userAuth":"REQUIRED""""), bare, release = false).config.vaultFiles.getValue("doc")
        assertEquals(io.github.umutcansu.pinvault.model.UserAuth.REQUIRED, debug.userAuth)
        parse("""{"configApis":[{$block}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"IF_SCREEN_LOCK"}]}""", null)
    }

    @Test fun `a native vault entry can fix the file's Config API, endpoint and access policy`() {
        val fixed = file(top = ""","vaultFiles":[{"key":"doc","configApi":"default","endpoint":"api/v1/vault/doc","accessPolicy":"TOKEN"}]""")
        fun doc(fields: String) = """{$api}],"vaultFiles":[{"key":"doc"$fields}]}"""
        // JS may leave them out or repeat them.
        val vault = parse(doc(""), fixed).config.vaultFiles.getValue("doc")
        assertEquals("api/v1/vault/doc", vault.endpoint)
        assertEquals("default", vault.configApiId)
        assertEquals(io.github.umutcansu.pinvault.model.VaultFileAccessPolicy.TOKEN, vault.accessPolicy)
        assertTrue(vault.accessTokenProvider != null)
        parse(doc(""","endpoint":"api/v1/vault/doc","configApi":"default","accessPolicy":"TOKEN""""), fixed)
        // A different value is refused, in a debug build too.
        refused(doc(""","endpoint":"api/v1/vault/other""""), fixed, "vaultFiles[0].endpoint", "native value is fixed")
        refused(doc(""","configApi":"other""""), fixed, "vaultFiles[0].configApi", "native value is fixed")
        refused(doc(""","accessPolicy":"PUBLIC""""), fixed, "vaultFiles[0].accessPolicy", "native value is fixed")
        try {
            parse(doc(""","accessPolicy":"PUBLIC""""), fixed, release = false)
            fail("a debug build took another accessPolicy")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("native value is fixed"))
        }
        // An entry that does not give them leaves them to JS, as before.
        val bare = file(top = ""","vaultFiles":[{"key":"doc"}]""")
        assertEquals("elsewhere/doc", parse(doc(""","endpoint":"elsewhere/doc","accessPolicy":"TOKEN""""), bare).config.vaultFiles.getValue("doc").endpoint)
        refused(doc(""), bare, "vaultFiles[0].endpoint", "required")
        // The file's endpoint follows the endpoint rule too.
        try {
            file(top = ""","vaultFiles":[{"key":"doc","endpoint":"../admin"}]""")
            fail("the native file took an endpoint with '..'")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("'..' path segment"))
        }
    }

    // Review 2026-11-17: a vault file without its own signaturePublicKey is checked with the keys
    // of the block its configApi names; with two declared blocks a bare entry let JS pick that block.
    @Test fun `with several native blocks a release build takes a vault file's configApi from JS only when it names the default block`() {
        val second = """,{"id":"second","url":"https://h2.example/","bootstrapPins":[{"hostname":"h2.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]}"""
        fun two(vault: String) =
            NativeSecurity.parse("""{"configApis":[{$block}$second],"vaultFiles":[$vault]}""", "assets/pinvault_security.json")
        val both = """$api},{"id":"second","url":"https://h2.example/"}]"""
        fun doc(fields: String) = """{$both,"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"$fields}]}"""
        val bare = two("""{"key":"doc"}""")
        refused(doc(""","configApi":"second""""), bare,
            "vaultFiles[0].configApi", "declares more than one Config API", "does not give configApi", "only from there", "vaultFiles entry")
        // The default block (what an absent value resolves to) cannot select another block.
        assertEquals("default", parse(doc(""","configApi":"default""""), bare).config.vaultFiles.getValue("doc").configApiId)
        assertEquals("default", parse(doc(""), bare).config.vaultFiles.getValue("doc").configApiId)
        // An entry that gives configApi keeps today's rule: the entry wins, another JS value is refused.
        val fixed = two("""{"key":"doc","configApi":"second"}""")
        assertEquals("second", parse(doc(""), fixed).config.vaultFiles.getValue("doc").configApiId)
        assertEquals("second", parse(doc(""","configApi":"second""""), fixed).config.vaultFiles.getValue("doc").configApiId)
        refused(doc(""","configApi":"default""""), fixed, "vaultFiles[0].configApi", "native value is fixed")
        // A debug build takes JS's value as before.
        assertEquals("second", parse(doc(""","configApi":"second""""), bare, release = false).config.vaultFiles.getValue("doc").configApiId)
        // One native block: JS can only name that block, whatever its id.
        val mainBlock = block.replace(""""id":"default"""", """"id":"main"""")
        val one = NativeSecurity.parse("""{"configApis":[{$mainBlock}],"vaultFiles":[{"key":"doc"}]}""", "assets/pinvault_security.json")
        val js = """{"configApis":[{"id":"main","url":"https://h.example:8081/"}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","configApi":"main"}]}"""
        assertEquals("main", parse(js, one).config.vaultFiles.getValue("doc").configApiId)
    }

    // Review 2026-11-14 (K2): narrowing wantPinsFor took a pinned host's pins out of the signed
    // view; with managed trust roots that host is then accepted through the roots.
    @Test fun `with managed trust roots a release build takes wantPinsFor from the file only`() {
        val roots = ""","require":{"managedTrustRoots":true}"""
        val js = """{$api,"wantPinsFor":["cdn.example"]}]}"""
        refused(js, file(top = roots), "configApis[0].wantPinsFor", "managed trust roots", "only from there")
        // None in the file = every host's pins.
        assertEquals(emptyList<String>(), parse("""{$api}]}""", file(top = roots)).config.configApis.getValue("default").wantPinsFor)
        // The file's list is the value; JS may leave it out or repeat it (any order, any case), not change it.
        val declared = file(""","wantPinsFor":["api.example","cdn.example"]""", roots)
        assertEquals(listOf("api.example", "cdn.example"), parse("""{$api}]}""", declared).config.configApis.getValue("default").wantPinsFor)
        parse("""{$api,"wantPinsFor":["CDN.example","api.example"]}]}""", declared)
        refused(js, declared, "configApis[0].wantPinsFor", "native value is fixed")
        // Without managed roots: JS's list as before, unless the file gives one.
        assertEquals(listOf("cdn.example"), parse(js).config.configApis.getValue("default").wantPinsFor)
        refused(js, file(""","wantPinsFor":["api.example"]"""), "configApis[0].wantPinsFor", "native value is fixed")
        // A debug build takes JS's list with managed roots on.
        parse(js, file(top = roots), release = false)
    }

    // Review 2026-11-14 (R-03): the rules judged only the blocks the config sent; a bundle
    // that left a declared block out dropped its pins (with managed roots: a pin -> root downgrade).
    @Test fun `a release build runs every Config API its native file declares`() {
        fun second(extra: String = "") = """,{"id":"second","url":"https://h2.example/","bootstrapPins":[{"hostname":"h2.example","sha256":["$pinA","$pinB"]}],"signaturePublicKeys":["$key"]$extra}"""
        fun two(extra: String = "", top: String = "") =
            NativeSecurity.parse("""{"configApis":[{$block}${second(extra)}]$top}""", "assets/pinvault_security.json")
        val one = """{$api}]}"""
        val both = """{$api},{"id":"second","url":"https://h2.example/"}]}"""
        refused(one, two(), "config.configApis", "'second'", "runs every Config API its native file declares", "\"optional\": true")
        refused("""{"configApis":[]}""", two(), "'default', 'second'")
        refused("""{"deviceAlias":"x"}""", two(), "'default', 'second'")
        assertEquals(setOf("default", "second"), parse(both, two()).config.configApis.keys)
        // A debug build, and a release build without a native file, take the config as it comes.
        assertEquals(setOf("default"), parse(one, two(), release = false).config.configApis.keys)
        parse("""{"configApis":[{$block}]}""", null)
        // The file may let the app start without a block ...
        val optional = two(""","optional":true""")
        assertEquals(setOf("default"), parse(one, optional).config.configApis.keys)
        parse(both, optional)
        // ... but not the other one,
        refused("""{"configApis":[{"id":"second","url":"https://h2.example/"}]}""", optional, "'default'")
        // and not with managed trust roots: the missing block's hosts would fall back to the roots.
        val roots = two(""","optional":true""", ""","require":{"managedTrustRoots":true}""")
        refused(one, roots, "'second'", "managedTrustRoots", "cannot be left out")
        parse(both, roots)
        // A file with static pins only declares no block to run.
        val pins = """{"pins":[{"hostname":"s.example","sha256":["$pinA","$pinB"]}]}"""
        parse("""{"staticPins":$pins}""", NativeSecurity.parse("""{"staticPins":$pins}""", "assets/pinvault_security.json"))
    }

    @Test fun `the file can make a vault file wipe its stale copy`() {
        val wipes = file(top = ""","vaultFiles":[{"key":"doc","wipeWhenStale":true}]""")
        val vault = parse("""{$api}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}""", wipes)
            .config.vaultFiles.getValue("doc")
        assertTrue(vault.wipeWhenStale)
    }

    @Test fun `a release build with a native file has no expired-config grace unless the file gives one`() {
        refused("""{$api}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}""", file(), "expiredConfigGrace")
        parse("""{$api}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}""", file(top = ""","require":{"expiredConfigGraceSeconds":3600}"""))
    }

    @Test fun `a release build never raises the client certificate lifetime past the file's`() {
        refused("""{$api,"maxClientCertLifetimeDays":3650}]}""", file(), "maxClientCertLifetimeDays", "825")
        assertEquals(30, parse("""{$api,"maxClientCertLifetimeDays":30}]}""").config.configApis.getValue("default").maxClientCertLifetimeDays)
        parse("""{$api,"maxClientCertLifetimeDays":1000}]}""", file(""","maxClientCertLifetimeDays":1000"""))
    }
}
