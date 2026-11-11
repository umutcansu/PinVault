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
