package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.SignedConfigSource
import io.github.umutcansu.pinvault.internal.ConfigApiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The rules a Config API block is held to at init, whichever way it was
 * built: https, bootstrap pins, and — when it has signing keys — configs that
 * are really verified.
 */
class ConfigApiBlockRulesTest {

    private val pins = listOf(HostPin("config.example.com", listOf("A".repeat(43) + "=", "B".repeat(43) + "=")))
    private val key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"

    private fun builder(url: String = "https://config.example.com") =
        ConfigApiBlock.Builder("api", url).bootstrapPins(pins).signaturePublicKey(key)

    private open class PlainApi : CertificateConfigApi {
        override suspend fun healthCheck() = true
        override suspend fun fetchConfig(currentVersion: Int): CertificateConfig = CertificateConfig(pins = emptyList())
        override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
        override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
        override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) =
            EnrollmentResult(ByteArray(0), null)
    }

    private class EnvelopeApi : PlainApi(), SignedConfigSource {
        override suspend fun fetchSignedConfig(currentVersion: Int) = SignedConfigResponse("{}", "")
    }

    // ── https and bootstrap pins ────────────────────────────────────────

    @Test
    fun `a block built with the constructor is held to the same rules as the builder`() {
        // The data-class constructor has no checks of its own.
        val noPins = ConfigApiBlock(id = "api", configUrl = "https://config.example.com/", bootstrapPins = emptyList())
        assertTrue(noPins.configurationError()!!.contains("bootstrapPins"))

        val http = ConfigApiBlock(id = "api", configUrl = "http://config.example.com/", bootstrapPins = pins)
        assertTrue(http.configurationError()!!.contains("configUrl must be an https:// URL"))

        assertNull(ConfigApiBlock(id = "api", configUrl = "https://config.example.com/", bootstrapPins = pins).configurationError())
        assertNull(ConfigApiBlock(id = "api", configUrl = "HTTPS://config.example.com/", bootstrapPins = pins).configurationError())
    }

    @Test
    fun `enrollment and renewal URLs must be https too`() {
        assertTrue(builder().enrollmentUrl("http://config.example.com:8091").build().configurationError()!!.contains("enrollmentUrl"))
        assertTrue(builder().renewalUrl("http://config.example.com:8093").build().configurationError()!!.contains("renewalUrl"))
        assertNull(builder().enrollmentUrl("https://config.example.com:8091").renewalUrl("https://config.example.com:8093").build().configurationError())
    }

    @Test
    fun `allowUnpinnedConfigApi is the explicit way out`() {
        val block = ConfigApiBlock.Builder("api", "http://10.0.2.2:8090").allowUnsigned().allowUnpinnedConfigApi().build()
        assertTrue(block.allowUnpinnedConfigApi)
        assertNull(block.configurationError())

        // The PinVaultConfig builder accepts a block without pins only with it.
        PinVaultConfig.Builder().configApi("api", "http://10.0.2.2:8090") { allowUnsigned(); allowUnpinnedConfigApi() }.build()
        try {
            PinVaultConfig.Builder().configApi("api", "https://config.example.com") { allowUnsigned() }.build()
            fail("bootstrap pins are required")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("bootstrapPins"))
        }
    }

    // ── serverScope ─────────────────────────────────────────────────────

    @Test
    fun `serverScope is carried on the block and off by default`() {
        assertNull(builder().build().serverScope)
        val block = builder().serverScope(" default-tls ").build()
        assertEquals("default-tls", block.serverScope)
        assertFalse(block == builder().build())
        try {
            builder().serverScope("  ")
            fail("a blank scope is a mistake")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    // ── A block that looks signed is verified, or says it is not ────────

    @Test
    fun `signing keys with a custom API that has no envelopes is refused`() {
        val error = ConfigApiClient.configurationError(builder().build(), PlainApi())
        assertNotNull(error)
        assertTrue(error, error!!.contains("SignedConfigSource") && error.contains("allowUnsigned()"))
    }

    @Test
    fun `a custom API that hands over envelopes is accepted`() {
        assertNull(ConfigApiClient.configurationError(builder().build(), EnvelopeApi()))
    }

    @Test
    fun `allowUnsigned accepts the unverified custom API, in the app's own words`() {
        assertNull(ConfigApiClient.configurationError(builder().allowUnsigned().build(), PlainApi()))
        // No signing keys at all: nothing looks signed.
        val unsigned = ConfigApiBlock.Builder("api", "https://config.example.com").bootstrapPins(pins).allowUnsigned().build()
        assertNull(ConfigApiClient.configurationError(unsigned, PlainApi()))
    }

    @Test
    fun `the library's own client needs nothing extra`() {
        assertNull(ConfigApiClient.configurationError(builder().build(), null))
        // The block's own rules still come first.
        assertNotNull(ConfigApiClient.configurationError(builder("http://config.example.com").build(), null))
    }

    // ── clientCertHosts ──────────────────────────────────────────────────

    @Test
    fun `clientCertHosts takes host-port or https URLs and nothing without a port`() {
        val block = builder().clientCertHosts("api.example.com:8092", "https://mtls.example.com:9443/").build()
        assertEquals(listOf("https://api.example.com:8092/", "https://mtls.example.com:9443/"), block.clientCertHosts)
        for (bad in listOf("api.example.com", "http://api.example.com:80/", "https://api.example.com/")) {
            try {
                builder().clientCertHosts(bad)
                fail("accepted $bad")
            } catch (expected: IllegalArgumentException) {
            }
        }
    }
}
