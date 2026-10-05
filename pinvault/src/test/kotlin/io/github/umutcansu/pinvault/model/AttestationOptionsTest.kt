package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.integrity.IntegrityVerdict
import io.github.umutcansu.pinvault.integrity.IntegrityVerdictProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.TimeUnit

/** The attestation options on the builders, and the public status types. */
class AttestationOptionsTest {

    private fun block(init: ConfigApiBlock.Builder.() -> Unit = {}) =
        ConfigApiBlock.Builder("api", "https://config.example.com:8091").allowUnpinnedConfigApi().allowUnsigned().apply(init).build()

    @Test
    fun `attestation is off by default, with a five minute interval and no token hosts`() {
        val plain = block()
        assertFalse(plain.attestationEnabled)
        assertEquals(5L * 60_000, plain.attestationIntervalMs)
        assertTrue(plain.tokenHosts.isEmpty())

        val attesting = block { attestation(); attestationInterval(2, TimeUnit.MINUTES); tokenHosts("API.Example.com", "*.cdn.example.com:443") }
        assertTrue(attesting.attestationEnabled)
        assertEquals(120_000L, attesting.attestationIntervalMs)
        assertEquals(listOf("api.example.com", "*.cdn.example.com:443"), attesting.tokenHosts)
        assertEquals(listOf("api.example.com"), block { tokenHosts(listOf("api.example.com", "api.example.com")) }.tokenHosts)
    }

    @Test
    fun `the interval is at least a minute`() {
        try {
            block { attestationInterval(59, TimeUnit.SECONDS) }
            fail("expected a refusal")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("1 minute"))
        }
        assertEquals(60_000L, block { attestationInterval(60, TimeUnit.SECONDS) }.attestationIntervalMs)
    }

    @Test
    fun `token hosts are host patterns`() {
        for (bad in listOf("https://api.example.com/", "*.com", "api example.com", "")) {
            try {
                block { tokenHosts(bad) }
                fail("'$bad' should be refused")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message, e.message!!.startsWith("tokenHosts:"))
            }
        }
    }

    @Test
    fun `the new fields take part in equals and hashCode`() {
        val a = block { attestation() }
        val b = block { attestation() }
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, block())
        assertNotEquals(a, block { attestation(); tokenHosts("api.example.com") })
        assertNotEquals(a, block { attestation(); attestationInterval(1, TimeUnit.MINUTES) })
    }

    @Test
    fun `expected signer digests are normalised, and the verdict provider is kept`() {
        val provider = object : IntegrityVerdictProvider {
            override suspend fun verdict(nonce: String): IntegrityVerdict? = null
        }
        val config = PinVaultConfig.Builder()
            .configApi("api", "https://config.example.com") { allowUnpinnedConfigApi(); allowUnsigned(); attestation() }
            .expectedSignerSha256("3C:4F:" + "AB:".repeat(29) + "AB", "a".repeat(64), "A".repeat(64))
            .integrityVerdictProvider(provider)
            .build()
        assertEquals(listOf("3c4f" + "ab".repeat(30), "a".repeat(64)), config.expectedSignerSha256)
        assertSame(provider, config.integrityVerdictProvider)
        assertTrue(config.defaultConfigApi!!.attestationEnabled)

        try {
            PinVaultConfig.Builder().expectedSignerSha256("not hex")
            fail("expected a refusal")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("expectedSignerSha256"))
        }
        assertTrue(PinVaultConfig.Builder().configApi("api", "https://c.example.com") { allowUnpinnedConfigApi(); allowUnsigned() }.build().expectedSignerSha256.isEmpty())
        assertNull(PinVaultConfig.Builder().configApi("api", "https://c.example.com") { allowUnpinnedConfigApi(); allowUnsigned() }.build().integrityVerdictProvider)
    }

    @Test
    fun `a status has a valid token only after a pass that has not expired`() {
        val passed = AttestationStatus("api", AttestationResult.PASS, tokenExpiresAt = 2_000L)
        assertTrue(passed.hasValidToken(now = 1_000L))
        assertFalse(passed.hasValidToken(now = 2_000L))
        assertFalse(AttestationStatus("api", AttestationResult.REJECT, tokenExpiresAt = 2_000L).hasValidToken(1_000L))
        assertFalse(AttestationStatus("api", AttestationResult.NOT_ATTESTED).hasValidToken(1_000L))
        assertEquals("NOT_ATTESTED defaults", emptyList<String>(), AttestationStatus("api", AttestationResult.NOT_ATTESTED).rejectionReasons)
    }

    @Test
    fun `token results never print the token`() {
        val token = AttestationTokenResult.Token("eyJ.secret", 5L)
        assertFalse(token.toString().contains("secret"))
        assertEquals("eyJ.secret", token.value)
        assertEquals(token, AttestationTokenResult.Token("eyJ.secret", 5L))
        assertEquals("Unsupported", AttestationTokenResult.Unsupported.toString())
        assertFalse(IntegrityVerdict("play-integrity", "tok").toString().contains("tok"))
    }
}
