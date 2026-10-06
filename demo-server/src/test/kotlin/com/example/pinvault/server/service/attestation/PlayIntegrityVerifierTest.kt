package com.example.pinvault.server.service.attestation

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [PlayIntegrityVerifier]: a Google-shaped token opened with the Play Console keys, every check and its reason. */
class PlayIntegrityVerifierTest {

    private val keys = PlayIntegrityTokens()
    private val now: Instant = Instant.parse("2026-10-06T10:00:00Z")
    private val nonce = "n5qZ3cJ9Qm3y5gL0bU6W2A-pQx1dS7kR9tV4wXyZ0aBcDeFgHiJkLmNo"

    private fun fresh() = keys.payload(nonce, now.toEpochMilli() - 5_000)

    @Test
    fun `a genuine token for this nonce passes and is summarised without the token`() {
        val result = keys.verifier().verify(keys.token(fresh()), nonce, now)
        assertTrue(result.passed, result.toString())
        assertEquals("ok", result.reason)
        val summary = result.summary
        assertEquals("PLAY_RECOGNIZED", summary["appVerdict"]!!.jsonPrimitive.content)
        assertEquals(PlayIntegrityTokens.PACKAGE, summary["packageName"]!!.jsonPrimitive.content)
        assertEquals("LICENSED", summary["licensing"]!!.jsonPrimitive.content)
        assertEquals(listOf("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"), (summary["deviceVerdicts"] as JsonArray).map { (it as JsonPrimitive).content })
        assertEquals(now.toString(), summary["verifiedAt"]!!.jsonPrimitive.content)
        assertFalse(summary.toString().contains(nonce), "the nonce is not stored")
        assertNull(summary["token"])
    }

    @Test
    fun `the nonce inside the signed payload must be this round's`() {
        val result = keys.verifier().verify(keys.token(fresh()), "another-nonce-of-the-right-shape-AAAAAAAAAAAAAAAA", now)
        assertFalse(result.passed)
        assertEquals("nonce_mismatch", result.reason)
    }

    @Test
    fun `a token older than the allowed age, or from the future, is stale`() {
        val verifier = keys.verifier(tokenMaxAgeSeconds = 600)
        assertEquals("token_stale", verifier.verify(keys.token(keys.payload(nonce, now.toEpochMilli() - 601_000)), nonce, now).reason)
        assertEquals("token_stale", verifier.verify(keys.token(keys.payload(nonce, now.toEpochMilli() + 120_000)), nonce, now).reason)
        assertTrue(verifier.verify(keys.token(keys.payload(nonce, now.toEpochMilli() - 599_000)), nonce, now).passed)
    }

    @Test
    fun `another package's verdict is refused when packages are configured`() {
        val other = keys.payload(nonce, now.toEpochMilli(), packageName = "com.other.app")
        assertEquals("package_mismatch", keys.verifier().verify(keys.token(other), nonce, now).reason)
        assertTrue(keys.verifier(packageNames = emptySet()).verify(keys.token(other), nonce, now).passed, "no package list = any package")
    }

    @Test
    fun `an app Google does not recognise fails unless the server does not care`() {
        val sideloaded = keys.payload(nonce, now.toEpochMilli(), appVerdict = "UNRECOGNIZED_VERSION")
        assertEquals("app_unrecognized", keys.verifier().verify(keys.token(sideloaded), nonce, now).reason)
        assertTrue(keys.verifier(requireAppRecognized = false).verify(keys.token(sideloaded), nonce, now).passed)
    }

    @Test
    fun `the device verdict must reach the configured level`() {
        val basicOnly = keys.token(keys.payload(nonce, now.toEpochMilli(), deviceVerdicts = listOf("MEETS_BASIC_INTEGRITY")))
        val strong = keys.token(keys.payload(nonce, now.toEpochMilli(), deviceVerdicts = listOf("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY")))
        val none = keys.token(keys.payload(nonce, now.toEpochMilli(), deviceVerdicts = emptyList()))
        assertEquals("device_integrity", keys.verifier().verify(basicOnly, nonce, now).reason)
        assertTrue(keys.verifier(deviceLevel = PlayIntegrityVerifier.DeviceLevel.BASIC).verify(basicOnly, nonce, now).passed)
        assertTrue(keys.verifier(deviceLevel = PlayIntegrityVerifier.DeviceLevel.STRONG).verify(strong, nonce, now).passed)
        assertEquals("device_integrity", keys.verifier(deviceLevel = PlayIntegrityVerifier.DeviceLevel.STRONG).verify(keys.token(fresh()), nonce, now).reason)
        assertEquals("device_integrity", keys.verifier(deviceLevel = PlayIntegrityVerifier.DeviceLevel.BASIC).verify(none, nonce, now).reason)
        // The failure summary still tells the operator what Google said.
        val summary = keys.verifier().verify(basicOnly, nonce, now).summary
        assertEquals(listOf("MEETS_BASIC_INTEGRITY"), (summary["deviceVerdicts"] as JsonArray).map { (it as JsonPrimitive).content })
    }

    @Test
    fun `a token signed with another key, or wrapped with another key, does not open`() {
        val otherSigner = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        assertEquals("signature_invalid", keys.verifier().verify(keys.token(fresh(), signer = otherSigner), nonce, now).reason)
        val otherWrap = ByteArray(32) { 7 }
        assertEquals("decrypt_failed", keys.verifier().verify(keys.token(fresh(), wrapKey = otherWrap), nonce, now).reason)
    }

    @Test
    fun `garbage and unexpected algorithms are refused with a fixed reason`() {
        val verifier = keys.verifier()
        assertEquals("malformed", verifier.verify("not-a-token", nonce, now).reason)
        assertEquals("malformed", verifier.verify("a.b.c.d.e", nonce, now).reason)
        assertEquals("unsupported_alg", verifier.verify(keys.encrypt("x.y.z", alg = "dir"), nonce, now).reason)
        assertEquals("unsupported_alg", verifier.verify(keys.encrypt(keys.sign(fresh().toString(), alg = "HS256")), nonce, now).reason)
        assertEquals("payload_invalid", verifier.verify(keys.encrypt(keys.sign("[]")), nonce, now).reason)
        assertEquals("payload_invalid", verifier.verify(keys.encrypt(keys.sign("""{"appIntegrity":{}}""")), nonce, now).reason)
    }

    @Test
    fun `fromEnv needs both keys, honours the switch and the knobs`() {
        assertNull(PlayIntegrityVerifier.fromEnv(emptyMap()), "nothing configured = off")
        assertNull(PlayIntegrityVerifier.fromEnv(mapOf(
            "PLAY_INTEGRITY_ENABLED" to "false",
            "PLAY_INTEGRITY_DECRYPTION_KEY" to keys.decryptionKeyBase64,
            "PLAY_INTEGRITY_VERIFICATION_KEY" to keys.verificationKeyBase64
        )), "the switch wins over the keys")
        assertFailsWith<IllegalStateException> { PlayIntegrityVerifier.fromEnv(mapOf("PLAY_INTEGRITY_ENABLED" to "true")) }
        assertFailsWith<IllegalStateException> { PlayIntegrityVerifier.fromEnv(mapOf("PLAY_INTEGRITY_DECRYPTION_KEY" to keys.decryptionKeyBase64)) }
        assertFailsWith<IllegalArgumentException> {
            PlayIntegrityVerifier.fromEnv(mapOf(
                "PLAY_INTEGRITY_DECRYPTION_KEY" to Base64.getEncoder().encodeToString(ByteArray(16)),
                "PLAY_INTEGRITY_VERIFICATION_KEY" to keys.verificationKeyBase64
            ))
        }
        val verifier = PlayIntegrityVerifier.fromEnv(mapOf(
            "PLAY_INTEGRITY_DECRYPTION_KEY" to keys.decryptionKeyBase64,
            "PLAY_INTEGRITY_VERIFICATION_KEY" to keys.verificationKeyBase64,
            "PLAY_INTEGRITY_DEVICE_LEVEL" to "strong",
            "PLAY_INTEGRITY_REQUIRE_APP_RECOGNIZED" to "false",
            "PLAY_INTEGRITY_TOKEN_MAX_AGE_SECONDS" to "120",
            "PLAY_INTEGRITY_MAX_AGE_SECONDS" to "3600"
        ), fallbackPackageNames = setOf("com.fallback"))
        assertNotNull(verifier)
        assertEquals(PlayIntegrityVerifier.DeviceLevel.STRONG, verifier.deviceLevel)
        assertFalse(verifier.requireAppRecognized)
        assertEquals(120L, verifier.tokenMaxAgeSeconds)
        assertEquals(3600L, verifier.verdictMaxAgeSeconds)
        assertEquals(setOf("com.fallback"), verifier.packageNames, "ATTESTATION_PACKAGE_NAMES is the fallback")
        val own = PlayIntegrityVerifier.fromEnv(mapOf(
            "PLAY_INTEGRITY_DECRYPTION_KEY" to keys.decryptionKeyBase64,
            "PLAY_INTEGRITY_VERIFICATION_KEY" to keys.verificationKeyBase64,
            "PLAY_INTEGRITY_PACKAGE_NAMES" to "com.a, com.b"
        ), fallbackPackageNames = setOf("com.fallback"))!!
        assertEquals(setOf("com.a", "com.b"), own.packageNames)
        // The real token of the configured verifier opens.
        assertTrue(own.verify(keys.token(keys.payload(nonce, now.toEpochMilli(), packageName = "com.a")), nonce, now).passed)
    }
}
