package com.example.pinvault.server.service.attestation

import com.example.pinvault.server.service.attestation.AppAttestFixtures.APP_ID
import com.example.pinvault.server.service.attestation.AppAttestFixtures.Key
import com.example.pinvault.server.service.attestation.AppAttestFixtures.Pki
import com.example.pinvault.server.service.attestation.AppAttestFixtures.assertion
import com.example.pinvault.server.service.attestation.AppAttestFixtures.attestation
import com.example.pinvault.server.service.attestation.AppAttestFixtures.sha256
import java.io.File
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Apple App Attest on the server (ATTESTATION.md §12) against synthetic
 * fixtures: every check of Apple's list fails on its own with its reason,
 * assertions need the registered key and a rising counter, the CBOR decoder
 * refuses what an App Attest object never holds, and the root is required.
 */
class AppAttestVerifierTest {

    private val pki = Pki()
    private val verifier = pki.verifier()
    private val clientDataHash = AppAttestVerifier.roundClientDataHash("nonce-1", "ios-device")
    private val now = Instant.now()

    private fun assertFails(reason: String, result: AppAttestVerifier.Attestation) {
        assertFalse(result.passed, "expected $reason, got a pass")
        assertEquals(reason, result.reason)
    }

    // ── attestation ──────────────────────────────────────────────────────

    @Test
    fun `a genuine attestation passes and hands back the key and the app id`() {
        val key = Key()
        val result = verifier.verifyAttestation(attestation(pki, key, clientDataHash), key.keyId, clientDataHash, now)
        assertTrue(result.passed, result.reason)
        assertEquals("ok", result.reason)
        assertEquals(APP_ID, result.appId)
        assertContentEquals(key.pair.public.encoded, result.publicKey)
    }

    @Test
    fun `an attestation made for another challenge fails nonce_mismatch`() {
        val key = Key()
        val other = AppAttestVerifier.roundClientDataHash("nonce-2", "ios-device")
        assertFails("nonce_mismatch", verifier.verifyAttestation(attestation(pki, key, other), key.keyId, clientDataHash, now))
        // A leaf whose nonce extension names something else entirely.
        assertFails("nonce_mismatch", verifier.verifyAttestation(attestation(pki, key, clientDataHash, nonceFor = ByteArray(32)), key.keyId, clientDataHash, now))
    }

    @Test
    fun `another app's key fails app_id_mismatch`() {
        val key = Key()
        assertFails("app_id_mismatch", verifier.verifyAttestation(
            attestation(pki, key, clientDataHash, appId = "ZZZZZ99999.com.evil.app"), key.keyId, clientDataHash, now))
        // The same bundle id under another team is another app.
        assertFails("app_id_mismatch", verifier.verifyAttestation(
            attestation(pki, key, clientDataHash, appId = "ZZZZZ99999.${AppAttestFixtures.BUNDLE_ID}"), key.keyId, clientDataHash, now))
        // Any of several configured app ids passes.
        val two = pki.verifier(appIds = setOf(APP_ID, "ZZZZZ99999.com.other"))
        assertTrue(two.verifyAttestation(attestation(pki, key, clientDataHash, appId = "ZZZZZ99999.com.other"), key.keyId, clientDataHash, now).passed)
    }

    @Test
    fun `the aaguid must be the configured environment's`() {
        val key = Key()
        val development = attestation(pki, key, clientDataHash, aaguid = AppAttestVerifier.Environment.DEVELOPMENT.aaguid)
        assertFails("environment_mismatch", verifier.verifyAttestation(development, key.keyId, clientDataHash, now))
        val devVerifier = pki.verifier(environment = AppAttestVerifier.Environment.DEVELOPMENT)
        assertTrue(devVerifier.verifyAttestation(development, key.keyId, clientDataHash, now).passed)
        assertFails("environment_mismatch", devVerifier.verifyAttestation(attestation(pki, key, clientDataHash), key.keyId, clientDataHash, now))
        assertContentEquals("appattest".toByteArray() + ByteArray(7), AppAttestVerifier.Environment.PRODUCTION.aaguid)
        assertContentEquals("appattestdevelop".toByteArray(), AppAttestVerifier.Environment.DEVELOPMENT.aaguid)
    }

    @Test
    fun `a chain to another root fails chain_invalid`() {
        val key = Key()
        val stranger = Pki("CN=Not Apple")
        assertFails("chain_invalid", verifier.verifyAttestation(attestation(stranger, key, clientDataHash), key.keyId, clientDataHash, now))
        // Valid once, but not at a time outside the certificates' validity.
        assertFails("chain_invalid", verifier.verifyAttestation(attestation(pki, key, clientDataHash), key.keyId, clientDataHash,
            Instant.parse("2050-01-01T00:00:00Z")))
    }

    @Test
    fun `key id, counter, credential id and format are each checked`() {
        val key = Key()
        val other = Key()
        // The key id names another key than the leaf's.
        assertFails("key_id_mismatch", verifier.verifyAttestation(attestation(pki, key, clientDataHash), other.keyId, clientDataHash, now))
        assertFails("key_id_mismatch", verifier.verifyAttestation(attestation(pki, key, clientDataHash, leafKey = other.pair.public), key.keyId, clientDataHash, now))
        assertFails("counter_not_zero", verifier.verifyAttestation(attestation(pki, key, clientDataHash, counter = 1), key.keyId, clientDataHash, now))
        assertFails("credential_id_mismatch", verifier.verifyAttestation(attestation(pki, key, clientDataHash, credentialId = other.keyId), key.keyId, clientDataHash, now))
        assertFails("unsupported_format", verifier.verifyAttestation(attestation(pki, key, clientDataHash, fmt = "packed"), key.keyId, clientDataHash, now))
        val good = attestation(pki, key, clientDataHash)
        assertFails("malformed", verifier.verifyAttestation(good + byteArrayOf(0), key.keyId, clientDataHash, now))
        assertFails("malformed", verifier.verifyAttestation(good.copyOf(good.size - 10), key.keyId, clientDataHash, now))
        assertFails("malformed", verifier.verifyAttestation(ByteArray(0), key.keyId, clientDataHash, now))
    }

    // ── assertion ────────────────────────────────────────────────────────

    @Test
    fun `an assertion verifies with the stored key and needs a rising counter`() {
        val key = Key()
        val stored = verifier.verifyAttestation(attestation(pki, key, clientDataHash), key.keyId, clientDataHash, now).publicKey!!
        val round = AppAttestVerifier.roundClientDataHash("nonce-3", "ios-device")
        val first = verifier.verifyAssertion(assertion(key, round, counter = 1), round, stored, storedCounter = 0)
        assertTrue(first.passed, first.reason)
        assertEquals(1L, first.counter)
        // The same counter again (a replay, or a cloned key behind): refused.
        assertEquals("counter_replay", verifier.verifyAssertion(assertion(key, round, counter = 1), round, stored, storedCounter = 1).reason)
        assertEquals("counter_replay", verifier.verifyAssertion(assertion(key, round, counter = 0), round, stored, storedCounter = 0).reason)
        assertTrue(verifier.verifyAssertion(assertion(key, round, counter = 7), round, stored, storedCounter = 1).passed)
    }

    @Test
    fun `an assertion by another key, for another challenge or another app fails`() {
        val key = Key()
        val stored = key.pair.public.encoded
        val round = AppAttestVerifier.roundClientDataHash("nonce-4", "ios-device")
        assertEquals("signature_invalid", verifier.verifyAssertion(assertion(key, round, 1, signer = Key().pair.private), round, stored, 0).reason)
        val other = AppAttestVerifier.roundClientDataHash("nonce-5", "ios-device")
        assertEquals("signature_invalid", verifier.verifyAssertion(assertion(key, other, 1), round, stored, 0).reason)
        assertEquals("app_id_mismatch", verifier.verifyAssertion(assertion(key, round, 1, appId = "ZZZZZ99999.com.evil"), round, stored, 0).reason)
        assertEquals("malformed", verifier.verifyAssertion(byteArrayOf(0xA0.toByte()), round, stored, 0).reason)
    }

    // ── tokens, hashes, CBOR ─────────────────────────────────────────────

    @Test
    fun `the token is the JSON of PORTING section 6`() {
        val key = Key()
        val token = AppAttestVerifier.parseToken(AppAttestFixtures.token(key.keyIdBase64, attestation = byteArrayOf(1, 2)))
        assertNotNull(token)
        assertTrue(token.wellFormed)
        assertContentEquals(key.keyId, token.keyId)
        assertNull(token.assertion)
        assertNull(AppAttestVerifier.parseToken("eyJhbGciOi.not-json"), "a Play Integrity token is not one")
        assertNull(AppAttestVerifier.parseToken("""{"provider":"play-integrity","keyId":"x"}"""))
        assertFalse(AppAttestVerifier.parseToken("""{"provider":"app-attest","keyId":"${key.keyIdBase64}"}""")!!.wellFormed, "neither attestation nor assertion")
        assertFalse(AppAttestVerifier.parseToken("""{"provider":"app-attest","keyId":"AAAA","assertion":"AQI="}""")!!.wellFormed, "a key id is 32 bytes")
        assertFalse(AppAttestVerifier.parseToken(AppAttestFixtures.token(key.keyIdBase64, byteArrayOf(1), byteArrayOf(2)))!!.wellFormed, "not both")
    }

    @Test
    fun `the client data hashes are the ones the iOS library makes`() {
        assertContentEquals(sha256("pinvault-app-attest:v1:n0nce:dev-1".toByteArray()), AppAttestVerifier.roundClientDataHash("n0nce", "dev-1"))
        assertContentEquals(sha256("abc".toByteArray()), AppAttestVerifier.enrollmentClientDataHash("abc"))
    }

    @Test
    fun `the CBOR decoder reads what App Attest uses and refuses the rest`() {
        val encoded = AppAttestFixtures.CborWriter.encode(linkedMapOf("a" to 1L, "b" to listOf(byteArrayOf(9), "x", -5L), "c" to 70_000L))
        val decoded = Cbor.decode(encoded) as Map<*, *>
        assertEquals(1L, decoded["a"])
        assertEquals(70_000L, decoded["c"])
        val list = decoded["b"] as List<*>
        assertContentEquals(byteArrayOf(9), list[0] as ByteArray)
        assertEquals("x", list[1])
        assertEquals(-5L, list[2])
        for (bad in listOf(
            byteArrayOf(0x5F),                                  // indefinite byte string
            byteArrayOf(0x9F.toByte(), 0xFF.toByte()),          // indefinite array
            byteArrayOf(0x01, 0x02),                            // trailing bytes
            byteArrayOf(0x5A, 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()), // a length beyond the input
            byteArrayOf(0xC0.toByte(), 0x01),                   // a tag
            byteArrayOf(0xF5.toByte()),                         // true
            byteArrayOf(0xA2.toByte(), 0x61, 0x61, 0x01, 0x61, 0x61, 0x02), // a repeated key
            byteArrayOf(0x62, 0xC3.toByte(), 0x28),             // invalid UTF-8
            ByteArray(40) { 0x81.toByte() } + byteArrayOf(0x01) // nested too deeply
        )) {
            assertFailsWith<Cbor.Malformed>(bad.joinToString { "%02x".format(it) }) { Cbor.decode(bad) }
        }
    }

    // ── configuration ────────────────────────────────────────────────────

    @Test
    fun `the environment is checked at start and the root is required`() {
        assertNull(AppAttestVerifier.fromEnv(emptyMap()), "off without app ids")
        val missing = assertFailsWith<IllegalStateException> { AppAttestVerifier.fromEnv(mapOf("APP_ATTEST_APP_IDS" to APP_ID)) }
        assertTrue(missing.message!!.contains("APP_ATTEST_ROOT_CA_FILE") && missing.message!!.contains(AppAttestVerifier.ROOT_CA_URL), missing.message)
        val unreadable = assertFailsWith<IllegalStateException> {
            AppAttestVerifier.fromEnv(mapOf("APP_ATTEST_APP_IDS" to APP_ID, "APP_ATTEST_ROOT_CA_FILE" to "/nonexistent/apple-root.pem"))
        }
        assertTrue(unreadable.message!!.contains("/nonexistent/apple-root.pem"), unreadable.message)
        val dir = kotlin.io.path.createTempDirectory("pinvault-appattest-").toFile()
        try {
            val garbage = File(dir, "garbage.pem").apply { writeText("not a certificate") }
            assertFailsWith<IllegalStateException> {
                AppAttestVerifier.fromEnv(mapOf("APP_ATTEST_APP_IDS" to APP_ID, "APP_ATTEST_ROOT_CA_FILE" to garbage.path))
            }
            val root = File(dir, "root.pem").apply { writeText(pki.rootPem()) }
            val env = mapOf("APP_ATTEST_APP_IDS" to " $APP_ID , ZZZZZ99999.com.other ", "APP_ATTEST_ROOT_CA_FILE" to root.path)
            val loaded = assertNotNull(AppAttestVerifier.fromEnv(env))
            assertEquals(setOf(APP_ID, "ZZZZZ99999.com.other"), loaded.appIds)
            assertEquals(AppAttestVerifier.Environment.PRODUCTION, loaded.environment)
            assertEquals(86_400L, loaded.verdictMaxAgeSeconds)
            val key = Key()
            assertTrue(loaded.verifyAttestation(attestation(pki, key, clientDataHash), key.keyId, clientDataHash, now).passed, "the file's root is trusted")
            val dev = AppAttestVerifier.fromEnv(env + mapOf("APP_ATTEST_ENVIRONMENT" to "development", "APP_ATTEST_MAX_AGE_SECONDS" to "3600"))!!
            assertEquals(AppAttestVerifier.Environment.DEVELOPMENT, dev.environment)
            assertEquals(3600L, dev.verdictMaxAgeSeconds)
            assertFailsWith<IllegalArgumentException> { AppAttestVerifier.fromEnv(env + ("APP_ATTEST_ENVIRONMENT" to "sandbox")) }
            assertFailsWith<IllegalArgumentException> { AppAttestVerifier.fromEnv(env + ("APP_ATTEST_MAX_AGE_SECONDS" to "5")) }
            assertFailsWith<IllegalArgumentException> { AppAttestVerifier.fromEnv(env + ("APP_ATTEST_APP_IDS" to AppAttestFixtures.BUNDLE_ID)) }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the iOS rules parse versions and team ids at start`() {
        val rules = IosAttestationRules.fromEnv(mapOf("ATTESTATION_MIN_IOS_VERSION" to "17.4", "ATTESTATION_IOS_TEAM_IDS" to "ABCDE12345, ZZZZZ99999"))
        assertEquals(listOf(17, 4), rules.minOsVersion)
        assertEquals(setOf("ABCDE12345", "ZZZZZ99999"), rules.teamIds)
        assertFalse(rules.osVersionTooOld("26.5"))
        assertFalse(rules.osVersionTooOld("17.4"))
        assertFalse(rules.osVersionTooOld("17.4.1"))
        assertTrue(rules.osVersionTooOld("17.3.9"))
        assertTrue(rules.osVersionTooOld("16"))
        assertTrue(rules.osVersionTooOld(null), "no version is no proof of a new one")
        assertTrue(rules.osVersionTooOld("beta"))
        assertFalse(IosAttestationRules().osVersionTooOld(null), "not configured: not checked")
        assertFailsWith<IllegalArgumentException> { IosAttestationRules.fromEnv(mapOf("ATTESTATION_MIN_IOS_VERSION" to "seventeen")) }
        assertFailsWith<IllegalArgumentException> { IosAttestationRules.fromEnv(mapOf("ATTESTATION_IOS_TEAM_IDS" to "abc")) }
        assertNull(IosAttestationRules.fromEnv(emptyMap()).minOsVersion)
    }
}
