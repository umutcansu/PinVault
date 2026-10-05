package com.example.pinvault.server.service

import com.example.pinvault.server.service.TestAttestationChains.Description
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.chain
import com.example.pinvault.server.service.TestAttestationChains.identityDescription
import com.example.pinvault.server.service.TestAttestationChains.rsa
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.test.*

/**
 * The second attestation profile (client identity keys, ENROLLMENT_ATTESTATION),
 * the user-auth key rules against root running as the app (N1: a time-bound
 * key made in the app's uid after deleting the per-use one), the patch level,
 * and the revocation list that is re-read and can go stale.
 */
class AttestationRulesTest {

    private val pki = Pki()
    private val deviceId = "android-rules"

    private fun ecKey() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun assertRefused(reason: String, verdict: AndroidKeyAttestation.Verdict) {
        assertFalse(verdict.passed, "expected $reason, got a pass")
        assertEquals(reason, verdict.reason)
    }

    // ── identity keys ────────────────────────────────────────────────────

    @Test
    fun `the identity challenge is SHA-256 of its own prefix and the device id`() {
        val expected = MessageDigest.getInstance("SHA-256").digest("pinvault-identity-key:v1:$deviceId".toByteArray(Charsets.UTF_8))
        assertContentEquals(expected, AndroidKeyAttestation.identityChallengeFor(deviceId))
        assertFalse(AndroidKeyAttestation.identityChallengeFor(deviceId).contentEquals(AndroidKeyAttestation.challengeFor(deviceId)),
            "a user-auth key's attestation never passes as an identity key's, and back")
    }

    @Test
    fun `an identity key passes as a hardware signing key with no user auth`() {
        val key = ecKey()
        val verdict = pki.verifier().verifyIdentityKey(chain(pki, key.public, identityDescription(deviceId)), key.public, deviceId)
        assertTrue(verdict.passed, verdict.reason)
        assertEquals("tee", verdict.securityLevel)
        assertNull(verdict.keyKind, "a kind is a user-auth key's")
        // StrongBox too.
        val strongBox = identityDescription(deviceId).copy(attestationLevel = 2, keyMintLevel = 2)
        assertEquals("strongbox", pki.verifier().verifyIdentityKey(chain(pki, key.public, strongBox), key.public, deviceId).securityLevel)
    }

    @Test
    fun `an identity key is refused for the wrong challenge, purpose, key, origin, level or app`() {
        val key = ecKey()
        val verifier = pki.verifier()
        fun verify(d: Description, submitted: java.security.PublicKey = key.public) =
            verifier.verifyIdentityKey(chain(pki, key.public, d), submitted, deviceId)
        val good = identityDescription(deviceId)
        // A user-auth challenge, or another device's identity challenge.
        assertRefused("challenge_mismatch", verify(good.copy(challenge = AndroidKeyAttestation.challengeFor(deviceId))))
        assertRefused("challenge_mismatch", verify(good.copy(challenge = AndroidKeyAttestation.identityChallengeFor("other"))))
        // An encryption key is not a signing key.
        assertRefused("purpose_not_sign", verify(good.copy(purposes = listOf(0, 1))))
        // The CSR's key must be the attested one.
        assertRefused("key_mismatch", verify(good, submitted = ecKey().public))
        assertRefused("origin_not_generated", verify(good.copy(origin = 2)))
        assertRefused("software_attestation", verify(good.copy(attestationLevel = 0)))
        assertRefused("device_unlocked", verify(good.copy(deviceLocked = false)))
        assertRefused("package_not_allowed", verify(good.copy(packages = listOf("com.evil"))))
        assertRefused("signer_not_allowed", verify(good.copy(signers = listOf(ByteArray(32) { 3 }))))
        // A user-auth key's chain (DECRYPT, needs the user) is no identity key.
        val userAuth = rsa()
        assertRefused("challenge_mismatch",
            verifier.verifyIdentityKey(chain(pki, userAuth.public, Description(deviceId)), userAuth.public, deviceId))
    }

    // ── user-auth keys: root running as the app (N1) ─────────────────────

    @Test
    fun `from Android 11 on a time-bound user-auth key is refused, before it only up to 10 seconds`() {
        val key = rsa()
        val verifier = pki.verifier()
        fun verify(d: Description) = verifier.verify(chain(pki, key.public, d), key.public, deviceId)
        // Android 11+: the library makes per-use keys only; 10 s there is root's key.
        assertRefused("time_bound_key", verify(Description(deviceId, authTimeout = 10, osVersion = 110000)))
        assertRefused("time_bound_key", verify(Description(deviceId, authTimeout = 1, osVersion = 140000)))
        // A per-use key passes everywhere; 0 is per use.
        val perUse = verify(Description(deviceId, osVersion = 140000))
        assertTrue(perUse.passed, perUse.reason)
        assertEquals(AndroidKeyAttestation.KeyKind(perUse = true, timeoutSeconds = null, biometricOnly = true), perUse.keyKind)
        assertEquals("per_use", perUse.keyKind!!.name)
        assertTrue(verify(Description(deviceId, authTimeout = 0, osVersion = 120000)).passed)
        // Android 7–10: the library's 10 s window passes, and is told as such.
        val legacy = verify(Description(deviceId, authTimeout = 10, osVersion = 100000, userAuthTypeValue = 3))
        assertTrue(legacy.passed, legacy.reason)
        assertEquals(AndroidKeyAttestation.KeyKind(perUse = false, timeoutSeconds = 10, biometricOnly = false), legacy.keyKind)
        assertEquals("time_bound", legacy.keyKind!!.name)
        assertRefused("auth_timeout_too_long", verify(Description(deviceId, authTimeout = 11, osVersion = 100000)))
    }

    @Test
    fun `USER_AUTH_REQUIRE_PER_USE refuses any time-bound key on every version`() {
        val key = rsa()
        val strict = pki.verifier(requirePerUse = true)
        assertRefused("time_bound_key", strict.verify(chain(pki, key.public, Description(deviceId, authTimeout = 10, osVersion = 90000)), key.public, deviceId))
        assertRefused("time_bound_key", strict.verify(chain(pki, key.public, Description(deviceId, authTimeout = 5)), key.public, deviceId))
        assertTrue(strict.verify(chain(pki, key.public, Description(deviceId, osVersion = 90000)), key.public, deviceId).passed)
        // Identity keys have no user-auth rules: per-use does not touch them.
        val identity = ecKey()
        assertTrue(strict.verifyIdentityKey(chain(pki, identity.public, identityDescription(deviceId)), identity.public, deviceId).passed)
    }

    @Test
    fun `both lists count - noAuthRequired or a long timeout in the software list, allowWhileOnBody anywhere`() {
        val key = rsa()
        val verifier = pki.verifier()
        fun verify(d: Description) = verifier.verify(chain(pki, key.public, d), key.public, deviceId)
        assertRefused("no_user_auth", verify(Description(deviceId, softwareNoAuthRequired = true)))
        assertRefused("auth_timeout_too_long", verify(Description(deviceId, softwareAuthTimeout = 3600)))
        assertRefused("time_bound_key", verify(Description(deviceId, softwareAuthTimeout = 5, osVersion = 110000)))
        assertRefused("allow_while_on_body", verify(Description(deviceId, allowWhileOnBody = true)))
    }

    @Test
    fun `ATTESTATION_MIN_PATCH_LEVEL refuses an older or missing security patch`() {
        val key = rsa()
        val verifier = pki.verifier(minPatchLevel = 202401)
        fun verify(d: Description) = verifier.verify(chain(pki, key.public, d), key.public, deviceId)
        assertRefused("patch_level_too_old", verify(Description(deviceId, osPatchLevel = 202312)))
        assertRefused("patch_level_too_old", verify(Description(deviceId)))
        assertTrue(verify(Description(deviceId, osPatchLevel = 202401)).passed)
        assertTrue(verify(Description(deviceId, osPatchLevel = 202509)).passed)
        // Not configured: not checked.
        assertTrue(pki.verifier().verify(chain(pki, key.public, Description(deviceId)), key.public, deviceId).passed)

        assertNull(AndroidKeyAttestation.parsePatchLevel(null))
        assertNull(AndroidKeyAttestation.parsePatchLevel(" "))
        assertEquals(202401, AndroidKeyAttestation.parsePatchLevel("202401"))
        for (bad in listOf("2024-01", "20241", "202413", "202400", "19991", "abcdef")) {
            assertFailsWith<IllegalArgumentException>(bad) { AndroidKeyAttestation.parsePatchLevel(bad) }
        }
    }

    // ── the revocation list ──────────────────────────────────────────────

    private fun statusJson(vararg revoked: String) =
        """{"entries":{${revoked.joinToString(",") { "\"$it\":{\"status\":\"REVOKED\",\"reason\":\"KEY_COMPROMISE\"}" }}}}"""

    private fun intermediateSerial(): String =
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(Base64.getDecoder().decode(chain(pki, rsa().public, Description(deviceId))[1]).inputStream())
            .let { (it as java.security.cert.X509Certificate).serialNumber.toString(16) }

    @Test
    fun `the revocation list is re-read when the file changes, no more often than its interval`() {
        val dir = createTempDir()
        try {
            val file = File(dir, "status.json").apply { writeText(statusJson("abc")) }
            var now = Instant.now()
            val list = RevocationList(file, checkInterval = Duration.ofMinutes(10), clock = { now })
            val verifier = pki.verifier(revocationList = list)
            val key = rsa()
            val chain = chain(pki, key.public, Description(deviceId))
            assertTrue(verifier.verify(chain, key.public, deviceId).passed)
            assertEquals(setOf("abc"), verifier.revokedSerials)

            // The cron job replaces the file: Google revoked the intermediate.
            file.writeText(statusJson(intermediateSerial()))
            file.setLastModified(System.currentTimeMillis() + 5_000)
            now = now.plus(Duration.ofMinutes(5))
            assertTrue(verifier.verify(chain, key.public, deviceId).passed, "not looked at again before the interval")
            now = now.plus(Duration.ofMinutes(6))
            assertRefused("certificate_revoked", verifier.verify(chain, key.public, deviceId))

            // A broken download keeps the list read before.
            file.writeText("{not json")
            file.setLastModified(System.currentTimeMillis() + 10_000)
            now = now.plus(Duration.ofMinutes(11))
            assertRefused("certificate_revoked", verifier.verify(chain, key.public, deviceId))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `an old revocation list lets no attestation pass when ATTESTATION_STATUS_MAX_AGE_HOURS is set`() {
        val dir = createTempDir()
        try {
            val file = File(dir, "status.json").apply { writeText(statusJson()) }
            file.setLastModified(System.currentTimeMillis() - Duration.ofHours(30).toMillis())
            val list = RevocationList(file, maxAge = Duration.ofHours(25), checkInterval = Duration.ZERO)
            val verifier = pki.verifier(revocationList = list)
            val key = rsa()
            assertRefused("revocation_list_stale", verifier.verify(chain(pki, key.public, Description(deviceId)), key.public, deviceId))
            val identity = ecKey()
            assertRefused("revocation_list_stale",
                verifier.verifyIdentityKey(chain(pki, identity.public, identityDescription(deviceId)), identity.public, deviceId))
            // The job ran again.
            file.setLastModified(System.currentTimeMillis())
            assertTrue(verifier.verify(chain(pki, key.public, Description(deviceId)), key.public, deviceId).passed)
            // No maximum age: never stale.
            file.setLastModified(System.currentTimeMillis() - Duration.ofDays(400).toMillis())
            assertFalse(RevocationList(file).isStale())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the environment is checked at start`() {
        assertFailsWith<IllegalStateException> {
            AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_STATUS_MAX_AGE_HOURS" to "48"))
        }
        assertFailsWith<IllegalArgumentException> {
            AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_STATUS_MAX_AGE_HOURS" to "two days"))
        }
        assertFailsWith<IllegalArgumentException> { AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_MIN_PATCH_LEVEL" to "2024")) }
        assertFailsWith<IllegalStateException> {
            AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_REVOKED_SERIALS_FILE" to "/nonexistent/status.json"))
        }
        val defaults = AndroidKeyAttestation.fromEnv(emptyMap())
        assertFalse(defaults.requirePerUse)
        assertNull(defaults.minPatchLevel)
        assertNull(defaults.revocationListFile)
        val strict = AndroidKeyAttestation.fromEnv(mapOf("USER_AUTH_REQUIRE_PER_USE" to "true", "ATTESTATION_MIN_PATCH_LEVEL" to "202501"))
        assertTrue(strict.requirePerUse)
        assertEquals(202501, strict.minPatchLevel)
    }

    // ── ENROLLMENT_ATTESTATION ───────────────────────────────────────────

    @Test
    fun `the enrollment mode parses strictly and enforce needs the app binding`() {
        assertEquals(EnrollmentAttestationMode.WARN, EnrollmentAttestationMode.parse(null))
        assertEquals(EnrollmentAttestationMode.ENFORCE, EnrollmentAttestationMode.parse(" ENFORCE "))
        assertEquals(EnrollmentAttestationMode.OFF, EnrollmentAttestationMode.parse("off"))
        assertFailsWith<IllegalArgumentException> { EnrollmentAttestationMode.parse("strict") }
        val unbound = pki.verifier(signerDigests = emptySet())
        val refused = assertFailsWith<IllegalStateException> { EnrollmentAttestationMode.startupCheck(EnrollmentAttestationMode.ENFORCE, unbound) }
        assertTrue(refused.message!!.contains("ATTESTATION_SIGNER_SHA256"), refused.message)
        assertNotNull(EnrollmentAttestationMode.startupCheck(EnrollmentAttestationMode.WARN, unbound))
        assertNull(EnrollmentAttestationMode.startupCheck(EnrollmentAttestationMode.ENFORCE, pki.verifier()))
        assertNull(EnrollmentAttestationMode.startupCheck(EnrollmentAttestationMode.OFF, unbound))
    }

    @Suppress("DEPRECATION")
    private fun createTempDir(): File = kotlin.io.createTempDir("pinvault-att-")
}
