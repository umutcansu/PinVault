package com.example.pinvault.server.service

import com.example.pinvault.server.service.TestAttestationChains.Description
import com.example.pinvault.server.service.TestAttestationChains.Pki
import com.example.pinvault.server.service.TestAttestationChains.chain
import com.example.pinvault.server.service.TestAttestationChains.rsa
import java.security.MessageDigest
import java.util.Base64
import java.util.Date
import kotlin.test.*

/**
 * Android Key Attestation of user-auth keys, against chains built here with a
 * fake root injected in place of the Google roots.
 */
class AndroidKeyAttestationTest {

    private val deviceId = "android-att"
    private val pki = Pki()
    private val verifier = pki.verifier()
    private val key = rsa()

    private fun verify(
        description: Description = Description(deviceId),
        chain: List<String>? = chain(pki, key.public, description),
        submitted: java.security.PublicKey = key.public,
        with: AndroidKeyAttestation = verifier
    ) = with.verify(chain, submitted, deviceId)

    private fun assertRefused(reason: String, verdict: AndroidKeyAttestation.Verdict) {
        assertFalse(verdict.passed, "expected $reason, got a pass")
        assertEquals(reason, verdict.reason)
    }

    @Test
    fun `a hardware key that needs the user, made by the app on a locked device, passes`() {
        val verdict = verify()
        assertTrue(verdict.passed, verdict.reason)
        assertEquals("ok", verdict.reason)
        assertEquals("tee", verdict.securityLevel)
        val strongBox = verify(Description(deviceId, attestationLevel = 2, keyMintLevel = 2))
        assertTrue(strongBox.passed, strongBox.reason)
        assertEquals("strongbox", strongBox.securityLevel)
        // Keymaster 3 and 4 (versions 3, 4) and KeyMint 1–4 (100–400) read the same way.
        for (version in listOf(3, 4, 100, 300, 400)) assertTrue(verify(Description(deviceId, version = version)).passed, "v$version")
        // A chain that stops below the root is fine when the root signed its last link.
        assertTrue(verify(chain = chain(pki, key.public, Description(deviceId), includeRoot = false)).passed)
    }

    @Test
    fun `the challenge is SHA-256 of the agreed prefix and the device id`() {
        val expected = MessageDigest.getInstance("SHA-256").digest("pinvault-user-auth-key:v1:$deviceId".toByteArray(Charsets.UTF_8))
        assertContentEquals(expected, AndroidKeyAttestation.challengeFor(deviceId))
        assertEquals(32, expected.size)
        assertRefused("challenge_mismatch", verify(Description(deviceId, challenge = AndroidKeyAttestation.challengeFor("someone-else"))))
    }

    @Test
    fun `a software key or software KeyMint is refused`() {
        assertRefused("software_attestation", verify(Description(deviceId, attestationLevel = 0)))
        assertRefused("software_attestation", verify(Description(deviceId, keyMintLevel = 0)))
    }

    @Test
    fun `a key that does not need the user is refused`() {
        assertRefused("no_user_auth", verify(Description(deviceId, noAuthRequired = true)))
        assertRefused("no_user_auth", verify(Description(deviceId, userAuthType = false)))
    }

    @Test
    fun `purpose, origin and boot state are checked`() {
        assertRefused("purpose_not_decrypt", verify(Description(deviceId, purposes = listOf(2, 3))))
        assertRefused("origin_not_generated", verify(Description(deviceId, origin = 2)))
        assertRefused("device_unlocked", verify(Description(deviceId, deviceLocked = false)))
        assertRefused("boot_not_verified", verify(Description(deviceId, verifiedBootState = 2)))
        assertRefused("root_of_trust_missing", verify(Description(deviceId, rootOfTrust = false)))
        // ATTESTATION_REQUIRE_VERIFIED_BOOT=false: an unlocked test device passes.
        val lenient = AndroidKeyAttestation(listOf(pki.root), setOf(TestAttestationChains.PACKAGE), requireVerifiedBoot = false)
        assertTrue(verify(Description(deviceId, deviceLocked = false), with = lenient).passed)
    }

    @Test
    fun `the package and signer must be the app's`() {
        assertRefused("package_not_allowed", verify(Description(deviceId, packages = listOf("com.evil.reader"))))
        assertRefused("signer_not_allowed", verify(Description(deviceId, signers = listOf(ByteArray(32) { 9 }))))
        // Not configured: not checked.
        val any = AndroidKeyAttestation(listOf(pki.root))
        assertTrue(verify(Description(deviceId, packages = listOf("com.other"), signers = listOf(ByteArray(32))), with = any).passed)
        // Digests from the env: colons and case do not matter.
        assertEquals(setOf("ab01", "cd02"), AndroidKeyAttestation.parseDigests("AB:01, cd02,,"))
    }

    @Test
    fun `a broken chain, an unknown root and another key are refused`() {
        val other = Pki()
        assertRefused("chain_broken", verify(chain = chain(pki, key.public, Description(deviceId), leafSigner = other.intermediateKey.private)))
        assertRefused("untrusted_root", verify(chain = chain(other, key.public, Description(deviceId))))
        assertRefused("key_mismatch", verify(submitted = rsa().public))
        assertRefused("chain_missing", verify(chain = null))
        assertRefused("chain_missing", verify(chain = emptyList()))
        assertRefused("chain_malformed", verify(chain = listOf("bm90IGEgY2VydA==")))
        assertRefused("extension_in_intermediate", verify(chain = chain(pki, key.public, Description(deviceId), extensionOnIntermediate = true)))
    }

    @Test
    fun `an expired leaf or intermediate is refused, an expired root is not`() {
        assertRefused("certificate_expired", verify(chain = chain(pki, key.public, Description(deviceId),
            leafNotAfter = Date(System.currentTimeMillis() - 86_400_000))))
        val oldIntermediate = Pki(intermediateNotAfter = Date(System.currentTimeMillis() - 86_400_000))
        assertRefused("certificate_expired", verify(chain = chain(oldIntermediate, key.public, Description(deviceId)), with = oldIntermediate.verifier()))
        // Google: trust is by root key; one of the published roots is past its notAfter.
        val oldRoot = Pki(rootNotAfter = Date(System.currentTimeMillis() - 86_400_000))
        assertTrue(verify(chain = chain(oldRoot, key.public, Description(deviceId)), with = oldRoot.verifier()).passed)
    }

    @Test
    fun `old attestation versions are refused`() {
        assertRefused("unsupported_attestation_version", verify(Description(deviceId, version = 2)))
    }

    @Test
    fun `a revoked certificate in the chain is refused`() {
        val serial = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(Base64.getDecoder().decode(chain(pki, key.public, Description(deviceId))[1]).inputStream())
            .let { (it as java.security.cert.X509Certificate).serialNumber.toString(16) }
        assertRefused("certificate_revoked", verify(with = pki.verifier(revokedSerials = setOf(serial.uppercase()))))
        val list = """{"entries":{"$serial":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"0abc":{"status":"SUSPENDED"},"ff":{"status":"OK"}}}"""
        assertEquals(setOf(serial.lowercase().trimStart('0'), "abc"), AndroidKeyAttestation.parseRevocationList(list))
    }

    @Test
    fun `the shipped Google roots load and none of their own chains is accepted for a foreign key`() {
        val roots = AndroidKeyAttestation.googleRoots()
        assertTrue(roots.size >= 5, "five roots on Google's page, got ${roots.size}")
        val google = AndroidKeyAttestation(roots)
        // Our test chain does not end in a Google root.
        assertRefused("untrusted_root", google.verify(chain(pki, key.public, Description(deviceId)), key.public, deviceId))
    }

    @Test
    fun `a key usable for more than 10 seconds after an unlock is refused`() {
        assertRefused("auth_timeout_too_long", verify(Description(deviceId, authTimeout = 11)))
        assertRefused("auth_timeout_too_long", verify(Description(deviceId, authTimeout = 3600)))
        // The library's Android 7–10 window, and a per-use key (0 or none), pass.
        assertTrue(verify(Description(deviceId, authTimeout = 10)).passed)
        assertTrue(verify(Description(deviceId, authTimeout = 0)).passed)
        assertTrue(verify(Description(deviceId, authTimeout = null)).passed)
    }

    @Test
    fun `cheap checks come before any signature work`() {
        val other = Pki()
        val broken = chain(pki, key.public, Description(deviceId), leafSigner = other.intermediateKey.private)
        // Another key's chain is refused as such, even when its signatures would not verify.
        assertRefused("key_mismatch", verify(chain = broken, submitted = rsa().public))
        // A chain that neither ends in a trusted root nor names one as issuer: refused by name,
        // before its (broken) links are verified.
        val google = AndroidKeyAttestation(AndroidKeyAttestation.googleRoots())
        assertRefused("untrusted_root", google.verify(broken, key.public, deviceId))
        // Too many certificates, or one far too large, are refused before parsing.
        assertRefused("chain_too_long", verify(chain = List(11) { broken[0] }))
        assertRefused("chain_malformed", verify(chain = listOf("A".repeat(20_000))))
    }

    @Test
    fun `an attestation binds the app only with both the package and the signer`() {
        assertTrue(pki.verifier().bindsApp)
        assertFalse(pki.verifier(signerDigests = emptySet()).bindsApp)
        assertFalse(pki.verifier(packageNames = emptySet()).bindsApp)
        assertFalse(AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_PACKAGE_NAMES" to "com.example.sampleclient")).bindsApp)
        assertTrue(AndroidKeyAttestation.fromEnv(mapOf(
            "ATTESTATION_PACKAGE_NAMES" to "com.example.sampleclient",
            "ATTESTATION_SIGNER_SHA256" to TestAttestationChains.SIGNER_HEX
        )).bindsApp)
    }

    @Test
    fun `enforce without the package and signer refuses to start, warn warns`() {
        val unbound = AndroidKeyAttestation.fromEnv(mapOf("ATTESTATION_PACKAGE_NAMES" to "com.example.sampleclient"))
        val refused = assertFailsWith<IllegalStateException> { UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.ENFORCE, unbound) }
        assertTrue(refused.message!!.contains("ATTESTATION_SIGNER_SHA256"), refused.message)
        assertFailsWith<IllegalStateException> {
            UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.ENFORCE, AndroidKeyAttestation.fromEnv(emptyMap()))
        }
        val warning = UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.WARN, unbound)
        assertNotNull(warning)
        assertTrue(warning.contains("no attestation counts"), warning)
        assertNull(UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.OFF, unbound))
        assertNull(UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.ENFORCE, pki.verifier()))
        assertNull(UserAuthAttestationMode.startupCheck(UserAuthAttestationMode.WARN, pki.verifier()))
    }

    @Test
    fun `the mode parses strictly`() {
        assertEquals(UserAuthAttestationMode.WARN, UserAuthAttestationMode.parse(null))
        assertEquals(UserAuthAttestationMode.WARN, UserAuthAttestationMode.parse(""))
        assertEquals(UserAuthAttestationMode.ENFORCE, UserAuthAttestationMode.parse(" Enforce "))
        assertEquals(UserAuthAttestationMode.OFF, UserAuthAttestationMode.parse("off"))
        assertFailsWith<IllegalArgumentException> { UserAuthAttestationMode.parse("strict") }
    }
}
