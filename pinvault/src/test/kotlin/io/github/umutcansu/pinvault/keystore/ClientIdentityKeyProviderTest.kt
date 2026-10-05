package io.github.umutcansu.pinvault.keystore

import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.Signature

/** The software identity key that stands in for the Android Keystore in unit tests. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ClientIdentityKeyProviderTest {

    private val label = "test-" + System.nanoTime()

    @Test
    fun `ensureKeyPair is idempotent and shared per label`() {
        val a = ClientIdentityKeyProvider.software(label)
        assertFalse(a.exists())
        a.ensureKeyPair()
        assertTrue(a.exists())
        val first = a.publicKey()

        a.ensureKeyPair()
        assertEquals(first, a.publicKey())

        // A second instance for the same label sees the same key, like the Keystore.
        val b = ClientIdentityKeyProvider.software(label)
        assertTrue(b.exists())
        assertEquals(first, b.publicKey())

        a.clear()
        assertFalse(b.exists())
    }

    @Test
    fun `sign produces a verifiable SHA256withECDSA signature`() {
        val provider = ClientIdentityKeyProvider.software(label).apply { ensureKeyPair() }
        val data = "certification request info".toByteArray()
        val sig = provider.sign(data)

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(provider.publicKey())
        verifier.update(data)
        assertTrue(verifier.verify(sig))
        provider.clear()
    }

    @Test
    fun `spki hash matches the CSR helper and changes after clear`() {
        val provider = ClientIdentityKeyProvider.software(label).apply { ensureKeyPair() }
        assertEquals(Pkcs10Csr.spkiSha256Base64(provider.publicKey()), provider.spkiSha256())
        val before = provider.spkiSha256()

        provider.clear()
        provider.ensureKeyPair()
        assertNotEquals(before, provider.spkiSha256())
        provider.clear()
    }

    @Test
    fun `accessors fail before the key exists`() {
        val provider = ClientIdentityKeyProvider.software(label)
        try {
            provider.publicKey()
            fail("expected IllegalStateException")
        } catch (_: IllegalStateException) { }
    }

    @Test
    fun `alias is derived from the label`() {
        assertEquals("pinvault_client_identity_ec_default", ClientIdentityKeyProvider.aliasFor("default"))
    }

    // ── Attestation (the software key plays the Keystore) ───────────────

    @Test
    fun `a key generated with a challenge carries it, an existing key is left as it is`() {
        val label = "attest-" + System.nanoTime()
        val provider = ClientIdentityKeyProvider.software(label)
        SoftwareClientIdentityKeyProvider.attestation = { challenge -> listOf(challenge) }
        try {
            // Made without a challenge (an earlier version): no chain.
            provider.ensureKeyPair()
            val first = provider.spkiSha256()
            assertTrue(provider.attestationChain().isEmpty())

            // Asking again with a challenge does not replace or re-attest an existing key.
            val challenge = ClientIdentityKeyProvider.attestationChallenge("device-1")
            provider.ensureKeyPair(challenge)
            assertEquals(first, provider.spkiSha256())
            assertTrue(provider.attestationChain().isEmpty())

            // A new key gets the challenge it was asked for.
            provider.clear()
            provider.ensureKeyPair(challenge)
            assertArrayEquals(challenge, provider.attestationChain().single())
            // Another instance for the same label sees the same key and chain.
            assertArrayEquals(challenge, ClientIdentityKeyProvider.software(label).attestationChain().single())

            provider.clear()
            assertTrue(provider.attestationChain().isEmpty())
        } finally {
            provider.clear()
            SoftwareClientIdentityKeyProvider.attestation = null
        }
    }

    @Test
    fun `the identity challenge differs per device and from the user-auth key's`() {
        val a = ClientIdentityKeyProvider.attestationChallenge("device-1")
        assertEquals(32, a.size)
        assertFalse(a.contentEquals(ClientIdentityKeyProvider.attestationChallenge("device-2")))
        assertFalse(a.contentEquals(UserAuthKeys.attestationChallenge("device-1")))
        assertArrayEquals(
            java.security.MessageDigest.getInstance("SHA-256").digest("pinvault-identity-key:v1:device-1".toByteArray()),
            a
        )
    }

    @Test
    fun `the unlocked-device option is off unless the config turns it on`() {
        assertFalse(KeystoreOptions.unlockedDeviceRequired)
        // Off: the generator is asked once, without the flag.
        val asked = mutableListOf<Boolean>()
        assertEquals("key", KeystoreOptions.generating("test") { unlocked -> asked += unlocked; "key" })
        assertEquals(listOf(false), asked)
    }
}
