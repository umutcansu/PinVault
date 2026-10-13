package io.github.umutcansu.pinvault

import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.keystore.KeystoreUnreadableException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Only a key that could not be MADE gives way to a server-made one
 * (`allowServerGeneratedKey()`): a key that is there but failed for a moment,
 * or a Keystore that cannot say, is never replaced.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnrollmentCsrFallbackTest {

    private class Key(
        private val base: ClientIdentityKeyProvider,
        private val exists: () -> Boolean,
        private val failSign: Boolean = false,
        private val failMake: Boolean = false
    ) : ClientIdentityKeyProvider by base {
        var cleared = 0
        override fun exists(): Boolean = exists.invoke()
        override fun ensureKeyPair(attestationChallenge: ByteArray?) {
            if (failMake) throw java.security.ProviderException("this ROM cannot make the key")
            base.ensureKeyPair(attestationChallenge)
        }
        override fun sign(data: ByteArray): ByteArray =
            if (failSign) throw java.security.KeyStoreException("keystore busy") else base.sign(data)
        override fun clear() { cleared++; base.clear() }
    }

    private fun software() = ClientIdentityKeyProvider.software("csr-fallback-${System.nanoTime()}")

    @Test
    fun `a working key gives a CSR`() {
        val key = Key(software(), exists = { false })
        assertNotNull(PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true))
    }

    @Test
    fun `a key that cannot be made falls back only with the opt-in`() {
        val key = Key(software(), exists = { false }, failMake = true)
        assertNull(PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true))
        val e = assertThrows(IllegalStateException::class.java) {
            PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = false)
        }
        assertTrue(e.message, e.message!!.contains("allowServerGeneratedKey"))
    }

    @Test
    fun `a key made now that cannot be used is removed when falling back, so the next attempt falls back again`() {
        var made = false
        val base = software()
        val key = object : ClientIdentityKeyProvider by base {
            override fun exists(): Boolean = made
            override fun ensureKeyPair(attestationChallenge: ByteArray?) { base.ensureKeyPair(attestationChallenge); made = true }
            override fun sign(data: ByteArray): ByteArray = throw java.security.ProviderException("this ROM cannot use the key")
            override fun clear() { made = false; base.clear() }
        }
        assertNull(PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true))
        assertTrue("the half-usable key is gone", !made)
        // The server-made answer did not arrive (no network): the next attempt falls back again.
        assertNull(PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true))

        // Refused without the opt-in, the key goes too: an update that adds it can fall back.
        assertThrows(IllegalStateException::class.java) {
            PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = false)
        }
        assertTrue("the half-usable key is gone", !made)
        assertNull(PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true))
    }

    @Test
    fun `an existing key that fails for a moment is never given up`() {
        val base = software().also { it.ensureKeyPair() }
        val key = Key(base, exists = { true }, failSign = true)
        val e = assertThrows(IllegalStateException::class.java) {
            PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true)
        }
        assertTrue(e.message, e.message!!.contains("nothing was sent"))
        assertEquals(0, key.cleared)
    }

    @Test
    fun `a Keystore that does not open is not taken for a missing key`() {
        val base = software().also { it.ensureKeyPair() }
        val key = Key(base, exists = { throw java.security.KeyStoreException("AndroidKeyStore did not load") })
        assertThrows(IllegalStateException::class.java) {
            PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true)
        }
        assertEquals("nothing deleted", 0, key.cleared)
    }

    @Test
    fun `a Keystore that cannot say is never given up either`() {
        val key = Key(software(), exists = { throw KeystoreUnreadableException("busy") })
        assertThrows(IllegalStateException::class.java) {
            PinVault.enrollmentCsr(key, null, "dev", allowServerGeneratedKey = true)
        }
    }
}
