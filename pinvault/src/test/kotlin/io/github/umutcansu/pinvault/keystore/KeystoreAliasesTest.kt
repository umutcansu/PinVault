package io.github.umutcansu.pinvault.keystore

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.KeyStoreSpi
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import javax.crypto.spec.SecretKeySpec

/**
 * A Keystore that cannot be read for a moment (Keystore2 answers false from
 * `containsAlias` for every error but KEY_NOT_FOUND) must never look like a
 * missing key: nothing is generated over the alias, nothing is dropped.
 */
class KeystoreAliasesTest {

    /** `containsAlias` answers [contains]; `getKey` returns [key] or throws [keyError]. */
    private class FakeSpi(
        private val contains: Boolean,
        private val key: Key? = null,
        private val keyError: Exception? = null
    ) : KeyStoreSpi() {
        var deleted = 0
        override fun engineContainsAlias(alias: String?) = contains
        override fun engineGetKey(alias: String?, password: CharArray?): Key? {
            keyError?.let { throw it }
            return key
        }
        override fun engineDeleteEntry(alias: String?) { deleted++ }
        override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
        override fun engineGetCertificate(alias: String?): Certificate? = null
        override fun engineGetCreationDate(alias: String?): Date? = null
        override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) = Unit
        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) = Unit
        override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) = Unit
        override fun engineAliases(): Enumeration<String> = Collections.emptyEnumeration()
        override fun engineSize() = 0
        override fun engineIsKeyEntry(alias: String?) = contains
        override fun engineIsCertificateEntry(alias: String?) = false
        override fun engineGetCertificateAlias(cert: Certificate?): String? = null
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    }

    private class FakeKeyStore(spi: KeyStoreSpi) : KeyStore(spi, null, "fake") {
        init { load(null) }
    }

    private val someKey = SecretKeySpec(ByteArray(16), "AES")
    private val busy = UnrecoverableKeyException("Failed to obtain information about key (SYSTEM_ERROR)")

    @Test
    fun `a listed alias is present`() {
        assertEquals(KeystoreAliases.Presence.PRESENT, KeystoreAliases.presence(FakeKeyStore(FakeSpi(true)), "a"))
    }

    @Test
    fun `an unlisted alias whose key loads is present`() {
        assertEquals(KeystoreAliases.Presence.PRESENT, KeystoreAliases.presence(FakeKeyStore(FakeSpi(false, key = someKey)), "a"))
    }

    @Test
    fun `an unlisted alias without a key is absent`() {
        val store = FakeKeyStore(FakeSpi(false))
        assertEquals(KeystoreAliases.Presence.ABSENT, KeystoreAliases.presence(store, "a"))
        assertFalse(KeystoreAliases.exists(store, "a", "key"))
    }

    @Test
    fun `a Keystore that throws on getKey cannot say`() {
        val store = FakeKeyStore(FakeSpi(false, keyError = busy))
        assertEquals(KeystoreAliases.Presence.UNKNOWN, KeystoreAliases.presence(store, "a"))
        assertThrows(KeystoreUnreadableException::class.java) { KeystoreAliases.exists(store, "a", "key") }
        assertTrue(KeystoreUnreadableException("x") is KeyStoreException)
    }

    @Test
    fun `the identity key is not regenerated while the Keystore cannot say`() {
        val spi = FakeSpi(false, keyError = busy)
        val provider = AndroidKeystoreClientIdentityKeyProvider("alias") { FakeKeyStore(spi) }

        // Throws before any key generation is tried (which would be NoSuchProviderException here).
        assertThrows(KeystoreUnreadableException::class.java) { provider.ensureKeyPair(ByteArray(32)) }
        assertThrows(KeystoreUnreadableException::class.java) { provider.exists() }
        assertEquals(io.github.umutcansu.pinvault.model.KeySecurityLevel.UNKNOWN, provider.securityLevel())
        assertEquals(0, spi.deleted)
    }

    @Test
    fun `an identity key the Keystore lists is kept as it is`() {
        val spi = FakeSpi(true)
        val provider = AndroidKeystoreClientIdentityKeyProvider("alias") { FakeKeyStore(spi) }
        provider.ensureKeyPair(null)
        assertTrue(provider.exists())
        assertEquals(0, spi.deleted)
    }

    @Test
    fun `a delete that was asked for is not skipped because the Keystore could not list the alias`() {
        val unsure = FakeSpi(false, keyError = busy)
        AndroidKeystoreClientIdentityKeyProvider("alias") { FakeKeyStore(unsure) }.clear()
        assertEquals(1, unsure.deleted)

        val absent = FakeSpi(false)
        AndroidKeystoreClientIdentityKeyProvider("alias") { FakeKeyStore(absent) }.clear()
        assertEquals("nothing to delete", 0, absent.deleted)
    }

    @Test
    fun `the device RSA key is not regenerated while the Keystore cannot say`() {
        val provider = AndroidKeystoreDeviceKeyProvider(mockk(relaxed = true), "alias") {
            FakeKeyStore(FakeSpi(false, keyError = busy))
        }
        assertThrows(KeystoreUnreadableException::class.java) { provider.ensureKeyPair() }
    }
}
