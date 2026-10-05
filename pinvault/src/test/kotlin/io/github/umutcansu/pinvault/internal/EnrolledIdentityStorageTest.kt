package io.github.umutcansu.pinvault.internal

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.keystore.ClientIdentityKeyProvider
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.store.ClientCertSecureStore
import io.github.umutcansu.pinvault.store.PrefsCipher
import io.github.umutcansu.pinvault.store.SecurePreferences
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.PrivateKey
import java.security.ProviderException

/**
 * A Keystore that fails right now says nothing about an enrolled identity:
 * loading it presents nothing but keeps everything (A2), and the enroll
 * paths read the credential store strictly, so "cannot read" never looks
 * like "not enrolled" and never costs the key behind a stored chain (A8).
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class EnrolledIdentityStorageTest {

    /** A cipher whose `open` fails the way a broken Keystore does. */
    private class FlakyCipher : PrefsCipher {
        private val real = SoftwarePrefsCipher()
        var broken = false
        override fun seal(plaintext: ByteArray, aad: ByteArray) = real.seal(plaintext, aad)
        override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
            if (broken) throw ProviderException("Keystore operation failed")
            return real.open(sealed, aad)
        }
        override fun mac(input: ByteArray) = real.mac(input)
    }

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val cipher = FlakyCipher()
    private val label = "identity-" + System.nanoTime()
    private val key = ClientIdentityKeyProvider.software(label)
    private val chain = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1").certificate.let {
        listOf(Pkcs10Csr.toPem(it), Pkcs10Csr.toPem(it))
    }

    private fun store(strict: Boolean) = ClientCertSecureStore.createForTest(
        SecurePreferences(context.getSharedPreferences(FILE, Context.MODE_PRIVATE), FILE, "ns", cipher, strict)
    )

    @Before
    fun setUp() {
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().clear().commit()
        key.clear()
        key.ensureKeyPair()
        store(strict = false).saveChain(label, chain)
    }

    private var presented = 0
    private val present: (PrivateKey, Array<java.security.cert.X509Certificate>) -> Unit = { _, _ -> presented++ }

    /** [key] with one operation made to fail. */
    private fun failing(exists: (() -> Boolean)? = null, privateKey: (() -> PrivateKey)? = null) =
        object : ClientIdentityKeyProvider by key {
            override fun exists(): Boolean = exists?.invoke() ?: key.exists()
            override fun privateKey(): PrivateKey = privateKey?.invoke() ?: key.privateKey()
        }

    // ── A2: loading the enrolled chain ──────────────────────────────────

    @Test
    fun `a readable chain over an existing key is presented`() {
        assertEquals(ConfigApiClient.EnrolledChain.LOADED, ConfigApiClient.loadEnrolledChain(store(false), label, key, present))
        assertEquals(1, presented)
    }

    @Test
    fun `a chain the store cannot decrypt right now is kept, not dropped`() {
        cipher.broken = true
        val s = store(strict = false)
        assertEquals(ClientCertSecureStore.Mode.CHAIN, s.mode(label))
        assertNull("the non-strict store reads it as absent", s.loadChain(label))

        assertEquals(ConfigApiClient.EnrolledChain.UNAVAILABLE, ConfigApiClient.loadEnrolledChain(s, label, key, present))
        assertEquals(0, presented)
        cipher.broken = false
        assertEquals(chain, store(false).loadChain(label))
        assertTrue(key.exists())
    }

    @Test
    fun `a Keystore error reading the key keeps the chain and the key`() {
        val busy = failing(privateKey = { throw ProviderException("Keystore operation failed") })
        assertEquals(ConfigApiClient.EnrolledChain.UNAVAILABLE, ConfigApiClient.loadEnrolledChain(store(false), label, busy, present))
        val unreachable = failing(exists = { throw java.security.KeyStoreException("Keystore unavailable") })
        assertEquals(ConfigApiClient.EnrolledChain.UNAVAILABLE, ConfigApiClient.loadEnrolledChain(store(false), label, unreachable, present))
        assertEquals(chain, store(false).loadChain(label))
        assertTrue(key.exists())
    }

    @Test
    fun `a retired or missing key, or a chain that does not parse, ends the enrollment`() {
        val retired = failing(privateKey = { throw android.security.keystore.KeyPermanentlyInvalidatedException("gone") })
        assertEquals(ConfigApiClient.EnrolledChain.DROPPED, ConfigApiClient.loadEnrolledChain(store(false), label, retired, present))
        assertFalse(store(false).exists(label))

        store(false).saveChain(label, chain)
        key.clear()
        assertEquals(ConfigApiClient.EnrolledChain.DROPPED, ConfigApiClient.loadEnrolledChain(store(false), label, key, present))
        assertFalse(store(false).exists(label))

        key.ensureKeyPair()
        store(false).saveChain(label, listOf("not a certificate"))
        assertEquals(ConfigApiClient.EnrolledChain.DROPPED, ConfigApiClient.loadEnrolledChain(store(false), label, key, present))
        assertEquals(0, presented)
    }

    // ── A8: the enroll paths' checks ─────────────────────────────────────

    @Test
    fun `a strict store says 'cannot tell' where the plain one says 'nothing stored'`() {
        cipher.broken = true
        assertNull(store(strict = false).loadChain(label))
        try {
            store(strict = true).loadChain(label)
            fail("a strict read must not answer 'absent'")
        } catch (e: StoreUnreadableException) {
            // expected
        }
    }

    @Test
    fun `a key under a stored chain is never deleted by an enrollment answer`() {
        assertFalse("a chain is stored over this key", EnrollmentRequests.mayDeleteKey(store(strict = true), label))

        cipher.broken = true
        assertFalse("cannot tell: keep it", EnrollmentRequests.mayDeleteKey(throwingStore(), label))

        cipher.broken = false
        store(false).clear(label)
        assertTrue(EnrollmentRequests.mayDeleteKey(store(strict = true), label))
    }

    /** A strict store whose name lookups fail too (the HMAC key is in the Keystore as well). */
    private fun throwingStore(): ClientCertSecureStore {
        val failingMac = object : PrefsCipher by cipher {
            var calls = 0
            override fun mac(input: ByteArray): ByteArray {
                // The namespace tag is computed when the store is made; every lookup after that fails.
                if (calls++ > 0) throw ProviderException("Keystore operation failed")
                return cipher.mac(input)
            }
        }
        return ClientCertSecureStore.createForTest(
            SecurePreferences(context.getSharedPreferences(FILE, Context.MODE_PRIVATE), FILE, "ns", failingMac, strict = true)
        )
    }

    @Test
    fun `an attestation refusal does not take the key from under a stored chain`() = kotlinx.coroutines.test.runTest {
        val refusing = io.mockk.mockk<io.github.umutcansu.pinvault.api.CertificateConfigApi>()
        io.mockk.coEvery { refusing.enrollWithCsr(any(), any(), any(), any(), any(), any(), any()) } throws
            io.github.umutcansu.pinvault.model.EnrollmentRefusedException(403, "attestation_required", "no chain")
        try {
            EnrollmentRequests.send(refusing, store(strict = true), key, label, "tok", null, null, "uid") { byteArrayOf(1) }
            fail("refused")
        } catch (e: io.github.umutcansu.pinvault.model.EnrollmentRefusedException) {
            assertEquals("attestation_required", e.serverError)
        }
        assertTrue("the key behind the stored chain stays", key.exists())
        assertNotNull(store(false).loadChain(label))
    }

    private companion object {
        const val FILE = "enrolled_identity_test"
    }
}
