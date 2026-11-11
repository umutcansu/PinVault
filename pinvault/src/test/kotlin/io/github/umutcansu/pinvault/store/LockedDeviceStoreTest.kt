package io.github.umutcansu.pinvault.store

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.PinVault
import io.github.umutcansu.pinvault.crypto.Pkcs10Csr
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import io.github.umutcansu.pinvault.util.TestCertUtil
import org.junit.After
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
import java.security.InvalidKeyException

/**
 * With `requireUnlockedDevice()` neither store key works on a locked device —
 * the name key (HMAC) included. Opening a store, listing it and writing to it
 * used to let the raw Keystore exception out; the public status calls on
 * `PinVault` passed it on to the app.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class LockedDeviceStoreTest {

    /** Every operation fails while [locked], the way a key that needs an unlocked device does. */
    private class LockableCipher : PrefsCipher {
        private val real = SoftwarePrefsCipher()
        var locked = false
        private fun check() {
            if (locked) throw InvalidKeyException("User not authenticated: device is locked")
        }
        override fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray { check(); return real.seal(plaintext, aad) }
        override fun open(sealed: ByteArray, aad: ByteArray): ByteArray { check(); return real.open(sealed, aad) }
        override fun mac(input: ByteArray): ByteArray { check(); return real.mac(input) }
    }

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val cipher = LockableCipher()
    private val backing get() = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
    private val savedFactory = PinVault.clientCertStoreFactory

    /** A new instance each time: nothing cached from before the lock, as after a process start. */
    private fun prefs(strict: Boolean) = SecurePreferences(backing, FILE, "ns", cipher, strict)
    private fun certStore(strict: Boolean = false) = ClientCertSecureStore.createForTest(prefs(strict))

    @Before
    fun setUp() {
        backing.edit().clear().commit()
    }

    @After
    fun tearDown() {
        PinVault.clientCertStoreFactory = savedFactory
    }

    private fun unreadable(block: () -> Any?) {
        try {
            block()
            fail("expected StoreUnreadableException")
        } catch (e: StoreUnreadableException) {
            assertTrue(e.cause is InvalidKeyException)
        }
    }

    // ── SecurePreferences ───────────────────────────────────────────────

    @Test
    fun `a store opened on a locked device opens, and a strict one says unreadable on every read`() {
        prefs(strict = true).edit().putLong("watermark", 42L).commit()

        cipher.locked = true
        val strict = prefs(strict = true) // the constructor used to throw InvalidKeyException here
        unreadable { strict.getLong("watermark", 0L) }
        unreadable { strict.contains("watermark") }
        unreadable { strict.all }

        cipher.locked = false
        assertEquals(42L, strict.getLong("watermark", 0L))
        assertEquals(mapOf("watermark" to 42L), strict.all)
    }

    @Test
    fun `a store that is not strict reads absent while locked and keeps everything`() {
        prefs(strict = false).edit().putString("text", "kept").commit()

        cipher.locked = true
        val lenient = prefs(strict = false)
        assertNull(lenient.getString("text", null))
        assertFalse(lenient.contains("text"))
        assertTrue(lenient.all.isEmpty())
        assertFalse(lenient.isReadable())

        cipher.locked = false
        assertTrue(lenient.isReadable())
        assertEquals("kept", lenient.getString("text", null))
        assertEquals(mapOf("text" to "kept"), lenient.all)
    }

    @Test
    fun `a write the Keystore refuses throws StoreUnreadableException and writes nothing, in either kind of store`() {
        prefs(strict = false).edit().putString("a", "1").putString("b", "2").commit()
        val before = backing.all.toMap()

        cipher.locked = true
        for (strict in listOf(true, false)) {
            val store = prefs(strict)
            unreadable { store.edit().putString("c", "3").commit() }
            unreadable { store.edit().remove("a").apply() }
            unreadable { store.edit().clear().apply() }
        }
        assertEquals("nothing reached the file", before, backing.all.toMap())

        // Names computed before the lock do not help the value through either,
        // and no part of the edit is written.
        cipher.locked = false
        val warm = prefs(strict = false).also { it.getString("a", null) }
        cipher.locked = true
        unreadable { warm.edit().remove("a").putString("b", "changed").commit() }
        cipher.locked = false
        assertEquals("1", warm.getString("a", null))
        assertEquals("2", warm.getString("b", null))
    }

    // ── PinVault status calls ───────────────────────────────────────────

    private val label = "locked-" + System.nanoTime()
    private val leaf = TestCertUtil.generateSelfSigned(cn = "PinVault Client: dev-1").certificate

    @Test
    fun `the status calls answer without throwing while the credential store is locked`() {
        certStore().saveChain(label, listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(leaf)))
        certStore().savePendingRequest("waiting", "req-1", null)
        PinVault.clientCertStoreFactory = { certStore() }
        assertTrue(PinVault.isEnrolled(context, label))
        assertTrue(PinVault.isEnrollmentPending(context, "waiting"))
        assertEquals("PinVault Client: dev-1", PinVault.enrolledClientCN(context, label))

        cipher.locked = true
        assertFalse(certStore().isReadable())
        assertFalse(PinVault.isEnrolled(context, label))
        assertFalse(PinVault.isEnrollmentPending(context, "waiting"))
        assertNull(PinVault.enrolledClientCN(context, label))
        assertNull(PinVault.enrolledClientNotAfter(context, label))
        // The strict store the enroll paths use says "cannot tell" instead.
        unreadable { certStore(strict = true).exists(label) }

        // "Cannot tell" cost nothing: the answers are back with the Keystore.
        cipher.locked = false
        assertTrue(PinVault.isEnrolled(context, label))
        assertTrue(PinVault.isEnrollmentPending(context, "waiting"))
        assertEquals(leaf.notAfter.time, PinVault.enrolledClientNotAfter(context, label))
    }

    @Test
    fun `the status calls answer when the store cannot even be opened`() {
        PinVault.clientCertStoreFactory = { throw java.security.KeyStoreException("AndroidKeyStore not available") }
        assertFalse(PinVault.isEnrolled(context, label))
        assertFalse(PinVault.isEnrollmentPending(context, label))
        assertNull(PinVault.enrolledClientCN(context, label))
        assertNull(PinVault.enrolledClientNotAfter(context, label))
        PinVault.unenroll(context, label)
    }

    @Test
    fun `unenroll on a locked device does not throw and leaves the stored copy for the next try`() {
        certStore().saveChain(label, listOf(Pkcs10Csr.toPem(leaf), Pkcs10Csr.toPem(leaf)))
        PinVault.clientCertStoreFactory = { certStore() }

        cipher.locked = true
        PinVault.unenroll(context, label)

        cipher.locked = false
        assertNotNull("the write was refused, so the copy is still there", certStore().loadChain(label))
        PinVault.unenroll(context, label)
        assertFalse(PinVault.isEnrolled(context, label))
    }

    private companion object {
        const val FILE = "locked_device_test"
    }
}
