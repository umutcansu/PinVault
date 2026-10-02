package io.github.umutcansu.pinvault.store

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** P12 and certificate-chain credentials side by side, one form per label. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class ClientCertSecureStoreTest {

    private lateinit var store: ClientCertSecureStore

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val backing = context.getSharedPreferences("cc-test", Context.MODE_PRIVATE).also { it.edit().clear().commit() }
        store = ClientCertSecureStore.createForTest(SecurePreferences(backing, "cc-test", "ns", SoftwarePrefsCipher()))
    }

    private val pemA = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
    private val pemB = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----"

    @Test
    fun `empty store has no credentials`() {
        assertEquals(ClientCertSecureStore.Mode.NONE, store.mode("default"))
        assertFalse(store.exists("default"))
        assertNull(store.load("default"))
        assertNull(store.loadChain("default"))
    }

    @Test
    fun `P12 round-trips and reports P12 mode`() {
        store.save("default", byteArrayOf(1, 2, 3))
        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("default"))
        assertTrue(store.exists("default"))
        assertTrue(store.hasP12("default"))
        assertFalse(store.hasChain("default"))
        assertArrayEquals(byteArrayOf(1, 2, 3), store.load("default"))
    }

    @Test
    fun `chain round-trips in order and reports CHAIN mode`() {
        store.saveChain("default", listOf(pemA, pemB))
        assertEquals(ClientCertSecureStore.Mode.CHAIN, store.mode("default"))
        assertTrue(store.exists("default"))
        assertEquals(listOf(pemA, pemB), store.loadChain("default"))
        assertNull(store.load("default"))
    }

    @Test
    fun `saving a chain replaces a P12 and vice versa`() {
        store.save("default", byteArrayOf(9))
        store.saveChain("default", listOf(pemA))
        assertFalse(store.hasP12("default"))
        assertEquals(ClientCertSecureStore.Mode.CHAIN, store.mode("default"))

        store.save("default", byteArrayOf(8))
        assertFalse(store.hasChain("default"))
        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("default"))
    }

    @Test
    fun `labels are independent and clear removes both forms`() {
        store.saveChain("default", listOf(pemA))
        store.save("host_a", byteArrayOf(1))

        assertEquals(ClientCertSecureStore.Mode.CHAIN, store.mode("default"))
        assertEquals(ClientCertSecureStore.Mode.P12, store.mode("host_a"))

        store.clear("default")
        assertFalse(store.exists("default"))
        assertTrue(store.exists("host_a"))

        store.clearAll()
        assertFalse(store.exists("host_a"))
    }

    @Test
    fun `an empty chain is refused`() {
        try {
            store.saveChain("default", emptyList())
            org.junit.Assert.fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) { }
        assertFalse(store.exists("default"))
    }

    @Test
    fun `a pending enrollment request round-trips and is forgotten when a credential arrives`() {
        assertNull(store.loadPendingRequest("default"))
        store.savePendingRequest("default", "r-1", "field-7k2m9x")
        assertEquals(ClientCertSecureStore.PendingRequest("r-1", "field-7k2m9x"), store.loadPendingRequest("default"))
        assertFalse("waiting is not enrolled", store.exists("default"))
        assertNull("per label", store.loadPendingRequest("other"))

        store.saveChain("default", listOf(pemA))
        assertNull(store.loadPendingRequest("default"))

        store.savePendingRequest("other", "r-2", null)
        assertEquals(ClientCertSecureStore.PendingRequest("r-2", null), store.loadPendingRequest("other"))
        store.save("other", byteArrayOf(1))
        assertNull(store.loadPendingRequest("other"))
    }

    @Test
    fun `clearing a label gives up its pending request`() {
        store.savePendingRequest("default", "r-1", null)
        store.clear("default")
        assertNull(store.loadPendingRequest("default"))
        store.savePendingRequest("default", "r-2", null)
        store.clearPendingRequest("default")
        assertNull(store.loadPendingRequest("default"))
    }
}
