package io.github.umutcansu.pinvault.store

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A.2 — ClientCertSecureStore multi-label CRUD
 * Instrumented test — EncryptedSharedPreferences requires AndroidKeyStore.
 */
@RunWith(AndroidJUnit4::class)
class ClientCertSecureStoreTest {

    private lateinit var store: ClientCertSecureStore

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        store = ClientCertSecureStore(context)
        store.clearAll()
    }

    @Test
    fun save_and_load_default_label() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        store.save(data)
        val loaded = store.load()
        assertNotNull(loaded)
        assertArrayEquals(data, loaded)
    }

    @Test
    fun save_and_load_named_label() {
        val data = byteArrayOf(10, 20, 30)
        store.save("host_api.example.com", data)
        val loaded = store.load("host_api.example.com")
        assertNotNull(loaded)
        assertArrayEquals(data, loaded)
    }

    @Test
    fun multiple_labels_stored_independently() {
        val defaultData = byteArrayOf(1, 1, 1)
        val hostAData = byteArrayOf(2, 2, 2)
        val hostBData = byteArrayOf(3, 3, 3)

        store.save(defaultData)
        store.save("host_a.com", hostAData)
        store.save("host_b.com", hostBData)

        assertArrayEquals(defaultData, store.load())
        assertArrayEquals(hostAData, store.load("host_a.com"))
        assertArrayEquals(hostBData, store.load("host_b.com"))
    }

    @Test
    fun exists_returns_true_for_saved_label() {
        assertFalse(store.exists("my_cert"))
        store.save("my_cert", byteArrayOf(9, 8, 7))
        assertTrue(store.exists("my_cert"))
    }

    @Test
    fun load_returns_null_for_missing_label() {
        assertNull(store.load("nonexistent"))
    }

    @Test
    fun clear_removes_specific_label() {
        store.save("cert_a", byteArrayOf(1))
        store.save("cert_b", byteArrayOf(2))

        store.clear("cert_a")
        assertNull(store.load("cert_a"))
        assertNotNull(store.load("cert_b"))
    }

    @Test
    fun clearAll_removes_everything() {
        store.save(byteArrayOf(1))
        store.save("host_x", byteArrayOf(2))
        store.save("host_y", byteArrayOf(3))

        store.clearAll()

        assertNull(store.load())
        assertNull(store.load("host_x"))
        assertNull(store.load("host_y"))
    }

    @Test
    fun overwrite_existing_label() {
        store.save("cert", byteArrayOf(1, 2, 3))
        store.save("cert", byteArrayOf(4, 5, 6))
        assertArrayEquals(byteArrayOf(4, 5, 6), store.load("cert"))
    }

    @Test
    fun large_P12_data_round_trip() {
        val bigData = ByteArray(4096) { it.toByte() }
        store.save("big_cert", bigData)
        assertArrayEquals(bigData, store.load("big_cert"))
    }
}
