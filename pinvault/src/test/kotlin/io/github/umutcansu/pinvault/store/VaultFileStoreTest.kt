package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.test.core.app.ApplicationProvider

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileStoreTest {

    private lateinit var prefs: SharedPreferences
    private lateinit var store: VaultFileStore

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("test_vault_files", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        store = VaultFileStore.createForTest(prefs)
    }

    @Test
    fun `save and load round-trip binary`() {
        val bytes = byteArrayOf(0x00, 0x01, 0x02, 0x50, 0x4B, 0x03, 0x04)
        store.save("model", bytes, 1)
        val loaded = store.load("model")
        assertArrayEquals(bytes, loaded)
    }

    @Test
    fun `save and load round-trip string content`() {
        val json = """{"feature":"enabled","version":3}"""
        store.save("flags", json.toByteArray(), 2)
        val loaded = store.load("flags")
        assertNotNull(loaded)
        assertEquals(json, String(loaded!!))
    }

    @Test
    fun `load returns null when empty`() {
        assertNull(store.load("nonexistent"))
    }

    @Test
    fun `getVersion returns 0 when empty`() {
        assertEquals(0, store.getVersion("nonexistent"))
    }

    @Test
    fun `getVersion reflects saved version`() {
        store.save("model", byteArrayOf(1, 2, 3), 5)
        assertEquals(5, store.getVersion("model"))
    }

    @Test
    fun `exists returns false then true`() {
        assertFalse(store.exists("model"))
        store.save("model", byteArrayOf(1), 1)
        assertTrue(store.exists("model"))
    }

    @Test
    fun `clear removes file and version`() {
        store.save("model", byteArrayOf(1, 2, 3), 3)
        assertTrue(store.exists("model"))

        store.clear("model")
        assertFalse(store.exists("model"))
        assertNull(store.load("model"))
        assertEquals(0, store.getVersion("model"))
    }

    @Test
    fun `multiple files independent`() {
        store.save("file-a", byteArrayOf(0x0A), 1)
        store.save("file-b", byteArrayOf(0x0B), 2)

        assertArrayEquals(byteArrayOf(0x0A), store.load("file-a"))
        assertArrayEquals(byteArrayOf(0x0B), store.load("file-b"))
        assertEquals(1, store.getVersion("file-a"))
        assertEquals(2, store.getVersion("file-b"))

        store.clear("file-a")
        assertNull(store.load("file-a"))
        assertNotNull(store.load("file-b"))
    }

    @Test
    fun `overwrite updates version and content`() {
        store.save("model", byteArrayOf(0x01), 1)
        store.save("model", byteArrayOf(0x02), 2)

        assertArrayEquals(byteArrayOf(0x02), store.load("model"))
        assertEquals(2, store.getVersion("model"))
    }

    @Test
    fun `large binary content round-trip`() {
        val large = ByteArray(100_000) { (it % 256).toByte() }
        store.save("big", large, 1)
        val loaded = store.load("big")
        assertArrayEquals(large, loaded)
    }

    // ── Content and version are one entry ───────────────────────────────

    @Test
    fun `content and version are stored as one entry`() {
        store.save("flags", "flags".toByteArray(), 7)
        assertEquals("one entry: the two cannot be taken from different moments", 1, prefs.all.size)
        assertFalse(prefs.contains("vault_ver_flags"))
        assertEquals(7, store.getVersion("flags"))
        assertArrayEquals("flags".toByteArray(), store.load("flags"))
    }

    @Test
    fun `an empty file keeps its version`() {
        store.save("empty", ByteArray(0), 3)
        assertEquals(3, store.getVersion("empty"))
        assertArrayEquals(ByteArray(0), store.load("empty"))
        assertTrue(store.exists("empty"))
    }

    @Test
    fun `a copy stored by an earlier version is read and written again as one entry`() {
        // 2.1.x: Base64 content under one name, the version under another.
        prefs.edit()
            .putString("vault_data_model", android.util.Base64.encodeToString("legacy".toByteArray(), android.util.Base64.NO_WRAP))
            .putInt("vault_ver_model", 5)
            .commit()

        assertEquals(5, store.getVersion("model"))
        assertArrayEquals("legacy".toByteArray(), store.load("model"))

        assertFalse("the separate version entry is gone", prefs.contains("vault_ver_model"))
        assertTrue(prefs.getString("vault_data_model", "")!!.startsWith("2:5:"))
        assertEquals(5, store.getVersion("model"))
        assertArrayEquals("legacy".toByteArray(), store.load("model"))
    }
}
