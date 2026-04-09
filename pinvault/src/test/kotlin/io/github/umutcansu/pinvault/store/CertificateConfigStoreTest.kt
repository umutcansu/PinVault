package io.github.umutcansu.pinvault.store

import android.content.Context
import android.content.SharedPreferences
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.test.core.app.ApplicationProvider

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class CertificateConfigStoreTest {

    private lateinit var prefs: SharedPreferences
    private lateinit var store: CertificateConfigStore

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("test_cert_config", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        store = CertificateConfigStore.createForTest(prefs)
    }

    @Test
    fun `save and load round-trip -- single host`() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.example.com", listOf("hash1aaa", "hash2bbb"), version = 1)
            )
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals(listOf("hash1aaa", "hash2bbb"), loaded.pins[0].sha256)
        assertEquals(1, loaded.pins[0].version)
    }

    @Test
    fun `save and load round-trip -- multiple hosts`() {
        val config = CertificateConfig(
            version = 3,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 1),
                HostPin("cdn.example.com", listOf("h3", "h4"), version = 2),
                HostPin("auth.example.com", listOf("h5", "h6"), version = 3)
            )
        )

        store.save(config)
        val loaded = store.load()

        assertNotNull(loaded)
        assertEquals(3, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals("cdn.example.com", loaded.pins[1].hostname)
        assertEquals("auth.example.com", loaded.pins[2].hostname)
    }

    @Test
    fun `load returns null when nothing saved`() {
        assertNull(store.load())
    }

    @Test
    fun `getCurrentVersion returns 0 when empty`() {
        assertEquals(0, store.getCurrentVersion())
    }

    @Test
    fun `getCurrentVersion reflects saved config version`() {
        val config = CertificateConfig(
            version = 5,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 5)
            )
        )

        store.save(config)
        assertEquals(5, store.getCurrentVersion())
    }

    @Test
    fun `clear removes all data`() {
        val config = CertificateConfig(
            version = 1,
            pins = listOf(
                HostPin("api.example.com", listOf("h1", "h2"), version = 1)
            )
        )

        store.save(config)
        assertNotNull(store.load())

        store.clear()
        assertNull(store.load())
        assertEquals(0, store.getCurrentVersion())
    }

    @Test
    fun `save overwrites previous config`() {
        val v1 = CertificateConfig(
            version = 1,
            pins = listOf(HostPin("old.example.com", listOf("h1", "h2"), version = 1))
        )
        val v2 = CertificateConfig(
            version = 2,
            pins = listOf(HostPin("new.example.com", listOf("h3", "h4"), version = 2))
        )

        store.save(v1)
        store.save(v2)

        val loaded = store.load()
        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("new.example.com", loaded.pins[0].hostname)
        assertEquals(2, store.getCurrentVersion())
    }

    @Test
    fun `backward compatible parsing -- old format`() {
        // Old format: hostname|hash1,hash2 (no version field)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "api.example.com|hashA,hashB")
            .apply()

        val loaded = store.load()
        assertNotNull(loaded)
        assertEquals(1, loaded!!.pins.size)
        assertEquals("api.example.com", loaded.pins[0].hostname)
        assertEquals(listOf("hashA", "hashB"), loaded.pins[0].sha256)
        assertEquals(0, loaded.pins[0].version) // old format defaults to version 0
    }

    @Test
    fun `malformed data returns null`() {
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "")
            .apply()

        assertNull(store.load())
    }

    @Test
    fun `single hash host is filtered out`() {
        // Write entry with only 1 hash (HostPin requires >= 2)
        prefs.edit()
            .putInt(CertificateConfigStore.KEY_VERSION, 1)
            .putString(CertificateConfigStore.KEY_PINS, "api.example.com|1|singlehash")
            .apply()

        // Should filter out the host since it has only 1 hash
        assertNull(store.load())
    }

    @Test
    fun `computedVersion uses max of host versions`() {
        val config = CertificateConfig(
            version = 0,
            pins = listOf(
                HostPin("a.com", listOf("h1", "h2"), version = 2),
                HostPin("b.com", listOf("h3", "h4"), version = 7),
                HostPin("c.com", listOf("h5", "h6"), version = 3)
            )
        )

        store.save(config)
        assertEquals(7, store.getCurrentVersion())
    }
}
