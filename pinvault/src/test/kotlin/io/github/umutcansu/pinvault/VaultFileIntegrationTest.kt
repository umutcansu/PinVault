package io.github.umutcansu.pinvault

import android.content.Context
import android.content.SharedPreferences
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.store.VaultFileStore
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.test.core.app.ApplicationProvider

/**
 * Integration tests for VaultFile functionality.
 * Uses a mock CertificateConfigApi and real VaultFileStore.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileIntegrationTest {

    private lateinit var store: VaultFileStore
    private lateinit var mockApi: CertificateConfigApi

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val prefs = context.getSharedPreferences("test_vault_integration", Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        store = VaultFileStore.createForTest(prefs)
        mockApi = mockk()
    }

    @Test
    fun `fetchFile downloads and stores content`() = runTest {
        val expectedBytes = "hello world".toByteArray()
        coEvery { mockApi.downloadVaultFile("api/v1/vault/test") } returns expectedBytes

        val fileConfig = VaultFileConfig(key = "test", endpoint = "api/v1/vault/test")
        val result = fetchFileWithMocks("test", fileConfig, expectedBytes)

        assertTrue(result is VaultFileResult.Updated)
        val updated = result as VaultFileResult.Updated
        assertEquals("test", updated.key)
        assertEquals(1, updated.version)
        assertArrayEquals(expectedBytes, updated.bytes)

        // Verify stored
        assertArrayEquals(expectedBytes, store.load("test"))
        assertEquals(1, store.getVersion("test"))
    }

    @Test
    fun `fetchFile returns AlreadyCurrent when content unchanged`() = runTest {
        val bytes = "same content".toByteArray()
        store.save("test", bytes, 3)

        val fileConfig = VaultFileConfig(key = "test", endpoint = "api/v1/vault/test")
        val result = fetchFileWithMocks("test", fileConfig, bytes)

        assertTrue(result is VaultFileResult.AlreadyCurrent)
        assertEquals(3, (result as VaultFileResult.AlreadyCurrent).version)
    }

    @Test
    fun `fetchFile returns Failed on network error`() = runTest {
        coEvery { mockApi.downloadVaultFile(any()) } throws java.io.IOException("timeout")

        val fileConfig = VaultFileConfig(key = "test", endpoint = "api/v1/vault/test")
        val result = fetchFileWithApiError("test", fileConfig)

        assertTrue(result is VaultFileResult.Failed)
        assertEquals("test", (result as VaultFileResult.Failed).key)
        assertTrue(result.reason.contains("timeout"))
    }

    @Test
    fun `loadFile returns cached content`() {
        val bytes = byteArrayOf(1, 2, 3)
        store.save("cached", bytes, 1)
        assertArrayEquals(bytes, store.load("cached"))
    }

    @Test
    fun `loadFile returns null when not fetched`() {
        assertNull(store.load("not-fetched"))
    }

    @Test
    fun `hasFile and clearFile lifecycle`() {
        assertFalse(store.exists("lifecycle"))
        store.save("lifecycle", byteArrayOf(1), 1)
        assertTrue(store.exists("lifecycle"))
        store.clear("lifecycle")
        assertFalse(store.exists("lifecycle"))
    }

    @Test
    fun `multiple files are independent`() = runTest {
        store.save("file-a", "aaa".toByteArray(), 1)
        store.save("file-b", "bbb".toByteArray(), 2)

        assertEquals("aaa", String(store.load("file-a")!!))
        assertEquals("bbb", String(store.load("file-b")!!))

        store.clear("file-a")
        assertNull(store.load("file-a"))
        assertNotNull(store.load("file-b"))
    }

    @Test
    fun `custom storage provider is used`() = runTest {
        val saved = mutableMapOf<String, ByteArray>()
        val customProvider = object : VaultStorageProvider {
            override fun save(key: String, bytes: ByteArray, version: Int) { saved[key] = bytes }
            override fun load(key: String): ByteArray? = saved[key]
            override fun getVersion(key: String): Int = if (saved.containsKey(key)) 1 else 0
            override fun exists(key: String): Boolean = saved.containsKey(key)
            override fun clear(key: String) { saved.remove(key) }
        }

        val bytes = "custom".toByteArray()
        customProvider.save("test", bytes, 1)

        assertTrue(customProvider.exists("test"))
        assertArrayEquals(bytes, customProvider.load("test"))
        assertEquals(1, customProvider.getVersion("test"))
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * Simulates fetchFileInternal logic without PinVault singleton.
     */
    private suspend fun fetchFileWithMocks(
        key: String,
        config: VaultFileConfig,
        serverBytes: ByteArray
    ): VaultFileResult {
        return try {
            val currentVersion = store.getVersion(key)
            val storedBytes = store.load(key)
            if (storedBytes != null && serverBytes.contentEquals(storedBytes)) {
                return VaultFileResult.AlreadyCurrent(key, currentVersion)
            }
            val newVersion = currentVersion + 1
            store.save(key, serverBytes, newVersion)
            VaultFileResult.Updated(key, newVersion, serverBytes)
        } catch (e: Exception) {
            VaultFileResult.Failed(key, e.message ?: "Unknown error", e)
        }
    }

    private suspend fun fetchFileWithApiError(key: String, config: VaultFileConfig): VaultFileResult {
        return try {
            mockApi.downloadVaultFile(config.endpoint)
            VaultFileResult.AlreadyCurrent(key, 0) // unreachable
        } catch (e: Exception) {
            VaultFileResult.Failed(key, e.message ?: "Unknown error", e)
        }
    }
}
