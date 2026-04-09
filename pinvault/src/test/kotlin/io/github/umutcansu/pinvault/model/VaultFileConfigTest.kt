package io.github.umutcansu.pinvault.model

import io.github.umutcansu.pinvault.store.VaultStorageProvider
import org.junit.Assert.*
import org.junit.Test

class VaultFileConfigTest {

    @Test
    fun `builder creates valid config`() {
        val config = VaultFileConfig.Builder("ml-model")
            .endpoint("api/v1/vault/ml-model")
            .build()

        assertEquals("ml-model", config.key)
        assertEquals("api/v1/vault/ml-model", config.endpoint)
        assertNull(config.signaturePublicKey)
        assertFalse(config.updateWithPins)
        assertNull(config.storageProvider)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `builder fails with empty endpoint`() {
        VaultFileConfig.Builder("test").endpoint("").build()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `builder fails with blank endpoint`() {
        VaultFileConfig.Builder("test").endpoint("   ").build()
    }

    @Test
    fun `builder with signature key`() {
        val config = VaultFileConfig.Builder("signed")
            .endpoint("api/v1/vault/signed")
            .signaturePublicKey("MFkwEwYH...")
            .build()

        assertEquals("MFkwEwYH...", config.signaturePublicKey)
    }

    @Test
    fun `builder with updateWithPins flag`() {
        val config = VaultFileConfig.Builder("flags")
            .endpoint("api/v1/vault/flags")
            .updateWithPins(true)
            .build()

        assertTrue(config.updateWithPins)
    }

    @Test
    fun `builder with custom storage provider`() {
        val customProvider = object : VaultStorageProvider {
            override fun save(key: String, bytes: ByteArray, version: Int) {}
            override fun load(key: String): ByteArray? = null
            override fun getVersion(key: String): Int = 0
            override fun exists(key: String): Boolean = false
            override fun clear(key: String) {}
        }

        val config = VaultFileConfig.Builder("custom")
            .endpoint("api/v1/vault/custom")
            .storage(customProvider)
            .build()

        assertSame(customProvider, config.storageProvider)
    }

    @Test
    fun `builder with storage strategy`() {
        val config = VaultFileConfig.Builder("big")
            .endpoint("api/v1/vault/big")
            .storage(StorageStrategy.ENCRYPTED_FILE)
            .build()

        assertEquals(StorageStrategy.ENCRYPTED_FILE, config.storageStrategy)
    }

    @Test
    fun `endpoint leading slash is trimmed`() {
        val config = VaultFileConfig.Builder("test")
            .endpoint("/api/v1/vault/test")
            .build()

        assertEquals("api/v1/vault/test", config.endpoint)
    }
}
