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
        assertEquals(UserAuth.NONE, config.userAuth)
    }

    @Test
    fun `builder carries the user-auth lock`() {
        val config = VaultFileConfig.Builder("statement")
            .endpoint("api/v1/vault/statement")
            .userAuth(UserAuth.IF_SCREEN_LOCK)
            .build()

        assertEquals(UserAuth.IF_SCREEN_LOCK, config.userAuth)
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

    @Test
    fun `USER_AUTH encryption needs a userAuth policy`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            VaultFileConfig.Builder("statement")
                .endpoint("api/v1/vault/statement")
                .encryption(VaultFileEncryption.USER_AUTH)
                .build()
        }
        assertTrue(e.message!!.contains("userAuth"))

        val config = VaultFileConfig.Builder("statement")
            .endpoint("api/v1/vault/statement")
            .encryption(VaultFileEncryption.USER_AUTH)
            .userAuth(UserAuth.IF_SCREEN_LOCK)
            .build()
        assertEquals(VaultFileEncryption.USER_AUTH, config.encryption)
    }

    @Test
    fun `unlock prompt has a cancel text for fingerprint-only prompts`() {
        assertEquals("Cancel", VaultFileUnlockPrompt("Open").negativeButtonText)
        assertEquals("Vazgeç", VaultFileUnlockPrompt("Aç", negativeButtonText = "Vazgeç").negativeButtonText)
    }

    // ── Offline lifetime and the opt-in hardening ───────────────────────

    @Test
    fun `offline lifetime is unlimited unless set, per file or for the whole config`() {
        val plain = VaultFileConfig.Builder("flags").endpoint("api/v1/vault/flags").build()
        assertNull("null = whatever the config says", plain.maxOfflineAgeMs)
        assertFalse(plain.wipeWhenStale)

        val secret = VaultFileConfig.Builder("secret")
            .endpoint("api/v1/vault/secret")
            .maxOfflineAge(7, java.util.concurrent.TimeUnit.DAYS)
            .wipeWhenStale()
            .build()
        assertEquals(7L * 24 * 60 * 60 * 1000, secret.maxOfflineAgeMs)
        assertTrue(secret.wipeWhenStale)

        assertThrows(IllegalArgumentException::class.java) {
            VaultFileConfig.Builder("x").maxOfflineAge(-1, java.util.concurrent.TimeUnit.DAYS)
        }
    }

    private fun config(configure: PinVaultConfig.Builder.() -> Unit = {}) = PinVaultConfig.Builder()
        .configApi("default", "https://config.example.com/") {
            bootstrapPins(listOf(HostPin("config.example.com", listOf("h1", "h2"))))
            allowUnsigned()
        }
        .apply(configure)
        .build()

    @Test
    fun `the config carries a default offline lifetime and the unlocked-device option, both off by default`() {
        val defaults = config()
        assertEquals("0 = no limit", 0L, defaults.vaultFileMaxOfflineAgeMs)
        assertFalse(defaults.requireUnlockedDevice)

        val hardened = config {
            vaultFileMaxOfflineAge(30, java.util.concurrent.TimeUnit.DAYS)
            requireUnlockedDevice()
        }
        assertEquals(30L * 24 * 60 * 60 * 1000, hardened.vaultFileMaxOfflineAgeMs)
        assertTrue(hardened.requireUnlockedDevice)
        assertThrows(IllegalArgumentException::class.java) {
            PinVaultConfig.Builder().vaultFileMaxOfflineAge(-1, java.util.concurrent.TimeUnit.HOURS)
        }
    }

    @Test
    fun `a block takes a server-made key only when it says so`() {
        assertFalse(config().configApis.getValue("default").allowServerGeneratedKey)
        val optedIn = PinVaultConfig.Builder()
            .configApi("default", "https://config.example.com/") {
                bootstrapPins(listOf(HostPin("config.example.com", listOf("h1", "h2"))))
                allowUnsigned()
                allowServerGeneratedKey()
                maxClientCertLifetimeDays(120)
            }.build().configApis.getValue("default")
        assertTrue(optedIn.allowServerGeneratedKey)
        assertEquals(120, optedIn.maxClientCertLifetimeDays)
        assertThrows(IllegalArgumentException::class.java) {
            ConfigApiBlock.Builder("x", "https://x/").maxClientCertLifetimeDays(0)
        }
    }

    @Test
    fun `there is a status for every way a stored file may not be handed out`() {
        assertEquals(
            setOf("AVAILABLE", "LOCKED", "NOT_STORED", "STALE", "NEEDS_FETCH", "INTEGRITY_FAILED", "STORAGE_UNAVAILABLE"),
            VaultFileStatus.entries.map { it.name }.toSet()
        )
        assertEquals(VaultFileUnlockResult.Stale("statement"), VaultFileUnlockResult.Stale("statement"))
    }
}
