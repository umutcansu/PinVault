package io.github.umutcansu.pinvault.model

import org.junit.Assert.*
import org.junit.Test

/** PinVaultConfig builder validation tests */
class PinVaultConfigTest {

    private val validPins = listOf(
        HostPin("api.example.com", listOf("pin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", "pin2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="))
    )

    @Test
    fun `Builder — minimal config`() {
        val config = PinVaultConfig.Builder("https://api.example.com")
            .bootstrapPins(validPins)
            .build()

        assertEquals("https://api.example.com/", config.configUrl)
        assertEquals("api/v1/certificate-config", config.configEndpoint)
        assertEquals("health", config.healthEndpoint)
        assertEquals(3, config.maxRetryCount)
        assertEquals(12L, config.updateIntervalHours)
        assertNull(config.signaturePublicKey)
        assertNull(config.clientKeystoreBytes)
        assertEquals("changeit", config.clientKeyPassword)
    }

    @Test
    fun `Builder — URL without trailing slash gets normalized`() {
        val config = PinVaultConfig.Builder("https://api.example.com")
            .bootstrapPins(validPins)
            .build()
        assertEquals("https://api.example.com/", config.configUrl)
    }

    @Test
    fun `Builder — URL with trailing slash stays unchanged`() {
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(validPins)
            .build()
        assertEquals("https://api.example.com/", config.configUrl)
    }

    @Test
    fun `Builder — custom endpoints trimmed`() {
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(validPins)
            .configEndpoint("/custom/config")
            .healthEndpoint("/custom/health")
            .build()
        assertEquals("custom/config", config.configEndpoint)
        assertEquals("custom/health", config.healthEndpoint)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Builder — blank URL throws`() {
        PinVaultConfig.Builder("").bootstrapPins(validPins).build()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Builder — empty bootstrap pins throws`() {
        PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(emptyList())
            .build()
    }

    @Test
    fun `Builder — all fields set`() {
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(validPins)
            .configEndpoint("my/config")
            .healthEndpoint("my/health")
            .maxRetryCount(5)
            .updateIntervalHours(6)
            .updateIntervalMinutes(30)
            .signaturePublicKey("ABCDEF123")
            .clientKeystore(byteArrayOf(1, 2, 3), "mypass")
            .enrollmentToken("tok123")
            .clientCertLabel("myLabel")
            .build()

        assertEquals("my/config", config.configEndpoint)
        assertEquals("my/health", config.healthEndpoint)
        assertEquals(5, config.maxRetryCount)
        assertEquals(6L, config.updateIntervalHours)
        assertEquals(30L, config.updateIntervalMinutes)
        assertEquals("ABCDEF123", config.signaturePublicKey)
        assertArrayEquals(byteArrayOf(1, 2, 3), config.clientKeystoreBytes)
        assertEquals("mypass", config.clientKeyPassword)
        assertEquals("tok123", config.enrollmentToken)
        assertEquals("myLabel", config.clientCertLabel)
    }

    @Test
    fun `config with vaultFiles DSL`() {
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(validPins)
            .vaultFile("ml-model") {
                endpoint("api/v1/vault/ml-model")
                storage(StorageStrategy.ENCRYPTED_FILE)
            }
            .vaultFile("flags") {
                endpoint("api/v1/vault/flags")
                updateWithPins(true)
            }
            .build()

        assertEquals(2, config.vaultFiles.size)
        assertNotNull(config.vaultFiles["ml-model"])
        assertEquals("api/v1/vault/ml-model", config.vaultFiles["ml-model"]!!.endpoint)
        assertEquals(StorageStrategy.ENCRYPTED_FILE, config.vaultFiles["ml-model"]!!.storageStrategy)
        assertTrue(config.vaultFiles["flags"]!!.updateWithPins)
    }

    @Test
    fun `config without vaultFiles has empty map`() {
        val config = PinVaultConfig.Builder("https://api.example.com/")
            .bootstrapPins(validPins)
            .build()

        assertTrue(config.vaultFiles.isEmpty())
    }
}
