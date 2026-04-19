package io.github.umutcansu.pinvault.model

import org.junit.Assert.*
import org.junit.Test

/** PinVaultConfig builder validation tests (V2 DSL). */
class PinVaultConfigTest {

    private val validPins = listOf(
        HostPin("api.example.com", listOf(
            "pin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
            "pin2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="
        ))
    )

    private fun api(url: String, init: ConfigApiBlock.Builder.() -> Unit = {}) =
        PinVaultConfig.Builder().configApi("api", url) {
            bootstrapPins(validPins)
            init()
        }

    @Test
    fun `Builder — minimal config`() {
        val config = api("https://api.example.com").build()

        val block = config.defaultConfigApi!!
        assertEquals("https://api.example.com/", block.configUrl)
        assertEquals("api/v1/certificate-config", block.configEndpoint)
        assertEquals("health", block.healthEndpoint)
        assertEquals(3, config.maxRetryCount)
        assertEquals(12L, config.updateIntervalHours)
        assertNull(block.signaturePublicKey)
        assertNull(block.clientKeystoreBytes)
        assertEquals("changeit", block.clientKeyPassword)
    }

    @Test
    fun `Builder — URL without trailing slash gets normalized`() {
        val block = api("https://api.example.com").build().defaultConfigApi!!
        assertEquals("https://api.example.com/", block.configUrl)
    }

    @Test
    fun `Builder — URL with trailing slash stays unchanged`() {
        val block = api("https://api.example.com/").build().defaultConfigApi!!
        assertEquals("https://api.example.com/", block.configUrl)
    }

    @Test
    fun `Builder — custom endpoints trimmed`() {
        val block = api("https://api.example.com/") {
            configEndpoint("/custom/config")
            healthEndpoint("/custom/health")
        }.build().defaultConfigApi!!
        assertEquals("custom/config", block.configEndpoint)
        assertEquals("custom/health", block.healthEndpoint)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Builder — blank URL throws`() {
        PinVaultConfig.Builder().configApi("api", "") { bootstrapPins(validPins) }.build()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Builder — empty bootstrap pins throws`() {
        PinVaultConfig.Builder().configApi("api", "https://api.example.com/") {
            bootstrapPins(emptyList())
        }.build()
    }

    @Test
    fun `Builder — all fields set`() {
        val config = PinVaultConfig.Builder()
            .configApi("api", "https://api.example.com/") {
                bootstrapPins(validPins)
                configEndpoint("my/config")
                healthEndpoint("my/health")
                signaturePublicKey("ABCDEF123")
                clientKeystore(byteArrayOf(1, 2, 3), "mypass")
                enrollmentToken("tok123")
                clientCertLabel("myLabel")
            }
            .maxRetryCount(5)
            .updateIntervalHours(6)
            .updateIntervalMinutes(30)
            .build()

        val block = config.defaultConfigApi!!
        assertEquals("my/config", block.configEndpoint)
        assertEquals("my/health", block.healthEndpoint)
        assertEquals(5, config.maxRetryCount)
        assertEquals(6L, config.updateIntervalHours)
        assertEquals(30L, config.updateIntervalMinutes)
        assertEquals("ABCDEF123", block.signaturePublicKey)
        assertArrayEquals(byteArrayOf(1, 2, 3), block.clientKeystoreBytes)
        assertEquals("mypass", block.clientKeyPassword)
        assertEquals("tok123", block.enrollmentToken)
        assertEquals("myLabel", block.clientCertLabel)
    }

    @Test
    fun `config with vaultFiles DSL`() {
        val config = PinVaultConfig.Builder()
            .configApi("api", "https://api.example.com/") { bootstrapPins(validPins) }
            .vaultFile("ml-model") {
                configApi("api")
                endpoint("api/v1/vault/ml-model")
                storage(StorageStrategy.ENCRYPTED_FILE)
            }
            .vaultFile("flags") {
                configApi("api")
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
        val config = api("https://api.example.com/").build()
        assertTrue(config.vaultFiles.isEmpty())
    }
}
