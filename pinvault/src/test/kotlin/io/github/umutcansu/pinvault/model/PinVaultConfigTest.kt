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
            allowUnsigned()
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
        PinVaultConfig.Builder().configApi("api", "") {
            bootstrapPins(validPins); allowUnsigned()
        }.build()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Builder — empty bootstrap pins throws`() {
        PinVaultConfig.Builder().configApi("api", "https://api.example.com/") {
            bootstrapPins(emptyList()); allowUnsigned()
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
                wantPinsFor("scoped.example.com")
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
        assertEquals(listOf("scoped.example.com"), block.wantPinsFor)
        assertEquals("myLabel", block.clientCertLabel)
    }

    @Test
    fun `config with vaultFiles DSL`() {
        val config = PinVaultConfig.Builder()
            .configApi("api", "https://api.example.com/") {
                bootstrapPins(validPins); allowUnsigned()
            }
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

    @Test
    fun `Builder — missing signaturePublicKey throws without allowUnsigned`() {
        try {
            PinVaultConfig.Builder().configApi("api", "https://api.example.com/") {
                bootstrapPins(validPins)
                // no signaturePublicKey(...) and no allowUnsigned()
            }.build()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue("Error must mention signaturePublicKey: ${e.message}",
                e.message!!.contains("signaturePublicKey"))
        }
    }

    @Test
    fun `Builder — signaturePublicKey set satisfies requirement`() {
        // No exception — explicit key provided, allowUnsigned() not needed.
        PinVaultConfig.Builder().configApi("api", "https://api.example.com/") {
            bootstrapPins(validPins)
            signaturePublicKey("ABCDEF123")
        }.build()
    }

    // ── Several signing keys, m-of-n, recovery keys ─────────────────────────

    private fun blockWith(init: io.github.umutcansu.pinvault.model.ConfigApiBlock.Builder.() -> Unit) =
        PinVaultConfig.Builder().configApi("api", "https://api.example.com/") {
            bootstrapPins(validPins)
            init()
        }.build().configApis.getValue("api")

    private fun assertBuildFails(expected: String, init: io.github.umutcansu.pinvault.model.ConfigApiBlock.Builder.() -> Unit) {
        try {
            blockWith(init)
            fail("expected IllegalArgumentException mentioning '$expected'")
        } catch (e: IllegalArgumentException) {
            assertTrue("Error must mention $expected: ${e.message}", e.message!!.contains(expected))
        }
    }

    @Test
    fun `Builder — signaturePublicKeys keeps the first key in signaturePublicKey`() {
        val block = blockWith { signaturePublicKeys("K1", "K2", "K1") }
        assertEquals(listOf("K1", "K2"), block.signaturePublicKeys)
        assertEquals("K1", block.signaturePublicKey)
        assertEquals(1, block.requiredSignatures)
        assertTrue(block.recoveryPublicKeys.isEmpty())
    }

    @Test
    fun `Builder — signaturePublicKey alone still works as a one-key list`() {
        val block = blockWith { signaturePublicKey("K1") }
        assertEquals(listOf("K1"), block.signaturePublicKeys)
        assertEquals("K1", block.signaturePublicKey)
    }

    @Test
    fun `Builder — requiredSignatures must fit the key count`() {
        assertBuildFails("requiredSignatures(3)") { signaturePublicKeys("K1", "K2"); requiredSignatures(3) }
        assertBuildFails("requiredSignatures(0)") { signaturePublicKeys("K1", "K2"); requiredSignatures(0) }
        assertEquals(2, blockWith { signaturePublicKeys("K1", "K2"); requiredSignatures(2) }.requiredSignatures)
    }

    @Test
    fun `Builder — recovery keys need signing keys and a separate role`() {
        assertBuildFails("recoveryPublicKeys") { allowUnsigned(); recoveryPublicKeys("R1") }
        assertBuildFails("recovery key must not also be a signing key") {
            signaturePublicKeys("K1", "R1"); recoveryPublicKeys("R1")
        }
        assertBuildFails("requiredRecoverySignatures(2)") {
            signaturePublicKey("K1"); recoveryPublicKeys("R1"); requiredRecoverySignatures(2)
        }
        val block = blockWith {
            signaturePublicKey("K1"); recoveryPublicKeys("R1", "R2"); requiredRecoverySignatures(2)
        }
        assertEquals(listOf("R1", "R2"), block.recoveryPublicKeys)
        assertEquals(2, block.requiredRecoverySignatures)
    }

    @Test
    fun `Builder — PEM armour and stray whitespace do not make a second key`() {
        val pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYH\nKoZIzj0C\n-----END PUBLIC KEY-----\n"
        val block = blockWith { signaturePublicKeys(pem, "MFkwEwYHKoZIzj0C", " MFkwEwYHKoZIzj0C\n") }
        assertEquals(listOf("MFkwEwYHKoZIzj0C"), block.signaturePublicKeys)
        assertBuildFails("recovery key must not also be a signing key") {
            signaturePublicKey("MFkwEwYHKoZIzj0C"); recoveryPublicKeys(pem)
        }
    }
}
