package io.github.umutcansu.pinvault.model

import org.junit.Assert.*
import org.junit.Test

/**
 * DSL validation for multi-Config-API support.
 */
class MultiConfigApiConfigTest {

    private fun pin(host: String) = HostPin(host, listOf("pin1", "pin2"))

    @Test
    fun `Builder with multiple configApis`() {
        val config = PinVaultConfig.Builder()
            .configApi("prod-tls", "https://host:8091") {
                bootstrapPins(listOf(pin("host:8091")))
            }
            .configApi("secure-mtls", "https://host:8092") {
                bootstrapPins(listOf(pin("host:8092")))
            }
            .build()

        assertEquals(2, config.configApis.size)
        assertEquals(setOf("prod-tls", "secure-mtls"), config.configApis.keys)
    }

    @Test
    fun `Builder requires at least one configApi or staticPins`() {
        try {
            PinVaultConfig.Builder().build()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Config API"))
        }
    }

    @Test
    fun `vaultFile bound to unknown configApi id is rejected at build`() {
        try {
            PinVaultConfig.Builder()
                .configApi("prod-tls", "https://host:8091") { bootstrapPins(listOf(pin("host:8091"))) }
                .vaultFile("feature-flags") {
                    configApi("nonexistent")
                    endpoint("api/v1/vault/feature-flags")
                }
                .build()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("nonexistent"))
        }
    }

    @Test
    fun `vaultFile bound to known configApi builds cleanly`() {
        val config = PinVaultConfig.Builder()
            .configApi("prod", "https://host/") { bootstrapPins(listOf(pin("host"))) }
            .vaultFile("flags") {
                configApi("prod")
                endpoint("api/v1/vault/flags")
            }
            .build()

        assertEquals(1, config.vaultFiles.size)
        assertEquals("prod", config.vaultFiles["flags"]!!.configApiId)
    }

    @Test
    fun `token policy without accessToken is rejected`() {
        try {
            PinVaultConfig.Builder()
                .configApi("prod", "https://host/") { bootstrapPins(listOf(pin("host"))) }
                .vaultFile("secret") {
                    configApi("prod")
                    endpoint("api/v1/vault/secret")
                    accessPolicy(VaultFileAccessPolicy.TOKEN)
                    // missing accessToken { … }
                }
                .build()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("accessToken"))
        }
    }

    @Test
    fun `token_mtls policy also requires accessToken`() {
        try {
            PinVaultConfig.Builder()
                .configApi("prod", "https://host/") { bootstrapPins(listOf(pin("host"))) }
                .vaultFile("secret") {
                    configApi("prod")
                    endpoint("api/v1/vault/secret")
                    accessPolicy(VaultFileAccessPolicy.TOKEN_MTLS)
                }
                .build()
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) { /* expected */ }
    }

    @Test
    fun `public policy needs no accessToken`() {
        PinVaultConfig.Builder()
            .configApi("prod", "https://host/") { bootstrapPins(listOf(pin("host"))) }
            .vaultFile("open") {
                configApi("prod")
                endpoint("api/v1/vault/open")
                accessPolicy(VaultFileAccessPolicy.PUBLIC)
            }
            .build()
    }

    @Test
    fun `wantPinsFor stores the list on the block`() {
        val config = PinVaultConfig.Builder()
            .configApi("prod", "https://host/") {
                bootstrapPins(listOf(pin("host")))
                wantPinsFor("cdn.example.com", "api.example.com")
            }
            .build()
        assertEquals(listOf("cdn.example.com", "api.example.com"),
            config.configApis["prod"]!!.wantPinsFor)
    }

    @Test
    fun `static() factory creates offline-mode config`() {
        val config = PinVaultConfig.static(pin("offline.com"))
        assertNotNull(config.staticPins)
        assertEquals(0, config.configApis.size)
    }

    @Test
    fun `defaultConfigApi returns the first registered block`() {
        val config = PinVaultConfig.Builder()
            .configApi("first", "https://first.com/") { bootstrapPins(listOf(pin("first.com"))) }
            .configApi("second", "https://second.com/") { bootstrapPins(listOf(pin("second.com"))) }
            .build()
        assertEquals("first", config.defaultConfigApi?.id)
    }

    @Test
    fun `duplicate configApi id replaces the prior block`() {
        val config = PinVaultConfig.Builder()
            .configApi("api", "https://first.com/") { bootstrapPins(listOf(pin("first.com"))) }
            .configApi("api", "https://second.com/") { bootstrapPins(listOf(pin("second.com"))) }
            .build()
        assertEquals(1, config.configApis.size)
        assertEquals("https://second.com/", config.configApis["api"]!!.configUrl)
    }
}
