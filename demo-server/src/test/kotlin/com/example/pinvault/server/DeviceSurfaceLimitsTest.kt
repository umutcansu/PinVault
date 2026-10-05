package com.example.pinvault.server

import com.example.pinvault.server.service.AdminKeyStrength
import com.example.pinvault.server.service.ConcurrencyLimiter
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.SignedConfigService
import com.example.pinvault.server.service.WebhookNotifier
import com.example.pinvault.server.store.ClientDeviceStore
import com.example.pinvault.server.store.DatabaseManager
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The smaller device-surface limits of the 2026-10-05 review (D-A2, D-A4, D-A5) and the admin key's length. */
class DeviceSurfaceLimitsTest {

    private val dir: File = Files.createTempDirectory("device-limits").toFile()

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    @Test
    fun `a vault signature is made once per file version, without hashing the file per request`() {
        // CONFIG_SIGNATURE_CACHE off: vault signatures are cached anyway (they carry no time).
        val envelopes = SignedConfigService(ConfigSigningService(File(dir, "k.pem")))
        val content = ByteArray(1024) { it.toByte() }
        val first = envelopes.vaultSignatures("scope", "model", 3, content)
        val again = envelopes.vaultSignatures("scope", "model", 3, content)
        assertTrue(first === again, "served from the cache")
        val next = envelopes.vaultSignatures("scope", "model", 4, content)
        assertFalse(next === first, "a new version is signed")
    }

    @Test
    fun `downloads at once are bounded per source`() {
        val slots = ConcurrencyLimiter(2)
        assertTrue(slots.tryAcquire("203.0.113.7"))
        assertTrue(slots.tryAcquire("203.0.113.7"))
        assertFalse(slots.tryAcquire("203.0.113.7"))
        assertTrue(slots.tryAcquire("198.51.100.1"), "another source is not affected")
        slots.release("203.0.113.7")
        assertTrue(slots.tryAcquire("203.0.113.7"))
    }

    @Test
    fun `reported devices are trimmed to the most recently seen`() {
        val store = ClientDeviceStore(DatabaseManager(File(dir, "db.sqlite").absolutePath), maxRows = 100)
        repeat(160) { store.upsert("h", "made-up-$it", null, null, 1, "ok", "2026-10-05T00:%02d:%02dZ".format(it / 60, it % 60)) }
        store.trim()
        assertEquals(100, store.count())
        assertTrue(store.getByHostname("h").any { it.deviceId == "made-up-159" }, "the newest stay")
        assertFalse(store.getByHostname("h").any { it.deviceId == "made-up-0" })
    }

    @Test
    fun `security events keep their place in a full webhook queue`() {
        for (event in listOf("pins_changed", "client_cert_revoked", "device_key_replaced", "change_approved", "auth_failed")) {
            assertTrue(WebhookNotifier.isSecurityEvent(event), event)
        }
        for (event in listOf("client_cert_issued", "enrollment_request_pending", "device_key_registered", "vault_downloaded")) {
            assertFalse(WebhookNotifier.isSecurityEvent(event), event)
        }
    }

    @Test
    fun `a short shared admin key is refused unless demo secrets are allowed`() {
        assertNull(AdminKeyStrength.check(mapOf("API_KEY" to "0123456789abcdef0123")))
        assertNull(AdminKeyStrength.check(emptyMap()), "ADMIN_KEYS only")
        val refused = assertFailsWith<IllegalStateException> { AdminKeyStrength.check(mapOf("API_KEY" to "admin-key-123")) }
        assertTrue(refused.message!!.contains("at least 16"))
        assertNotNull(AdminKeyStrength.check(mapOf("API_KEY" to "admin-key-123", "ALLOW_DEMO_SECRETS" to "true")), "a warning")
    }
}
