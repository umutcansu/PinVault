package com.example.pinvault.server.store

import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * Server-side device public key registration. The store is idempotent
 * per (deviceId, configApiId) and isolated per-Config-API — re-enrollment
 * on device A never overwrites device B's key, and the same device can
 * have different keys registered with different Config APIs.
 */
class DevicePublicKeyStoreTest {

    private val pem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
        -----END PUBLIC KEY-----
    """.trimIndent()
    private val pem2 = """
        -----BEGIN PUBLIC KEY-----
        DIFFERENT_KEY_VALUE_HERE
        -----END PUBLIC KEY-----
    """.trimIndent()

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: DevicePublicKeyStore
    private val now get() = Instant.now().toString()

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("device-pk-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = DevicePublicKeyStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    @Test
    fun `register then get returns the PEM`() {
        store.register("dev-a", "api-1", pem, timestamp = now)
        val entry = store.get("dev-a", "api-1")!!
        assertEquals(pem, entry.publicKeyPem)
        assertEquals("RSA-OAEP-SHA256", entry.algorithm)
    }

    @Test
    fun `get returns null for unknown device`() {
        assertNull(store.get("never-seen", "api-1"))
    }

    @Test
    fun `get isolated per Config API (same device, different API)`() {
        store.register("dev-a", "api-1", pem, timestamp = now)
        assertNull(store.get("dev-a", "api-2"))
    }

    @Test
    fun `re-register overwrites PEM for same scope`() {
        store.register("dev-a", "api-1", pem, timestamp = now)
        store.register("dev-a", "api-1", pem2, timestamp = now)
        assertEquals(pem2, store.get("dev-a", "api-1")!!.publicKeyPem)
    }

    @Test
    fun `same device can have different keys in different Config APIs`() {
        store.register("dev-a", "api-1", pem, timestamp = now)
        store.register("dev-a", "api-2", pem2, timestamp = now)

        assertEquals(pem, store.get("dev-a", "api-1")!!.publicKeyPem)
        assertEquals(pem2, store.get("dev-a", "api-2")!!.publicKeyPem)
    }

    @Test
    fun `listForConfigApi returns only rows for that API`() {
        store.register("dev-a", "api-1", pem, timestamp = now)
        store.register("dev-b", "api-1", pem, timestamp = now)
        store.register("dev-a", "api-2", pem, timestamp = now)

        val list1 = store.listForConfigApi("api-1").map { it.deviceId }.toSet()
        val list2 = store.listForConfigApi("api-2").map { it.deviceId }.toSet()
        assertEquals(setOf("dev-a", "dev-b"), list1)
        assertEquals(setOf("dev-a"), list2)
    }

    @Test
    fun `custom algorithm string is persisted`() {
        store.register("dev-a", "api-1", pem, algorithm = "RSA-OAEP-SHA384", timestamp = now)
        assertEquals("RSA-OAEP-SHA384", store.get("dev-a", "api-1")!!.algorithm)
    }
}
