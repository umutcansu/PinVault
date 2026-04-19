package com.example.pinvault.server.store

import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * Token store security properties:
 *   - Plaintext is never stored (only SHA-256 hash)
 *   - Triple binding (configApiId, vaultKey, deviceId) is strict
 *   - Revocation is permanent until a new token replaces the row
 *   - Constant-time compare via MessageDigest.isEqual (verified indirectly
 *     by happy-path + wrong-token scenarios)
 */
class VaultFileTokenStoreTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: VaultFileTokenStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("token-store-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = VaultFileTokenStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    @Test
    fun `put then validate returns true for exact triple`() {
        store.put("api-1", "file-a", "device-x", "secret-plaintext-123", Instant.now().toString())
        assertTrue(store.validate("api-1", "file-a", "device-x", "secret-plaintext-123"))
    }

    @Test
    fun `validate returns false for wrong token`() {
        store.put("api-1", "file-a", "device-x", "correct-token", Instant.now().toString())
        assertFalse(store.validate("api-1", "file-a", "device-x", "wrong-token"))
    }

    @Test
    fun `validate returns false for different device`() {
        store.put("api-1", "file-a", "device-x", "tok", Instant.now().toString())
        assertFalse(store.validate("api-1", "file-a", "device-y", "tok"))
    }

    @Test
    fun `validate returns false for different file key`() {
        store.put("api-1", "file-a", "device-x", "tok", Instant.now().toString())
        assertFalse(store.validate("api-1", "file-b", "device-x", "tok"))
    }

    @Test
    fun `validate returns false for different config API scope`() {
        store.put("api-1", "file-a", "device-x", "tok", Instant.now().toString())
        assertFalse(store.validate("api-2", "file-a", "device-x", "tok"))
    }

    @Test
    fun `plaintext is not stored — only the hash`() {
        val plaintext = "totally-secret-token-xyz"
        store.put("api-1", "file-a", "device-x", plaintext, Instant.now().toString())

        // Dump raw DB and scan for plaintext
        db.connection().use { conn ->
            conn.createStatement().use { stmt ->
                val rs = stmt.executeQuery("SELECT token_hash FROM vault_file_tokens")
                rs.next()
                val stored = rs.getString("token_hash")
                assertNotEquals(plaintext, stored)
                assertFalse(stored.contains(plaintext), "Hash must not leak plaintext")
                // SHA-256 hex → 64 chars
                assertEquals(64, stored.length)
            }
        }
    }

    @Test
    fun `reissuing replaces the prior token hash (old token invalid)`() {
        store.put("api-1", "file-a", "device-x", "old-token", Instant.now().toString())
        store.put("api-1", "file-a", "device-x", "new-token", Instant.now().toString())

        assertFalse(store.validate("api-1", "file-a", "device-x", "old-token"))
        assertTrue(store.validate("api-1", "file-a", "device-x", "new-token"))
    }

    @Test
    fun `revoke disables the token permanently`() {
        val id = store.put("api-1", "file-a", "device-x", "tok", Instant.now().toString())
        assertTrue(store.validate("api-1", "file-a", "device-x", "tok"))
        assertTrue(store.revoke(id))
        assertFalse(store.validate("api-1", "file-a", "device-x", "tok"))
    }

    @Test
    fun `listForFile returns only rows for that config API + key`() {
        val t = Instant.now().toString()
        store.put("api-1", "file-a", "d1", "t1", t)
        store.put("api-1", "file-a", "d2", "t2", t)
        store.put("api-1", "file-b", "d1", "t3", t)
        store.put("api-2", "file-a", "d1", "t4", t)

        val rows = store.listForFile("api-1", "file-a")
        assertEquals(2, rows.size)
        assertEquals(setOf("d1", "d2"), rows.map { it.deviceId }.toSet())
    }
}
