package com.example.pinvault.server.store

import java.io.File
import kotlin.test.*

/**
 * V2 scope isolation: the same key under two different Config APIs must not
 * collide. Prior to V2 the vault had a single global key space — this is the
 * regression guard.
 */
class VaultFileStoreScopingTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: VaultFileStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("vault-scope-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = VaultFileStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    @Test
    fun `same key in two Config APIs does not collide`() {
        store.put("api-1", "ml-model", "v1-bytes-api1".toByteArray())
        store.put("api-2", "ml-model", "v1-bytes-api2".toByteArray())

        val e1 = store.get("api-1", "ml-model")!!
        val e2 = store.get("api-2", "ml-model")!!

        assertEquals("api-1", e1.configApiId)
        assertEquals("api-2", e2.configApiId)
        assertEquals("v1-bytes-api1", String(e1.content))
        assertEquals("v1-bytes-api2", String(e2.content))
    }

    @Test
    fun `get for wrong scope returns null even if key exists elsewhere`() {
        store.put("api-1", "secret", "payload".toByteArray())
        assertNull(store.get("api-2", "secret"))
        assertNull(store.get("api-9", "secret"))
    }

    @Test
    fun `listForConfigApi only returns rows for that scope`() {
        store.put("api-1", "a", "1".toByteArray())
        store.put("api-1", "b", "2".toByteArray())
        store.put("api-2", "a", "3".toByteArray())

        val list1 = store.listForConfigApi("api-1").map { it.key }.toSet()
        val list2 = store.listForConfigApi("api-2").map { it.key }.toSet()
        val list3 = store.listForConfigApi("api-3").map { it.key }.toSet()

        assertEquals(setOf("a", "b"), list1)
        assertEquals(setOf("a"), list2)
        assertEquals(emptySet(), list3)
    }

    @Test
    fun `listAll returns every scope`() {
        store.put("api-1", "a", "x".toByteArray())
        store.put("api-2", "a", "y".toByteArray())
        val all = store.listAll()
        assertEquals(2, all.size)
        assertEquals(setOf("api-1", "api-2"), all.map { it.configApiId }.toSet())
    }

    @Test
    fun `put in one scope doesn't bump version in another`() {
        store.put("api-1", "shared-key", "v1".toByteArray())
        store.put("api-2", "shared-key", "v1".toByteArray())
        store.put("api-1", "shared-key", "v2".toByteArray())
        store.put("api-1", "shared-key", "v3".toByteArray())

        assertEquals(3, store.get("api-1", "shared-key")!!.version)
        assertEquals(1, store.get("api-2", "shared-key")!!.version)  // unchanged
    }

    @Test
    fun `delete in one scope preserves the other`() {
        store.put("api-1", "target", "a".toByteArray())
        store.put("api-2", "target", "b".toByteArray())

        store.delete("api-1", "target")

        assertNull(store.get("api-1", "target"))
        assertNotNull(store.get("api-2", "target"))
    }

    @Test
    fun `access_policy and encryption stored per-scope`() {
        store.put("api-1", "f", "x".toByteArray(),
            accessPolicy = "token", encryption = "end_to_end")
        store.put("api-2", "f", "x".toByteArray(),
            accessPolicy = "public", encryption = "plain")

        val e1 = store.get("api-1", "f")!!
        val e2 = store.get("api-2", "f")!!

        assertEquals("token", e1.accessPolicy)
        assertEquals("end_to_end", e1.encryption)
        assertEquals("public", e2.accessPolicy)
        assertEquals("plain", e2.encryption)
    }
}
