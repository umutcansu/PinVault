package com.example.pinvault.server

import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.VaultFileStore
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Proves that `encryption = at_rest` is real: content is AES-256-GCM encrypted
 * in the DB and transparently decrypted on read, while `plain` stays verbatim.
 */
class VaultAtRestEncryptionTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: VaultFileStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-atrest-", ".db").apply { deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        store = VaultFileStore(db)
    }

    @AfterTest
    fun tearDown() {
        dbFile.delete()
    }

    /** Raw bytes straight from the DB, bypassing the store's transparent decrypt. */
    private fun rawContent(cid: String, key: String): ByteArray =
        db.connection().use { c ->
            c.prepareStatement("SELECT content FROM vault_files WHERE config_api_id=? AND key=?").use { s ->
                s.setString(1, cid); s.setString(2, key)
                val rs = s.executeQuery(); check(rs.next()); rs.getBytes("content")
            }
        }

    @Test
    fun `at_rest stores ciphertext but round-trips to plaintext`() {
        val plain = "top secret feature flags".toByteArray()
        store.put("api", "secret", plain, accessPolicy = "token", encryption = "at_rest")

        assertContentEquals(plain, store.get("api", "secret")!!.content, "get() must return plaintext")
        val raw = rawContent("api", "secret")
        assertFalse(raw.contentEquals(plain), "DB content must be encrypted, not raw plaintext")
        assertTrue(raw.size > plain.size, "ciphertext carries marker+salt+iv+tag")
    }

    // end_to_end used to sit in the clear on the server disk: the server
    // encrypts each download for one device, so it needs the content, but
    // not unencrypted on disk.
    @Test
    fun `end_to_end is stored encrypted too`() {
        val plain = "model weights".toByteArray()
        store.put("api", "model", plain, accessPolicy = "token", encryption = "end_to_end")
        assertFalse(rawContent("api", "model").contentEquals(plain), "DB content must be encrypted")
        assertContentEquals(plain, store.get("api", "model")!!.content)
    }

    @Test
    fun `end_to_end files stored before are encrypted at startup`() {
        val plain = "stored long ago".toByteArray()
        store.put("api", "old", plain, accessPolicy = "token", encryption = "plain")
        db.connection().use { c -> c.createStatement().use { it.executeUpdate("UPDATE vault_files SET encryption = 'end_to_end' WHERE key = 'old'") } }
        assertContentEquals(plain, rawContent("api", "old"), "the old layout: in the clear")

        kotlin.test.assertEquals(1, store.encryptStoredDeviceFiles())
        assertFalse(rawContent("api", "old").contentEquals(plain))
        assertContentEquals(plain, store.get("api", "old")!!.content)
        kotlin.test.assertEquals(0, store.encryptStoredDeviceFiles(), "a second run changes nothing")
    }

    @Test
    fun `plain stores verbatim`() {
        val plain = "not secret".toByteArray()
        store.put("api", "pub", plain, accessPolicy = "public", encryption = "plain")
        assertContentEquals(plain, rawContent("api", "pub"), "plain must be stored raw")
        assertContentEquals(plain, store.get("api", "pub")!!.content)
    }

    @Test
    fun `updatePolicy plain to at_rest encrypts existing content`() {
        val plain = "becomes secret".toByteArray()
        store.put("api", "f", plain, accessPolicy = "token", encryption = "plain")
        assertContentEquals(plain, rawContent("api", "f"))
        store.updatePolicy("api", "f", "token", "at_rest")
        assertFalse(rawContent("api", "f").contentEquals(plain), "must be encrypted after switch")
        assertContentEquals(plain, store.get("api", "f")!!.content, "still decrypts to plaintext")
    }

    @Test
    fun `updatePolicy at_rest to plain decrypts existing content`() {
        val plain = "becomes public".toByteArray()
        store.put("api", "g", plain, accessPolicy = "token", encryption = "at_rest")
        store.updatePolicy("api", "g", "public", "plain")
        assertContentEquals(plain, rawContent("api", "g"), "stored raw after switch to plain")
        assertContentEquals(plain, store.get("api", "g")!!.content)
    }
}
