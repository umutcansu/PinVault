package com.example.pinvault.server.store

import com.example.pinvault.server.service.VaultAtRestCipher
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The HS256 secrets of PinVault-Token sit in the database sealed under
 * `VAULT_AT_REST_PASSWORD`. A store that has no cipher used to hand the
 * ciphertext back as the secret, so a server started without the password
 * signed and verified tokens with bytes that were not the secret — and
 * nothing said so. Now that is an error, at start-up (Main calls
 * [AttestationTokenSecretStore.checkReadable]) and on every read.
 */
class AttestationTokenSecretStoreTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-token-secrets-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    @Test
    fun `a sealed secret is refused without the cipher, and with another password`() {
        val sealed = AttestationTokenSecretStore(db, VaultAtRestCipher("right-password"))
        val made = sealed.rotate("alice")
        assertContentEquals(made.secret, sealed.active().secret, "opens with its own cipher")

        val noCipher = AttestationTokenSecretStore(db, cipher = null)
        val error = assertFailsWith<IllegalStateException> { noCipher.checkReadable() }
        assertTrue(error.message!!.contains("VAULT_AT_REST_PASSWORD"), error.message)
        assertFailsWith<IllegalStateException> { noCipher.verificationKeys() }
        assertFailsWith<IllegalStateException> { noCipher.active() }

        val wrong = AttestationTokenSecretStore(db, VaultAtRestCipher("other-password"))
        val mismatch = assertFailsWith<IllegalStateException> { wrong.checkReadable() }
        assertTrue(mismatch.message!!.contains("VAULT_AT_REST_PASSWORD"), mismatch.message)
        assertFailsWith<IllegalStateException> { wrong.verificationKeys() }
    }

    @Test
    fun `a password change re-seals the secrets at start-up, as for vault files`() {
        val old = AttestationTokenSecretStore(db, VaultAtRestCipher("old-password"))
        val made = old.rotate("alice")

        val rotated = AttestationTokenSecretStore(db, VaultAtRestCipher("new-password", previous = listOf("old-password")))
        rotated.checkReadable()
        assertContentEquals(made.secret, rotated.all().first { it.kid == made.kid }.secret, "the same secret: issued tokens stay valid")

        // Sealed under the new password now: the old one alone no longer opens it.
        assertFailsWith<IllegalStateException> { old.checkReadable() }
        val current = AttestationTokenSecretStore(db, VaultAtRestCipher("new-password"))
        assertContentEquals(made.secret, current.active().secret)
    }

    @Test
    fun `a secret stored in the clear is still read, with or without a cipher`() {
        val plain = AttestationTokenSecretStore(db, cipher = null)
        val made = plain.rotate("alice")
        assertContentEquals(made.secret, plain.active().secret)
        plain.checkReadable()

        val withCipher = AttestationTokenSecretStore(db, VaultAtRestCipher("right-password"))
        assertContentEquals(made.secret, withCipher.all().first { it.kid == made.kid }.secret, "a legacy row is read as it is")
        assertEquals(made.kid, withCipher.active().kid, "no new secret is made for a readable one")

        // The start-up pass seals it; the content is unchanged.
        withCipher.checkReadable()
        assertContentEquals(made.secret, AttestationTokenSecretStore(db, VaultAtRestCipher("right-password")).active().secret)
        assertFailsWith<IllegalStateException> { plain.checkReadable() }
    }

    @Test
    fun `the active key is read from the database once, not on every token`() {
        val store = AttestationTokenSecretStore(db, VaultAtRestCipher("pw"))
        val first = store.active()
        val signer = store.activeSigningKey()
        assertEquals(first.kid, signer.kid)
        // The database is gone: a store that read it per call would fail now.
        db.connection().use { conn -> conn.createStatement().use { it.executeUpdate("DROP TABLE attestation_token_secrets") } }
        repeat(1_000) { assertEquals(first.kid, store.active().kid) }
        kotlin.test.assertSame(signer, store.activeSigningKey(), "parsed once per key")
    }

    @Test
    fun `a rotation or a deletion takes effect at once in the same process`() {
        val store = AttestationTokenSecretStore(db, VaultAtRestCipher("pw"))
        val first = store.active()
        val second = store.rotate("admin")
        assertEquals(second.kid, store.active().kid, "the new key signs from the next token on")
        assertEquals(second.kid, store.activeSigningKey().kid)
        assertEquals(setOf(first.kid, second.kid), store.verificationKeys().keys, "the old one still verifies")
        assertEquals(AttestationTokenSecretStore.Deletion.Deleted, store.delete(first.kid))
        assertEquals(setOf(second.kid), store.verificationKeys().keys)
        assertEquals(second.kid, store.active().kid)
        // Many threads asking while another rotates: each gets a whole key, and the newest once the rotation is done.
        val pool = java.util.concurrent.Executors.newFixedThreadPool(16)
        val seen = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val tasks = (0 until 2_000).map { pool.submit { seen.add(store.activeSigningKey().kid) } }
        val third = store.rotate("admin")
        tasks.forEach { it.get() }
        pool.shutdown()
        assertTrue(seen.all { it == second.kid || it == third.kid }, "$seen")
        assertEquals(third.kid, store.active().kid)
    }
}
