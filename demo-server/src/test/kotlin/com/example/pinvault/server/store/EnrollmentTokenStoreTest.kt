package com.example.pinvault.server.store

import java.io.File
import kotlin.test.*

/**
 * audit N-8: enrollment tokens must never be recoverable from the database or
 * from the admin listing. The store keeps only SHA-256(plaintext); the
 * plaintext exists exactly once, as the return value of [EnrollmentTokenStore.create].
 *
 * These tests assert both halves: validation still works through the hash, and
 * nothing that leaves the store can be replayed as a token.
 */
class EnrollmentTokenStoreTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: EnrollmentTokenStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("enrollment-token-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = EnrollmentTokenStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun storedTokenColumn(clientId: String): String =
        db.connection().use { conn ->
            conn.prepareStatement("SELECT token FROM enrollment_tokens WHERE client_id = ?").use { stmt ->
                stmt.setString(1, clientId)
                val rs = stmt.executeQuery()
                assertTrue(rs.next(), "no row for $clientId")
                rs.getString("token")
            }
        }

    @Test
    fun `created token validates and resolves the client id`() {
        val token = store.create("dev-1")
        assertEquals("dev-1", store.validate(token))
    }

    @Test
    fun `database stores only the SHA-256 hash, never the plaintext`() {
        val token = store.create("dev-2")
        val stored = storedTokenColumn("dev-2")

        assertNotEquals(token, stored)
        assertEquals(EnrollmentTokenStore.hash(token), stored)
        // 32 bytes of SHA-256 as lowercase hex.
        assertEquals(64, stored.length)
        assertTrue(stored.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `the stored hash cannot be replayed as a token`() {
        store.create("dev-3")
        val stored = storedTokenColumn("dev-3")
        // Feeding the hash back in would hash it again — no match.
        assertNull(store.validate(stored))
    }

    @Test
    fun `listing exposes a masked prefix, not a usable credential`() {
        val token = store.create("dev-4")
        val listed = store.getAll().single { it.clientId == "dev-4" }

        assertTrue(listed.masked)
        assertNotEquals(token, listed.token)
        assertTrue(listed.token.endsWith("…"))
        // The prefix identifies the row but is far too short to enroll with.
        assertTrue(listed.token.length < token.length)
        assertNull(store.validate(listed.token))
    }

    @Test
    fun `masked prefix matches the plaintext head so admins can tell rows apart`() {
        val token = store.create("dev-5")
        val listed = store.getAll().single { it.clientId == "dev-5" }
        assertEquals(token.take(8) + "…", listed.token)
    }

    @Test
    fun `markUsed consumes the token exactly once`() {
        val token = store.create("dev-6")
        assertEquals("dev-6", store.validate(token))
        store.markUsed(token)
        assertNull(store.validate(token))
        assertTrue(store.getAll().single { it.clientId == "dev-6" }.used)
    }

    @Test
    fun `a wrong token never validates`() {
        store.create("dev-7")
        assertNull(store.validate("definitely-not-the-token"))
    }

    @Test
    fun `two tokens for the same client are independent`() {
        val first = store.create("dev-8")
        val second = store.create("dev-8")
        assertNotEquals(first, second)

        store.markUsed(first)
        assertNull(store.validate(first))
        assertEquals("dev-8", store.validate(second))
    }

    // ── Expiry in the admin listing ─────────────────────────────────────
    //
    // validate() has always honoured expires_at, but getAll() did not report
    // it: an expired token was listed exactly like a fresh one, so the
    // dashboard showed "waiting" for a credential the server would refuse.

    /** Rewrites a row's expiry directly; TTL is read from the env var at create() time. */
    private fun forceExpiry(clientId: String, expiresAt: java.time.Instant) {
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE enrollment_tokens SET expires_at = ? WHERE client_id = ?").use { stmt ->
                stmt.setString(1, expiresAt.toString())
                stmt.setString(2, clientId)
                assertEquals(1, stmt.executeUpdate())
            }
        }
    }

    @Test
    fun `listing carries the expiry instant`() {
        store.create("dev-9")
        val listed = store.getAll().single { it.clientId == "dev-9" }

        val expiresAt = assertNotNull(listed.expiresAt, "expiresAt must be listed")
        assertTrue(java.time.Instant.parse(expiresAt).isAfter(java.time.Instant.now()))
        assertFalse(listed.expired)
    }

    @Test
    fun `an expired token is listed as expired`() {
        val token = store.create("dev-10")
        forceExpiry("dev-10", java.time.Instant.now().minusSeconds(60))

        val listed = store.getAll().single { it.clientId == "dev-10" }
        assertTrue(listed.expired, "the listing must match what validate() does")
        assertFalse(listed.used, "expired is a separate state from used")
        assertNull(store.validate(token), "sanity: the server really does refuse it")
    }

    @Test
    fun `a used token stays used even after it expires`() {
        val token = store.create("dev-11")
        store.markUsed(token)
        forceExpiry("dev-11", java.time.Instant.now().minusSeconds(60))

        val listed = store.getAll().single { it.clientId == "dev-11" }
        assertTrue(listed.used)
        assertTrue(listed.expired)
    }

    @Test
    fun `a row without an expiry is never reported as expired`() {
        store.create("dev-12")
        db.connection().use { conn ->
            conn.prepareStatement("UPDATE enrollment_tokens SET expires_at = NULL WHERE client_id = ?").use { stmt ->
                stmt.setString(1, "dev-12")
                stmt.executeUpdate()
            }
        }

        val listed = store.getAll().single { it.clientId == "dev-12" }
        assertNull(listed.expiresAt)
        assertFalse(listed.expired, "absent expiry means no expiry, same rule as validate()")
    }
}
