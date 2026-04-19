package com.example.pinvault.server.store

import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * ACL store is the authority for pin scoping — an off-by-one bug here would
 * either leak pins to unauthorized devices or starve legitimate ones. Tests
 * nail down the intersection semantics, union-with-defaults, and the
 * "denied" audit stream used by CertificateConfigRoutes' log warnings.
 */
class DeviceHostAclStoreTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: DeviceHostAclStore
    private val now get() = Instant.now().toString()

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("device-acl-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        store = DeviceHostAclStore(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    @Test
    fun `grant then list returns the hostname`() {
        store.grant("api-1", "dev-a", "cdn.example.com", now)
        assertEquals(listOf("cdn.example.com"), store.listForDevice("api-1", "dev-a"))
    }

    @Test
    fun `grant is idempotent`() {
        store.grant("api-1", "dev-a", "x.com", now)
        store.grant("api-1", "dev-a", "x.com", now)   // duplicate
        assertEquals(1, store.listForDevice("api-1", "dev-a").size)
    }

    @Test
    fun `revoke removes the row`() {
        store.grant("api-1", "dev-a", "x.com", now)
        assertTrue(store.revoke("api-1", "dev-a", "x.com"))
        assertEquals(emptyList(), store.listForDevice("api-1", "dev-a"))
    }

    @Test
    fun `getAllowed unions device ACL with default ACL`() {
        store.grant("api-1", "dev-a", "cdn.example.com", now)
        store.addDefault("api-1", "api.example.com")
        store.addDefault("api-1", "cdn.example.com")   // overlap is fine

        val allowed = store.getAllowed("api-1", "dev-a")
        assertEquals(setOf("cdn.example.com", "api.example.com"), allowed)
    }

    @Test
    fun `getAllowed returns only defaults when device has no ACL`() {
        store.addDefault("api-1", "api.example.com")
        assertEquals(setOf("api.example.com"), store.getAllowed("api-1", "never-seen"))
    }

    @Test
    fun `resolve with no requested returns the full allowed set, no denied`() {
        store.grant("api-1", "dev-a", "cdn.example.com", now)
        val decision = store.resolve("api-1", "dev-a", requested = null)
        assertEquals(setOf("cdn.example.com"), decision.granted)
        assertEquals(emptySet(), decision.denied)
        assertFalse(decision.hasUnauthorized)
    }

    @Test
    fun `resolve intersects requested with allowed`() {
        store.grant("api-1", "dev-a", "cdn.example.com", now)
        store.grant("api-1", "dev-a", "api.example.com", now)

        val decision = store.resolve("api-1", "dev-a",
            requested = listOf("cdn.example.com", "internal.acme.com"))
        assertEquals(setOf("cdn.example.com"), decision.granted)
        assertEquals(setOf("internal.acme.com"), decision.denied)
        assertTrue(decision.hasUnauthorized)
    }

    @Test
    fun `per-API scope isolated`() {
        store.grant("api-1", "dev-a", "x.com", now)
        assertEquals(emptySet(), store.getAllowed("api-2", "dev-a"))
    }

    @Test
    fun `per-device scope isolated`() {
        store.grant("api-1", "dev-a", "x.com", now)
        assertEquals(emptySet(), store.getAllowed("api-1", "dev-b"))
    }
}
