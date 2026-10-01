package com.example.pinvault.server.store

import java.io.File
import kotlin.test.*

/** The registry a CSR renewal is checked against: never un-revokes, never changes the key on renewal. */
class ClientIdentityStoreTest {

    private lateinit var dbFile: File
    private lateinit var store: ClientIdentityStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-identity-test-", ".db").also { it.deleteOnExit() }
        store = ClientIdentityStore(DatabaseManager(dbFile.absolutePath))
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun register(id: String = "dev-1", spki: String = "spki-A", api: String = "default-tls") =
        store.register(id, api, spki, "01", "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "Pixel", "uid-1", "2026-01-01T00:00:00Z")

    @Test
    fun `register, renew and read back`() {
        assertTrue(register())
        val fresh = assertNotNull(store.get("dev-1"))
        assertEquals("spki-A", fresh.spkiSha256)
        assertEquals(0, fresh.renewCount)
        assertNull(fresh.lastRenewedAt)
        assertFalse(fresh.revoked)

        assertTrue(store.recordRenewal("dev-1", "02", "2026-03-01T00:00:00Z", "2026-06-01T00:00:00Z", "2026-03-01T00:00:00Z"))
        val renewed = assertNotNull(store.get("dev-1"))
        assertEquals("02", renewed.serial)
        assertEquals("2026-06-01T00:00:00Z", renewed.notAfter)
        assertEquals(1, renewed.renewCount)
        assertEquals("2026-03-01T00:00:00Z", renewed.lastRenewedAt)
        assertEquals("spki-A", renewed.spkiSha256, "renewal never changes the key")
        assertEquals("uid-1", renewed.deviceUid)
        assertEquals(listOf("dev-1"), store.getAll().map { it.clientId })
    }

    @Test
    fun `re-registering an active identity replaces its key and resets the counters`() {
        register()
        store.recordRenewal("dev-1", "02", "b", "c", "now")
        assertTrue(register(spki = "spki-B"))
        val again = assertNotNull(store.get("dev-1"))
        assertEquals("spki-B", again.spkiSha256)
        assertEquals(0, again.renewCount)
        assertNull(again.lastRenewedAt)
    }

    @Test
    fun `a revoked identity can neither renew nor enroll again`() {
        register()
        store.revoke("dev-1")
        assertTrue(assertNotNull(store.get("dev-1")).revoked)

        assertFalse(store.recordRenewal("dev-1", "02", "b", "c", "now"))
        assertFalse(register(spki = "spki-B"), "enrollment of a revoked client id is refused")
        val still = assertNotNull(store.get("dev-1"))
        assertTrue(still.revoked)
        assertEquals("spki-A", still.spkiSha256)
    }

    @Test
    fun `unknown identities`() {
        assertNull(store.get("nobody"))
        assertFalse(store.recordRenewal("nobody", "02", "b", "c", "now"))
        store.revoke("nobody") // no-op, no error
    }
}
