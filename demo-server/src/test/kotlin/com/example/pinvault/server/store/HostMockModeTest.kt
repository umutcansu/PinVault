package com.example.pinvault.server.store

import java.io.File
import java.time.Instant
import kotlin.test.*

/**
 * The server starts the mock listeners again when it starts, from the hosts
 * table. Only the port used to be stored, so an mTLS mock came back as a plain
 * TLS one that accepted every caller. The mode is stored with the port now and
 * survives the host record being rewritten (a new certificate).
 */
class HostMockModeTest {

    private lateinit var dbFile: File
    private lateinit var db: DatabaseManager
    private lateinit var store: HostStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("host-mock-mode-", ".db").also { it.deleteOnExit() }
        db = DatabaseManager(dbFile.absolutePath)
        store = HostStore(db)
        store.save(HostRecord("mock-mtls.sample", "default-tls", "/data/certs/m.jks", "2027-01-01T00:00:00Z", null, Instant.now().toString()))
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun mode(host: String): Pair<Int?, Int> = db.connection().use { conn ->
        conn.prepareStatement("SELECT mock_server_port, mock_server_mtls FROM hosts WHERE hostname = ?").use { stmt ->
            stmt.setString(1, host)
            val rs = stmt.executeQuery()
            assertTrue(rs.next())
            (rs.getObject("mock_server_port") as? Int) to rs.getInt("mock_server_mtls")
        }
    }

    @Test
    fun `an mTLS mock is stored as one and stays one when the host record is rewritten`() {
        store.updateMockPort("mock-mtls.sample", "default-tls", 8444, mtls = true)
        assertEquals(8444 to 1, mode("mock-mtls.sample"))

        // regenerate-cert rewrites the record with the running mock's port.
        val record = assertNotNull(store.get("mock-mtls.sample", "default-tls"))
        store.save(record.copy(keystorePath = "/data/certs/m2.jks", certValidUntil = "2028-01-01T00:00:00Z"))
        assertEquals(8444 to 1, mode("mock-mtls.sample"))
        assertEquals("/data/certs/m2.jks", store.get("mock-mtls.sample", "default-tls")?.keystorePath)
    }

    @Test
    fun `a TLS mock and a stopped mock are not mTLS`() {
        store.updateMockPort("mock-mtls.sample", "default-tls", 8444, mtls = true)
        store.updateMockPort("mock-mtls.sample", "default-tls", null)
        assertEquals(null to 0, mode("mock-mtls.sample"))
        store.updateMockPort("mock-mtls.sample", "default-tls", 8443)
        assertEquals(8443 to 0, mode("mock-mtls.sample"))
    }
}
