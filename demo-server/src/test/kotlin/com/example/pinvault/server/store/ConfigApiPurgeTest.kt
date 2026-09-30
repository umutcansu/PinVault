package com.example.pinvault.server.store

import java.io.File
import kotlin.test.*

/**
 * Deleting a Config API must remove everything scoped to it. It used to clear
 * only the pin tables: the `config_apis` row brought the API back on the next
 * boot, and vault files, tokens, device keys and ACLs passed to any new API
 * created under the same id.
 */
class ConfigApiPurgeTest {

    private lateinit var db: DatabaseManager
    private lateinit var dbFile: File
    private lateinit var registry: ConfigApiRegistry

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-purge-test-", ".db")
        dbFile.deleteOnExit()
        db = DatabaseManager(dbFile.absolutePath)
        registry = ConfigApiRegistry(db)
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun exec(sql: String, vararg args: Any) = db.connection().use { conn ->
        conn.prepareStatement(sql).use { stmt ->
            args.forEachIndexed { i, a -> stmt.setObject(i + 1, a) }
            stmt.executeUpdate()
        }
    }

    private fun count(table: String, where: String, vararg args: Any): Int = db.connection().use { conn ->
        conn.prepareStatement("SELECT COUNT(*) FROM $table WHERE $where").use { stmt ->
            args.forEachIndexed { i, a -> stmt.setObject(i + 1, a) }
            stmt.executeQuery().getInt(1)
        }
    }

    private fun seed(api: String) {
        registry.ensureRegistered(api, 9000, "tls")
        exec("INSERT INTO pin_config (config_api_id, force_update) VALUES (?, 0)", api)
        exec("INSERT INTO pin_hashes (config_api_id, hostname, sha256, version, force_update, mtls) VALUES (?, 'a.example', 'pin', 3, 0, 0)", api)
        exec("INSERT INTO pin_history (config_api_id, hostname, version, timestamp, event, pin_prefix) VALUES (?, 'a.example', 3, 0, 'x', 'p')", api)
        exec("INSERT INTO hosts (hostname, config_api_id, created_at) VALUES ('a.example', ?, 'now')", api)
        exec("INSERT INTO host_version_watermark (config_api_id, hostname, max_version) VALUES (?, 'a.example', 3)", api)
        exec("INSERT INTO vault_files (config_api_id, key, content, version, updated_at) VALUES (?, 'f', X'00', 1, 'now')", api)
        exec("INSERT INTO default_host_acl (config_api_id, hostname) VALUES (?, 'a.example')", api)
    }

    private fun pendingRequest(api: String): Long {
        exec(
            "INSERT INTO change_requests (created_at, expires_at, requested_by, method, path, config_api_id, summary, status) " +
                "VALUES ('now', 'later', 'alice', 'POST', '/x', ?, 's', 'pending')", api
        )
        return db.connection().use { it.createStatement().executeQuery("SELECT MAX(id) FROM change_requests").getLong(1) }
    }

    @Test
    fun `purge removes every scoped row and the registry row`() {
        seed("gone")
        val purged = registry.purge("gone")

        assertEquals(listOf("a.example"), purged.hostnames)
        assertEquals(0, count("config_apis", "id = ?", "gone"), "row left → API auto-starts again on boot")
        for (table in ConfigApiRegistry.SCOPED_TABLES) {
            assertEquals(0, count(table, "config_api_id = ?", "gone"), "$table not purged")
        }
    }

    @Test
    fun `purge leaves other Config APIs untouched`() {
        seed("gone")
        seed("kept")
        registry.purge("gone")

        assertEquals(1, count("config_apis", "id = ?", "kept"))
        assertEquals(1, count("pin_hashes", "config_api_id = ?", "kept"))
        assertEquals(1, count("vault_files", "config_api_id = ?", "kept"))
        assertEquals(1, count("default_host_acl", "config_api_id = ?", "kept"))
    }

    @Test
    fun `version watermark survives so a recreated API never looks like a downgrade`() {
        seed("gone")
        registry.purge("gone")
        assertEquals(1, count("host_version_watermark", "config_api_id = ? AND max_version = 3", "gone"))
    }

    @Test
    fun `pending change requests are rejected except the one performing the delete`() {
        seed("gone")
        val stale = pendingRequest("gone")
        val self = pendingRequest("gone")
        val other = pendingRequest("kept")

        val purged = registry.purge("gone", keepChangeRequest = self)

        assertEquals(listOf(stale), purged.cancelledChangeRequests)
        assertEquals(1, count("change_requests", "id = ? AND status = 'rejected' AND reason = 'Config API deleted'", stale))
        assertEquals(1, count("change_requests", "id = ? AND status = 'pending'", self))
        assertEquals(1, count("change_requests", "id = ? AND status = 'pending'", other))
    }
}
