package com.example.pinvault.server.store

import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Rules that close a CLASS of mistake, not one instance of it (review
 * 2026-11-17). Each of these was found one case at a time before:
 *
 *  - a transaction that reads before it writes on a deferred connection fails
 *    with SQLITE_BUSY_SNAPSHOT under WAL as soon as another connection
 *    commits in between (`PinConfigStore.save`, after three stores had been
 *    moved to IMMEDIATE and this one left out);
 *  - a table that belongs to something that can be deleted — a Config API, a
 *    vault file, a client identity — and that the delete does not know about
 *    (`pin_snapshots` missing from the purge; a deleted vault file's tokens
 *    opening the file uploaded under its name later).
 *
 * The second kind is checked against the schema itself: a migration that adds
 * a table with one of these columns fails here until someone writes down what
 * happens to its rows.
 */
class StoreInvariantsTest {

    private lateinit var dir: File
    private lateinit var db: DatabaseManager

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-invariants-").toFile()
        db = DatabaseManager(File(dir, "db.sqlite").absolutePath)
    }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    // ── Transactions ────────────────────────────────────────────────

    @Test
    fun `every explicit transaction takes the write lock up front`() {
        val root = File("src/main/kotlin")
        assertTrue(root.isDirectory, "run from the demo-server directory (${root.absolutePath})")
        val offenders = mutableListOf<String>()
        root.walkTopDown().filter { it.isFile && it.extension == "kt" && it.name != "DatabaseManager.kt" }.forEach { file ->
            val lines = file.readLines()
            fun code(i: Int) = lines.getOrNull(i)?.takeUnless { it.trimStart().startsWith("*") }?.substringBefore("//").orEmpty()
            lines.indices.forEach { i ->
                val line = code(i)
                val where = "${file.relativeTo(root)}:${i + 1}: ${lines[i].trim()}"
                // A transaction opened in place: the connection is taken on one of the lines just above.
                if (Regex("""autoCommit\s*=\s*false""").containsMatchIn(line)) {
                    val above = (1..3).joinToString("\n") { code(i - it) }
                    val helper = "fun <T> inTransaction(" in above
                    if (!helper && "immediateConnection()" !in above) offenders += where
                }
                // A transaction opened through a store's inTransaction(conn) helper: the caller takes the connection.
                if (Regex("""\binTransaction\(conn\)""").containsMatchIn(line) && "fun " !in line) {
                    if ("immediateConnection()" !in code(i - 1) && "immediateConnection()" !in line) offenders += where
                }
            }
        }
        assertTrue(
            offenders.isEmpty(),
            "a transaction (autoCommit off) must run on db.immediateConnection(): on a deferred one, a read followed by a write " +
                "fails with SQLITE_BUSY_SNAPSHOT when another connection commits in between, whatever the busy timeout:\n" +
                offenders.joinToString("\n")
        )
    }

    // ── What a delete leaves behind ────────────────────────────────

    private fun tablesWith(vararg columns: String): Set<String> = db.connection().use { conn ->
        val tables = conn.createStatement().use { stmt ->
            stmt.executeQuery("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'flyway_%'").use { rs ->
                buildList { while (rs.next()) add(rs.getString(1)) }
            }
        }
        tables.filterTo(sortedSetOf()) { table ->
            val have = conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT name FROM pragma_table_info('$table')").use { rs -> buildSet { while (rs.next()) add(rs.getString(1)) } }
            }
            columns.all { it in have }
        }
    }

    private fun assertDeclared(what: String, found: Set<String>, declared: Map<String, String>) {
        assertEquals(
            declared.keys.toSortedSet(), found.toSortedSet(),
            "$what: the schema and this list differ. A new table must be handled by the delete (or kept on purpose) " +
                "and written down here with what happens to its rows; a table that is gone must be removed from the list."
        )
    }

    @Test
    fun `every table that belongs to a Config API is purged with it or kept on purpose`() {
        val kept = mapOf(
            "audit_log" to "the record of what happened, also to an API that no longer exists",
            "change_requests" to "history; purge closes the pending ones as rejected",
            "host_version_watermark" to "a recreated API must not hand devices a lower host version",
            "vault_version_watermark" to "a recreated API must not hand devices a lower file version",
            "enrollment_requests" to "purge closes the waiting ones as rejected; decided ones are the history of who was let in"
        )
        val purged = ConfigApiRegistry.SCOPED_TABLES.associateWith { "deleted by ConfigApiRegistry.purge" }
        assertTrue(kept.keys.intersect(purged.keys).isEmpty(), "a table is either purged or kept")
        assertDeclared("tables with a config_api_id column", tablesWith("config_api_id"), kept + purged)
    }

    @Test
    fun `every table that names a vault file says what deleting the file does to it`() {
        val byVaultKey = mapOf(
            "vault_file_tokens" to "revoked (VaultFileTokenStore.revokeForFile): they must not open a later file of the same name",
            "vault_distributions" to "kept: the history of which device fetched which version"
        )
        val byKey = mapOf(
            "vault_files" to "the row is deleted",
            "vault_version_watermark" to "kept: a file uploaded again continues its version"
        )
        assertDeclared("tables with a vault_key column", tablesWith("config_api_id", "vault_key"), byVaultKey)
        assertDeclared("tables with config_api_id + key", tablesWith("config_api_id", "key"), byKey)
    }

    @Test
    fun `every table that names a client identity says what forgetting it does`() {
        val byClientId = mapOf(
            "client_identities" to "deleted (ClientIdentityStore.forgetWithDevices)",
            "identity_devices" to "deleted (ClientIdentityStore.forgetWithDevices)",
            "client_keys" to "kept, every key retired: a certificate over one of them is refused for good",
            "enrollment_requests" to "kept: history of the request the identity came from",
            "enrollment_tokens" to "kept: a forgotten id may enroll again over a new key, with a token an admin issued",
            "client_renewal_csrs" to "deleted (ClientIdentityStore.forgetWithDevices): the keys they were signed with are retired"
        )
        assertDeclared("tables with a client_id column", tablesWith("client_id"), byClientId)
    }
}
