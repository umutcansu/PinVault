package com.example.pinvault.server.store

import org.sqlite.SQLiteConfig
import java.sql.Connection
import java.sql.DriverManager

/**
 * The server's SQLite database.
 *
 * Every connection waits up to [BUSY_TIMEOUT_MS] for a lock instead of
 * failing at once with `SQLITE_BUSY`, and runs with `synchronous=NORMAL`.
 * The journal mode is set once, at start-up, from `DB_JOURNAL_MODE`:
 *  - `wal` (default): readers no longer wait for the writer, and a commit is
 *    one append to `<db>-wal` instead of rewriting a rollback journal. The
 *    load test (demo-server/loadtest/RESULTS.md) found per-round writes in
 *    rollback-journal mode, with readers blocking writers, to be what limits
 *    an instance. With WAL, `synchronous=NORMAL` keeps the database
 *    consistent after a crash or power loss; a power loss can lose the last
 *    commits, never corrupt the file.
 *  - `delete`: the rollback journal (the mode before). For a database that a
 *    process on ANOTHER machine or VM opens while the server runs — WAL's
 *    shared-memory index (`<db>-shm`) works only between processes of one
 *    host, so not across a network filesystem or from macOS into a Docker
 *    Desktop bind mount (the E2E harness reads its hosts' databases that way).
 *
 * In WAL mode the database is three files: `pinvault.db`, `pinvault.db-wal`
 * and `pinvault.db-shm`. Committed data may sit in `-wal` until a checkpoint,
 * so the main file alone is not a copy of the database: copy a stopped
 * server's database directory whole (or checkpoint first:
 * `sqlite3 pinvault.db 'PRAGMA wal_checkpoint(TRUNCATE)'`), and a running
 * one only through SQLite (`sqlite3 pinvault.db ".backup copy.db"` or
 * `VACUUM INTO`). The server itself never copies the database file.
 */
class DatabaseManager(
    dbPath: String = "pinvault.db",
    journalMode: JournalMode = JournalMode.fromEnv()
) {

    enum class JournalMode {
        WAL, DELETE;

        companion object {
            /** `DB_JOURNAL_MODE`: `wal` (default) or `delete`; anything else stops the start. */
            fun fromEnv(value: String? = com.example.pinvault.server.service.ServerEnv.get("DB_JOURNAL_MODE")): JournalMode =
                when (value?.trim()?.lowercase()) {
                    null, "", "wal" -> WAL
                    "delete" -> DELETE
                    else -> error("DB_JOURNAL_MODE must be wal or delete (got '$value')")
                }
        }
    }

    private val url = "jdbc:sqlite:$dbPath"

    /** Per-connection settings (sqlite-jdbc applies them as PRAGMAs when a connection opens). */
    private val properties = SQLiteConfig().apply {
        setBusyTimeout(BUSY_TIMEOUT_MS)
        setSynchronous(SQLiteConfig.SynchronousMode.NORMAL)
    }.toProperties()

    init {
        // Run Flyway migrations (creates tables on fresh DB, no-op on existing)
        FlywayMigrator.migrate(dbPath)
        // The journal mode is a property of the database file: set once, before any other connection.
        connection().use { conn ->
            conn.createStatement().use { stmt ->
                val mode = stmt.executeQuery("PRAGMA journal_mode=${journalMode.name}").use { rs -> rs.next(); rs.getString(1) }
                check(mode.equals(journalMode.name, ignoreCase = true)) {
                    "SQLite would not switch $dbPath to journal_mode=${journalMode.name} (it stays '$mode'): " +
                        "another process has the database open, or its filesystem does not support it (set DB_JOURNAL_MODE=delete)."
                }
            }
        }
    }

    fun connection(): Connection = DriverManager.getConnection(url, properties)

    companion object {
        const val BUSY_TIMEOUT_MS = 5_000
    }
}
