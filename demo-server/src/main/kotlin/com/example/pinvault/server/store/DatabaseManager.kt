package com.example.pinvault.server.store

import org.sqlite.SQLiteConfig
import java.sql.Connection
import java.sql.DriverManager

/**
 * The server's SQLite database.
 *
 * Every connection waits up to [BUSY_TIMEOUT_MS] for a lock instead of
 * failing at once with `SQLITE_BUSY`, and runs with `synchronous` NORMAL under
 * WAL or FULL under the rollback journal (`DB_SYNCHRONOUS` overrides; see [Synchronous]).
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
    journalMode: JournalMode = JournalMode.fromEnv(),
    /** `DB_SYNCHRONOUS`; unset = NORMAL under WAL, FULL under the rollback journal. */
    synchronous: Synchronous? = Synchronous.fromEnv()
) {

    /**
     * How hard a commit waits for the disk. FULL: a commit is on disk when it
     * returns. NORMAL (WAL only): the WAL is synced at checkpoints, so a power
     * loss or an OS crash (not a server crash) can undo the last commits — a
     * spent token or nonce, a revocation, an audit row, a pin version already
     * served — while the database stays consistent. NORMAL under the rollback
     * journal could corrupt the file on a power loss, so it is refused there.
     */
    enum class Synchronous {
        NORMAL, FULL;

        companion object {
            fun fromEnv(value: String? = com.example.pinvault.server.service.ServerEnv.get("DB_SYNCHRONOUS")): Synchronous? =
                when (value?.trim()?.lowercase()) {
                    null, "" -> null
                    "normal" -> NORMAL
                    "full" -> FULL
                    else -> error("DB_SYNCHRONOUS must be normal or full (got '$value')")
                }
        }
    }

    /** What every connection runs with. */
    val synchronousMode: Synchronous = synchronous ?: if (journalMode == JournalMode.WAL) Synchronous.NORMAL else Synchronous.FULL

    init {
        check(!(journalMode == JournalMode.DELETE && synchronousMode == Synchronous.NORMAL)) {
            "DB_SYNCHRONOUS=normal needs DB_JOURNAL_MODE=wal: with the rollback journal a power loss could corrupt the database."
        }
    }

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
        setSynchronous(if (synchronousMode == Synchronous.FULL) SQLiteConfig.SynchronousMode.FULL else SQLiteConfig.SynchronousMode.NORMAL)
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

    private val immediateProperties = SQLiteConfig(java.util.Properties().apply { putAll(properties) }).apply {
        setTransactionMode(SQLiteConfig.TransactionMode.IMMEDIATE)
    }.toProperties()

    /**
     * A connection whose transactions (autoCommit off) start with `BEGIN IMMEDIATE`:
     * for a transaction that reads and then writes. A DEFERRED one takes the write
     * lock only at its first write, and when another writer got there first SQLite
     * answers `SQLITE_BUSY` at once instead of waiting [BUSY_TIMEOUT_MS] (it cannot
     * upgrade a read snapshot that is no longer the latest). IMMEDIATE takes the
     * lock up front, so the busy timeout applies.
     */
    fun immediateConnection(): Connection = DriverManager.getConnection(url, immediateProperties)

    companion object {
        const val BUSY_TIMEOUT_MS = 5_000
    }
}
