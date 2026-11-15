package com.example.pinvault.server.store

import java.io.File
import java.sql.Connection
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The SQLite settings every connection runs with (load test 2026-11-15, demo-server/loadtest/RESULTS.md). */
class DatabaseManagerTest {

    private lateinit var dir: File
    private val dbPath get() = File(dir, "pinvault.db").absolutePath

    @BeforeTest
    fun setUp() { dir = kotlin.io.path.createTempDirectory("pinvault-db-").toFile() }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun Connection.pragma(name: String): String =
        createStatement().use { it.executeQuery("PRAGMA $name").use { rs -> rs.next(); rs.getString(1) } }

    @Test
    fun `every connection runs in WAL mode with a busy timeout and synchronous NORMAL`() {
        val db = DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL)
        repeat(3) {
            db.connection().use { conn ->
                assertEquals("wal", conn.pragma("journal_mode"))
                assertEquals(DatabaseManager.BUSY_TIMEOUT_MS.toString(), conn.pragma("busy_timeout"))
                assertEquals("1", conn.pragma("synchronous"), "NORMAL")
            }
        }
        // The mode is the file's: a second manager (a restart) finds it, after Flyway has run again.
        DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL).connection().use { assertEquals("wal", it.pragma("journal_mode")) }
    }

    @Test
    fun `DB_JOURNAL_MODE delete keeps the rollback journal, and switches a WAL database back`() {
        DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL)
        val db = DatabaseManager(dbPath, DatabaseManager.JournalMode.DELETE)
        db.connection().use { conn ->
            assertEquals("delete", conn.pragma("journal_mode"))
            assertEquals(DatabaseManager.BUSY_TIMEOUT_MS.toString(), conn.pragma("busy_timeout"))
            assertEquals("2", conn.pragma("synchronous"), "FULL: the rollback journal is not safe with NORMAL")
        }
        assertTrue(!File("$dbPath-wal").exists(), "no -wal file in delete mode")
    }

    @Test
    fun `DB_JOURNAL_MODE accepts wal, delete or nothing`() {
        assertEquals(DatabaseManager.JournalMode.WAL, DatabaseManager.JournalMode.fromEnv(null))
        assertEquals(DatabaseManager.JournalMode.WAL, DatabaseManager.JournalMode.fromEnv(" WAL "))
        assertEquals(DatabaseManager.JournalMode.DELETE, DatabaseManager.JournalMode.fromEnv("delete"))
        assertFailsWith<IllegalStateException> { DatabaseManager.JournalMode.fromEnv("memory") }
    }

    @Test
    fun `readers do not wait for a writer, and a second writer waits instead of failing busy`() {
        val db = DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL)
        db.connection().use { it.createStatement().use { s -> s.executeUpdate("CREATE TABLE t (n INTEGER)"); s.executeUpdate("INSERT INTO t VALUES (1)") } }
        val writer = db.connection()
        writer.autoCommit = false
        writer.createStatement().use { it.executeUpdate("INSERT INTO t VALUES (2)") } // holds the write lock, uncommitted
        // A reader sees the committed state at once (rollback-journal mode would block it behind the writer's commit).
        val started = System.nanoTime()
        db.connection().use { conn -> assertEquals("1", conn.createStatement().use { it.executeQuery("SELECT COUNT(*) FROM t").use { rs -> rs.next(); rs.getString(1) } }) }
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1), "the reader did not wait")
        // A second writer waits for the lock (busy_timeout) and gets in once the first commits.
        val pool = Executors.newSingleThreadExecutor()
        val waiting = CountDownLatch(1)
        val second = pool.submit {
            db.connection().use { conn -> waiting.countDown(); conn.createStatement().use { it.executeUpdate("INSERT INTO t VALUES (3)") } }
        }
        waiting.await()
        Thread.sleep(300)
        writer.commit(); writer.close()
        second.get(10, TimeUnit.SECONDS)
        pool.shutdown()
        db.connection().use { conn -> assertEquals("3", conn.createStatement().use { it.executeQuery("SELECT COUNT(*) FROM t").use { rs -> rs.next(); rs.getString(1) } }) }
    }

    @Test
    fun `a stopped server's WAL is checkpointed into the main file`() {
        val db = DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL)
        db.connection().use { it.createStatement().use { s -> s.executeUpdate("CREATE TABLE marker (v TEXT)"); s.executeUpdate("INSERT INTO marker VALUES ('wal-marker-7f3a')") } }
        // Every connection is closed (as when the server stopped): SQLite checkpointed and removed the -wal file,
        // so a copy of pinvault.db alone holds the data.
        assertTrue(!File("$dbPath-wal").exists() || File("$dbPath-wal").length() == 0L, "the last close checkpoints the WAL")
        assertTrue(String(File(dbPath).readBytes(), Charsets.ISO_8859_1).contains("wal-marker-7f3a"))
    }

    @Test
    fun `DB_SYNCHRONOUS sets full or normal, and normal is refused without WAL`() {
        assertEquals(null, DatabaseManager.Synchronous.fromEnv(null))
        assertEquals(DatabaseManager.Synchronous.FULL, DatabaseManager.Synchronous.fromEnv("FULL"))
        assertEquals(DatabaseManager.Synchronous.NORMAL, DatabaseManager.Synchronous.fromEnv("normal"))
        assertFailsWith<IllegalStateException> { DatabaseManager.Synchronous.fromEnv("off") }
        DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL, DatabaseManager.Synchronous.FULL).connection().use {
            assertEquals("wal", it.pragma("journal_mode")); assertEquals("2", it.pragma("synchronous"))
        }
        assertFailsWith<IllegalStateException> { DatabaseManager(dbPath, DatabaseManager.JournalMode.DELETE, DatabaseManager.Synchronous.NORMAL) }
    }

    @Test
    fun `a read-then-write transaction on an immediate connection waits for another writer instead of failing busy`() {
        val db = DatabaseManager(dbPath, DatabaseManager.JournalMode.WAL)
        db.connection().use { it.createStatement().use { s -> s.executeUpdate("CREATE TABLE v (n INTEGER)"); s.executeUpdate("INSERT INTO v VALUES (1)") } }
        val holder = db.immediateConnection()
        holder.autoCommit = false
        holder.createStatement().use { it.executeUpdate("UPDATE v SET n = n + 1") } // holds the write lock
        val pool = Executors.newSingleThreadExecutor()
        val done = pool.submit<Int> {
            db.immediateConnection().use { conn ->
                conn.autoCommit = false
                val n = conn.createStatement().use { it.executeQuery("SELECT n FROM v").use { rs -> rs.next(); rs.getInt(1) } }
                conn.prepareStatement("UPDATE v SET n = ?").use { it.setInt(1, n + 10); it.executeUpdate() }
                conn.commit()
                n
            }
        }
        Thread.sleep(300)
        holder.commit(); holder.close()
        assertEquals(2, done.get(10, TimeUnit.SECONDS), "it read after the other commit: no lost update, no SQLITE_BUSY")
        pool.shutdown()
        db.connection().use { conn -> assertEquals("12", conn.createStatement().use { it.executeQuery("SELECT n FROM v").use { rs -> rs.next(); rs.getString(1) } }) }
    }
}
