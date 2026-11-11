package com.example.pinvault.server.service

import com.example.pinvault.server.store.DatabaseManager
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Review 2026-11-11, C-10: a start that found key material missing used to
 * make a new key and come up cleanly; every device then refused everything.
 */
class KeyMaterialGuardTest {

    private val dir: File = Files.createTempDirectory("key-guard").toFile()
    private val db = DatabaseManager(File(dir, "pinvault.db").absolutePath)
    private val guard = KeyMaterialGuard(db)

    private val signing = KeyMaterialGuard.Item(KeyMaterialGuard.SIGNING_KEY, File(dir, "signing-key.pem"))
    private val clientCa = KeyMaterialGuard.Item(KeyMaterialGuard.CLIENT_CA, File(dir, "certs/client-ca.jks"))
    private val tlsBackup = KeyMaterialGuard.Item(KeyMaterialGuard.SERVER_TLS_BACKUP, File(dir, "certs/demo-server.backup.jks"), alwaysMade = false)
    private val items = listOf(signing, clientCa, tlsBackup)

    @AfterTest
    fun cleanUp() { dir.deleteRecursively() }

    private fun make(vararg item: KeyMaterialGuard.Item) = item.forEach { it.file.parentFile.mkdirs(); it.file.writeText("key") }

    private fun addPin() = db.connection().use { conn ->
        conn.createStatement().use { it.executeUpdate("INSERT INTO pin_hashes (hostname, sha256) VALUES ('api.example.com', 'x')") }
    }

    @Test
    fun `a first start makes everything and records it`() {
        assertNull(guard.startProblem(items, allowed = emptySet()), "nothing made yet and nothing recorded: a first start")
        make(signing, clientCa, tlsBackup)
        guard.record(items)
        assertEquals(setOf("signing-key", "client-ca", "server-tls-backup"), guard.recorded())
        assertNull(guard.startProblem(items, allowed = emptySet()))
    }

    @Test
    fun `a recorded file that is gone stops the start and says which`() {
        make(signing, clientCa)
        guard.record(items)
        clientCa.file.delete()

        val problem = assertNotNull(guard.startProblem(items, allowed = emptySet()))
        assertTrue(problem.contains("client-ca"), problem)
        assertTrue(!problem.contains("signing-key ("), problem)
        assertTrue(problem.contains("ALLOW_KEY_REGENERATION=client-ca"), problem)
    }

    @Test
    fun `ALLOW_KEY_REGENERATION lets the named ones be made again`() {
        make(signing, clientCa)
        guard.record(items)
        signing.file.delete()
        clientCa.file.delete()

        assertNotNull(guard.startProblem(items, allowed = setOf("client-ca")), "the signing key is not allowed")
        assertNull(guard.startProblem(items, allowed = setOf("client-ca", "signing-key")))
        assertNull(guard.startProblem(items, allowed = setOf("all")))
        assertEquals(setOf("client-ca", "signing-key"), KeyMaterialGuard.allowedFromEnv(" Client-CA, signing-key ,"))
        assertEquals(emptySet(), KeyMaterialGuard.allowedFromEnv(null))
    }

    @Test
    fun `a database from before the records that holds data counts as an existing install`() {
        addPin()
        val problem = assertNotNull(guard.startProblem(items, allowed = emptySet()))
        assertTrue(problem.contains("signing-key") && problem.contains("client-ca"), problem)
        assertTrue(!problem.contains("server-tls-backup"), "a file not every start makes is checked only once recorded: $problem")
    }

    @Test
    fun `an empty database without records is a first start`() {
        assertNull(guard.startProblem(items, allowed = emptySet()))
    }

    @Test
    fun `once anything is recorded the data rule no longer applies`() {
        make(signing)
        guard.record(listOf(signing))
        addPin()
        assertNull(guard.startProblem(items, allowed = emptySet()), "client-ca was never recorded here")
    }
}
