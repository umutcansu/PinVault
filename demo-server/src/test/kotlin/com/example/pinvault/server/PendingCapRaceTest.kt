package com.example.pinvault.server

import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.EnrollmentPolicyStore
import java.io.File
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Review 2026-11-11: the pending list of a policy was counted, then
 * written to; devices asking at the same moment could all pass the count.
 */
class PendingCapRaceTest {

    private val dbFile = File.createTempFile("pinvault-pending-cap-", ".db").also { it.deleteOnExit() }
    private val db = DatabaseManager(dbFile.absolutePath)
    private val store = EnrollmentPolicyStore(db)

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun policy(maxDevices: Int) =
        store.create("kiosk", maxDevices, Duration.ofDays(1), requireApproval = true, createdBy = "admin").policy

    @Test
    fun `the list takes no request beyond its place`() {
        val policy = policy(maxDevices = 2)
        assertNotNull(store.createPendingRequest(policy, "key-1", "default-tls", null, "uid-1", "10.0.0.1", maxPending = 2))
        assertNotNull(store.createPendingRequest(policy, "key-2", "default-tls", null, "uid-2", "10.0.0.2", maxPending = 2))
        assertNull(store.createPendingRequest(policy, "key-3", "default-tls", null, "uid-3", "10.0.0.3", maxPending = 2))
        // The same key asking again gets its own request back, list full or not.
        val again = assertNotNull(store.createPendingRequest(policy, "key-1", "default-tls", null, "uid-1", "10.0.0.1", maxPending = 2))
        assertEquals(false, again.created)
        assertEquals(2, store.countPending(policy.id))
    }

    @Test
    fun `devices asking at the same moment cannot all take the last places`() {
        val policy = policy(maxDevices = 3)
        val threads = 16
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        val results = (1..threads).map { n ->
            pool.submit<Boolean> {
                start.await()
                runCatching { store.createPendingRequest(policy, "key-$n", "default-tls", null, "uid-$n", "10.0.0.$n", maxPending = 3) }
                    .getOrNull()?.created == true
            }
        }
        start.countDown()
        val created = results.count { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()
        assertTrue(created <= 3, "$created requests went in")
        assertTrue(store.countPending(policy.id) <= 3, "${store.countPending(policy.id)} pending")
    }
}
