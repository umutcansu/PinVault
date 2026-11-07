package com.example.pinvault.server

import com.example.pinvault.server.service.CertExpiryMonitor
import com.example.pinvault.server.service.ExpiryCandidate
import com.example.pinvault.server.service.VaultExpiry
import com.example.pinvault.server.store.DatabaseManager
import com.example.pinvault.server.store.HostRecord
import com.example.pinvault.server.store.HostStore
import java.io.File
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The expiry monitor watches more than the pinned hosts' certificates: every
 * registered source (the server's own certificates, vault files with an
 * expiry) gets the same warning / expired levels, and a broken source never
 * hides the others.
 */
class ExpiryMonitorTest {

    private lateinit var dbFile: File
    private lateinit var hosts: HostStore

    @BeforeTest
    fun setUp() {
        dbFile = File.createTempFile("pinvault-expiry-", ".db").also { it.deleteOnExit() }
        hosts = HostStore(DatabaseManager(dbFile.absolutePath))
    }

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun inDays(days: Long): Instant = Instant.now().plus(days, ChronoUnit.DAYS).plusSeconds(60)

    @Test
    fun `every kind gets a level and the overall status is the worst of them`() {
        hosts.save(HostRecord("api.example.com", "default-tls", null, inDays(200).toString(), null, "2026-01-01T00:00:00Z"))
        val monitor = CertExpiryMonitor(hosts, warnDays = 30, sources = listOf(
            { listOf(ExpiryCandidate(CertExpiryMonitor.KIND_CONFIG_API, "Config API TLS", "*", inDays(400))) },
            { listOf(ExpiryCandidate(CertExpiryMonitor.KIND_VAULT_FILE, "licence.json", "default-tls", inDays(5))) },
            { listOf(ExpiryCandidate(CertExpiryMonitor.KIND_CLIENT_CA, "Client CA", "*", inDays(-2))) },
            { throw IllegalStateException("keystore unreadable") }
        ))
        val all = monitor.checkAll()
        val byLabel = all.associateBy { it.hostname }
        assertEquals("ok", byLabel.getValue("api.example.com").level)
        assertEquals(CertExpiryMonitor.KIND_HOST, byLabel.getValue("api.example.com").kind)
        assertEquals("ok", byLabel.getValue("Config API TLS").level)
        assertEquals("warning", byLabel.getValue("licence.json").level)
        assertEquals(CertExpiryMonitor.KIND_VAULT_FILE, byLabel.getValue("licence.json").kind)
        assertEquals("expired", byLabel.getValue("Client CA").level)
        assertEquals(listOf("Client CA", "licence.json", "api.example.com", "Config API TLS"), all.map { it.hostname }, "soonest first")
        assertEquals("critical", monitor.getOverallStatus())
        assertEquals(4, all.size, "the failing source is skipped, the rest are reported")
    }

    @Test
    fun `something that ran out an hour ago is expired, not a warning with zero days`() {
        val monitor = CertExpiryMonitor(hosts, warnDays = 30, sources = listOf(
            { listOf(ExpiryCandidate(CertExpiryMonitor.KIND_VAULT_FILE, "licence.json", "default-tls", Instant.now().minusSeconds(3600))) },
            { listOf(ExpiryCandidate(CertExpiryMonitor.KIND_VAULT_FILE, "soon.json", "default-tls", Instant.now().plusSeconds(3600))) }
        ))
        val byLabel = monitor.checkAll().associateBy { it.hostname }
        assertEquals("expired", byLabel.getValue("licence.json").level)
        assertEquals(-1, byLabel.getValue("licence.json").daysRemaining)
        assertEquals("warning", byLabel.getValue("soon.json").level)
        assertEquals(0, byLabel.getValue("soon.json").daysRemaining)
        assertEquals("critical", monitor.getOverallStatus())
    }

    @Test
    fun `a vault expiry is a date or an instant, stored as an instant`() {
        assertEquals("2027-01-31T23:59:59Z", VaultExpiry.parse("2027-01-31"))
        assertEquals("2027-01-31T10:00:00Z", VaultExpiry.parse("2027-01-31T10:00:00Z"))
        assertNull(VaultExpiry.parse(""))
        assertNull(VaultExpiry.parse(null))
        assertFailsWith<VaultExpiry.Invalid> { VaultExpiry.parse("2027-02-31") }
        assertFailsWith<VaultExpiry.Invalid> { VaultExpiry.parse("next week") }
        assertTrue(assertFailsWith<VaultExpiry.Invalid> { VaultExpiry.parse("2999-01-01") }.message!!.contains("100 years"))
    }
}
