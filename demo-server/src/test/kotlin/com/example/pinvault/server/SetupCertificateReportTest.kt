package com.example.pinvault.server

import com.example.pinvault.server.route.setupCertificatesRoute
import com.example.pinvault.server.service.SetupCertificateFacts
import com.example.pinvault.server.service.SetupCertificateFacts.Authority
import com.example.pinvault.server.service.SetupCertificateFacts.Host
import com.example.pinvault.server.service.SetupCertificateFacts.Listener
import com.example.pinvault.server.service.SetupCertificateFacts.ServerCertificate
import com.example.pinvault.server.service.SetupCertificateFacts.VaultFile
import com.example.pinvault.server.service.SetupCertificateReport
import com.example.pinvault.server.service.SetupReport
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The wizard's "Certificates" step: one row per decision an operator makes
 * before production, each with the level the facts earn and the panel page
 * that changes it.
 */
class SetupCertificateReportTest {

    private val now = Instant.parse("2026-11-07T12:00:00Z")
    private fun inDays(days: Long) = now.plus(days, ChronoUnit.DAYS).toString()

    private fun facts(
        cert: ServerCertificate? = ServerCertificate("CN=localhost", "CN=localhost", listOf("DNS: localhost", "IP: 192.168.1.80"), inDays(300), listOf("A".repeat(43) + "=", "B".repeat(43) + "="), backupKey = true),
        publicHost: String? = "192.168.1.80",
        hosts: List<Host> = emptyList(),
        vault: List<VaultFile> = emptyList(),
        enrollmentMode: String = "token",
        recoveryPort: Int? = 8093,
        listeners: List<Listener> = listOf(Listener("default-tls", 8091, "tls", true), Listener("mtls", 8092, "mtls", true))
    ) = SetupCertificateFacts(
        configApiCert = cert, listeners = listeners, publicHost = publicHost,
        clientCa = Authority("CN=PinVault Client CA", inDays(3000), "C".repeat(43) + "="),
        clientCertTtlDays = 90, enrollmentMode = enrollmentMode, activeIdentities = 3, p12Enrollment = false,
        serverCa = Authority("CN=PinVault Server CA", inDays(3000), "D".repeat(43) + "="),
        recoveryPort = recoveryPort, recoveryRunning = recoveryPort != null,
        hosts = hosts, vaultFiles = vault, warnDays = 30, now = now
    )

    private fun level(checks: List<SetupCertificateReport.Check>, id: String, host: String? = null) =
        checks.first { it.id == id && (host == null || it.hostname == host) }.level

    @Test
    fun `a healthy server is all ready, with the self-signed certificate explained as pinned`() {
        val checks = SetupCertificateReport.checks(facts())
        assertTrue(checks.none { it.level != SetupReport.Level.OK }, checks.filter { it.level != SetupReport.Level.OK }.toString())
        assertEquals("self-signed, pinned", checks.first { it.id == "config_api_cert_source" }.current)
        assertEquals("bootstrap", checks.first { it.id == "config_api_cert" }.action)
        assertEquals("default-tls", checks.first { it.id == "config_api_cert" }.configApiId)
    }

    @Test
    fun `an expiring certificate, a missing backup key and a name the certificate lacks are flagged`() {
        val checks = SetupCertificateReport.checks(facts(
            cert = ServerCertificate("CN=localhost", "CN=localhost", listOf("DNS: localhost"), inDays(10), listOf("A".repeat(43) + "="), backupKey = false),
            publicHost = "pins.example.com"
        ))
        assertEquals(SetupReport.Level.WARN, level(checks, "config_api_cert"))
        assertEquals(SetupReport.Level.WARN, level(checks, "config_api_backup_key"))
        assertEquals(SetupReport.Level.WARN, level(checks, "config_api_cert_name"))
        assertTrue(checks.first { it.id == "config_api_cert_name" }.current.contains("pins.example.com"))
        val expired = SetupCertificateReport.checks(facts(cert = ServerCertificate("CN=x", "CN=x", emptyList(), inDays(-1), emptyList(), true)))
        assertEquals(SetupReport.Level.FAIL, level(expired, "config_api_cert"))
    }

    @Test
    fun `hosts are judged by source and backup key, vault files by their expiry`() {
        val checks = SetupCertificateReport.checks(facts(
            hosts = listOf(
                Host("api.example.com", "default-tls", "fetched", servedHere = false, notAfter = inDays(60), backupKey = false, pinCount = 2, mtls = false, clientCertNotAfter = null),
                Host("mock.sample", "default-tls", "generated", servedHere = true, notAfter = inDays(-3), backupKey = true, pinCount = 2, mtls = true, clientCertNotAfter = inDays(20)),
                Host("manual.example", "default-tls", "manual", servedHere = false, notAfter = null, backupKey = false, pinCount = 2, mtls = false, clientCertNotAfter = null)
            ),
            vault = listOf(VaultFile("default-tls", "licence", inDays(5)), VaultFile("default-tls", "model", inDays(500)))
        ))
        assertEquals(SetupReport.Level.OK, level(checks, "host_cert", "api.example.com"))
        assertEquals(SetupReport.Level.WARN, level(checks, "host_backup_pin", "api.example.com"))
        assertTrue(checks.first { it.id == "host_backup_pin" && it.hostname == "api.example.com" }.current.contains("CA"))
        assertEquals(SetupReport.Level.FAIL, level(checks, "host_cert", "mock.sample"))
        assertEquals(SetupReport.Level.OK, level(checks, "host_backup_pin", "mock.sample"))
        assertEquals(SetupReport.Level.WARN, level(checks, "host_served_here", "mock.sample"))
        assertEquals(SetupReport.Level.WARN, level(checks, "host_client_cert", "mock.sample"))
        assertEquals(SetupReport.Level.WARN, level(checks, "host_cert", "manual.example"))
        assertEquals(SetupReport.Level.WARN, level(checks, "host_backup_pin", "manual.example"))
        val vault = checks.filter { it.id == "vault_file" }.associate { it.key to it.level }
        assertEquals(mapOf<String?, SetupReport.Level>("licence" to SetupReport.Level.WARN, "model" to SetupReport.Level.OK), vault)
        assertTrue(checks.filter { it.id == "vault_file" }.all { it.action == "vault" && it.configApiId == "default-tls" })
    }

    @Test
    fun `mTLS rows appear only with an mTLS listener and open enrollment is a failure`() {
        val tlsOnly = SetupCertificateReport.checks(facts(listeners = listOf(Listener("default-tls", 8091, "tls", true))))
        assertTrue(tlsOnly.none { it.id in setOf("enrollment_mode", "recovery_door", "client_cert_ttl") })
        assertTrue(tlsOnly.any { it.id == "client_ca" }, "the client CA is shown even so: its pin goes into the app")
        val open = SetupCertificateReport.checks(facts(enrollmentMode = "open", recoveryPort = null))
        assertEquals(SetupReport.Level.FAIL, level(open, "enrollment_mode"))
        assertEquals(SetupReport.Level.WARN, level(open, "recovery_door"))
        assertEquals("mtls", open.first { it.id == "enrollment_mode" }.configApiId)
    }

    @Test
    fun `the route serves the facts and the checks as JSON`() = testApplication {
        routing { setupCertificatesRoute { facts(hosts = listOf(Host("api.example.com", "default-tls", "uploaded", false, inDays(100), true, 2, false, null))) } }
        val body = Json.parseToJsonElement(client.get("/api/v1/setup/certificates").bodyAsText()).jsonObject
        assertEquals("192.168.1.80", body["publicHost"]!!.jsonPrimitive.content)
        assertEquals(true, body["configApiCert"]!!.jsonObject["selfSigned"]!!.jsonPrimitive.content.toBoolean())
        assertEquals("C".repeat(43) + "=", body["clientCa"]!!.jsonObject["pin"]!!.jsonPrimitive.content)
        assertEquals(1, body["hosts"]!!.jsonArray.size)
        assertEquals("uploaded", body["hosts"]!!.jsonArray[0].jsonObject["source"]!!.jsonPrimitive.content)
        val checks = body["checks"]!!.jsonArray.map { it.jsonObject }
        assertTrue(checks.any { it["id"]!!.jsonPrimitive.content == "host_cert" && it["hostname"]!!.jsonPrimitive.content == "api.example.com" })
        assertTrue(checks.all { it["level"]!!.jsonPrimitive.content in setOf("ok", "warn", "fail") })
    }
}
