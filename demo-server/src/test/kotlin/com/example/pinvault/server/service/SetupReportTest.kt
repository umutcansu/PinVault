package com.example.pinvault.server.service

import com.example.pinvault.server.route.SetupFacts
import com.example.pinvault.server.route.parsePublicHost
import com.example.pinvault.server.route.parsePublicPorts
import com.example.pinvault.server.route.setupRoutes
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The setup wizard's checklist: what a demo setup lacks, what a production
 * one has, and that it never repeats a secret.
 */
class SetupReportTest {

    private val secrets = mapOf(
        "KEYSTORE_PASSWORD" to "ks-secret-123",
        "VAULT_AT_REST_PASSWORD" to "vault-secret-456",
        "SIGNING_KEY_PASSWORD" to "signing-secret-789",
        "API_KEY" to "admin-secret-000"
    )

    private val production = secrets + mapOf(
        "ADMIN_KEYS" to "ayse:" + "a".repeat(64) + ",mehmet:" + "b".repeat(64),
        "PIN_CHANGE_APPROVALS" to "2",
        "NOTIFY_WEBHOOK_URL" to "https://hooks.example.com/x",
        "MANAGEMENT_HTTPS_PORT" to "6655",
        "CONFIG_SIGNERS" to "pkcs11,command:kms",
        "RECOVERY_PUBLIC_KEYS" to "MFkw",
        "CONFIG_TTL_SECONDS" to "86400",
        "PIN_LIVE_CHECK" to "enforce",
        "ENROLLMENT_MODE" to "token",
        "ENROLLMENT_ATTESTATION" to "enforce",
        "ATTESTATION_PACKAGE_NAMES" to "com.example.app",
        "ATTESTATION_SIGNER_SHA256" to "c".repeat(64),
        "ATTESTATION_REVOKED_SERIALS_FILE" to "/data/attestation-status.json",
        "ATTESTATION_STATUS_MAX_AGE_HOURS" to "24",
        "ENROLLMENT_P12" to "off",
        "INTEGRITY_VERIFICATION" to "enforce",
        "INTEGRITY_VERIFIER_COMMAND" to "/opt/pinvault/scripts/play-integrity-verify.sh"
    )

    private fun levels(env: Map<String, String>) = SetupReport.checks(env).associate { it.id to it.level }

    @Test
    fun `a production setup passes every check`() {
        val checks = SetupReport.checks(production)
        assertTrue(checks.all { it.level == SetupReport.Level.OK }, checks.filter { it.level != SetupReport.Level.OK }.toString())
        assertTrue(checks.all { it.fix == null })
    }

    @Test
    fun `an empty environment is flagged where it matters`() {
        val l = levels(emptyMap())
        assertEquals(SetupReport.Level.FAIL, l["demo_secrets"])
        assertEquals(SetupReport.Level.WARN, l["admin_auth"])
        assertEquals(SetupReport.Level.WARN, l["signers"])
        assertEquals(SetupReport.Level.WARN, l["attestation"])
        assertEquals(SetupReport.Level.WARN, l["integrity"])
        assertEquals(SetupReport.Level.WARN, l["p12"])
        assertEquals(SetupReport.Level.OK, l["enrollment_mode"])
        assertNull(l["test_hooks"])
    }

    @Test
    fun `dangerous settings fail`() {
        val l = levels(production + mapOf(
            "ALLOW_ANONYMOUS_ADMIN" to "true", "ENROLLMENT_MODE" to "open",
            "ENROLLMENT_ATTESTATION" to "off", "ALLOW_TEST_HOOKS" to "true"
        ))
        assertEquals(SetupReport.Level.FAIL, l["admin_auth"])
        assertEquals(SetupReport.Level.FAIL, l["enrollment_mode"])
        assertEquals(SetupReport.Level.FAIL, l["attestation"])
        assertEquals(SetupReport.Level.FAIL, l["test_hooks"])
        // Attestation off: its revocation list is not asked for.
        assertNull(l["attestation_revocation"])
    }

    @Test
    fun `one signer on disk is a warning, two with one off disk is fine`() {
        assertEquals(SetupReport.Level.WARN, levels(production + ("CONFIG_SIGNERS" to "local"))["signers"])
        assertEquals(SetupReport.Level.WARN, levels(production + ("CONFIG_SIGNERS" to "local,local:b"))["signers"])
        assertEquals(SetupReport.Level.OK, levels(production + ("CONFIG_SIGNERS" to "local,command:kms"))["signers"])
    }

    @Test
    fun `enforce attestation without the app binding is not ok`() {
        val c = SetupReport.checks(production - "ATTESTATION_SIGNER_SHA256").first { it.id == "attestation" }
        assertEquals(SetupReport.Level.WARN, c.level)
        assertTrue(c.fix!!.contains("ATTESTATION_SIGNER_SHA256="))
    }

    @Test
    fun `no secret value ever appears in the report`() {
        val all = SetupReport.checks(production).joinToString { "${it.current} ${it.fix}" } +
            SetupReport.checks(secrets).joinToString { "${it.current} ${it.fix}" }
        secrets.values.forEach { assertFalse(all.contains(it), "leaked $it") }
        assertFalse(all.contains("a".repeat(64)))
    }

    @Test
    fun `the setup endpoint answers checks and the app's public values`() = testApplication {
        routing {
            setupRoutes(env = { production }) {
                SetupFacts(
                    configApis = listOf(SetupFacts.Api("default-tls", 6651, "tls", true), SetupFacts.Api("sample-mtls", 6652, "mtls", false)),
                    bootstrapHost = "localhost", bootstrapPins = listOf("P1", "P2"),
                    signingKeys = listOf("K1", "K2"), requiredSignatures = 2, recoveryKeys = listOf("R1"),
                    clientCaPin = "CA", recoveryPort = 6656, recoveryPins = listOf("RP1", "RP2"),
                    enrollmentMode = "token", attestationMode = "enforce", integrityMode = "warn", configTtlSeconds = 86400,
                    publicHost = "192.168.1.10", publicPorts = mapOf(6651 to 443)
                )
            }
        }
        val response = client.get("/api/v1/setup")
        assertEquals(HttpStatusCode.OK, response.status)
        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(SetupReport.checks(production).size, json["checks"]!!.jsonArray.size)
        assertEquals("ok", json["checks"]!!.jsonArray.first().jsonObject["level"]!!.jsonPrimitive.content)
        assertEquals(listOf("default-tls", "sample-mtls"), json["configApis"]!!.jsonArray.map { it.jsonObject["id"]!!.jsonPrimitive.content })
        assertEquals("2", json["requiredSignatures"]!!.jsonPrimitive.content)
        assertEquals("CA", json["clientCaPin"]!!.jsonPrimitive.content)
        assertEquals("warn", json["integrityMode"]!!.jsonPrimitive.content)
        val apis = json["configApis"]!!.jsonArray.map { it.jsonObject }
        assertEquals(listOf("443", "6652"), apis.map { it["publicPort"]!!.jsonPrimitive.content })
        assertEquals("6656", json["recoveryPublicPort"]!!.jsonPrimitive.content)
        assertEquals("192.168.1.10", json["publicHost"]!!.jsonPrimitive.content)
        secrets.values.forEach { assertFalse(response.bodyAsText().contains(it)) }
    }

    @Test
    fun `public ports and host are read leniently`() {
        assertEquals(mapOf(8081 to 6651, 8092 to 6652), parsePublicPorts("8081:6651, 8092:6652,bad,8083:,0:1,8084:70000"))
        assertEquals(emptyMap(), parsePublicPorts(null))
        assertEquals("pins.example.com", parsePublicHost(" https://pins.example.com:443/x "))
        assertEquals("192.168.1.10", parsePublicHost("192.168.1.10"))
        assertNull(parsePublicHost("  "))
    }
}
