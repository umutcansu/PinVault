package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.route.configApiRequestError
import com.example.pinvault.server.store.AttestedDeviceStore
import com.example.pinvault.server.store.DatabaseManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Server findings of the 2026-11-14 review other than the query reading (S3, S4, S5). */
class Review20261114ServerTest {

    private fun dir(): File = Files.createTempDirectory("review-1114").toFile()

    // ── S3: a Config API id that is not a JSON string ───────────────────

    @Test
    fun `a Config API id must be a JSON string - a bare word or a number is refused`() {
        fun error(body: String, start: Boolean = true) = configApiRequestError(Json.parseToJsonElement(body).jsonObject, start)
        assertNull(error("""{"id":"staging","port":9443}"""))
        assertNull(error("""{"port":9443}"""), "start may leave the id out")
        // kotlinx reads an unquoted literal as a primitive that is not a string.
        assertEquals("id must be a string", error("""{"id": a|b<x>, "port": 9443}"""))
        assertEquals("id must be a string", error("""{"id": 5, "port": 9443}"""))
        assertEquals("id must be a string", error("""{"id": null, "port": 9443}"""))
        assertEquals("id must be a string", error("""{"id": ["a"], "port": 9443}"""))
        assertEquals("id must be a string", error("""{"id": 5}""", start = false))
        assertNotNull(error("""{"id":"staging","port":9443,"mode": mtls}"""), "mode is a string too")
    }

    // ── S4: a token anomaly survives the device's own re-registration ───

    @Test
    fun `a device that registers a new key after a release keeps its token anomaly`() {
        val store = AttestedDeviceStore(DatabaseManager(File(dir(), "db.sqlite").absolutePath))
        assertTrue(store.register("api", "dev-1", "spki-old", "key-old", attestation = null))
        assertTrue(store.recordAnomaly("api", "dev-1", "token used from too many addresses", Instant.parse("2026-11-14T10:00:00Z")))

        // What AttestationService does when the device proves a new identity key over mTLS.
        assertTrue(store.releaseKey("api", "dev-1"))
        assertTrue(store.register("api", "dev-1", "spki-new", "key-new", attestation = null))

        val device = store.get("api", "dev-1")!!
        assertEquals("spki-new", device.spkiSha256)
        assertNotNull(device.anomalyAt, "only an admin lifts an anomaly")
        assertEquals("token used from too many addresses", device.anomalyReason)
    }

    // ── V1: a re-uploaded vault file does not start over at v1 ───────────

    @Test
    fun `a vault file deleted and uploaded again continues its version sequence`() {
        val db = DatabaseManager(File(dir(), "db.sqlite").absolutePath)
        val store = com.example.pinvault.server.store.VaultFileStore(
            db, com.example.pinvault.server.service.VaultAtRestCipher(com.example.pinvault.server.service.VaultAtRestCipher.DEMO_PASSWORD))
        store.put("api", "flags", "one".toByteArray(), accessPolicy = "token", encryption = "plain")
        store.put("api", "flags", "two".toByteArray())
        assertTrue(store.updatePolicy("api", "flags", "public", "plain"), "a policy change is a new version too")
        assertEquals(3, store.meta("api", "flags")!!.version)

        // Devices that verified v3 keep it as their floor: v1 again would be refused by all of them.
        store.delete("api", "flags")
        store.put("api", "flags", "again".toByteArray())
        assertEquals(4, store.meta("api", "flags")!!.version)

        // Per file and per Config API: nothing else is moved.
        store.put("api", "other", "x".toByteArray())
        store.put("staging", "flags", "x".toByteArray())
        assertEquals(1, store.meta("api", "other")!!.version)
        assertEquals(1, store.meta("staging", "flags")!!.version)
    }

    // ── S5: what an approver is shown, and a card that cannot be read ───

    @Test
    fun `a key-set card names the version, the keys, how many must sign and the Config APIs`() {
        GovernanceHarness(dir()).use { h ->
            val keys = listOf(TestPki.keys(), TestPki.keys()).map { java.util.Base64.getEncoder().encodeToString(it.public.encoded) }
            val payload = """{"type":"signing-key-set","version":7,"keys":["${keys[0]}","${keys[1]}"],"requiredSignatures":2,"configApiIds":["default-tls","sample-mtls"]}"""
            val body = """{"payload":${Json.encodeToString(kotlinx.serialization.serializer<String>(), payload)},"signatures":[]}"""

            val pending = h.call("PUT", "/api/v1/signing-keyset", ALICE, body)
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertEquals("Publish signing-key set v7: 2 signing key(s), 2 signature(s) required, for Config API default-tls, sample-mtls", cr.summary)
            val set = h.detail(pending.changeRequestId)["keySet"]!!.jsonObject
            assertEquals("7", set["version"]!!.jsonPrimitive.content)
            assertEquals(2, set["keySha256"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet().size, "each key by its own fingerprint")
            assertEquals(listOf("default-tls", "sample-mtls"), set["configApiIds"]!!.jsonArray.map { it.jsonPrimitive.content })
        }
    }

    @Test
    fun `a key set that names no Config API says so on its card`() {
        GovernanceHarness(dir()).use { h ->
            val key = java.util.Base64.getEncoder().encodeToString(TestPki.keys().public.encoded)
            val payload = """{"type":"signing-key-set","version":2,"keys":["$key"],"requiredSignatures":1}"""
            val body = """{"payload":${Json.encodeToString(kotlinx.serialization.serializer<String>(), payload)}}"""
            val pending = h.call("PUT", "/api/v1/signing-keyset", ALICE, body)
            assertEquals(202, pending.status, pending.body)
            assertTrue(h.changeRequest(pending.changeRequestId).summary.endsWith("for NO named Config API"), h.changeRequest(pending.changeRequestId).summary)
        }
    }

    @Test
    fun `a request whose card cannot be read is not applied`() {
        GovernanceHarness(dir()).use { h ->
            val pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            val pending = h.call("PUT", "/api/v1/certificate-config", ALICE,
                """{"pins":[{"hostname":"api.example.com","sha256":["$pin","B${pin.drop(1)}"],"version":1}]}""")
            assertEquals(202, pending.status, pending.body)
            for (damaged in listOf("not json", """["an","array"]""", """{"baseHash":{"not":"text"}}""")) {
                h.db.connection().use { c ->
                    c.prepareStatement("UPDATE change_requests SET detail = ?, status = 'pending', decided_by = NULL, decided_at = NULL WHERE id = ?").use { s ->
                        s.setString(1, damaged); s.setLong(2, pending.changeRequestId); s.executeUpdate()
                    }
                }
                val answer = h.approve(pending.changeRequestId)
                assertEquals(409, answer.status, "$damaged: ${answer.body}")
                assertEquals("stale", h.changeRequest(pending.changeRequestId).status, damaged)
            }
            assertTrue(h.pins.load(h.scope).pins.isEmpty(), "nothing was written")
            assertTrue("change_stale" in h.actions())
        }
    }
}
