package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.service.ChangeDescriber
import com.example.pinvault.server.service.PinAffectingRoutes
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.ChangeRequestStore
import com.example.pinvault.server.store.DatabaseManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Review 2026-11-12: cards whose change depends on state other than pins —
 * the bootstrap certificate's backup key, which API a port serves, a vault
 * file's policy, a device's key — carried no staleness check. Two requests
 * approved out of order then did what neither card said (a rotate installed a
 * replaced backup; a secret upload landed under a policy made public in
 * between). They now record `stateRefs`, checked again at approval.
 */
class ApprovalStateRefsTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() { dir = kotlin.io.path.createTempDirectory("pinvault-state-refs-").toFile() }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun status(h: GovernanceHarness, id: Long) = h.changeRequest(id).status

    @Test
    fun `every gated operation says how its card is kept from going stale`() {
        assertEquals(PinAffectingRoutes.operations, ChangeDescriber.STALENESS.keys,
            "an operation without a Staleness entry in ChangeDescriber.STALENESS, or an entry for one that is gone")
    }

    @Test
    fun `a vault upload is stale when the file's policy changed in between`() {
        GovernanceHarness(dir).use { h ->
            val path = "/api/v1/config-apis/${h.scope}/vault/secret.bin"
            val first = h.call("PUT", path, ALICE, "v1".toByteArray(), contentType = "application/octet-stream")
            assertEquals(202, first.status, first.body)
            assertEquals("applied", h.approve(first.changeRequestId).json["status"]!!.jsonPrimitive.content)

            // #1: new content, no ?policy — the card says "access token".
            val upload = h.call("PUT", path, ALICE, "secret-v2".toByteArray(), contentType = "application/octet-stream")
            assertEquals(202, upload.status, upload.body)
            assertTrue(h.changeRequest(upload.changeRequestId).summary.contains("access token"), h.changeRequest(upload.changeRequestId).summary)
            assertNotNull(h.detail(upload.changeRequestId)[ApprovalService.STATE_REFS])

            // #2: the file is made public, approved first.
            val policy = h.call("PUT", "$path/policy", ALICE, """{"access_policy":"public","encryption":"plain"}""")
            assertEquals(202, policy.status, policy.body)
            assertEquals("applied", h.approve(policy.changeRequestId).json["status"]!!.jsonPrimitive.content)

            val late = h.approve(upload.changeRequestId)
            assertEquals(409, late.status, late.body)
            assertTrue(late.body.contains("vault file secret.bin", ignoreCase = true), late.body)
            assertEquals("stale", status(h, upload.changeRequestId))
            assertEquals("v1", h.vaultFiles.get(h.scope, "secret.bin")!!.content.toString(Charsets.UTF_8), "the secret never landed under the public policy")
            assertTrue(h.actions().contains("change_stale"))
        }
    }

    @Test
    fun `an unchanged vault file lets the upload through`() {
        GovernanceHarness(dir).use { h ->
            val path = "/api/v1/config-apis/${h.scope}/vault/model.bin"
            val upload = h.call("PUT", path, ALICE, "v1".toByteArray(), contentType = "application/octet-stream")
            assertEquals("applied", h.approve(upload.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals("v1", h.vaultFiles.get(h.scope, "model.bin")!!.content.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `a bootstrap rotate is stale after a regenerate replaced the backup it would promote`() {
        GovernanceHarness(dir).use { h ->
            val initial = h.call("POST", "/api/v1/server-tls-pins/regenerate", ALICE)
            val first = h.approve(initial.changeRequestId)
            assertEquals("applied", first.json["status"]!!.jsonPrimitive.content, first.body)

            val rotate = h.call("POST", "/api/v1/server-tls-pins/rotate-to-backup", ALICE)
            assertEquals(202, rotate.status, rotate.body)
            val regenerate = h.call("POST", "/api/v1/server-tls-pins/regenerate", ALICE)
            assertEquals(202, regenerate.status, regenerate.body)
            assertEquals("applied", h.approve(regenerate.changeRequestId).json["status"]!!.jsonPrimitive.content)
            val regenerated = h.serverPins.pins

            val late = h.approve(rotate.changeRequestId)
            assertEquals(409, late.status, late.body)
            assertTrue(late.body.contains("Config API TLS certificate"), late.body)
            assertEquals("stale", status(h, rotate.changeRequestId))
            assertEquals(regenerated, h.serverPins.pins, "the regenerated pins stay; the rotate did not install the old backup")
        }
    }

    @Test
    fun `a device key reset is stale when another key was registered after it was requested`() {
        GovernanceHarness(dir).use { h ->
            h.deviceKeys.register("dev-1", h.scope, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", timestamp = "2026-11-12T00:00:00Z")
            val reset = h.call("DELETE", "/api/v1/config-apis/${h.scope}/vault/devices/dev-1/public-key", ALICE)
            assertEquals(202, reset.status, reset.body)
            assertTrue(h.changeRequest(reset.changeRequestId).summary.contains("(key "), h.changeRequest(reset.changeRequestId).summary)

            h.deviceKeys.register("dev-1", h.scope, "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----", timestamp = "2026-11-12T00:01:00Z")
            val late = h.approve(reset.changeRequestId)
            assertEquals(409, late.status, late.body)
            assertNotNull(h.deviceKeys.get("dev-1", h.scope), "the key registered after the request was not removed")
        }
    }

    // ── The mechanism, without a server ───────────────────────────────

    private val dbFile = File.createTempFile("pinvault-state-refs-", ".db").also { it.deleteOnExit() }

    @Test
    fun `a start is stale when another API took the port, and a ref that vanished counts as moved`() {
        val db = DatabaseManager(dbFile.absolutePath)
        val holders = mutableMapOf<String, String?>("port|8091" to null)
        val replays = mutableListOf<Long>()
        val approvals = ApprovalService(
            store = ChangeRequestStore(db), audit = AuditLog(AuditLogStore(db), null), required = 2, managementPort = 1,
            describe = { _ ->
                ApprovalService.Description("staging", "Start Config API staging on port 8091 — that port serves this scope's pins", JsonObject(emptyMap()),
                    stateRefs = mapOf("port|8091" to (holders["port|8091"] ?: ApprovalService.MISSING_STATE)))
            },
            stateOf = { holders[it] },
            replay = { cr, _, _ -> replays += cr.id; 200 to "{}" }
        )
        fun submit() = approvals.submit("alice", "config_api_lifecycle", "POST", "/api/v1/config-apis/start", query = "",
            contentType = "application/json", body = """{"id":"staging","port":8091}""".toByteArray()).changeRequestId

        val clean = submit()
        assertEquals("applied", approvals.approve(clean, "bob").status)

        val stale = submit()
        holders["port|8091"] = "prod"
        val refused = assertFailsWith<ApprovalService.Refused> { approvals.approve(stale, "bob") }
        assertTrue(refused.message!!.contains("port 8091"), refused.message)
        assertEquals("stale", approvals.get(stale)!!.status)
        assertEquals(listOf(clean), replays)
        dbFile.delete()
    }
}
