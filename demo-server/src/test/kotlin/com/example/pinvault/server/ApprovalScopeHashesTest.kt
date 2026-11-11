package com.example.pinvault.server

import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.AuditLog
import com.example.pinvault.server.store.AuditLogStore
import com.example.pinvault.server.store.ChangeRequestStore
import com.example.pinvault.server.store.DatabaseManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Review 2026-11-11: a host certificate change writes pins to every
 * Config API that pins the host, but its card fingerprinted only the first.
 * A change approved in between in another of them was overwritten unseen.
 */
class ApprovalScopeHashesTest {

    private val dbFile = File.createTempFile("pinvault-scope-hashes-", ".db").also { it.deleteOnExit() }
    private val db = DatabaseManager(dbFile.absolutePath)
    private val audit = AuditLog(AuditLogStore(db), null)
    private val states = mutableMapOf("tls" to "s1", "mtls" to "m1")
    private val replays = mutableListOf<Long>()

    @AfterTest
    fun tearDown() { dbFile.delete() }

    private fun service() = ApprovalService(
        store = ChangeRequestStore(db), audit = audit, required = 2, managementPort = 1,
        describe = { _ ->
            ApprovalService.Description(
                "tls", "api.example.com: new certificate — changes Config API tls, mtls",
                JsonObject(mapOf(ApprovalService.SCOPE_HASHES to JsonObject(mapOf("mtls" to JsonPrimitive(states["mtls"]!!))))),
                baseHash = states["tls"]
            )
        },
        stateHash = { states[it] ?: "" },
        replay = { cr, _, _ -> replays += cr.id; 200 to "{}" }
    )

    private fun submit(approvals: ApprovalService) = approvals.submit(
        requestedBy = "alice", op = "host_cert", method = "POST", path = "/api/v1/hosts/api.example.com/cert",
        query = "", contentType = "application/json", body = "{}".toByteArray()
    ).changeRequestId

    @Test
    fun `a change in another Config API the plan writes to makes it stale`() {
        val approvals = service()
        val id = submit(approvals)
        states["mtls"] = "m2"

        val refused = assertFailsWith<ApprovalService.Refused> { approvals.approve(id, "bob") }
        assertTrue(refused.message!!.contains("mtls"), refused.message)
        assertEquals("stale", approvals.get(id)!!.status)
        assertTrue(replays.isEmpty(), "nothing was run")
    }

    @Test
    fun `unchanged Config APIs let it through`() {
        val approvals = service()
        val id = submit(approvals)
        assertEquals("applied", approvals.approve(id, "bob").status)
        assertEquals(listOf(id), replays)
    }
}
