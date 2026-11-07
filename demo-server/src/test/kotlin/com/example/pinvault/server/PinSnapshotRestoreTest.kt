package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.model.HostPin
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Every pin save leaves a snapshot; a snapshot can be brought back with one
 * call — as a NEW version with the old pins, never as the old version
 * (devices refuse version downgrades).
 */
class PinSnapshotRestoreTest {

    private lateinit var dir: File

    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val pinsB = listOf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=")
    private val pinsC = listOf("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA=")

    @BeforeTest
    fun setUp() { dir = kotlin.io.path.createTempDirectory("pinvault-snap-").toFile() }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun GovernanceHarness.publish(vararg entries: Pair<String, List<String>>) {
        val config = pins.load(scope)
        pins.save(scope, config.copy(pins = entries.map { (host, p) ->
            HostPin(host, p, version = config.pins.find { it.hostname == host }?.version?.plus(1) ?: 1)
        }))
    }

    private fun GovernanceHarness.snapshots() =
        Json.parseToJsonElement(call("GET", "/api/v1/pin-snapshots?configApiId=$scope", ALICE).body).jsonArray

    @Test
    fun `every save that changes something leaves a snapshot, an unchanged save does not`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA)
            h.publish("api.example.com" to pinsA)   // same pins, new version number only
            h.publish("api.example.com" to pinsB)
            val list = h.snapshots()
            // v1 (A), v2 (A), v3 (B): the version is part of what devices get, so each is a row.
            assertEquals(3, list.size, list.toString())
            assertEquals(listOf("api.example.com v3"), list[0].jsonObject["changed"]!!.jsonArray.map { it.jsonPrimitive.content })
            val config = h.pins.load(h.scope)
            h.pins.save(h.scope, config)            // nothing changed
            assertEquals(3, h.snapshots().size, "a save that changed nothing adds no snapshot")
        }
    }

    @Test
    fun `restoring a host publishes its old pins under a higher version`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA, "cdn.example.com" to pinsC)
            h.publish("api.example.com" to pinsB, "cdn.example.com" to pinsC)
            val versions = Json.parseToJsonElement(
                h.call("GET", "/api/v1/hosts/api.example.com/pin-versions?configApiId=${h.scope}", ALICE).body
            ).jsonArray
            assertEquals(listOf(2, 1), versions.map { it.jsonObject["version"]!!.jsonPrimitive.content.toInt() })
            val older = versions[1].jsonObject["snapshotId"]!!.jsonPrimitive.long

            val answer = h.call("POST", "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}", ALICE, """{"hostname":"api.example.com"}""")
            assertEquals(200, answer.status, answer.body)
            val api = h.pins.load(h.scope).pins.first { it.hostname == "api.example.com" }
            assertEquals(pinsA, api.sha256, "the old pins are back")
            assertEquals(3, api.version, "as a new version, never v1 again")
            assertEquals(pinsC, h.pinsOf("cdn.example.com"), "the other host is untouched")
            assertTrue(h.actions().contains("pins_restored"), h.actions().toString())
            assertTrue(h.history.getByHostname("api.example.com").first().event == "pins_restored")
        }
    }

    @Test
    fun `restoring a whole scope removes hosts added since and brings removed ones back above their watermark`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA, "old.example.com" to pinsC)
            val wanted = h.snapshots()[0].jsonObject["id"]!!.jsonPrimitive.long
            h.publish("api.example.com" to pinsA, "new.example.com" to pinsB)   // old removed, new added
            val answer = h.call("POST", "/api/v1/pin-snapshots/$wanted/restore?configApiId=${h.scope}", ALICE, "{}")
            assertEquals(200, answer.status, answer.body)
            val now = h.pins.load(h.scope).pins.associateBy { it.hostname }
            assertEquals(setOf("api.example.com", "old.example.com"), now.keys)
            assertEquals(2, now.getValue("api.example.com").version, "a host whose pins are the same keeps its current version")
            assertEquals(2, now.getValue("old.example.com").version, "a re-added host continues above its watermark (v1)")
        }
    }

    @Test
    fun `a restore to the current state changes nothing`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA)
            val latest = h.snapshots()[0].jsonObject["id"]!!.jsonPrimitive.long
            val answer = h.call("POST", "/api/v1/pin-snapshots/$latest/restore?configApiId=${h.scope}", ALICE, "{}")
            assertEquals(200, answer.status, answer.body)
            assertEquals("true", Json.parseToJsonElement(answer.body).jsonObject["unchanged"]!!.jsonPrimitive.content)
            assertFalse(h.actions().contains("pins_restored"))
        }
    }

    @Test
    fun `with two-person approval a restore waits and the approver sees the diff`() {
        GovernanceHarness(dir).use { h ->
            h.publish("api.example.com" to pinsA)
            h.publish("api.example.com" to pinsB)
            val older = h.snapshots()[1].jsonObject["id"]!!.jsonPrimitive.long
            val pending = h.call("POST", "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}", ALICE, """{"hostname":"api.example.com"}""")
            assertEquals(202, pending.status, pending.body)
            val id = pending.changeRequestId
            val cr = h.changeRequest(id)
            assertTrue(cr.summary.contains("restore api.example.com from snapshot $older"), cr.summary)
            assertTrue(cr.summary.contains("v2→v3"), cr.summary)
            assertEquals(pinsB, h.pinsOf("api.example.com"), "nothing changes before the approval")
            val approved = h.approve(id)
            assertEquals(200, approved.status, approved.body)
            assertEquals(pinsA, h.pinsOf("api.example.com"))
            assertEquals(3, h.pins.load(h.scope).pins.first().version)
        }
    }

    @Test
    fun `a snapshot of another scope is refused`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA)
            val id = h.snapshots()[0].jsonObject["id"]!!.jsonPrimitive.long
            val answer = h.call("POST", "/api/v1/pin-snapshots/$id/restore?configApiId=other", ALICE, "{}")
            assertEquals(409, answer.status, answer.body)
        }
    }

    @Test
    fun `the first save on an upgraded server keeps the state it replaces`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish("api.example.com" to pinsA)
            h.db.connection().use { it.createStatement().execute("DELETE FROM pin_snapshots") }   // a 2.8.x database
            h.publish("api.example.com" to pinsB)
            val list = h.snapshots()
            assertEquals(2, list.size, "the state before the change is kept too: $list")
            assertEquals("system", list[1].jsonObject["actor"]!!.jsonPrimitive.content)
        }
    }
}
