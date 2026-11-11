package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.GovernanceHarness.Companion.BOB
import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.ChangeDescriber
import com.example.pinvault.server.service.PinAffectingRoutes
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
import kotlin.test.fail

/**
 * What a second admin is shown before approving (security review 2026-11-09):
 * a managed trust root that a change adds or takes away is on the card, in the
 * audit entry and in the fingerprint a stale approval is refused by; a
 * settings save, an attestation policy and an attestation device change say
 * what they change; no gated operation is shown as a bare name and path.
 */
class ApprovalCardsTest {

    private lateinit var dir: File

    private val pinsA = listOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")
    private val pinsB = listOf("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA=")
    private val root = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRA="
    private val root2 = "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSA="
    private val host = "api.example.com"

    @BeforeTest
    fun setUp() { dir = kotlin.io.path.createTempDirectory("pinvault-cards-").toFile() }

    @AfterTest
    fun tearDown() { dir.deleteRecursively() }

    private fun GovernanceHarness.publish(pins: List<String>, roots: List<String>, name: String = host) {
        val config = this.pins.load(scope)
        val version = config.pins.find { it.hostname == name }?.let { if (it.sha256 == pins) it.version else it.version + 1 } ?: 1
        this.pins.save(scope, config.copy(pins = listOf(HostPin(name, pins, version = version)), trustRoots = roots))
    }

    private fun GovernanceHarness.snapshotIds(): List<Long> =
        Json.parseToJsonElement(call("GET", "/api/v1/pin-snapshots?configApiId=$scope", ALICE).body).jsonArray
            .map { it.jsonObject["id"]!!.jsonPrimitive.long }

    private fun pinsBody(pins: List<String>, roots: List<String>?): String =
        """{"version":0,"forceUpdate":false,"pins":[{"hostname":"$host","sha256":[${pins.joinToString(",") { "\"$it\"" }}],"version":1}]""" +
            (roots?.let { r -> ""","trustRoots":[${r.joinToString(",") { "\"$it\"" }}]""" } ?: "") + "}"

    // ── Managed trust roots ─────────────────────────────────────────────

    @Test
    fun `a whole-scope restore names the trust root it brings back - card, audit and history`() {
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, listOf(root))
            h.publish(pinsB, emptyList())           // the root is withdrawn
            val older = h.snapshotIds()[1]

            val pending = h.call("POST", "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}", ALICE, "{}")
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.contains("trust root ADDED (${root.take(12)}"), cr.summary)
            val roots = h.detail(pending.changeRequestId)["trustRoots"]!!.jsonObject
            assertEquals(listOf(root), roots["added"]!!.jsonArray.map { it.jsonPrimitive.content })
            assertEquals(emptyList(), h.pins.load(h.scope).trustRoots, "nothing changes before the approval")

            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertEquals(listOf(root), h.pins.load(h.scope).trustRoots)
            val restored = h.auditStore.page(50, 0).first { it.action == "pins_restored" }
            assertTrue(restored.summary.contains("trust root ADDED"), restored.summary)
            assertTrue(h.history.getByHostname("*").any { it.event == "trust_roots_updated" }, "the root change is in the history")
        }
    }

    @Test
    fun `a card that showed no root change is stale once a root moved`() {
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, listOf(root))
            // Requested against roots = [R]; the card shows a pin change only.
            val pending = h.call("PUT", "/api/v1/certificate-config", ALICE, pinsBody(pinsB, null))
            assertEquals(202, pending.status, pending.body)
            assertFalse(h.changeRequest(pending.changeRequestId).summary.contains("trust root"))
            // Meanwhile the root is withdrawn; the pins did not move.
            h.publish(pinsA, emptyList())
            assertEquals(409, h.approve(pending.changeRequestId).status, "the fingerprint covers the roots")
            assertEquals(pinsA, h.pinsOf(host))
        }
    }

    @Test
    fun `a pin update shows the roots it sends and keeps the ones it does not mention`() {
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, listOf(root))
            val replacing = h.call("PUT", "/api/v1/certificate-config", ALICE, pinsBody(pinsA, listOf(root2)))
            assertEquals(202, replacing.status, replacing.body)
            val summary = h.changeRequest(replacing.changeRequestId).summary
            assertTrue(summary.contains("trust root ADDED (${root2.take(12)}"), summary)
            assertTrue(summary.contains("trust root removed (${root.take(12)}"), summary)
            assertEquals(200, h.approve(replacing.changeRequestId).status)
            assertEquals(listOf(root2), h.pins.load(h.scope).trustRoots)

            val silent = h.call("PUT", "/api/v1/certificate-config", ALICE, pinsBody(pinsB, null))
            assertFalse(h.changeRequest(silent.changeRequestId).summary.contains("trust root"))
            assertEquals(200, h.approve(silent.changeRequestId).status)
            assertEquals(listOf(root2), h.pins.load(h.scope).trustRoots, "a body without trustRoots keeps them")

            val bad = h.call("PUT", "/api/v1/certificate-config", ALICE, pinsBody(pinsB, listOf("not-a-pin")))
            assertEquals(400, bad.status, "a root the handler would refuse is refused before anyone is asked")
        }
    }

    @Test
    fun `a snapshot that differs only in its roots can be restored and says so in the list`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.publish(pinsA, listOf(root))
            h.publish(pinsA, emptyList())           // same pins, the root withdrawn
            val list = Json.parseToJsonElement(h.call("GET", "/api/v1/pin-snapshots?configApiId=${h.scope}", ALICE).body).jsonArray
            assertEquals(2, list.size, list.toString())
            assertEquals(listOf("trust roots (0)"), list[0].jsonObject["changed"]!!.jsonArray.map { it.jsonPrimitive.content })
            val older = list[1].jsonObject["id"]!!.jsonPrimitive.long

            val answer = h.call("POST", "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}", ALICE, "{}")
            assertEquals(200, answer.status, answer.body)
            assertEquals("true", answer.json["restored"]!!.jsonPrimitive.content, answer.body)
            assertEquals(listOf(root), h.pins.load(h.scope).trustRoots)
            assertEquals(pinsA, h.pinsOf(host))
        }
    }

    @Test
    fun `restoring one host leaves the roots alone, also when its name is longer than a card line`() {
        val long = "a".repeat(60) + "." + "b".repeat(60) + ".example.com"     // 133 characters
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, listOf(root), long)
            h.publish(pinsB, emptyList(), long)
            val older = h.snapshotIds()[1]
            val pending = h.call("POST", "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}", ALICE, """{"hostname":"$long"}""")
            assertEquals(202, pending.status, pending.body)
            // The summary line is cut at 300 characters; the detail carries the whole name.
            val detail = h.detail(pending.changeRequestId)
            assertEquals(long, detail["changed"]!!.jsonArray.single().jsonObject["hostname"]!!.jsonPrimitive.content)
            assertFalse(detail.containsKey("trustRoots"), detail.toString())
            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertEquals(pinsA, h.pinsOf(long))
            assertEquals(emptyList(), h.pins.load(h.scope).trustRoots, "one host's restore does not touch the roots")
        }
    }

    // ── Settings and attestation ────────────────────────────────────────

    @Test
    fun `a settings save shows every value it changes and is refused like the handler refuses it`() {
        GovernanceHarness(dir).use { h ->
            h.settings.save(mapOf("CONFIG_TTL_SECONDS" to "3600"))
            val pending = h.call("PUT", "/api/v1/server-settings", ALICE, """{"values":{"PIN_LIVE_CHECK":"warn","CONFIG_TTL_SECONDS":""}}""")
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.contains("PIN_LIVE_CHECK: (server default) → warn"), cr.summary)
            assertTrue(cr.summary.contains("CONFIG_TTL_SECONDS: 3600 → (server default)"), cr.summary)
            val changes = h.detail(pending.changeRequestId)["changes"]!!.jsonArray.map { it.jsonObject }
            assertEquals(setOf("PIN_LIVE_CHECK", "CONFIG_TTL_SECONDS"), changes.map { it["name"]!!.jsonPrimitive.content }.toSet())
            assertEquals(mapOf("CONFIG_TTL_SECONDS" to "3600"), h.settings.values(), "nothing is saved before the approval")

            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertEquals(mapOf("PIN_LIVE_CHECK" to "warn"), h.settings.values())

            val before = h.changeRequests.list(null).size
            val bad = h.call("PUT", "/api/v1/server-settings", ALICE, """{"values":{"PIN_LIVE_CHECK":"maybe","API_KEY":"x"}}""")
            assertEquals(400, bad.status, bad.body)
            assertEquals("invalid_settings", bad.json["error"]!!.jsonPrimitive.content)
            assertEquals(2, bad.json["details"]!!.jsonArray.size)
            assertEquals(before, h.changeRequests.list(null).size, "a refused save leaves no request to approve")
        }
    }

    @Test
    fun `an attestation policy change shows the flags and numbers that move`() {
        GovernanceHarness(dir).use { h ->
            val path = "/api/v1/config-apis/${h.scope}/attestation/policy"
            val pending = h.call("PUT", path, ALICE, """{"flags":{"rooted":"warn"},"revealReasons":true,"tokenTtlSeconds":600}""")
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertEquals(h.scope, cr.configApiId)
            assertTrue(cr.summary.contains("rooted: reject → warn"), cr.summary)
            assertTrue(cr.summary.contains("revealReasons: false → true"), cr.summary)
            assertTrue(cr.summary.contains("tokenTtlSeconds: 300 → 600"), cr.summary)
            assertEquals(0, h.attestation.policyFor(h.scope).version, "nothing changes before the approval")

            assertEquals(200, h.approve(pending.changeRequestId).status)
            val stored = h.attestation.policyFor(h.scope)
            assertEquals("warn", stored.flags["rooted"])
            assertEquals(600, stored.tokenTtlSeconds)

            assertEquals(400, h.call("PUT", path, ALICE, """{"flags":{"rooted":"sometimes"}}""").status)
        }
    }

    @Test
    fun `an attestation device card says what the override does - force, forget, clear`() {
        GovernanceHarness(dir).use { h ->
            val device = "/api/v1/config-apis/${h.scope}/attestation/devices/ph-1"
            val pending = h.call("PUT", device, ALICE, """{"forcePass":true,"annotations":["vip"]}""")
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.contains("attestation device ph-1 (not seen yet)"), cr.summary)
            assertTrue(cr.summary.contains("forcePass: false → true"), cr.summary)
            assertTrue(cr.summary.contains("annotations: (none) → vip"), cr.summary)
            assertTrue(cr.summary.contains("PASSES attestation whatever it reports"), cr.summary)
            assertEquals(200, h.approve(pending.changeRequestId).status)
            assertTrue(h.attestedDevices.get(h.scope, "ph-1")!!.forcePass)

            assertEquals(400, h.call("PUT", device, ALICE, """{"forcePass":true,"forceFail":true}""").status)

            val forget = h.call("DELETE", device, ALICE)
            assertEquals(202, forget.status, forget.body)
            assertTrue(h.changeRequest(forget.changeRequestId).summary.contains("forget attestation device ph-1"), h.changeRequest(forget.changeRequestId).summary)
            assertEquals(404, h.call("DELETE", "/api/v1/config-apis/${h.scope}/attestation/devices/nobody", ALICE).status)

            assertEquals(404, h.call("DELETE", "$device/anomaly", ALICE).status, "no anomaly to clear: refused like the handler refuses it")
            assertTrue(h.attestedDevices.recordAnomaly(h.scope, "ph-1", "too many addresses", java.time.Instant.now()))
            val clear = h.call("DELETE", "$device/anomaly", ALICE)
            assertEquals(202, clear.status, clear.body)
            assertTrue(h.changeRequest(clear.changeRequestId).summary.contains("clear the token anomaly of device ph-1 (too many addresses)"))
        }
    }

    // ── The card and the handler read the same request (second pass, 2026-11-09) ──

    @Test
    fun `a gated request in another charset is refused whatever its media type`() {
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, listOf(root))
            h.publish(pinsB, emptyList())
            val older = h.snapshotIds()[1]
            val path = "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}"
            val body = """{"hostname":"$host"}""".toByteArray(Charsets.UTF_8)
            // The card reads UTF-8, the handler read the header's charset: a one-host card ran as a whole-scope restore.
            for (type in listOf("text/plain; charset=UTF-16", "Application/JSON; charset=UTF-16", "application/json;CHARSET=\"utf-16le\"", "TEXT/PLAIN;charset=shift_jis")) {
                val answer = h.call("POST", path, ALICE, body, contentType = type)
                assertEquals(415, answer.status, "$type: ${answer.body}")
            }
            assertEquals(0, h.changeRequests.list(null).size, "nothing was stored for approval")
            for (type in listOf("application/json", "application/json; charset=utf-8", "Application/JSON; charset=UTF8", "text/plain")) {
                assertEquals(202, h.call("POST", path, ALICE, body, contentType = type).status, type)
            }
            // The header check itself.
            assertTrue(ApprovalService.namesAnotherCharset("text/plain; charset=UTF-16"))
            assertTrue(ApprovalService.namesAnotherCharset("application/json; charset=ISO-8859-1; charset=utf-8"), "the first charset is the one Ktor reads")
            assertFalse(ApprovalService.namesAnotherCharset("multipart/form-data; boundary=x"))
            assertFalse(ApprovalService.namesAnotherCharset("application/json; charset=no-such-charset"), "Ktor reads an unknown name as none, so UTF-8")
            assertFalse(ApprovalService.namesAnotherCharset(null))
        }
    }

    @Test
    fun `a restore body that cannot be read is refused, never taken for the whole scope`() {
        GovernanceHarness(dir, required = 1).use { h ->        // approvals off: the handler alone
            h.publish(pinsA, listOf(root))
            h.publish(pinsB, emptyList())
            val older = h.snapshotIds()[1]
            val path = "/api/v1/pin-snapshots/$older/restore?configApiId=${h.scope}"
            for (bad in listOf("not json", "[]", """{"hostname":""}""", """{"hostname":5}""", """{"hostname":null}""", """{"hostname":["$host"]}""")) {
                val answer = h.call("POST", path, ALICE, bad)
                assertEquals(400, answer.status, "$bad: ${answer.body}")
                assertEquals("invalid_body", answer.json["error"]!!.jsonPrimitive.content)
            }
            assertEquals(pinsB, h.pinsOf(host), "nothing was restored")
            assertEquals(emptyList(), h.pins.load(h.scope).trustRoots)
            // A one-host body labelled UTF-16 is still read as the bytes it is: one host, no roots.
            val one = h.call("POST", path, ALICE, """{"hostname":"$host"}""".toByteArray(), contentType = "text/plain; charset=UTF-16")
            assertEquals(200, one.status, one.body)
            assertEquals(pinsA, h.pinsOf(host))
            assertEquals(emptyList(), h.pins.load(h.scope).trustRoots, "one host's restore does not bring the root back")
        }
    }

    // ── A card is bound to the state it was computed from ───────────────

    @Test
    fun `an attestation policy card is stale once the policy moved`() {
        GovernanceHarness(dir).use { h ->
            val path = "/api/v1/config-apis/${h.scope}/attestation/policy"
            assertEquals(200, h.approve(h.call("PUT", path, ALICE, """{"flags":{"rooted":"warn"}}""").changeRequestId).status)
            // The form sends the whole flag map; only the TTL differs, and that is all the card shows.
            val ttl = h.call("PUT", path, ALICE, """{"flags":{"rooted":"warn"},"tokenTtlSeconds":600}""")
            assertTrue(h.changeRequest(ttl.changeRequestId).summary.contains("(1 change) — tokenTtlSeconds: 300 → 600"), h.changeRequest(ttl.changeRequestId).summary)
            // Meanwhile rooted is tightened again.
            val tighten = h.call("PUT", path, BOB, """{"flags":{"rooted":"reject"}}""")
            assertEquals(200, h.approve(tighten.changeRequestId, ALICE).status)
            // Approving the TTL card would write its whole flag map: rooted back to warn, unseen.
            val late = h.approve(ttl.changeRequestId, BOB)
            assertEquals(409, late.status, late.body)
            assertEquals("stale", h.changeRequest(ttl.changeRequestId).status)
            val policy = h.attestation.policyFor(h.scope)
            assertEquals("reject", policy.flags["rooted"])
            assertEquals(300, policy.tokenTtlSeconds)
        }
    }

    @Test
    fun `a settings card is stale once a value it names moved`() {
        GovernanceHarness(dir).use { h ->
            // PIN_LIVE_CHECK is unset: clearing it is a "no change" card.
            val pending = h.call("PUT", "/api/v1/server-settings", ALICE, """{"values":{"PIN_LIVE_CHECK":""}}""")
            assertEquals(202, pending.status, pending.body)
            assertTrue(h.changeRequest(pending.changeRequestId).summary.contains("(0 changes): no change"), h.changeRequest(pending.changeRequestId).summary)
            h.settings.save(mapOf("PIN_LIVE_CHECK" to "enforce", "CONFIG_TTL_SECONDS" to "3600"))
            assertEquals(409, h.approve(pending.changeRequestId).status, "approved now it would remove the value")
            assertEquals("enforce", h.settings.values()["PIN_LIVE_CHECK"])

            // A key the card does not name may move: it is not part of what the card shows.
            val other = h.call("PUT", "/api/v1/server-settings", ALICE, """{"values":{"PIN_LIVE_CHECK":"warn"}}""")
            h.settings.save(h.settings.values() + ("CONFIG_TTL_SECONDS" to "7200"))
            assertEquals(200, h.approve(other.changeRequestId).status)
            assertEquals(mapOf("PIN_LIVE_CHECK" to "warn", "CONFIG_TTL_SECONDS" to "7200"), h.settings.values())
        }
    }

    @Test
    fun `forgetting a device lists everything that goes with its key and is stale once the device moved`() {
        GovernanceHarness(dir).use { h ->
            val device = "/api/v1/config-apis/${h.scope}/attestation/devices/ph-9"
            h.attestedDevices.annotate(h.scope, "ph-9", forcePass = false, forceFail = true, annotations = listOf("stolen"))
            assertTrue(h.attestedDevices.recordAnomaly(h.scope, "ph-9", "abuse", java.time.Instant.now()))
            val forget = h.call("DELETE", device, ALICE)
            assertEquals(202, forget.status, forget.body)
            val summary = h.changeRequest(forget.changeRequestId).summary
            assertTrue(summary.contains("ALSO dropped: its forceFail override (the device is REJECTED today whatever it reports), its annotations (stolen), its token anomaly"), summary)
            val names = h.detail(forget.changeRequestId)["changes"]!!.jsonArray.map { it.jsonObject["name"]!!.jsonPrimitive.content }
            assertEquals(listOf("forceFail", "annotations", "token anomaly"), names)

            // The override is lifted in between: the card no longer says what the forget would drop.
            h.attestedDevices.annotate(h.scope, "ph-9", forcePass = false, forceFail = false, annotations = listOf("stolen"))
            assertEquals(409, h.approve(forget.changeRequestId).status)
            assertTrue(h.attestedDevices.get(h.scope, "ph-9") != null, "the device is still there")
        }
    }

    @Test
    fun `a root change comes first in the summary line`() {
        val before = com.example.pinvault.server.model.PinConfig(pins = (1..12).map { HostPin("h$it.example.com", pinsA, version = 1) }, trustRoots = emptyList())
        val after = before.copy(pins = before.pins.map { it.copy(sha256 = pinsB, version = 2) }, trustRoots = listOf(root))
        val summary = com.example.pinvault.server.service.PinDiff.of(before, after).summary()
        assertTrue(summary.startsWith("trust root ADDED (${root.take(12)}"), summary)
        assertTrue(ApprovalService.plainText(summary).contains("trust root ADDED"), "it survives the 300-character cut")
    }

    // ── No bare cards ───────────────────────────────────────────────────

    @Test
    fun `every gated operation has a card of its own`() {
        GovernanceHarness(dir).use { h ->
            PinAffectingRoutes.rules.forEach { (method, pattern, op) ->
                // A path the rule matches: the first alternative of a group, a name for a segment.
                val path = pattern.pattern.removePrefix("^").removeSuffix("$")
                    .replace("(/[^/]+)?", "").replace("/?", "")
                    .replace(Regex("\\(([^|)]+)[^)]*\\)")) { it.groupValues[1] }
                    .replace("[^/]+", "x1")
                assertTrue(pattern.matches(path), "sample path $path for $pattern")
                try {
                    h.describer.describe(ApprovalService.ChangeInput(op, path, "", "application/json", "{}".toByteArray(), "alice", method.value))
                } catch (e: ChangeDescriber.Undescribed) {
                    fail("${method.value} $path ($op) has no approval card: ${e.message}")
                } catch (_: Exception) {
                    // Refused for its content (an empty body, an unknown id): it was read by a card of its own.
                }
            }
        }
    }

    // ── A full-config save from an old copy (pre-production review, F-1) ─

    @Test
    fun `with approvals on, a full-config save computed from an older state is refused when it is requested`() {
        GovernanceHarness(dir).use { h ->
            h.publish(pinsA, emptyList())
            val loaded = h.call("GET", "/api/v1/config/${h.scope}", ALICE)
            val state = loaded.headers.firstValue("X-PinVault-State").get()
            // Another admin's change lands; this tab still holds the old copy.
            h.publish(pinsA, listOf(root))

            val path = "/api/v1/certificate-config?configApiId=${h.scope}"
            val stale = h.call("PUT", path, ALICE, pinsBody(pinsB, emptyList()).toByteArray(), headers = mapOf("X-PinVault-Base-State" to state))
            // Not a card that reads "removes the trust root" for a second admin to wave through.
            assertEquals(409, stale.status, stale.body)
            assertEquals("stale_config", stale.json["error"]!!.jsonPrimitive.content)
            assertFalse("change_requested" in h.actions(), "nothing was put up for approval")

            val now = h.call("GET", "/api/v1/config/${h.scope}", ALICE).headers.firstValue("X-PinVault-State").get()
            val fresh = h.call("PUT", path, ALICE, pinsBody(pinsB, listOf(root)).toByteArray(), headers = mapOf("X-PinVault-Base-State" to now))
            assertEquals(202, fresh.status, fresh.body)
        }
    }

    // ── Host ACL (pre-production review, F-7) ───────────────────────────

    @Test
    fun `a host ACL card lists every name it grants and takes away, and goes stale when the list moved`() {
        GovernanceHarness(dir).use { h ->
            val path = "/api/v1/config-apis/${h.scope}/devices/dev-1/host-acl"
            h.hostAcl.grant(h.scope, "dev-1", "old.example.com", "2026-11-01T00:00:00Z")
            h.hostAcl.grant(h.scope, "dev-1", "kept.example.com", "2026-11-01T00:00:00Z")

            // 40 names: the summary used to show ten of them in a line cut at 300
            // characters, and the handler applied all 40.
            val names = (1..40).map { "host-%02d.example.com".format(it) } + "kept.example.com"
            val body = """{"hostnames":[${names.joinToString(",") { "\"$it\"" }}]}"""
            val pending = h.call("PUT", path, ALICE, body)
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.startsWith("${h.scope}: +40 −1 "), cr.summary)
            val shown = h.detail(cr.id)
            assertEquals((1..40).map { "host-%02d.example.com".format(it) }, shown["added"]!!.jsonArray.map { it.jsonPrimitive.content }, "every granted name, sorted")
            assertEquals(listOf("old.example.com"), shown["removed"]!!.jsonArray.map { it.jsonPrimitive.content })
            assertEquals("dev-1", shown["deviceId"]!!.jsonPrimitive.content)
            assertEquals(listOf("kept.example.com", "old.example.com"), h.hostAcl.listForDevice(h.scope, "dev-1").sorted(), "nothing applied before approval")

            // A name that is not a host name is refused when it is requested, as the handler refuses it.
            val bad = h.call("PUT", path, ALICE, """{"hostnames":["a.example.com","evil host <b>"]}""")
            assertEquals(400, bad.status, bad.body)
            assertEquals(400, h.call("PUT", "/api/v1/config-apis/${h.scope}/default-host-acl", ALICE, """{"hostnames":["*.com"]}""").status)

            // The list moves before the approval: the card compared with a list that is gone.
            h.hostAcl.grant(h.scope, "dev-1", "another.example.com", "2026-11-02T00:00:00Z")
            val stale = h.approve(cr.id)
            assertEquals(409, stale.status, stale.body)
            assertEquals("stale", h.changeRequest(cr.id).status)
            assertFalse("host-01.example.com" in h.hostAcl.listForDevice(h.scope, "dev-1"))

            // Requested again on the current list, it is applied as shown.
            val again = h.call("PUT", path, ALICE, body)
            assertEquals(202, again.status, again.body)
            assertEquals(listOf("another.example.com", "old.example.com"), h.detail(again.changeRequestId)["removed"]!!.jsonArray.map { it.jsonPrimitive.content })
            val applied = h.approve(again.changeRequestId)
            assertEquals("applied", applied.json["status"]!!.jsonPrimitive.content, applied.body)
            assertEquals(names.sorted(), h.hostAcl.listForDevice(h.scope, "dev-1").sorted())
        }
    }

    @Test
    fun `the default host ACL card is the same plan, and the dashboard draws both lists in full`() {
        GovernanceHarness(dir).use { h ->
            h.hostAcl.addDefault(h.scope, "gone.example.com")
            val pending = h.call("PUT", "/api/v1/config-apis/${h.scope}/default-host-acl", ALICE, """{"hostnames":["b.example.com","a.example.com"]}""")
            assertEquals(202, pending.status, pending.body)
            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.startsWith("${h.scope}: +2 −1 default hosts"), cr.summary)
            val shown = h.detail(cr.id)
            assertEquals(listOf("a.example.com", "b.example.com"), shown["added"]!!.jsonArray.map { it.jsonPrimitive.content })
            assertEquals(listOf("gone.example.com"), shown["removed"]!!.jsonArray.map { it.jsonPrimitive.content })
            assertEquals("applied", h.approve(cr.id).json["status"]!!.jsonPrimitive.content)
            assertEquals(listOf("a.example.com", "b.example.com"), h.hostAcl.listDefault(h.scope).sorted())
        }
        // The page: names come from the detail (never the cut summary) and are escaped.
        val js = File("src/main/resources/static/js/app-governance.js").readText()
        val block = js.substringAfter("const aclChange = d.operation === 'host_acl';").substringBefore("const hasDiff")
        assertTrue("aclAdded.forEach(n => out.push(" in block && "aclRemoved.forEach(n => out.push(" in block, "both lists are drawn, every entry")
        assertFalse(Regex("""\$\{n}""").containsMatchIn(block), "a name is never written unescaped")
        assertTrue(Regex("""\$\{esc\(n\)}""").findAll(block).count() == 2, "each name goes through esc()")
    }
}
