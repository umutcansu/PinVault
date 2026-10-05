package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.GovernanceHarness.Companion.multipart
import com.example.pinvault.server.service.CertPlan
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.LiveCertificateGate
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.cert.X509Certificate
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A certificate change is worked out when it is REQUESTED — pins, subject,
 * validity, the Config APIs that change — shown to the approver, and applied
 * exactly as shown. It used to be described as "fetch-cert-url (every Config
 * API that pins it)" and fetched, or generated, when it was approved.
 */
class HostCertPlanTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-plan-").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun pinsShown(h: GovernanceHarness, id: Long): List<String> =
        h.detail(id)["certificate"]!!.jsonObject["pins"]!!.jsonArray.map { it.jsonPrimitive.content }

    @Test
    fun `pins fetched from a URL are fixed when requested - the approval never fetches again`() {
        GovernanceHarness(dir).use { h ->
            h.seedHost("api.example.com", h.scope, "prod")
            h.pins.save("unrelated", GovernanceHarness.emptyConfig())
            val caA = TestPki.ca("CN=Honest CA")
            val (keyA, leafA) = TestPki.leaf(caA, "CN=api.example.com")
            val caB = TestPki.ca("CN=Other CA")
            val (keyB, leafB) = TestPki.leaf(caB, "CN=attacker.example")

            TestPki.SwitchableTlsServer().use { site ->
                site.serve(keyA.private, arrayOf(leafA, caA.cert))
                // "hostname" is not read by this route: the host is the one in the path.
                val pending = h.call("POST", "/api/v1/hosts/api.example.com/fetch-cert-url", ALICE,
                    """{"url":"${site.url}","hostname":"decoy.example.net"}""")
                assertEquals(202, pending.status, pending.body)
                val id = pending.changeRequestId
                val fetchedAtRequest = site.handshakes.get()
                assertEquals(1, fetchedAtRequest, "the certificate is read when the change is requested")

                val expected = listOf(TestPki.pin(leafA), TestPki.pin(caA.cert))
                val cr = h.changeRequest(id)
                assertEquals(expected, pinsShown(h, id), "the approver sees the full SPKI pins")
                val certificate = h.detail(id)["certificate"]!!.jsonObject
                assertEquals("fetched", certificate["source"]!!.jsonPrimitive.content)
                assertEquals("CN=api.example.com", certificate["subject"]!!.jsonPrimitive.content)
                assertEquals(leafA.notAfter.toInstant().toString(), certificate["notAfter"]!!.jsonPrimitive.content)
                assertEquals(listOf(h.scope, "prod").sorted(), h.detail(id)["scopes"]!!.jsonArray.map { it.jsonPrimitive.content })
                assertTrue(cr.summary.startsWith("api.example.com:"), cr.summary)
                assertTrue(cr.summary.contains(expected[0].take(12)) && cr.summary.contains("CN=api.example.com"), cr.summary)
                assertTrue(cr.summary.contains("prod"), cr.summary)
                assertFalse(cr.summary.contains("decoy") || cr.detail.contains("decoy"), "a field the handler ignores is not shown: ${cr.summary}")

                // The site serves something else by the time the change is approved.
                site.serve(keyB.private, arrayOf(leafB, caB.cert))
                val approved = h.approve(id)
                assertEquals("applied", approved.json["status"]!!.jsonPrimitive.content, approved.body)
                assertEquals(fetchedAtRequest, site.handshakes.get(), "no second fetch at approval")
                assertEquals(expected, h.pinsOf("api.example.com"), "exactly the pins that were approved")
                assertEquals(expected, h.pinsOf("api.example.com", "prod"), "in every Config API that pins the host")
                assertNull(h.changeRequests.prepared(id), "the stored plan is dropped with the decision")
            }
        }
    }

    @Test
    fun `a host added from a URL is named by the URL and gets the pins shown at request time`() {
        GovernanceHarness(dir).use { h ->
            val ca = TestPki.ca("CN=Site CA")
            val (key, leaf) = TestPki.leaf(ca)
            TestPki.SwitchableTlsServer().use { site ->
                site.serve(key.private, arrayOf(leaf, ca.cert))
                val pending = h.call("POST", "/api/v1/hosts/fetch-from-url", ALICE, """{"url":"${site.url}","hostname":"bank.example.com"}""")
                assertEquals(202, pending.status, pending.body)
                val cr = h.changeRequest(pending.changeRequestId)
                // The handler names the host after the URL; the body's "hostname" is not used and so not shown.
                assertTrue(cr.summary.startsWith("127.0.0.1: add host"), cr.summary)
                assertFalse(cr.summary.contains("bank.example.com") || cr.detail.contains("bank.example.com"), cr.summary)
                assertEquals(listOf(h.scope), h.detail(cr.id)["scopes"]!!.jsonArray.map { it.jsonPrimitive.content })

                val other = TestPki.ca("CN=Swapped CA")
                val (otherKey, otherLeaf) = TestPki.leaf(other)
                site.serve(otherKey.private, arrayOf(otherLeaf, other.cert))
                assertEquals("applied", h.approve(cr.id).json["status"]!!.jsonPrimitive.content)
                assertEquals(listOf(TestPki.pin(leaf), TestPki.pin(ca.cert)), h.pinsOf("127.0.0.1"))
                assertNull(h.pinsOf("bank.example.com"))
                assertEquals(1, site.handshakes.get())
            }
        }
    }

    @Test
    fun `a regenerated certificate is generated once - the keys the approver saw are the keys installed`() {
        GovernanceHarness(dir).use { h ->
            val before = h.seedHost("mock.example.com")
            val pending = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert", ALICE)
            assertEquals(202, pending.status, pending.body)
            val shown = pinsShown(h, pending.changeRequestId)
            assertEquals(2, shown.size)
            assertTrue(shown.none { it in before }, "new keys")
            assertEquals(before, h.pinsOf("mock.example.com"), "nothing changes before approval")
            val keystore = File(h.hosts.get("mock.example.com", h.scope)!!.keystorePath!!)
            assertEquals(before[0], h.certService.extractHashFromKeystore(keystore.absolutePath), "the keystore on disk is still the old one")
            assertTrue(h.changeRequest(pending.changeRequestId).summary.contains("generated certificate"))

            assertEquals("applied", h.approve(pending.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals(shown, h.pinsOf("mock.example.com"))
            assertEquals(shown[0], h.certService.extractHashFromKeystore(keystore.absolutePath), "the served key is the one whose pin was shown")
            assertEquals(shown[1], h.certService.backupPin("mock_example_com"), "and so is the backup key")
        }
    }

    @Test
    fun `rotation, upload and a new host are planned at request time too`() {
        GovernanceHarness(dir).use { h ->
            val before = h.seedHost("mock.example.com")

            val rotate = h.call("POST", "/api/v1/hosts/mock.example.com/rotate-to-backup", ALICE)
            assertEquals(202, rotate.status, rotate.body)
            val rotated = pinsShown(h, rotate.changeRequestId)
            assertEquals(before[1], rotated[0], "the stored backup key takes over")
            assertEquals("rotated", h.detail(rotate.changeRequestId)["certificate"]!!.jsonObject["source"]!!.jsonPrimitive.content)

            // An uploaded keystore: its own key first, a backup generated when requested.
            val source = h.certService.planGenerated("uploaded.example.com")
            val jks = java.util.Base64.getDecoder().decode(source.keystore)
            val (type, body) = multipart(
                mapOf("hostname" to "uploaded.example.com", "password" to CertificateService.KEYSTORE_PASSWORD, "format" to "jks"), jks, "site.jks"
            )
            val upload = h.call("POST", "/api/v1/hosts/upload-cert", ALICE, body, type)
            assertEquals(202, upload.status, upload.body)
            val uploaded = pinsShown(h, upload.changeRequestId)
            assertEquals(source.pins[0], uploaded[0])
            assertNotEquals(source.pins[1], uploaded[1])
            assertTrue(h.changeRequest(upload.changeRequestId).summary.startsWith("uploaded.example.com: add host"))

            val generate = h.call("POST", "/api/v1/management/hosts/prod/generate-cert", ALICE, """{"hostname":"new.example.com"}""")
            assertEquals(202, generate.status, generate.body)
            assertEquals("prod", h.changeRequest(generate.changeRequestId).configApiId)
            val generated = pinsShown(h, generate.changeRequestId)

            assertEquals("applied", h.approve(upload.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals(uploaded, h.pinsOf("uploaded.example.com"))
            assertEquals(uploaded[1], h.certService.backupPin("uploaded_example_com"))
            assertEquals("applied", h.approve(generate.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals(generated, h.pinsOf("new.example.com", "prod"))

            // The rotation was planned against pins that have since changed in its scope: stale, not applied.
            val stale = h.approve(rotate.changeRequestId)
            assertEquals(409, stale.status, stale.body)
            assertEquals(before, h.pinsOf("mock.example.com"))
        }
    }

    @Test
    fun `the Config API's own certificate is planned and applied the same way`() {
        GovernanceHarness(dir).use { h ->
            val pending = h.call("POST", "/api/v1/server-tls-pins/regenerate", ALICE)
            assertEquals(202, pending.status, pending.body)
            val shown = pinsShown(h, pending.changeRequestId)
            assertTrue(h.serverPins.pins.isEmpty())
            assertTrue(h.changeRequest(pending.changeRequestId).summary.contains("bootstrap pins become ${shown[0].take(12)}"))

            val approved = h.approve(pending.changeRequestId)
            assertEquals("applied", approved.json["status"]!!.jsonPrimitive.content, approved.body)
            assertEquals(shown, h.serverPins.pins)
            assertEquals(shown[0], h.certService.extractHashFromKeystore(File(dir, "certs/demo-server.jks").absolutePath))
            assertTrue(h.actions().contains("bootstrap_pins_changed"))

            // Reading them needs no approval.
            assertEquals(shown[0], h.call("GET", "/api/v1/server-tls-pins", ALICE).json["primaryPin"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `a replayed certificate change without a stored plan is refused, never fetched afresh`() {
        GovernanceHarness(dir).use { h ->
            h.seedHost("api.example.com")
            val before = h.pinsOf("api.example.com")
            val pending = h.call("POST", "/api/v1/hosts/api.example.com/regenerate-cert", ALICE)
            // The plan vanishes (a database edit, an older row).
            h.db.connection().use { it.createStatement().executeUpdate("UPDATE change_requests SET prepared = NULL WHERE id = ${pending.changeRequestId}") }
            val approved = h.approve(pending.changeRequestId)
            assertEquals("failed", approved.json["status"]!!.jsonPrimitive.content, approved.body)
            assertEquals(409, approved.json["resultStatus"]!!.jsonPrimitive.content.toInt())
            assertEquals(before, h.pinsOf("api.example.com"))
        }
    }

    @Test
    fun `without approvals the same plan is made and applied in one request`() {
        GovernanceHarness(dir, required = 1).use { h ->
            val added = h.call("POST", "/api/v1/hosts/generate-cert", ALICE, """{"hostname":"direct.example.com"}""")
            assertEquals(200, added.status, added.body)
            val pins = added.json["sha256Pins"]!!.jsonArray.map { it.jsonPrimitive.content }
            assertEquals(pins, h.pinsOf("direct.example.com"))
            assertEquals(pins[1], h.certService.backupPin("direct_example_com"))
            assertEquals(409, h.call("POST", "/api/v1/hosts/generate-cert", ALICE, """{"hostname":"direct.example.com"}""").status)

            val rotated = h.call("POST", "/api/v1/hosts/direct.example.com/rotate-to-backup", ALICE)
            assertEquals(200, rotated.status, rotated.body)
            assertEquals(pins[1], h.pinsOf("direct.example.com")!![0])
            assertEquals(404, h.call("POST", "/api/v1/hosts/ghost.example.com/regenerate-cert", ALICE).status)
        }
    }

    @Test
    fun `a plan carries everything that is applied and nothing secret is shown`() {
        val service = CertificateService(File(dir, "c").also { it.mkdirs() })
        val plan = service.planGenerated("h.example.com")
        val copy = CertPlan.decode(plan.encode())
        assertEquals(plan, copy)
        assertNotNull(copy.keystore)
        val shown = plan.publicJson().toString()
        assertFalse(shown.contains(plan.keystore!!.take(40)), "keystores never reach the approval card or the audit log")
        assertTrue(shown.contains(plan.pins[0]) && shown.contains(plan.pins[1]))
        val installed = service.install("h_example_com", copy)
        assertEquals(plan.pins[0], service.extractHashFromKeystore(installed.keystorePath))
    }

    // ── The live gate on certificate changes and new hosts ──────────────

    private fun gate(mode: LiveCertificateGate.Mode, served: X509Certificate, issuer: X509Certificate) =
        LiveCertificateGate(mode, probe = { _, _, _, _ -> listOf(served, issuer) })

    @Test
    fun `enforce refuses a certificate change the live host fails, an override is audited`() {
        val ca = TestPki.ca("CN=Live CA")
        val (_, liveLeaf) = TestPki.leaf(ca, "CN=mock.example.com")
        GovernanceHarness(dir, required = 1, liveGate = gate(LiveCertificateGate.Mode.ENFORCE, liveLeaf, ca.cert)).use { h ->
            val before = h.seedHost("mock.example.com", h.scope, "prod")

            // The host serves a certificate that is not among the new pins: refused, nothing written.
            val refused = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert", ALICE)
            assertEquals(422, refused.status, refused.body)
            assertTrue(refused.json["overridable"]!!.jsonPrimitive.content.toBoolean())
            assertEquals(TestPki.pin(liveLeaf), refused.json["liveCheck"]!!.jsonObject["checks"]!!.jsonArray.single().jsonObject["livePins"]!!.jsonArray.first().jsonPrimitive.content)
            assertEquals(before, h.pinsOf("mock.example.com"))
            assertEquals(before, h.pinsOf("mock.example.com", "prod"))
            val keystore = h.hosts.get("mock.example.com", h.scope)!!.keystorePath!!
            assertEquals(before[0], h.certService.extractHashFromKeystore(keystore), "the keystore was not replaced either")
            assertEquals("live_check_blocked", h.auditStore.page(1, 0).single().action)

            // A new host: the same gate.
            assertEquals(422, h.call("POST", "/api/v1/hosts/generate-cert", ALICE, """{"hostname":"new.example.com"}""").status)
            assertEquals(422, h.call("POST", "/api/v1/management/hosts/prod/generate-cert", ALICE, """{"hostname":"new.example.com"}""").status)
            assertNull(h.pinsOf("new.example.com"))
            assertNull(h.hosts.get("new.example.com", h.scope))

            // With a reason it goes through, and the reason is in the audit log.
            val overridden = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert?liveCheckOverride=mock%20restarts%20with%20it", ALICE)
            assertEquals(200, overridden.status, overridden.body)
            assertNotEquals(before, h.pinsOf("mock.example.com"))
            assertEquals(h.pinsOf("mock.example.com"), h.pinsOf("mock.example.com", "prod"))
            val entry = h.auditStore.page(20, 0, "live_check_overridden").single()
            assertTrue(entry.summary.contains("mock restarts with it"), entry.summary)
        }
    }

    @Test
    fun `pins fetched from the live host pass the gate, warn only flags`() {
        val ca = TestPki.ca("CN=Live CA")
        val (key, liveLeaf) = TestPki.leaf(ca, "CN=api.example.com")
        GovernanceHarness(dir, required = 1, liveGate = gate(LiveCertificateGate.Mode.ENFORCE, liveLeaf, ca.cert)).use { h ->
            h.seedHost("api.example.com")
            TestPki.SwitchableTlsServer().use { site ->
                site.serve(key.private, arrayOf(liveLeaf, ca.cert))
                val fetched = h.call("POST", "/api/v1/hosts/api.example.com/fetch-cert-url", ALICE, """{"url":"${site.url}"}""")
                assertEquals(200, fetched.status, fetched.body)
                assertEquals(listOf(TestPki.pin(liveLeaf), TestPki.pin(ca.cert)), h.pinsOf("api.example.com"))
            }
        }
        val other = File(dir, "warn").also { it.mkdirs() }
        GovernanceHarness(other, required = 1, liveGate = gate(LiveCertificateGate.Mode.WARN, liveLeaf, ca.cert)).use { h ->
            val before = h.seedHost("mock.example.com")
            val warned = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert", ALICE)
            assertEquals(200, warned.status, warned.body)
            assertEquals("warn", warned.headers.firstValue("X-PinVault-Live-Check").orElse(""))
            assertNotEquals(before, h.pinsOf("mock.example.com"))
            assertTrue(h.actions().contains("live_check_warning"))
        }
    }

    @Test
    fun `with approvals a failing live check is refused when the change is requested`() {
        val ca = TestPki.ca("CN=Live CA")
        val (_, liveLeaf) = TestPki.leaf(ca, "CN=mock.example.com")
        GovernanceHarness(dir, liveGate = gate(LiveCertificateGate.Mode.ENFORCE, liveLeaf, ca.cert)).use { h ->
            val before = h.seedHost("mock.example.com")
            // The dashboard gets the same 422 it knows from the pin editor and can ask for a reason.
            val refused = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert", ALICE)
            assertEquals(422, refused.status, refused.body)
            assertNotNull(refused.json["liveCheck"])
            assertTrue(h.approvals.list("pending").isEmpty(), "nobody is asked to approve what the gate will refuse")

            val pending = h.call("POST", "/api/v1/hosts/mock.example.com/regenerate-cert?liveCheckOverride=planned%20switch", ALICE)
            assertEquals(202, pending.status, pending.body)
            assertFalse(h.detail(pending.changeRequestId)["liveCheck"]!!.jsonObject["passed"]!!.jsonPrimitive.content.toBoolean(), "the approver sees the failed check")
            val shown = pinsShown(h, pending.changeRequestId)
            assertEquals("applied", h.approve(pending.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals(shown, h.pinsOf("mock.example.com"))
            assertNotEquals(before, shown)
            assertTrue(h.actions().contains("live_check_overridden"))
        }
    }
}
