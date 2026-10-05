package com.example.pinvault.server

import com.example.pinvault.server.GovernanceHarness.Companion.ALICE
import com.example.pinvault.server.GovernanceHarness.Companion.BOB
import com.example.pinvault.server.GovernanceHarness.Companion.SHARED
import com.example.pinvault.server.GovernanceHarness.Companion.multipart
import com.example.pinvault.server.service.ApprovalService
import com.example.pinvault.server.service.PinAffectingRoutes
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.MessageDigest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two-person approval beyond pins: who the mTLS listeners trust, who may
 * enroll, and what the vault hands to devices. One admin used to be able to
 * do all of it alone while `PIN_CHANGE_APPROVALS=2` was on.
 */
class GatedTrustAndVaultTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("pinvault-gated-").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun sha256Hex(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    // ── What is gated, and what is not ──────────────────────────────────

    @Test
    fun `trust material, enrollment and vault writes are gated under their own operations`() {
        val expected = mapOf(
            (HttpMethod.Post to "/api/v1/client-certs/upload") to "client_cert_upload",
            (HttpMethod.Post to "/api/v1/client-certs/generate") to "client_cert_generate",
            (HttpMethod.Post to "/api/v1/enrollment-policies") to "enrollment_policy_create",
            (HttpMethod.Put to "/api/v1/enrollment-open") to "enrollment_open",
            (HttpMethod.Post to "/api/v1/enrollment-tokens/generate") to "enrollment_token",
            (HttpMethod.Put to "/api/v1/config-apis/prod/vault/model.bin") to "vault_upload",
            (HttpMethod.Delete to "/api/v1/config-apis/prod/vault/model.bin") to "vault_delete",
            (HttpMethod.Put to "/api/v1/config-apis/prod/vault/model.bin/policy") to "vault_policy",
            (HttpMethod.Post to "/api/v1/config-apis/prod/vault/model.bin/tokens") to "vault_token_issue",
            (HttpMethod.Delete to "/api/v1/config-apis/prod/vault/tokens/7") to "vault_token_revoke",
            (HttpMethod.Delete to "/api/v1/config-apis/prod/vault/devices/dev-1/public-key") to "device_key_reset",
            (HttpMethod.Put to "/api/v1/config-apis/prod/vault-enabled") to "vault_enabled"
        )
        for ((request, op) in expected) assertEquals(op, PinAffectingRoutes.match(request.first, request.second), request.toString())
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/config-apis/prod/vault/model.bin", "configApiId=other"))
        assertEquals("prod", PinAffectingRoutes.scopeOf("/api/v1/config-apis/prod/vault-enabled", ""))

        // Emergencies and a second person's own decisions take effect at once.
        for ((method, path) in listOf(
            HttpMethod.Delete to "/api/v1/client-certs/dev-1",                   // revocation
            HttpMethod.Post to "/api/v1/client-certs/dev-1/forget",
            HttpMethod.Post to "/api/v1/enrollment-policies/p1/stop",            // stopping a leaked code
            HttpMethod.Delete to "/api/v1/enrollment-open",                      // closing code-less applications
            HttpMethod.Post to "/api/v1/enrollment-requests/r1/approve",         // itself the second person
            HttpMethod.Post to "/api/v1/enrollment-requests/r1/reject",
            HttpMethod.Get to "/api/v1/config-apis/prod/vault",
            HttpMethod.Get to "/api/v1/config-apis/prod/vault/model.bin/tokens"
        )) assertNull(PinAffectingRoutes.match(method, path), "$method $path")
        assertTrue(PinAffectingRoutes.operations.containsAll(PinAffectingRoutes.requesterRun))
    }

    @Test
    fun `APPROVAL_EXEMPT_OPERATIONS names known operations only`() {
        assertEquals(emptySet(), ApprovalService.exemptFromEnv(emptyMap()))
        assertEquals(
            setOf("enrollment_token", "vault_token_revoke"),
            ApprovalService.exemptFromEnv(mapOf("APPROVAL_EXEMPT_OPERATIONS" to " enrollment_token, vault_token_revoke ,"))
        )
        // A typo must not leave the operator believing something is exempt — or gated.
        val error = assertFailsWith<IllegalArgumentException> {
            ApprovalService.exemptFromEnv(mapOf("APPROVAL_EXEMPT_OPERATIONS" to "enrollment_tokens"))
        }
        assertTrue(error.message!!.contains("enrollment_tokens"), error.message)
    }

    @Test
    fun `an exempt operation runs at once, everything else still waits`() {
        GovernanceHarness(dir, exempt = setOf("enrollment_token")).use { h ->
            val token = h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, """{"clientId":"dev-1"}""")
            assertEquals(200, token.status, token.body)
            assertNotNull(token.json["token"])
            // Even the shared key may use an operation that is not gated.
            assertEquals(200, h.call("POST", "/api/v1/enrollment-tokens/generate", SHARED, """{"clientId":"dev-2"}""").status)

            assertEquals(202, h.call("PUT", "/api/v1/enrollment-open", ALICE, """{"enabled":true}""").status)
            val me = h.call("GET", "/api/v1/admin/me", ALICE).json
            assertEquals(listOf("enrollment_token"), me["approvalExemptOperations"]!!.jsonArray.map { it.jsonPrimitive.content })
        }
    }

    // ── Client certificates ─────────────────────────────────────────────

    private fun uploadBody(cert: java.security.cert.X509Certificate, clientId: String?) =
        multipart(clientId?.let { mapOf("clientId" to it) } ?: emptyMap(), TestPki.pem(cert), "client.pem")

    @Test
    fun `a CA, a certificate signer or a non-client leaf is never trusted as a client certificate`() {
        GovernanceHarness(dir, required = 1).use { h ->
            val ca = TestPki.ca("CN=Rogue CA")
            val key = TestPki.keys()
            val self = { extra: (String, java.security.PublicKey, String, java.security.PrivateKey) -> java.security.cert.X509Certificate ->
                extra("CN=client-1", key.public, "CN=client-1", key.private)
            }
            val refused = mapOf(
                "a CA" to ca.cert,
                "keyCertSign without the CA flag" to self { s, k, i, p -> TestPki.build(s, k, i, p, ca = false, keyCertSign = true) },
                "a server-only leaf" to self { s, k, i, p -> TestPki.build(s, k, i, p, eku = listOf("1.3.6.1.5.5.7.3.1")) },
                "an expired leaf" to self { s, k, i, p -> TestPki.build(s, k, i, p, notAfter = java.util.Date(System.currentTimeMillis() - 60_000)) }
            )
            for ((what, cert) in refused) {
                val (type, body) = uploadBody(cert, "client-1")
                val answer = h.call("POST", "/api/v1/client-certs/upload", ALICE, body, type)
                assertEquals(400, answer.status, "$what: ${answer.body}")
                assertEquals("invalid_client_certificate", answer.json["error"]!!.jsonPrimitive.content, what)
            }
            assertNull(h.certService.getTrustStore()?.getCertificate("client-1"), "nothing reached the truststore")
            assertTrue(h.clientCerts.getAll().isEmpty())
            assertTrue(h.trustRefreshes.isEmpty(), "no listener was restarted for a refused upload")

            // An id that is not an identifier (it becomes a truststore alias and a row the dashboard prints).
            val leaf = self { s, k, i, p -> TestPki.build(s, k, i, p, eku = listOf("1.3.6.1.5.5.7.3.2")) }
            for (id in listOf("<img src=x>", "a b", "x".repeat(65), "../ca")) {
                val (type, body) = uploadBody(leaf, id)
                val answer = h.call("POST", "/api/v1/client-certs/upload", ALICE, body, type)
                assertEquals(400, answer.status, "$id: ${answer.body}")
                assertEquals("invalid_client_id", answer.json["error"]!!.jsonPrimitive.content)
            }

            // An end-entity client certificate that says clientAuth is accepted.
            val (type, body) = uploadBody(leaf, "client-1")
            val accepted = h.call("POST", "/api/v1/client-certs/upload", ALICE, body, type)
            assertEquals(200, accepted.status, accepted.body)
            assertNotNull(h.certService.getTrustStore()!!.getCertificate("client-1"))
            assertEquals(listOf("client cert uploaded: client-1"), h.trustRefreshes)
            val entry = h.auditStore.page(10, 0, "client_cert_uploaded").single()
            assertEquals("client-1", entry.target)
            assertTrue(entry.summary.contains("CN=client-1"), entry.summary)

            // Without an extended key usage it does not say what it is for: refused.
            val plain = self { s, k, i, p -> TestPki.build(s, k, i, p, basicConstraints = false) }
            val (type2, body2) = uploadBody(plain, "client-2")
            val noEku = h.call("POST", "/api/v1/client-certs/upload", ALICE, body2, type2)
            assertEquals(400, noEku.status, noEku.body)
            assertEquals("invalid_client_certificate", noEku.json["error"]!!.jsonPrimitive.content)
            // A v1 certificate cannot say it is not a CA, and JSSE lets such an anchor sign: refused.
            val v1 = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder(
                    org.bouncycastle.asn1.x500.X500Name("CN=client-3"), java.math.BigInteger.ONE,
                    java.util.Date(System.currentTimeMillis() - 60_000), java.util.Date(System.currentTimeMillis() + 86_400_000),
                    org.bouncycastle.asn1.x500.X500Name("CN=client-3"), key.public
                ).build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(key.private))
            )
            val (type3, body3) = uploadBody(v1, "client-3")
            val refusedV1 = h.call("POST", "/api/v1/client-certs/upload", ALICE, body3, type3)
            assertEquals(400, refusedV1.status, refusedV1.body)
            assertTrue(refusedV1.body.contains("version 1"), refusedV1.body)
            assertNull(h.certService.getTrustStore()!!.getCertificate("client-2"))
            assertNull(h.certService.getTrustStore()!!.getCertificate("client-3"))
        }
    }

    @Test
    fun `generate and upload never bring a revoked client id back`() {
        GovernanceHarness(dir, required = 1).use { h ->
            assertEquals(200, h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"dev-1"}""").status)
            h.clientCerts.revoke("dev-1")
            h.certService.removeFromTrustStore("dev-1")
            val refreshes = h.trustRefreshes.size

            val generated = h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"dev-1"}""")
            assertEquals(409, generated.status, generated.body)
            assertEquals("revoked", generated.json["error"]!!.jsonPrimitive.content)

            val key = TestPki.keys()
            val (type, body) = uploadBody(TestPki.build("CN=dev-1", key.public, "CN=dev-1", key.private), "dev-1")
            assertEquals(409, h.call("POST", "/api/v1/client-certs/upload", ALICE, body, type).status)

            assertTrue(h.clientCerts.get("dev-1")!!.revoked, "INSERT OR REPLACE … revoked = 0 used to un-revoke it")
            assertNull(h.certService.getTrustStore()?.getCertificate("dev-1"), "and put its new certificate into the truststore")
            assertEquals(refreshes, h.trustRefreshes.size)

            // An id of the wrong shape is refused before anything is generated.
            val bad = h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"x, O=Evil"}""")
            assertEquals(400, bad.status, bad.body)
            assertEquals("invalid_client_id", bad.json["error"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `a certificate upload waits for a second admin, who is shown what will be trusted`() {
        GovernanceHarness(dir).use { h ->
            val key = TestPki.keys()
            val cert = TestPki.build("CN=partner-gateway", key.public, "CN=partner-gateway", key.private, eku = listOf("1.3.6.1.5.5.7.3.2"))
            val (type, body) = uploadBody(cert, "partner")
            val pending = h.call("POST", "/api/v1/client-certs/upload", ALICE, body, type)
            assertEquals(202, pending.status, pending.body)
            assertNull(h.certService.getTrustStore()?.getCertificate("partner"), "nothing is trusted before approval")

            val cr = h.changeRequest(pending.changeRequestId)
            assertTrue(cr.summary.contains("CN=partner-gateway") && cr.summary.contains("partner"), cr.summary)
            val shown = h.detail(cr.id)
            assertEquals("client_cert_upload", shown["operation"]!!.jsonPrimitive.content)
            assertEquals(sha256Hex(cert.encoded), shown["clientCertificate"]!!.jsonObject["fingerprint"]!!.jsonPrimitive.content)

            // A CA is refused when it is requested: nobody is asked to approve it.
            val (caType, caBody) = uploadBody(TestPki.ca("CN=Rogue CA").cert, "rogue")
            val refused = h.call("POST", "/api/v1/client-certs/upload", ALICE, caBody, caType)
            assertEquals(400, refused.status, refused.body)
            assertTrue(refused.body.contains("CA certificate"), refused.body)

            val approved = h.approve(cr.id)
            assertEquals("applied", approved.json["status"]!!.jsonPrimitive.content, approved.body)
            assertNotNull(h.certService.getTrustStore()!!.getCertificate("partner"))
            assertEquals("alice (approved by bob)", h.auditStore.page(10, 0, "client_cert_uploaded").single().actor)
        }
    }

    // ── Answers that carry a secret: run by the requester after approval ─

    @Test
    fun `an enrollment token is minted for its requester only after another admin approved`() {
        GovernanceHarness(dir).use { h ->
            val request = """{"clientId":"dev-42"}"""
            val pending = h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, request)
            assertEquals(202, pending.status, pending.body)
            assertTrue(pending.json["runAfterApproval"]!!.jsonPrimitive.content.toBoolean())
            assertTrue(h.enrollmentTokens.getAll().isEmpty(), "no token exists before approval")
            val id = pending.changeRequestId

            // The shared key can neither ask nor approve; nobody approves their own.
            assertEquals(409, h.call("POST", "/api/v1/enrollment-tokens/generate", SHARED, request).status)
            assertEquals(409, h.approve(id, ALICE).status)

            val approved = h.approve(id)
            assertEquals(200, approved.status, approved.body)
            assertEquals("approved", approved.json["status"]!!.jsonPrimitive.content)
            assertTrue(h.enrollmentTokens.getAll().isEmpty(), "approving mints nothing: the approver never sees a token")
            assertFalse(approved.body.contains("\"token\""), approved.body)

            // Another admin sending the same request does not ride on alice's approval…
            val bob = h.call("POST", "/api/v1/enrollment-tokens/generate", BOB, request)
            assertEquals(202, bob.status, bob.body)
            // …and a different request of alice's is a new request.
            assertEquals(202, h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, """{"clientId":"dev-43"}""").status)

            val run = h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, request)
            assertEquals(200, run.status, run.body)
            val token = run.json["token"]!!.jsonPrimitive.content
            assertEquals("dev-42", h.enrollmentTokens.validate(token))
            assertEquals("no-store", run.headers.firstValue("Cache-Control").orElse(""))

            val done = h.changeRequest(id)
            assertEquals("applied", done.status)
            assertEquals(200, done.resultStatus)
            assertNull(done.resultBody, "the token is not kept with the change request")
            assertFalse(h.auditStore.page(200, 0).any { token in it.summary || token in it.detail }, "nor in the audit log")
            val created = h.auditStore.page(10, 0, "enrollment_token_created").single()
            assertEquals("alice (approved by bob)", created.actor)
            assertTrue(h.actions().contains("change_applied"))

            // It ran once: the same request again waits for a new approval.
            val again = h.call("POST", "/api/v1/enrollment-tokens/generate", ALICE, request)
            assertEquals(202, again.status, again.body)
            assertEquals(1, h.enrollmentTokens.getAll().size)
        }
    }

    @Test
    fun `an approved request that was not run can be withdrawn, and a generated P12 reaches its requester`() {
        GovernanceHarness(dir).use { h ->
            val first = h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"kiosk-1"}""")
            assertEquals(202, first.status, first.body)
            assertEquals("approved", h.approve(first.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertEquals(200, h.call("POST", "/api/v1/change-requests/${first.changeRequestId}/reject", BOB, """{"reason":"wrong kiosk"}""").status)
            assertEquals(202, h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"kiosk-1"}""").status, "the approval is gone")
            assertNull(h.clientCerts.get("kiosk-1"))

            val second = h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"kiosk-2"}""")
            h.approve(second.changeRequestId)
            val p12 = h.call("POST", "/api/v1/client-certs/generate", ALICE, """{"clientId":"kiosk-2"}""")
            assertEquals(200, p12.status, p12.body)
            // A real PKCS#12, byte for byte (a replayed answer would have gone through a String).
            assertEquals(0x30, p12.bytes[0].toInt())
            assertNotNull(h.clientCerts.get("kiosk-2"))
            assertEquals("alice (approved by bob)", h.auditStore.page(10, 0, "client_cert_generated").single().actor)
        }
    }

    @Test
    fun `enrollment codes and the code-less switch wait, closing the switch does not`() {
        GovernanceHarness(dir).use { h ->
            val body = """{"name":"field-2026","maxDevices":50,"validDays":30,"requireApproval":false}"""
            val pending = h.call("POST", "/api/v1/enrollment-policies", ALICE, body)
            assertEquals(202, pending.status, pending.body)
            assertTrue(h.policies.getAll().isEmpty())
            val summary = h.changeRequest(pending.changeRequestId).summary
            assertTrue(summary.contains("field-2026") && summary.contains("50") && summary.contains("WITHOUT approval"), summary)
            h.approve(pending.changeRequestId)
            val created = h.call("POST", "/api/v1/enrollment-policies", ALICE, body)
            assertEquals(200, created.status, created.body)
            assertEquals(25, created.json["code"]!!.jsonPrimitive.content.replace("-", "").length)

            val open = h.call("PUT", "/api/v1/enrollment-open", ALICE, """{"enabled":true}""")
            assertEquals(202, open.status, open.body)
            assertNull(h.policies.openPolicy(), "still closed")
            assertTrue(h.changeRequest(open.changeRequestId).summary.contains("ON"))
            assertEquals("applied", h.approve(open.changeRequestId).json["status"]!!.jsonPrimitive.content)
            assertTrue(h.policies.openPolicy()!!.acceptsNewDevices())

            // Closing it is an emergency action: one admin, at once.
            val closed = h.call("DELETE", "/api/v1/enrollment-open", ALICE)
            assertEquals(200, closed.status, closed.body)
            assertFalse(closed.json["enabled"]!!.jsonPrimitive.content.toBoolean())
            assertFalse(h.policies.openPolicy()?.acceptsNewDevices() == true)
        }
    }

    // ── Vault ───────────────────────────────────────────────────────────

    @Test
    fun `replacing a vault file, opening it to everyone and minting a token each need a second admin`() {
        GovernanceHarness(dir).use { h ->
            h.vaultFiles.put(h.scope, "model.bin", "signed-v1".toByteArray(), "token_mtls", "at_rest")
            val base = "/api/v1/config-apis/${h.scope}/vault"
            val replacement = "malicious-v2".toByteArray()

            // Replace the content.
            val upload = h.call("PUT", "$base/model.bin", ALICE, replacement, "application/octet-stream")
            assertEquals(202, upload.status, upload.body)
            assertEquals("signed-v1", h.vaultFiles.get(h.scope, "model.bin")!!.content.decodeToString())
            val uploadRequest = h.changeRequest(upload.changeRequestId)
            assertEquals(h.scope, uploadRequest.configApiId)
            assertTrue(uploadRequest.summary.contains("replace vault file model.bin (v1)"), uploadRequest.summary)
            val shown = h.detail(upload.changeRequestId)["vaultFile"]!!.jsonObject
            assertEquals(sha256Hex(replacement), shown["sha256"]!!.jsonPrimitive.content, "the approver can compare the content hash")
            assertEquals(replacement.size.toString(), shown["size"]!!.jsonPrimitive.content)
            assertEquals("token_mtls", shown["accessPolicy"]!!.jsonPrimitive.content, "an upload without ?policy= keeps the file's own")

            // Open it to everyone.
            val policy = h.call("PUT", "$base/model.bin/policy", ALICE, """{"access_policy":"public","encryption":"plain"}""")
            assertEquals(202, policy.status, policy.body)
            assertEquals("token_mtls", h.vaultFiles.meta(h.scope, "model.bin")!!.accessPolicy)
            val policySummary = h.changeRequest(policy.changeRequestId).summary
            assertTrue(policySummary.contains("token_mtls → public") && policySummary.contains("anyone"), policySummary)

            // Mint a token, reset a device key, delete, switch the vault off.
            val token = h.call("POST", "$base/model.bin/tokens", ALICE, """{"deviceId":"dev-1"}""")
            assertEquals(202, token.status, token.body)
            assertTrue(h.vaultTokens.listForFile(h.scope, "model.bin").isEmpty())
            assertEquals(202, h.call("DELETE", "$base/devices/dev-1/public-key?purpose=user_auth", ALICE).status)
            assertEquals(202, h.call("DELETE", "$base/model.bin", ALICE).status)
            h.registry.ensureRegistered(h.scope, 8443, "tls")
            assertEquals(202, h.call("PUT", "/api/v1/config-apis/${h.scope}/vault-enabled", ALICE, """{"enabled":false}""").status)
            assertNotNull(h.vaultFiles.meta(h.scope, "model.bin"))
            assertTrue(h.registry.isVaultEnabled(h.scope))

            // Reads are not held.
            assertEquals(200, h.call("GET", base, ALICE).status)

            // Approval applies the upload exactly as it was requested…
            assertEquals("applied", h.approve(upload.changeRequestId).json["status"]!!.jsonPrimitive.content)
            val stored = h.vaultFiles.get(h.scope, "model.bin")!!
            assertEquals("malicious-v2", stored.content.decodeToString())
            assertEquals(2, stored.version)
            val audited = h.auditStore.page(10, 0, "vault_file_uploaded").single()
            assertEquals("alice (approved by bob)", audited.actor)
            assertTrue(audited.detail.contains(sha256Hex(replacement)), audited.detail)

            // …and the token goes to its requester alone, once.
            assertEquals("approved", h.approve(token.changeRequestId).json["status"]!!.jsonPrimitive.content)
            val minted = h.call("POST", "$base/model.bin/tokens", ALICE, """{"deviceId":"dev-1"}""")
            assertEquals(200, minted.status, minted.body)
            assertNotNull(minted.json["token"])
            val tokenId = h.vaultTokens.listForFile(h.scope, "model.bin").single().id

            val revoke = h.call("DELETE", "$base/tokens/$tokenId", ALICE)
            assertEquals(202, revoke.status, revoke.body)
            assertTrue(h.changeRequest(revoke.changeRequestId).summary.contains("device dev-1, file model.bin"))
            assertFalse(h.vaultTokens.listForFile(h.scope, "model.bin").single().revoked)
        }
    }

    @Test
    fun `a gated upload is capped while it is read, and a malformed one is refused, never stored blind`() {
        GovernanceHarness(dir, vaultMax = 1_000, adminBodyMax = 2_000).use { h ->
            val base = "/api/v1/config-apis/${h.scope}/vault"
            assertEquals(413, h.call("PUT", "$base/big", ALICE, ByteArray(1_001), "application/octet-stream").status)
            assertEquals(202, h.call("PUT", "$base/big", ALICE, ByteArray(1_000), "application/octet-stream").status)
            assertEquals(413, h.call("POST", "/api/v1/client-certs/upload", ALICE, ByteArray(2_001), "multipart/form-data; boundary=x").status)

            val unknownPolicy = h.call("PUT", "$base/model?policy=everyone", ALICE, "x".toByteArray(), "application/octet-stream")
            assertEquals(400, unknownPolicy.status, unknownPolicy.body)
            val noDevice = h.call("POST", "$base/model/tokens", ALICE, "{}")
            assertEquals(400, noDevice.status, noDevice.body)
            assertEquals(1, h.approvals.list("pending").size, "only the well-formed upload is waiting")
        }
    }

    @Test
    fun `revoking a vault token of another Config API is refused`() {
        GovernanceHarness(dir, required = 1).use { h ->
            h.vaultFiles.put("other", "f", "x".toByteArray(), "token", "plain")
            val generated = com.example.pinvault.server.service.VaultAccessTokenService(h.vaultTokens).generate("other", "f", "dev-1")
            assertEquals(404, h.call("DELETE", "/api/v1/config-apis/${h.scope}/vault/tokens/${generated.id}", ALICE).status)
            assertFalse(h.vaultTokens.info(generated.id)!!.revoked)
            assertEquals(200, h.call("DELETE", "/api/v1/config-apis/other/vault/tokens/${generated.id}", ALICE).status)
            assertEquals("vault_token_revoked", h.auditStore.page(1, 0, "vault_token_revoked").single().action)
        }
    }
}
