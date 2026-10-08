package com.example.pinvault.server

import com.example.pinvault.server.service.EnrollmentIntegrity
import com.example.pinvault.server.service.IntegrityRequestHash
import com.example.pinvault.server.service.IntegrityVerdict
import com.example.pinvault.server.service.IntegrityVerificationMode
import com.example.pinvault.server.service.IntegrityVerifier
import com.example.pinvault.server.service.ServerSettingsCatalog
import com.example.pinvault.server.service.attestation.AppAttestFixtures
import com.example.pinvault.server.service.attestation.AppAttestVerifier
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An iOS enrollment's `integrityToken` is App Attest JSON (PORTING.md §6): a
 * fresh key whose attestation used SHA-256 of the request hash as its client
 * data. The server verifies it itself, with the off / warn / enforce rules of
 * INTEGRITY_VERIFICATION; any other token still goes to the verifier command.
 */
class AppAttestEnrollmentTest {

    private val apple = AppAttestFixtures.Pki()
    private val deviceId = "3f2c9a4e-ios"
    private val commandCalls = mutableListOf<String>()
    private val command = IntegrityVerifier { token, _, _ ->
        commandCalls += token
        if (token == "play-ok") IntegrityVerdict(true, summary = "MEETS_DEVICE_INTEGRITY") else IntegrityVerdict(false, "device_integrity")
    }

    private fun csr(): ByteArray {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return JcaPKCS10CertificationRequestBuilder(X500Name("CN=device"), key.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private)).encoded
    }

    private fun body(csr: ByteArray, token: String?): JsonObject = buildJsonObject {
        put("csr", Base64.getEncoder().encodeToString(csr))
        put("deviceUid", deviceId)
        token?.let { put("integrityToken", it) }
    }

    /** An App Attest token made for [csrBoundTo]'s request hash. */
    private fun appAttestToken(csrBoundTo: ByteArray, pki: AppAttestFixtures.Pki = apple, appId: String = AppAttestFixtures.APP_ID): String {
        val key = AppAttestFixtures.Key()
        val hash = AppAttestVerifier.enrollmentClientDataHash(IntegrityRequestHash.of(deviceId, csrBoundTo))
        return AppAttestFixtures.token(key.keyIdBase64, attestation = AppAttestFixtures.attestation(pki, key, hash, appId = appId))
    }

    private fun integrity(mode: IntegrityVerificationMode, withCommand: Boolean = true) =
        EnrollmentIntegrity(mode, if (withCommand) command else null, apple.verifier())

    @Test
    fun `a genuine App Attest token bound to the request passes, without the command`() {
        val csr = csr()
        val outcome = integrity(IntegrityVerificationMode.ENFORCE, withCommand = false).check(body(csr, appAttestToken(csr)))
        val proceed = assertIs<EnrollmentIntegrity.Outcome.Proceed>(outcome)
        assertTrue(proceed.verdict!!.passed)
        assertTrue(proceed.note.contains("App Attest production"), proceed.note)
        assertTrue(commandCalls.isEmpty(), "App Attest tokens never reach the command")
    }

    @Test
    fun `an App Attest token made for another CSR, app or root is refused under enforce and recorded under warn`() {
        val csr = csr()
        val enforce = integrity(IntegrityVerificationMode.ENFORCE)
        for ((token, reason) in listOf(
            appAttestToken(csr()) to "app_attest_nonce_mismatch",
            appAttestToken(csr, appId = "ZZZZZ99999.com.evil") to "app_attest_app_id_mismatch",
            appAttestToken(csr, pki = AppAttestFixtures.Pki("CN=Not Apple")) to "app_attest_chain_invalid"
        )) {
            val refused = assertIs<EnrollmentIntegrity.Outcome.Refuse>(enforce.check(body(csr, token)))
            assertEquals("integrity_invalid", refused.error)
            assertEquals(reason, refused.reason)
        }
        // An assertion is no enrollment token: a fresh key's attestation is.
        val key = AppAttestFixtures.Key()
        val assertionOnly = AppAttestFixtures.token(key.keyIdBase64, assertion = AppAttestFixtures.assertion(key, ByteArray(32), 1))
        assertEquals("app_attest_attestation_required",
            assertIs<EnrollmentIntegrity.Outcome.Refuse>(enforce.check(body(csr, assertionOnly))).reason)

        val warned = assertIs<EnrollmentIntegrity.Outcome.Proceed>(integrity(IntegrityVerificationMode.WARN).check(body(csr, appAttestToken(csr()))))
        assertFalse(warned.verdict!!.passed)
        assertEquals("integrity not verified: app_attest_nonce_mismatch", warned.note)
        assertNull(assertIs<EnrollmentIntegrity.Outcome.Proceed>(integrity(IntegrityVerificationMode.OFF).check(body(csr, "garbage"))).verdict)
        assertTrue(commandCalls.isEmpty())
    }

    @Test
    fun `other tokens still go to the command, and without App Attest so does an App Attest token`() {
        val csr = csr()
        val outcome = assertIs<EnrollmentIntegrity.Outcome.Proceed>(integrity(IntegrityVerificationMode.ENFORCE).check(body(csr, "play-ok")))
        assertTrue(outcome.verdict!!.passed)
        assertEquals(listOf("play-ok"), commandCalls)
        val token = appAttestToken(csr)
        val noAppAttest = EnrollmentIntegrity(IntegrityVerificationMode.ENFORCE, command)
        assertIs<EnrollmentIntegrity.Outcome.Refuse>(noAppAttest.check(body(csr, token)))
        assertEquals(token, commandCalls.last())
        // No token at all: integrity_required, as before.
        assertEquals("integrity_required", assertIs<EnrollmentIntegrity.Outcome.Refuse>(integrity(IntegrityVerificationMode.ENFORCE).check(body(csr, null))).error)
    }

    @Test
    fun `enforce starts with App Attest alone and warns that Android tokens are not verified`() {
        val warning = assertNotNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.ENFORCE, null, appAttest = true))
        assertTrue(warning.contains("INTEGRITY_VERIFIER_COMMAND") && warning.contains("App Attest"), warning)
        assertNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.ENFORCE, command, appAttest = true))
        assertNull(IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.OFF, null, appAttest = true))
        assertTrue(runCatching { IntegrityVerificationMode.startupCheck(IntegrityVerificationMode.ENFORCE, null) }.isFailure)
        // The dashboard's settings check agrees.
        assertEquals(1, ServerSettingsCatalog.startProblems(mapOf("INTEGRITY_VERIFICATION" to "enforce")).size)
        assertTrue(ServerSettingsCatalog.startProblems(mapOf("INTEGRITY_VERIFICATION" to "enforce", "APP_ATTEST_APP_IDS" to AppAttestFixtures.APP_ID)).isEmpty())
    }
}
