package io.github.umutcansu.pinvault.reactnative

import io.github.umutcansu.pinvault.api.ConfigUpdateStatus
import io.github.umutcansu.pinvault.api.PinVaultConnectionEvent
import io.github.umutcansu.pinvault.model.AttestationResult
import io.github.umutcansu.pinvault.model.AttestationStatus
import io.github.umutcansu.pinvault.model.AttestationTokenResult
import io.github.umutcansu.pinvault.model.ClientCertEnrollmentResult
import io.github.umutcansu.pinvault.model.EnrollmentRefusal
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.KeySecurityLevel
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLPeerUnverifiedException

class ResultMapperTest {

    private val tokens = VaultTokenStore()
    private val mapper = ResultMapper(tokens)

    @Test fun `results keep the native names`() {
        assertEquals(mapOf("type" to "ready", "version" to 4), mapper.init(InitResult.Ready(4)))
        val failed = mapper.init(InitResult.Failed("pin check failed", SSLPeerUnverifiedException("Certificate pinning failure")))
        assertEquals("failed", failed["type"])
        assertEquals(mapOf("name" to "SSLPeerUnverifiedException", "message" to "Certificate pinning failure"), failed["exception"])
        assertEquals(mapOf("type" to "alreadyCurrent"), mapper.update(UpdateResult.AlreadyCurrent))
        assertEquals(mapOf("type" to "updated", "newVersion" to 9), mapper.update(UpdateResult.Updated(9)))
        val enrolled = mapper.enrollment(ClientCertEnrollmentResult.Enrolled(false, KeySecurityLevel.STRONGBOX))
        assertEquals("STRONGBOX", enrolled["keySecurityLevel"])
        val refused = mapper.enrollment(ClientCertEnrollmentResult.Refused(EnrollmentRefusal.INVALID_TOKEN, 401, "invalid_token", "no"))
        assertEquals("INVALID_TOKEN", refused["reason"])
        assertEquals(401, refused["httpStatus"])
        val status = mapper.attestation(AttestationStatus("a", AttestationResult.PASS, arc = "x", tokenExpiresAt = 5L))
        assertEquals("PASS", status["result"])
        assertEquals(5L, status["tokenExpiresAt"])
    }

    @Test fun `a download result never carries the content`() {
        val m = mapper.vaultFile(VaultFileResult.Updated("k", 3, "secret content".toByteArray()))
        assertEquals(mapOf("type" to "updated", "key" to "k", "version" to 3), m)
        assertFalse(m.values.any { it.toString().contains("secret content") })
        val f = mapper.vaultFile(VaultFileResult.Failed("k", "HTTP 401", code = VaultFileResult.Failed.http(401)))
        assertEquals("http_401", f["code"])
    }

    @Test fun `unlocked content comes back only in the asked encoding`() {
        val bytes = byteArrayOf(0, 1, 2, 'a'.code.toByte())
        assertEquals("AAECYQ==", mapper.unlock(VaultFileUnlockResult.Unlocked("k", 1, bytes), "base64")["content"])
        assertEquals("héllo", mapper.unlock(VaultFileUnlockResult.Unlocked("k", 1, "héllo".toByteArray()), "utf8")["content"])
        assertEquals(mapOf("type" to "cancelled", "key" to "k"), mapper.unlock(VaultFileUnlockResult.Cancelled("k"), "utf8"))
        assertEquals("stale", mapper.unlock(VaultFileUnlockResult.Stale("k"), "utf8")["type"])
    }

    @Test fun `tokens never reach JS through a message`() {
        tokens.put("file", "vault-token-abcdef")
        val m = mapper.enrollment(ClientCertEnrollmentResult.Failed("server said vault-token-abcdef is bad", IllegalStateException("echo vault-token-abcdef")))
        assertEquals("server said *** is bad", m["message"])
        @Suppress("UNCHECKED_CAST")
        assertEquals("echo ***", (m["cause"] as Map<String, Any?>)["message"])
        val withTransient = tokens.withTransientSecret("enroll-token-123456") { tokens.redact("refused enroll-token-123456") }
        assertEquals("refused ***", withTransient)
        assertEquals("refused enroll-token-123456", tokens.redact("refused enroll-token-123456"))
    }

    @Test fun `long messages are cut`() {
        val m = mapper.update(UpdateResult.Failed("x".repeat(5000)))
        assertTrue((m["reason"] as String).length <= VaultTokenStore.MAX_MESSAGE + 1)
    }

    @Test fun `the attestation token is a typed result, events carry none`() {
        assertEquals(mapOf("type" to "token", "value" to "t", "expiresAt" to 1L), mapper.attestationToken(AttestationTokenResult.Token("t", 1L)))
        assertEquals(mapOf("type" to "unsupported"), mapper.attestationToken(AttestationTokenResult.Unsupported))
        val e = mapper.event(PinVaultConnectionEvent.ConfigUpdate(ConfigUpdateStatus.UPDATED, 5, "m", "x"))
        assertEquals(mapOf("type" to "configUpdate", "status" to "UPDATED", "newVersion" to 5, "deviceManufacturer" to "m", "deviceModel" to "x", "failureReason" to null), e)
        val c = mapper.event(PinVaultConnectionEvent.Connection("h", false, 2, "m", "x", "pin", listOf("a", "b")))
        assertEquals(listOf("a", "b"), c["expectedPins"])
    }
}
