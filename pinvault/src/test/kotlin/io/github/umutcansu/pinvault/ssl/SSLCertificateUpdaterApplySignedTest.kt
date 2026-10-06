package io.github.umutcansu.pinvault.ssl

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.SignedKeySet
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.store.CertificateConfigStore
import io.github.umutcansu.pinvault.store.SigningKeyStore
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * `SSLCertificateUpdater.applySigned`: the config inside an attestation
 * answer takes the fetched config's road — verification, replay, storage —
 * without a fetch, and an unsigned block ignores it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SSLCertificateUpdaterApplySignedTest {

    private val gson = com.google.gson.GsonBuilder().disableHtmlEscaping().create()
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L

    private val pin1 = TestCertUtil.generateSelfSigned(cn = "a").sha256Pin
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "b").sha256Pin
    private val pin3 = TestCertUtil.generateSelfSigned(cn = "c").sha256Pin

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private val keyA = ecKeyPair()
    private val keyB = ecKeyPair()
    private val recovery = ecKeyPair()

    private fun KeyPair.pub(): String = Base64.getEncoder().encodeToString(public.encoded)
    private fun KeyPair.id(): String = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(public.encoded))
    private fun KeyPair.sign(payload: String): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(private)
        s.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(s.sign())
    }

    private lateinit var store: CertificateConfigStore
    private lateinit var keyStore: SigningKeyStore
    private lateinit var provider: HttpClientProvider
    /** Never asked: the config comes from the attestation answer. */
    private val api: CertificateConfigApi = mockk()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val prefs = context.getSharedPreferences("apply_signed_test", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        store = CertificateConfigStore.createForTest(prefs).also { it.clock = { now } }
        val keyPrefs = context.getSharedPreferences("apply_signed_keys", Context.MODE_PRIVATE)
        keyPrefs.edit().clear().commit()
        keyStore = SigningKeyStore.createForTest(keyPrefs)
        provider = HttpClientProvider(DynamicSSLManager())
    }

    private fun trust(keys: List<KeyPair> = listOf(keyA), withRecovery: Boolean = false) = SignatureTrust(
        "default", keys.map { it.pub() }, 1,
        if (withRecovery) listOf(recovery.pub()) else emptyList(), 1,
        if (withRecovery) keyStore else null
    )

    private fun updater(trust: SignatureTrust? = trust(), scope: String? = null) = SSLCertificateUpdater(
        context = mockk(relaxed = true),
        configApi = api,
        configStore = store,
        httpClientProvider = provider,
        maxRetryCount = 1,
        clock = { now },
        verifier = trust?.let { SignedConfigVerifier(it, scope) { now } }
    )

    private fun payload(version: Int, issuedAt: Long, expiresAt: Long = issuedAt + hour, pins: List<String> = listOf(pin1, pin2), scope: String? = null): String {
        val body = linkedMapOf<String, Any>(
            "version" to version,
            "pins" to listOf(mapOf("hostname" to "api.test", "sha256" to pins, "version" to version)),
            "forceUpdate" to false,
            "issuedAt" to issuedAt,
            "expiresAt" to expiresAt
        )
        if (scope != null) body[SignedConfigVerifier.SCOPE_FIELD] = scope
        return gson.toJson(body)
    }

    private fun signed(payload: String, signer: KeyPair = keyA, keySet: SignedKeySet? = null) =
        SignedConfigResponse(payload, signer.sign(payload), signer.id(), null, keySet)

    private fun keySet(version: Int, keys: List<KeyPair>): SignedKeySet {
        val payload = gson.toJson(linkedMapOf("type" to SignatureTrust.KEY_SET_TYPE, "version" to version, "keys" to keys.map { it.pub() }))
        return SignedKeySet(payload, listOf(SignatureEntry(recovery.id(), recovery.sign(payload))))
    }

    @Test
    fun `a valid envelope is applied, stored with its envelope and pins the client — without a fetch`() = runTest {
        val response = signed(payload(4, issuedAt = now))

        assertEquals(UpdateResult.Updated(4), updater().applySigned(response))

        assertEquals(response.payload, store.loadEnvelope()!!.payload)
        assertEquals(listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)
        assertEquals(now, store.getCurrentIssuedAt())
        coVerify(exactly = 0) { api.fetchConfig(any()) }
        coVerify(exactly = 0) { api.fetchScopedConfig(any(), any(), any()) }
    }

    @Test
    fun `the same envelope again is current, an older one with other pins is a replay`() = runTest {
        val u = updater()
        val current = signed(payload(4, issuedAt = now))
        assertEquals(UpdateResult.Updated(4), u.applySigned(current))

        assertEquals(UpdateResult.AlreadyCurrent, u.applySigned(current))

        val replay = u.applySigned(signed(payload(3, issuedAt = now - hour, expiresAt = now + hour, pins = listOf(pin1, pin3)))) as UpdateResult.Failed
        assertTrue(replay.reason, replay.reason.contains("replay", ignoreCase = true))
        assertEquals("the live config is untouched", listOf(pin1, pin2), provider.currentConfig!!.pins.single().sha256)

        assertEquals(UpdateResult.Updated(5), u.applySigned(signed(payload(5, issuedAt = now + 1, pins = listOf(pin1, pin3)))))
        assertEquals(listOf(pin1, pin3), provider.currentConfig!!.pins.single().sha256)
    }

    @Test
    fun `an unsigned block ignores the config`() = runTest {
        val result = updater(trust = null).applySigned(signed(payload(4, issuedAt = now))) as UpdateResult.Failed
        assertEquals("unsigned block: config inside an attestation response is ignored", result.reason)
        assertNull(store.load())
        assertNull(provider.currentConfig)
    }

    @Test
    fun `a forged, tampered, expired or out-of-scope envelope is refused`() = runTest {
        val forged = updater().applySigned(signed(payload(4, issuedAt = now), signer = keyB)) as UpdateResult.Failed
        assertTrue(forged.reason, forged.reason.contains("signature verification"))
        assertTrue(forged.reason, forged.reason.contains("attestation answer"))

        val tampered = signed(payload(4, issuedAt = now)).let { it.copy(payload = it.payload.replace(pin2, pin3)) }
        assertTrue(updater().applySigned(tampered) is UpdateResult.Failed)

        val expired = updater().applySigned(signed(payload(4, issuedAt = now - 2 * hour, expiresAt = now - hour))) as UpdateResult.Failed
        assertTrue(expired.reason, expired.reason.contains("expired"))

        val otherScope = updater(scope = "default-tls").applySigned(signed(payload(4, issuedAt = now, scope = "default-mtls"))) as UpdateResult.Failed
        assertTrue(otherScope.reason, otherScope.reason.contains("default-mtls"))

        assertNull(store.load())
        assertNull(provider.currentConfig)
    }

    @Test
    fun `a signing-key set riding along is applied first`() = runTest {
        val trust = trust(keys = listOf(keyA), withRecovery = true)
        val u = updater(trust = trust)
        val payload = payload(4, issuedAt = now)

        assertEquals(UpdateResult.Updated(4), u.applySigned(signed(payload, signer = keyB, keySet = keySet(1, listOf(keyB)))))

        assertEquals(1, trust.keySetVersion())
        assertNotNull(store.loadEnvelope())
        // Key A is revoked from now on.
        assertTrue(u.applySigned(signed(payload(5, issuedAt = now + 1), signer = keyA)) is UpdateResult.Failed)
    }

    @Test
    fun `applySigned and updateNow serialise on the same lock`() = runTest {
        // A fetch that answers the same config: whichever runs second finds it current.
        val response = signed(payload(4, issuedAt = now))
        val fetching = object : CertificateConfigApi, io.github.umutcansu.pinvault.api.SignedConfigSource {
            override suspend fun fetchSignedConfig(currentVersion: Int) = response
            override suspend fun healthCheck() = true
            override suspend fun fetchConfig(currentVersion: Int) = error("signed")
            override suspend fun downloadHostClientCert(hostname: String) = ByteArray(0)
            override suspend fun downloadVaultFile(endpoint: String) = ByteArray(0)
            override suspend fun enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) =
                io.github.umutcansu.pinvault.model.EnrollmentResult(ByteArray(0), null)
        }
        val u = SSLCertificateUpdater(
            context = mockk(relaxed = true), configApi = fetching, configStore = store, httpClientProvider = provider,
            maxRetryCount = 1, clock = { now }, verifier = SignedConfigVerifier(trust(), null) { now }
        )
        assertEquals(UpdateResult.Updated(4), u.applySigned(response))
        assertEquals(UpdateResult.AlreadyCurrent, u.updateNow())
        assertEquals(UpdateResult.AlreadyCurrent, u.applySigned(response))
    }
}
