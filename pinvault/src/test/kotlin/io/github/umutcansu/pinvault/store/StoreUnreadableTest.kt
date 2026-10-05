package io.github.umutcansu.pinvault.store

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.google.gson.Gson
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InitResult
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedKeySet
import io.github.umutcansu.pinvault.model.StoreUnreadableException
import io.github.umutcansu.pinvault.model.UpdateResult
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import io.github.umutcansu.pinvault.ssl.HttpClientProvider
import io.github.umutcansu.pinvault.ssl.SSLCertificateUpdater
import io.github.umutcansu.pinvault.util.SoftwarePrefsCipher
import io.github.umutcansu.pinvault.util.TestCertUtil
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * A Keystore that fails is not an empty store. The pin config store and the
 * signing-key store report it ([StoreUnreadableException]); the updater and
 * the signature check fail closed for that attempt and work again once the
 * Keystore does.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class StoreUnreadableTest {

    /** A cipher whose `open` can be made to fail the way a broken Keystore does. */
    private class FlakyCipher : PrefsCipher {
        private val real = SoftwarePrefsCipher()
        var broken = false
        override fun seal(plaintext: ByteArray, aad: ByteArray) = real.seal(plaintext, aad)
        override fun open(sealed: ByteArray, aad: ByteArray): ByteArray {
            if (broken) throw ProviderException("Keystore operation failed")
            return real.open(sealed, aad)
        }
        override fun mac(input: ByteArray) = real.mac(input)
    }

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val cipher = FlakyCipher()
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L
    private val pin1 = TestCertUtil.generateSelfSigned(cn = "a").sha256Pin
    private val pin2 = TestCertUtil.generateSelfSigned(cn = "b").sha256Pin

    private fun prefs(namespace: String, strict: Boolean) = SecurePreferences(
        context.getSharedPreferences("unreadable_test", Context.MODE_PRIVATE), "unreadable_test", namespace, cipher, strict
    )

    @Before
    fun setUp() {
        context.getSharedPreferences("unreadable_test", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun config(version: Int, issuedAt: Long, expiresAt: Long) = CertificateConfig(
        version = version,
        pins = listOf(HostPin("api.test", listOf(pin1, pin2), version = version)),
        issuedAt = issuedAt,
        expiresAt = expiresAt
    )

    // ── SecurePreferences ───────────────────────────────────────────────

    @Test
    fun `a strict store throws on a Keystore failure and keeps the entry`() {
        val strict = prefs("ns", strict = true)
        strict.edit().putLong("watermark", 42L).putString("text", "kept").commit()

        cipher.broken = true
        for (read in listOf<() -> Any?>({ strict.getLong("watermark", 0L) }, { strict.getString("text", null) }, { strict.all })) {
            try {
                read()
                fail("an unreadable entry must not read as absent")
            } catch (e: StoreUnreadableException) {
                assertTrue(e.cause is ProviderException)
            }
        }

        cipher.broken = false
        assertEquals(42L, strict.getLong("watermark", 0L))
        assertEquals("kept", strict.getString("text", null))
    }

    @Test
    fun `a store that is not strict reads the default, as before`() {
        val lenient = prefs("ns", strict = false)
        lenient.edit().putLong("value", 42L).commit()

        cipher.broken = true
        assertEquals(0L, lenient.getLong("value", 0L))
        cipher.broken = false
        assertEquals(42L, lenient.getLong("value", 0L))
    }

    @Test
    fun `an absent entry is still absent, in a strict store too`() {
        val strict = prefs("ns", strict = true)
        cipher.broken = true
        assertEquals(7L, strict.getLong("never-written", 7L))
        assertNull(strict.getString("never-written", null))
    }

    // ── CertificateConfigStore ──────────────────────────────────────────

    @Test
    fun `the replay watermark and expiresAt are unreadable, not zero`() {
        val store = CertificateConfigStore.createForTest(prefs("config", strict = true))
        store.save(config(4, issuedAt = now, expiresAt = now + hour), StoredEnvelope("{}", listOf(SignatureEntry(null, "c2ln"))))
        store.setHighestSeenTime(now)

        cipher.broken = true
        for (read in listOf<() -> Any?>(
            { store.getCurrentIssuedAt() }, { store.getVersionWatermarks() }, { store.load() },
            { store.loadEnvelope() }, { store.getCurrentVersion() }, { store.highestSeenTime() }
        )) {
            try {
                read()
                fail("must not read as 'nothing stored'")
            } catch (e: StoreUnreadableException) {
                // expected
            }
        }

        cipher.broken = false
        assertEquals(now, store.getCurrentIssuedAt())
        assertEquals(now + hour, store.load()!!.expiresAt)
    }

    // ── The updater fails closed for the attempt ────────────────────────

    @Test
    fun `an update with an unreadable store applies nothing and works again afterwards`() = runTest {
        val store = CertificateConfigStore.createForTest(prefs("config", strict = true)).also { it.clock = { now } }
        val api = mockk<CertificateConfigApi>()
        val provider = HttpClientProvider(DynamicSSLManager())
        val updater = SSLCertificateUpdater(
            context = mockk(relaxed = true), configApi = api, configStore = store,
            httpClientProvider = provider, maxRetryCount = 1, clock = { now }
        )
        coEvery { api.fetchConfig(any()) } returns config(4, issuedAt = now - hour, expiresAt = now + hour)
        assertEquals(UpdateResult.Updated(4), updater.updateNow())

        // An OLDER signed config arrives while the watermark cannot be read.
        // With the watermark read as 0 it would have been accepted.
        cipher.broken = true
        coEvery { api.fetchConfig(any()) } returns config(3, issuedAt = now - 2 * hour, expiresAt = now + hour)
        val failed = updater.updateNow() as UpdateResult.Failed
        assertTrue(failed.exception is StoreUnreadableException)
        assertEquals(4, provider.currentConfig!!.computedVersion())

        cipher.broken = false
        val replay = updater.updateNow() as UpdateResult.Failed
        assertTrue(replay.reason, replay.reason.contains("replay", ignoreCase = true))
        assertEquals(4, store.load()!!.computedVersion())
    }

    @Test
    fun `init with an unreadable store fails and applies no config`() = runTest {
        val store = CertificateConfigStore.createForTest(prefs("config", strict = true)).also { it.clock = { now } }
        store.save(config(4, issuedAt = now - hour, expiresAt = now + hour))
        val api = mockk<CertificateConfigApi>()
        coEvery { api.fetchConfig(any()) } returns config(5, issuedAt = now, expiresAt = now + hour)
        coEvery { api.healthCheck() } returns true
        val provider = HttpClientProvider(DynamicSSLManager())
        fun updater() = SSLCertificateUpdater(
            context = mockk(relaxed = true), configApi = api, configStore = store,
            httpClientProvider = provider, maxRetryCount = 1, clock = { now }
        )

        cipher.broken = true
        val result = updater().initializeAndUpdate() as InitResult.Failed
        assertTrue(result.exception is StoreUnreadableException)
        assertNull("nothing applied: pinned clients keep refusing", provider.currentConfig)

        cipher.broken = false
        assertEquals(InitResult.Ready(5), updater().initializeAndUpdate())
    }

    // ── SignatureTrust: no fallback to the compiled-in keys ─────────────

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun KeyPair.pub(): String = Base64.getEncoder().encodeToString(public.encoded)
    private fun KeyPair.id(): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(public.encoded))
    private fun KeyPair.sign(payload: String): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(private)
        s.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(s.sign())
    }

    @Test
    fun `a revoked signing key is not trusted again while the key set is unreadable`() {
        val revoked = ecKeyPair()
        val current = ecKeyPair()
        val recovery = ecKeyPair()
        val keyStore = SigningKeyStore.createForTest(prefs("keys", strict = true))
        fun trust() = SignatureTrust("default", listOf(revoked.pub(), current.pub()), 1, listOf(recovery.pub()), 1, keyStore)

        // Set v2 leaves the stolen key out.
        val setPayload = Gson().toJson(linkedMapOf("type" to SignatureTrust.KEY_SET_TYPE, "version" to 2, "keys" to listOf(current.pub())))
        assertTrue(trust().applyKeySetUpdate(SignedKeySet(setPayload, listOf(SignatureEntry(recovery.id(), recovery.sign(setPayload))))))

        val payload = """{"version":3,"pins":[]}"""
        val byRevoked = listOf(SignatureEntry(revoked.id(), revoked.sign(payload)))

        // A new process whose Keystore fails: the set cannot be read.
        cipher.broken = true
        val restarted = trust()
        for (attempt in 1..2) {
            try {
                restarted.verifyConfig(payload, byRevoked)
                fail("with the key set unreadable nothing may verify — least of all the revoked key")
            } catch (e: StoreUnreadableException) {
                // expected, and again on the next call: not remembered as "no set"
            }
        }
        try {
            restarted.keySetVersion()
            fail("the version is unknown, not 0")
        } catch (e: StoreUnreadableException) {
            // expected
        }

        // The Keystore works again: the same instance reads the set and the revocation holds.
        cipher.broken = false
        assertFalse(restarted.verifyConfig(payload, byRevoked).ok)
        assertTrue(restarted.verifyConfig(payload, listOf(SignatureEntry(current.id(), current.sign(payload)))).ok)
        assertEquals(2, restarted.keySetVersion())
    }

    @Test
    fun `a key-set store that cannot be opened is not 'no key set' either`() {
        val key = ecKeyPair()
        val recovery = ecKeyPair()
        var opens = 0
        val keyStore = SigningKeyStore.createForTest(prefs("keys", strict = true))
        val trust = SignatureTrust("default", listOf(key.pub()), 1, listOf(recovery.pub()), 1) {
            if (opens++ == 0) throw ProviderException("Keystore unavailable") else keyStore
        }
        val payload = """{"version":3,"pins":[]}"""
        val entries = listOf(SignatureEntry(key.id(), key.sign(payload)))

        try {
            trust.verifyConfig(payload, entries)
            fail("the store did not open")
        } catch (e: StoreUnreadableException) {
            // expected
        }
        // Tried again on the next use.
        assertTrue(trust.verifyConfig(payload, entries).ok)
        assertEquals(2, opens)
    }
}
