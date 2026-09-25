package io.github.umutcansu.pinvault.crypto

import android.content.Context
import com.google.gson.Gson
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedKeySet
import io.github.umutcansu.pinvault.store.SigningKeyStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * [SignatureTrust]: several trusted keys, m-of-n, and signing-key sets signed
 * by offline recovery keys (rotation and revocation without an app update).
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class SignatureTrustTest {

    private val gson = Gson()

    private fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private val a = ecKeyPair()
    private val b = ecKeyPair()
    private val c = ecKeyPair()
    private val recovery = ecKeyPair()
    private val recovery2 = ecKeyPair()

    private fun KeyPair.pub(): String = Base64.getEncoder().encodeToString(public.encoded)
    private fun KeyPair.id(): String =
        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(public.encoded))

    private fun KeyPair.sign(payload: String): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(private)
        s.update(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(s.sign())
    }

    private fun KeyPair.entry(payload: String, keyId: String? = id()) = SignatureEntry(keyId, sign(payload))

    private fun keySet(
        version: Int,
        keys: List<String>,
        signers: List<KeyPair> = listOf(recovery),
        required: Int? = null,
        type: String = SignatureTrust.KEY_SET_TYPE
    ): SignedKeySet {
        val body = linkedMapOf<String, Any>("type" to type, "version" to version, "keys" to keys)
        if (required != null) body["requiredSignatures"] = required
        val payload = gson.toJson(body)
        return SignedKeySet(payload, signers.map { it.entry(payload) })
    }

    private fun newStore(name: String = "signing-keys-test"): SigningKeyStore {
        val prefs = RuntimeEnvironment.getApplication().getSharedPreferences(name, Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        return SigningKeyStore.createForTest(prefs)
    }

    private fun trust(
        keys: List<String> = listOf(a.pub()),
        required: Int = 1,
        recoveryKeys: List<String> = listOf(recovery.pub()),
        recoveryRequired: Int = 1,
        store: SigningKeyStore? = null
    ) = SignatureTrust("default", keys, required, recoveryKeys, recoveryRequired, store)

    private val payload = """{"version":3,"pins":[],"issuedAt":1,"expiresAt":2}"""

    // ── Several keys, m-of-n ────────────────────────────────────────────────

    @Test
    fun `a single trusted key accepts its own signature and nothing else`() {
        val t = trust(recoveryKeys = emptyList())
        assertTrue(t.verifyConfig(payload, listOf(a.entry(payload))).ok)
        assertFalse(t.verifyConfig(payload, listOf(b.entry(payload))).ok)
        assertFalse(t.verifyConfig(payload + " ", listOf(a.entry(payload))).ok)
    }

    @Test
    fun `any of several trusted keys may sign when one signature is required`() {
        val t = trust(keys = listOf(a.pub(), b.pub()), recoveryKeys = emptyList())
        val result = t.verifyConfig(payload, listOf(b.entry(payload)))
        assertTrue(result.ok)
        assertEquals(listOf(b.id()), result.signedBy)
        assertEquals(listOf(b.id()), t.status().lastConfigSignedBy)
    }

    @Test
    fun `a wrong or missing keyId hint does not turn a good signature bad`() {
        val t = trust(keys = listOf(a.pub(), b.pub()), recoveryKeys = emptyList())
        assertTrue(t.verifyConfig(payload, listOf(b.entry(payload, keyId = a.id()))).ok)
        assertTrue(t.verifyConfig(payload, listOf(b.entry(payload, keyId = null))).ok)
    }

    @Test
    fun `m-of-n counts distinct keys, not signatures`() {
        val t = trust(keys = listOf(a.pub(), b.pub(), c.pub()), required = 2, recoveryKeys = emptyList())
        val byA = a.entry(payload)

        val one = t.verifyConfig(payload, listOf(byA, byA))
        assertFalse("the same key twice is still one signer", one.ok)
        assertTrue(one.detail, one.detail.contains("1 of 2 required signatures valid"))

        val two = t.verifyConfig(payload, listOf(byA, c.entry(payload)))
        assertTrue(two.ok)
        assertEquals(setOf(a.id(), c.id()), two.signedBy.toSet())
    }

    // ── Signing-key sets ────────────────────────────────────────────────────

    @Test
    fun `a recovery-signed key set replaces the compiled-in keys and revokes the old one`() {
        val store = newStore()
        val t = trust(store = store)

        t.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub())))

        assertTrue("the new key is trusted", t.verifyConfig(payload, listOf(b.entry(payload))).ok)
        val old = t.verifyConfig(payload, listOf(a.entry(payload)))
        assertFalse("the key left out of the set is revoked", old.ok)
        assertTrue(old.detail, old.detail.contains("revoked by signing-key set v1"))

        val status = t.status()
        assertEquals(1, status.keySetVersion)
        assertEquals(listOf(b.id()), status.trustedKeyIds)
        assertEquals(listOf(recovery.id()), status.recoveryKeyIds)
    }

    @Test
    fun `an applied key set survives a new process and is re-verified on load`() {
        val store = newStore()
        trust(store = store).applyKeySetUpdate(keySet(version = 2, keys = listOf(b.pub())))

        val reloaded = trust(store = store)
        assertEquals(2, reloaded.keySetVersion())
        assertEquals(listOf(b.pub()), reloaded.trustedKeys())

        // A build shipping different recovery keys no longer vouches for the
        // stored set → back to its own compiled-in keys.
        val otherBuild = trust(store = store, recoveryKeys = listOf(recovery2.pub()))
        assertEquals(0, otherBuild.keySetVersion())
        assertEquals(listOf(a.pub()), otherBuild.trustedKeys())
    }

    @Test
    fun `an older or equal key set is ignored`() {
        val t = trust(store = newStore())
        t.applyKeySetUpdate(keySet(version = 3, keys = listOf(b.pub())))
        t.applyKeySetUpdate(keySet(version = 2, keys = listOf(c.pub())))
        t.applyKeySetUpdate(keySet(version = 3, keys = listOf(c.pub())))
        assertEquals(3, t.keySetVersion())
        assertEquals(listOf(b.pub()), t.trustedKeys())
    }

    @Test
    fun `a key set signed by a signing key instead of a recovery key is rejected`() {
        val store = newStore()
        val t = trust(store = store)
        try {
            // Whoever stole signing key A tries to trust their own key C.
            t.applyKeySetUpdate(keySet(version = 9, keys = listOf(c.pub()), signers = listOf(a)))
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("0 of 1 required recovery signature"))
        }
        assertEquals(0, t.keySetVersion())
        assertNull("nothing may be persisted", store.load("default"))
    }

    @Test
    fun `malformed key sets are rejected`() {
        val cases = mapOf(
            "wrong type" to keySet(version = 1, keys = listOf(b.pub()), type = "something-else"),
            "no keys" to keySet(version = 1, keys = emptyList()),
            "recovery key as signing key" to keySet(version = 1, keys = listOf(b.pub(), recovery.pub())),
            "more signatures than keys" to keySet(version = 1, keys = listOf(b.pub()), required = 2),
            "zero version" to keySet(version = 0, keys = listOf(b.pub()))
        )
        for ((name, set) in cases) {
            val t = trust(store = newStore())
            try {
                t.applyKeySetUpdate(set)
                fail("$name: expected SecurityException")
            } catch (_: SecurityException) {
                assertEquals("$name: nothing applied", 0, t.keySetVersion())
            }
        }
    }

    @Test
    fun `a key set can raise the signature count but never lower it below the app's`() {
        val raised = trust(keys = listOf(a.pub()), store = newStore())
        raised.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub(), c.pub()), required = 2))
        assertEquals(2, raised.requiredSignatures())

        val floor = trust(keys = listOf(a.pub(), b.pub()), required = 2, store = newStore())
        floor.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub(), c.pub()), required = 1))
        assertEquals(2, floor.requiredSignatures())
    }

    @Test
    fun `a key set is ignored when the app configured no recovery keys`() {
        val t = trust(recoveryKeys = emptyList(), store = newStore())
        t.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub())))
        assertEquals(listOf(a.pub()), t.trustedKeys())
        assertEquals(0, t.keySetVersion())
    }

    @Test
    fun `two required recovery signatures need two distinct recovery keys`() {
        val t = trust(
            recoveryKeys = listOf(recovery.pub(), recovery2.pub()),
            recoveryRequired = 2,
            store = newStore()
        )
        try {
            t.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub())))
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("1 of 2 required recovery signature"))
        }
        t.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub()), signers = listOf(recovery, recovery2)))
        assertEquals(1, t.keySetVersion())
    }

    @Test
    fun `vault canonical signatures follow the same trust`() {
        val t = trust(keys = listOf(a.pub(), b.pub()), required = 2, recoveryKeys = emptyList())
        val content = "bytes".toByteArray()
        val canonical = ConfigSignatureVerifier.vaultCanonical("f", 4, content)
        assertFalse(t.verifyVaultFile("f", 4, content, listOf(a.entry(canonical))).ok)
        assertTrue(t.verifyVaultFile("f", 4, content, listOf(a.entry(canonical), b.entry(canonical))).ok)
    }

    // ── Canonical keys ──────────────────────────────────────────────────────

    private fun KeyPair.pem(): String =
        "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(public.encoded) +
            "\n-----END PUBLIC KEY-----\n"

    @Test
    fun `two spellings of one key are one signer, so they cannot satisfy 2-of-n alone`() {
        // Same key as single-line Base64, with a trailing newline, and as PEM.
        val t = trust(keys = listOf(a.pub(), a.pub() + "\n", a.pem(), b.pub()), required = 2, recoveryKeys = emptyList())
        assertEquals(2, t.trustedKeys().size)

        // Two different signatures from the one private key.
        val result = t.verifyConfig(payload, listOf(a.entry(payload, keyId = null), a.entry(payload, keyId = null)))
        assertFalse("one private key must not count twice", result.ok)
        assertTrue(t.verifyConfig(payload, listOf(a.entry(payload), b.entry(payload))).ok)
    }

    @Test
    fun `a recovery key spelled differently is still refused as a signing key`() {
        val t = trust(store = newStore())
        try {
            t.applyKeySetUpdate(keySet(version = 1, keys = listOf(b.pub(), recovery.pem())))
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertTrue(e.message, e.message!!.contains("recovery key may not be a signing key"))
        }
    }

    @Test
    fun `malformed configured keys fail closed instead of looking unsigned`() {
        val t = SignatureTrust("default", listOf("not-a-key"), 1, emptyList(), 1, null as SigningKeyStore?)
        assertTrue("a configured block stays enabled", t.isEnabled)
        assertFalse(t.verifyConfig(payload, listOf(a.entry(payload))).ok)
    }

    @Test
    fun `the stored set round-trips as the model class and survives a config wipe`() {
        val prefs = RuntimeEnvironment.getApplication().getSharedPreferences("keyset-roundtrip", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        val store = SigningKeyStore.createForTest(prefs)
        val set = keySet(version = 4, keys = listOf(b.pub()))
        store.save("default", set)
        assertEquals(set, store.load("default"))

        // PinVault.reset() / corrupt-store recovery wipe the CONFIG store — a
        // different file. The key set, and the revocation in it, stays.
        io.github.umutcansu.pinvault.store.CertificateConfigStore.createForTest(
            RuntimeEnvironment.getApplication().getSharedPreferences("ssl_cert_config_default", Context.MODE_PRIVATE)
        ).clear()
        assertEquals(4, trust(store = store).keySetVersion())
    }
}
