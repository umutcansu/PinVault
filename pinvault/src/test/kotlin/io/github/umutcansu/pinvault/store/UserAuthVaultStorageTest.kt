package io.github.umutcansu.pinvault.store

import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import io.github.umutcansu.pinvault.internal.UserAuthPrompt
import io.github.umutcansu.pinvault.keystore.UserAuthKeyKind
import io.github.umutcansu.pinvault.model.ScreenLockRequiredException
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.Cipher

/**
 * [UserAuthVaultStorage] with a software stand-in for the Keystore
 * ([SoftwareUserAuthKeys]) and the prompt lambda. The real Keystore path runs
 * on devices (androidTest UserAuthKeystoreTest).
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class UserAuthVaultStorageTest {

    private val inner = MemVaultStore()
    private val keys = SoftwareUserAuthKeys()
    private val content = "account-statement".toByteArray()

    private fun storage(policy: UserAuth = UserAuth.REQUIRED) = UserAuthVaultStorage(inner, keys, policy)

    /** A prompt that records what it was shown and answers [outcome]. */
    private class Prompt(private val outcome: (Cipher?) -> AuthOutcome) {
        var shown = 0
        var cipher: Cipher? = null
        var kind: UserAuthKeyKind? = null
        val fn: suspend (UserAuthKeyKind, Cipher?) -> AuthOutcome = { k, c -> shown++; kind = k; cipher = c; outcome(c) }
    }

    private val passes = Prompt { AuthOutcome.Succeeded(it) }

    // ── Sealed here ─────────────────────────────────────────────────────

    @Test
    fun `sealed copy opens only through the prompt`() = runTest {
        val s = storage()
        s.save("st", content, 3)

        assertFalse("stored copy must not hold the plaintext", String(inner.blobs.getValue("st")).contains("account-statement"))
        assertNull("load never prompts and never opens a sealed copy", s.load("st"))
        assertTrue(s.isLocked("st"))
        assertEquals(3, s.getVersion("st"))

        val result = s.unlock("st", passes.fn)
        assertEquals(VaultFileUnlockResult.Unlocked("st", 3, content), result)
        assertEquals(1, passes.shown)
        assertEquals(UserAuthKeyKind.PER_USE, passes.kind)
        assertNotNull("a per-use key: the prompt authorises a cipher", passes.cipher)
    }

    @Test
    fun `time-bound key opens inside the window, without a CryptoObject`() = runTest {
        keys.kind = UserAuthKeyKind.TIME_BOUND
        val s = storage()
        s.save("st", content, 1)

        assertTrue(s.unlock("st", passes.fn) is VaultFileUnlockResult.Unlocked)
        assertEquals(UserAuthKeyKind.TIME_BOUND, passes.kind)
        assertNull(passes.cipher)
    }

    @Test
    fun `per-use fingerprint key gets a fingerprint prompt with a cipher`() = runTest {
        keys.kind = UserAuthKeyKind.PER_USE_BIOMETRIC
        val s = storage()
        s.save("st", content, 1)

        assertTrue(s.unlock("st", passes.fn) is VaultFileUnlockResult.Unlocked)
        assertEquals(UserAuthKeyKind.PER_USE_BIOMETRIC, passes.kind)
        assertNotNull(passes.cipher)
    }

    @Test
    fun `one key for the whole device`() = runTest {
        val s = storage()
        s.save("a", content, 1)
        s.save("b", "other".toByteArray(), 1)

        assertEquals("both files share the device key", 1, keys.generated)
        assertTrue(s.unlock("a", passes.fn) is VaultFileUnlockResult.Unlocked)
        assertTrue(s.unlock("b", passes.fn) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `cancelled prompt keeps the file`() = runTest {
        val s = storage()
        s.save("st", content, 1)

        assertEquals(VaultFileUnlockResult.Cancelled("st"), s.unlock("st", Prompt { AuthOutcome.Cancelled }.fn))
        assertTrue(s.exists("st"))
        assertTrue(s.unlock("st", passes.fn) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `prompt error is reported and keeps the file`() = runTest {
        val s = storage()
        s.save("st", content, 1)

        val result = s.unlock("st", Prompt { AuthOutcome.Error("Unlock prompt error 7: too many attempts") }.fn)
        assertEquals("Unlock prompt error 7: too many attempts", (result as VaultFileUnlockResult.Failed).reason)
        assertTrue(s.exists("st"))
    }

    @Test
    fun `REQUIRED without a screen lock is not stored`() {
        keys.screenLock = false
        val s = storage(UserAuth.REQUIRED)

        val e = assertThrows(ScreenLockRequiredException::class.java) { s.save("st", content, 1) }
        assertEquals("st", e.key)
        assertFalse(inner.exists("st"))
    }

    @Test
    fun `IF_SCREEN_LOCK without a screen lock stores an open copy`() = runTest {
        keys.screenLock = false
        val s = storage(UserAuth.IF_SCREEN_LOCK)
        s.save("st", content, 1)

        assertArrayEquals(content, s.load("st"))
        assertFalse(s.isLocked("st"))
        val prompt = Prompt { AuthOutcome.Succeeded(it) }
        assertEquals(VaultFileUnlockResult.Unlocked("st", 1, content), s.unlock("st", prompt.fn))
        assertEquals("an open copy needs no prompt", 0, prompt.shown)
    }

    @Test
    fun `IF_SCREEN_LOCK copy is sealed once a screen lock exists`() = runTest {
        keys.screenLock = false
        val s = storage(UserAuth.IF_SCREEN_LOCK)
        s.save("st", content, 4)

        keys.screenLock = true
        assertArrayEquals("the read that seals still returns the content", content, s.load("st"))
        assertTrue(s.isLocked("st"))
        assertEquals("sealing keeps the version", 4, s.getVersion("st"))
        assertNull(s.load("st"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 4, content), s.unlock("st", passes.fn))
    }

    @Test
    fun `copy stored before the lock was turned on is sealed on first read`() = runTest {
        inner.save("st", content, 2)
        val s = storage(UserAuth.REQUIRED)

        assertArrayEquals(content, s.load("st"))
        assertTrue(s.isLocked("st"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 2, content), s.unlock("st", passes.fn))
    }

    @Test
    fun `REQUIRED refuses an open copy`() = runTest {
        keys.screenLock = false
        storage(UserAuth.IF_SCREEN_LOCK).save("st", content, 1)   // app later tightened the policy

        val s = storage(UserAuth.REQUIRED)
        assertNull(s.load("st"))
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes.fn))
    }

    @Test
    fun `sealed copy does not open under another file's name, and is deleted`() = runTest {
        val s = storage()
        s.save("a", content, 1)
        s.save("b", "other".toByteArray(), 1)
        inner.blobs["b"] = inner.blobs.getValue("a")

        val result = s.unlock("b", passes.fn)
        assertTrue(result is VaultFileUnlockResult.Failed)
        assertFalse("a copy that does not decrypt is gone, the next fetch replaces it", s.exists("b"))
        assertTrue(s.exists("a"))
    }

    // ── Retired keys vs. Keystore hiccups ───────────────────────────────

    @Test
    fun `retired key deletes the copy and the next save makes a new key`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        keys.retired = true   // a fingerprint was added

        val prompt = Prompt { AuthOutcome.Succeeded(it) }
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", prompt.fn))
        assertEquals("no prompt for a key that cannot open anything", 0, prompt.shown)
        assertFalse(s.exists("st"))

        s.save("st", content, 1)
        assertEquals("a new key replaces the retired one", 2, keys.generated)
        assertTrue(s.unlock("st", passes.fn) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `retired key reported inside another exception still counts as retired`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        keys.unwrapError = Exception("Keystore operation failed", KeyPermanentlyInvalidatedException())

        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes.fn))
        assertFalse(s.exists("st"))
    }

    @Test
    fun `a Keystore error while reading the key keeps the copy and the key`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        val key = keys.pair
        keys.stateError = java.security.KeyStoreException("Keystore busy")

        val prompt = Prompt { AuthOutcome.Succeeded(it) }
        val result = s.unlock("st", prompt.fn)

        assertTrue("expected Failed, was $result", result is VaultFileUnlockResult.Failed)
        assertEquals(0, prompt.shown)
        assertTrue("copy kept", s.exists("st"))
        assertSame("key kept", key, keys.pair)

        keys.stateError = null
        assertTrue(s.unlock("st", passes.fn) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `a Keystore error after the prompt keeps the copy`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        keys.unwrapError = IllegalStateException("Key user not authenticated")

        val result = s.unlock("st", passes.fn)

        assertTrue(result is VaultFileUnlockResult.Failed)
        assertTrue(s.exists("st"))
        assertEquals(1, keys.generated)
    }

    @Test
    fun `a Keystore error never replaces the key on save`() {
        val s = storage()
        s.save("st", content, 1)
        val key = keys.pair
        keys.stateError = java.security.KeyStoreException("Keystore busy")

        assertThrows(java.security.KeyStoreException::class.java) { s.save("st2", content, 1) }
        assertSame(key, keys.pair)
        assertEquals(1, keys.generated)
    }

    @Test
    fun `copy sealed with a key that was replaced is given up`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        keys.delete()
        keys.ensureKey()   // e.g. made for another file after the old key was retired

        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes.fn))
        assertFalse(s.exists("st"))
    }

    @Test
    fun `copy in the key-per-file format of development builds counts as retired`() = runTest {
        inner.save("st", "PVUA".toByteArray() + byteArrayOf(0x01) + ByteArray(40), 1)

        assertTrue(storage().isLocked("st"))
        assertEquals(VaultFileUnlockResult.Invalidated("st"), storage().unlock("st", passes.fn))
        assertFalse(inner.exists("st"))
    }

    @Test
    fun `nothing stored is NotFound`() = runTest {
        assertEquals(VaultFileUnlockResult.NotFound("st"), storage().unlock("st", passes.fn))
    }

    @Test
    fun `clear removes the copy but keeps the device key`() {
        val s = storage()
        s.save("st", content, 1)
        s.clear("st")
        assertFalse(s.exists("st"))
        assertNotNull("other files may still need it", keys.pair)
    }

    // ── Sealed by the server (USER_AUTH) ────────────────────────────────

    private fun storedEnvelope(s: UserAuthVaultStorage, version: Int = 5, sigs: List<SignatureEntry> = listOf(SignatureEntry("k1", "c2ln"))) {
        keys.ensureKey()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), version, sigs)
    }

    @Test
    fun `server-sealed copy is decrypted and verified only after the prompt`() = runTest {
        val s = storage()
        storedEnvelope(s)
        assertNull(s.load("st"))
        assertTrue(s.isLocked("st"))

        var verified: Triple<String, Int, List<SignatureEntry>>? = null
        val result = s.unlock("st", passes.fn) { plain, version, sigs ->
            verified = Triple(String(plain), version, sigs); null
        }

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), result)
        assertEquals(Triple("account-statement", 5, listOf(SignatureEntry("k1", "c2ln"))), verified)
    }

    @Test
    fun `server-sealed copy keeps signatures without a key id`() = runTest {
        val s = storage()
        storedEnvelope(s, sigs = listOf(SignatureEntry(null, "c2ln"), SignatureEntry("k2", "c2ln2")))

        var sigs: List<SignatureEntry>? = null
        s.unlock("st", passes.fn) { _, _, entries -> sigs = entries; null }

        assertEquals(listOf(SignatureEntry(null, "c2ln"), SignatureEntry("k2", "c2ln2")), sigs)
    }

    @Test
    fun `server-sealed copy that fails its signature is deleted`() = runTest {
        val s = storage()
        storedEnvelope(s)

        val result = s.unlock("st", passes.fn) { _, _, _ -> "signature verification failed" }

        assertTrue(result is VaultFileUnlockResult.Failed)
        assertTrue((result as VaultFileUnlockResult.Failed).reason.contains("signature verification failed"))
        assertFalse(s.exists("st"))
    }

    @Test
    fun `server-sealed copy stays sealed when the prompt is cancelled`() = runTest {
        val s = storage()
        storedEnvelope(s)
        var verifierRan = false

        val result = s.unlock("st", Prompt { AuthOutcome.Cancelled }.fn) { _, _, _ -> verifierRan = true; null }

        assertEquals(VaultFileUnlockResult.Cancelled("st"), result)
        assertFalse("nothing is decrypted before the prompt passes", verifierRan)
        assertTrue(s.exists("st"))
    }

    @Test
    fun `malformed server envelope is refused at save`() {
        keys.ensureKey()
        assertThrows(IllegalArgumentException::class.java) {
            storage().saveSealedByServer("st", ByteArray(8), 1, emptyList())
        }
        assertFalse(inner.exists("st"))
    }

    // ── encryption(USER_AUTH): only server-sealed copies ────────────────

    private fun strict(policy: UserAuth = UserAuth.REQUIRED) = UserAuthVaultStorage(inner, keys, policy, serverSealedOnly = true)
    private val noCheck: UnlockVerifier = { _, _, _ -> null }

    @Test
    fun `a USER_AUTH file accepts no blob the server did not seal`() = runTest {
        keys.ensureKey()
        val planted = listOf(
            "open" to "PVUA".toByteArray() + byteArrayOf(0x00) + content,
            "earlier" to content,
            "sealed here" to storage().let { it.save("x", content, 1); inner.load("x")!! }
        )
        for ((what, blob) in planted) {
            inner.save("st", blob, 7)
            val s = strict(UserAuth.IF_SCREEN_LOCK)
            assertFalse(what, s.isLocked("st"))
            assertNull("$what: load never hands out content", s.load("st"))
            assertFalse("$what: load deletes it", inner.exists("st"))

            inner.save("st", blob, 7)
            val prompt = Prompt { AuthOutcome.Succeeded(it) }
            assertEquals(what, VaultFileUnlockResult.Invalidated("st"), s.unlock("st", prompt.fn, verify = noCheck))
            assertEquals("$what: no prompt", 0, prompt.shown)
            assertFalse("$what: unlock deletes it", inner.exists("st"))
        }
    }

    @Test
    fun `a USER_AUTH copy without a verifier is not opened`() = runTest {
        val s = strict()
        storedEnvelope(s)

        val result = s.unlock("st", passes.fn, verify = null)

        assertTrue(result is VaultFileUnlockResult.Failed)
        assertEquals("fails before the prompt", 0, passes.shown)
        assertTrue("the copy is kept", s.exists("st"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), s.unlock("st", passes.fn, verify = noCheck))
    }

    @Test
    fun `a USER_AUTH file stores nothing but the server's copy`() {
        assertThrows(IllegalStateException::class.java) { strict().save("st", content, 1) }
        assertFalse(inner.exists("st"))
    }

    @Test
    fun `a copy is stamped with the key it was sealed for`() = runTest {
        val s = strict()
        keys.ensureKey()
        val registered = ByteArray(8) { 7 }
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 2, emptyList(), sealedFor = registered)

        assertArrayEquals(registered, s.sealedKeyId("st"))
        // Not the device's current key: it can never open, so it is given up.
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes.fn, verify = noCheck))
        assertFalse(s.exists("st"))
    }

    @Test
    fun `a copy sealed for another key is given up after the prompt`() = runTest {
        val s = strict()
        keys.ensureKey()
        // Stamped with the current key, but the server wrapped it for another one.
        val other = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, other.public), 2, emptyList())
        var forgotten = 0

        val result = s.unlock("st", passes.fn, onSealedForAnotherKey = { forgotten++ }, verify = noCheck)

        assertEquals(VaultFileUnlockResult.Invalidated("st"), result)
        assertFalse(s.exists("st"))
        assertEquals("the registration is forgotten, so the next fetch registers again", 1, forgotten)
        assertNotNull("the key itself stays", keys.pair)
    }

    @Test
    fun `a Keystore error that is not a padding failure still keeps a USER_AUTH copy`() = runTest {
        val s = strict()
        storedEnvelope(s)
        keys.unwrapError = java.security.ProviderException("Keystore operation failed")

        assertTrue(s.unlock("st", passes.fn, verify = noCheck) is VaultFileUnlockResult.Failed)
        assertTrue(s.exists("st"))
    }

    // ── The pending slot: a download never replaces a stored copy unchecked ──

    private fun envelope(bytes: ByteArray = content) = SoftwareUserAuthKeys.serverEnvelope(bytes, keys.publicKey())

    @Test
    fun `the first server copy goes straight to the stored slot`() = runTest {
        val s = strict()
        keys.ensureKey()

        assertFalse("nothing to protect yet", s.saveSealedByServer("st", envelope(), 1, emptyList()))

        assertEquals(1, s.getVersion("st"))
        assertEquals(0, s.pendingVersion("st"))
        assertFalse(inner.exists("st.pending"))
    }

    @Test
    fun `a download beside a stored copy waits in the pending slot until it is opened`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        val newer = "statement-v6".toByteArray()

        assertTrue("a second copy goes to the pending slot", s.saveSealedByServer("st", envelope(newer), 6, emptyList()))

        assertEquals("the stored copy is still the one the app sees", 5, s.getVersion("st"))
        assertEquals(6, s.pendingVersion("st"))
        assertTrue(inner.exists("st.pending"))
        assertTrue(s.isLocked("st"))
        assertNull(s.load("st"))

        val promoted = mutableListOf<Int>()
        val result = s.unlock("st", passes.fn, verify = noCheck, onPromoted = { promoted += it })

        assertEquals("the newer copy opens first", VaultFileUnlockResult.Unlocked("st", 6, newer), result)
        assertEquals(listOf(6), promoted)
        assertEquals("…and is the stored copy now", 6, s.getVersion("st"))
        assertEquals(0, s.pendingVersion("st"))
        assertFalse(inner.exists("st.pending"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 6, newer), s.unlock("st", passes.fn, verify = noCheck))
    }

    @Test
    fun `a pending copy that fails its signature is deleted alone and the stored copy opens`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope("garbage".toByteArray()), 6, emptyList())
        val checked = mutableListOf<Int>()
        val onlyV5Passes: UnlockVerifier = { _, version, _ -> checked += version; if (version == 5) null else "signature verification failed" }
        var promoted = 0
        val prompt = Prompt { AuthOutcome.Succeeded(it) }

        val result = s.unlock("st", prompt.fn, verify = onlyV5Passes, onPromoted = { promoted++ })

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), result)
        assertEquals("the pending copy first, then the stored one", listOf(6, 5), checked)
        assertEquals("a copy that fails is never promoted", 0, promoted)
        assertFalse("only the pending copy is gone", inner.exists("st.pending"))
        assertEquals(5, s.getVersion("st"))
        assertTrue(s.exists("st"))
        assertEquals("a per-use cipher does one operation: the stored copy asks again", 2, prompt.shown)
    }

    @Test
    fun `a time-bound key opens the stored copy after a bad pending one without a second prompt`() = runTest {
        keys.kind = UserAuthKeyKind.TIME_BOUND
        val s = strict()
        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope("garbage".toByteArray()), 6, emptyList())
        val prompt = Prompt { AuthOutcome.Succeeded(it) }

        val result = s.unlock("st", prompt.fn, verify = { _, version, _ -> if (version == 5) null else "signature verification failed" })

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), result)
        assertEquals("the window is still open", 1, prompt.shown)
        assertEquals(0, s.pendingVersion("st"))
    }

    @Test
    fun `a pending copy sealed for another key is given up, the stored copy stays`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        val other = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, other.public), 6, emptyList())
        var forgotten = 0

        val result = s.unlock("st", passes.fn, onSealedForAnotherKey = { forgotten++ }, verify = noCheck)

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), result)
        assertEquals("the registration is made again before the next fetch", 1, forgotten)
        assertEquals(0, s.pendingVersion("st"))
        assertEquals(5, s.getVersion("st"))
    }

    @Test
    fun `a pending copy stamped for a key that is gone is dropped alone`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        val gone = ByteArray(8) { 9 }
        s.saveSealedByServer("st", envelope(), 6, emptyList(), sealedFor = gone)
        assertArrayEquals(gone, s.pendingSealedKeyId("st"))
        val prompt = Prompt { AuthOutcome.Succeeded(it) }

        val result = s.unlock("st", prompt.fn, verify = noCheck)

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), result)
        assertNull(s.pendingSealedKeyId("st"))
        assertEquals("given up before any prompt; the stored copy prompts once", 1, prompt.shown)
    }

    @Test
    fun `a cancelled prompt leaves both copies where they are`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope(), 6, emptyList())

        assertEquals(VaultFileUnlockResult.Cancelled("st"), s.unlock("st", Prompt { AuthOutcome.Cancelled }.fn, verify = noCheck))

        assertEquals(5, s.getVersion("st"))
        assertEquals(6, s.pendingVersion("st"))
    }

    @Test
    fun `a Keystore fault on the pending copy keeps both copies and marks nothing for download`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope(), 6, emptyList())
        keys.unwrapError = java.security.ProviderException("Keystore operation failed")

        assertTrue(s.unlock("st", passes.fn, verify = noCheck) is VaultFileUnlockResult.Failed)

        assertEquals(5, s.getVersion("st"))
        assertEquals(6, s.pendingVersion("st"))
        assertFalse("the whole file is there already", s.needsFetch("st"))

        keys.unwrapError = null
        assertEquals(VaultFileUnlockResult.Unlocked("st", 6, content), s.unlock("st", passes.fn, verify = noCheck))
    }

    @Test
    fun `a pending download clears the mark left by an inconclusive failure`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        keys.unwrapError = java.security.ProviderException("Keystore operation failed")
        assertTrue(s.unlock("st", passes.fn, verify = noCheck) is VaultFileUnlockResult.Failed)
        assertTrue(s.needsFetch("st"))
        keys.unwrapError = null

        s.saveSealedByServer("st", envelope(), 5, emptyList())

        assertFalse("the whole download arrived, in the pending slot", s.needsFetch("st"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), s.unlock("st", passes.fn, verify = noCheck))
    }

    @Test
    fun `clear and a retired key take the pending copy too`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope(), 6, emptyList())
        s.clear("st")
        assertFalse(inner.exists("st"))
        assertFalse(inner.exists("st.pending"))

        storedEnvelope(s, version = 5)
        s.saveSealedByServer("st", envelope(), 6, emptyList())
        keys.retired = true
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes.fn, verify = noCheck))
        assertFalse(inner.exists("st"))
        assertFalse(inner.exists("st.pending"))
    }

    @Test
    fun `a planted blob in the pending slot is deleted unread`() = runTest {
        val s = strict()
        storedEnvelope(s, version = 5)
        inner.save("st.pending", "PVUA".toByteArray() + byteArrayOf(0x00) + content, 6)

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), s.unlock("st", passes.fn, verify = noCheck))
        assertFalse(inner.exists("st.pending"))
    }

    // ── The prompt ──────────────────────────────────────────────────────

    @Test
    fun `prompt errors map to outcomes`() {
        assertSame(AuthOutcome.Cancelled, UserAuthPrompt.outcomeOf(BiometricPrompt.ERROR_USER_CANCELED, ""))
        assertSame(AuthOutcome.Cancelled, UserAuthPrompt.outcomeOf(BiometricPrompt.ERROR_NEGATIVE_BUTTON, ""))
        assertSame(AuthOutcome.Cancelled, UserAuthPrompt.outcomeOf(BiometricPrompt.ERROR_CANCELED, ""))
        assertSame(AuthOutcome.NoScreenLock, UserAuthPrompt.outcomeOf(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL, ""))
        assertTrue(UserAuthPrompt.outcomeOf(BiometricPrompt.ERROR_LOCKOUT, "Too many attempts") is AuthOutcome.Error)
    }

    @Test
    fun `prompt asks for what the key takes`() {
        assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.PER_USE, 33))
        assertEquals("fingerprint key: no screen-lock option", BIOMETRIC_STRONG,
            UserAuthPrompt.authenticators(UserAuthKeyKind.PER_USE_BIOMETRIC, 28))
        assertEquals(BIOMETRIC_WEAK or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND, 28))
        assertEquals("a time-bound key that survived an upgrade to 11",
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL, UserAuthPrompt.authenticators(UserAuthKeyKind.TIME_BOUND, 30))
    }
}
