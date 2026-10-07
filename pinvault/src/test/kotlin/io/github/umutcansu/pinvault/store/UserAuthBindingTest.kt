package io.github.umutcansu.pinvault.store

import io.github.umutcansu.pinvault.model.UserAuthKeyKind
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Two things about a copy sealed on the device:
 *  - its GCM tag covers the file name AND the version it is stored as, so
 *    neither can be changed under it;
 *  - after a passed prompt, only a failure that says "this ciphertext was not
 *    made for this key" gives the copy up. A Keystore that merely failed —
 *    and the Android Keystore reports nearly everything as an
 *    IllegalBlockSizeException — keeps it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class UserAuthBindingTest {

    private val inner = MemVaultStore()
    private val keys = SoftwareUserAuthKeys()
    private val content = "account-statement".toByteArray()
    private val passes: suspend (UserAuthKeyKind, Cipher?) -> AuthOutcome = { _, c -> AuthOutcome.Succeeded(c) }

    private fun storage() = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED)

    // ── The version is under the tag ────────────────────────────────────

    @Test
    fun `a sealed copy opens only as the version it was sealed as`() = runTest {
        val s = storage()
        s.save("st", content, 3)
        assertEquals(VaultFileUnlockResult.Unlocked("st", 3, content), s.unlock("st", passes))

        // The version label is changed in storage (so the server's newer file would look older).
        inner.versions["st"] = 2_000_000

        val result = s.unlock("st", passes) as VaultFileUnlockResult.Failed
        assertTrue(result.reason, result.reason.contains("did not decrypt for this file and version"))
        assertFalse("the copy is given up; the next fetch starts from zero", s.exists("st"))
        assertEquals(0, s.getVersion("st"))
    }

    @Test
    fun `a sealed copy does not open under another file's name`() = runTest {
        val s = storage()
        s.save("public-notes", "notes".toByteArray(), 1)
        s.save("st", content, 1)
        inner.blobs["st"] = inner.blobs.getValue("public-notes")

        assertTrue(s.unlock("st", passes) is VaultFileUnlockResult.Failed)
        assertFalse(s.exists("st"))
    }

    /** What earlier builds wrote: kind 0x02, the tag covering the file name only. */
    private fun legacySealed(key: String, bytes: ByteArray): ByteArray {
        keys.ensureKey()
        val publicKey = keys.publicKey()
        val random = SecureRandom()
        val fileKey = ByteArray(32).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(fileKey, "AES"), GCMParameterSpec(128, iv))
            updateAAD("pinvault-user-auth:v2:$key".toByteArray(Charsets.UTF_8))
            doFinal(bytes)
        }
        val wrapped = Cipher.getInstance(io.github.umutcansu.pinvault.keystore.UserAuthKeys.RSA_TRANSFORMATION).run {
            init(Cipher.ENCRYPT_MODE, publicKey, io.github.umutcansu.pinvault.keystore.UserAuthKeys.OAEP)
            doFinal(fileKey)
        }
        return ByteBuffer.allocate(5 + 8 + 2 + wrapped.size + iv.size + ciphertext.size)
            .put("PVUA".toByteArray(Charsets.US_ASCII)).put(0x02)
            .put(io.github.umutcansu.pinvault.keystore.UserAuthKeys.keyId(publicKey))
            .putShort(wrapped.size.toShort()).put(wrapped).put(iv).put(ciphertext).array()
    }

    @Test
    fun `a copy sealed by an earlier build opens once and is written again with the version bound`() = runTest {
        inner.save("st", legacySealed("st", content), 5)
        val s = storage()
        assertTrue(s.isLocked("st"))

        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), s.unlock("st", passes))

        assertEquals("rewritten in the current form", 0x04.toByte(), inner.blobs.getValue("st")[4])
        assertEquals(5, s.getVersion("st"))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 5, content), s.unlock("st", passes))
        // And from now on the version is held to.
        inner.versions["st"] = 6
        assertTrue(s.unlock("st", passes) is VaultFileUnlockResult.Failed)
    }

    @Test
    fun `new copies are written in the current form`() {
        storage().save("st", content, 1)
        assertEquals(0x04.toByte(), inner.blobs.getValue("st")[4])
    }

    // ── "Wrong key" versus "the Keystore failed" ────────────────────────

    /** android.security.KeyStoreException with a keymaster error code, as the Keystore attaches it as a cause. */
    private fun keystoreException(code: Int, message: String): Exception? = try {
        val type = Class.forName("android.security.KeyStoreException")
        type.getConstructor(Int::class.javaPrimitiveType, String::class.java).newInstance(code, message) as Exception
    } catch (_: ReflectiveOperationException) {
        null
    }

    @Test
    fun `an exception without a cause from OAEP decoding means the copy is for another key`() {
        assertTrue(WrongKeyForCopy.matches(BadPaddingException("Decryption error")))
        assertTrue("what Keystore2 was seen to throw on API 33", WrongKeyForCopy.matches(IllegalBlockSizeException()))
    }

    @Test
    fun `the Keystore's INVALID_ARGUMENT is a decoding failure, every other Keystore error is not`() {
        val invalidArgument = keystoreException(-38, "Invalid argument")
        val locked = keystoreException(-72, "Device locked")
        val busy = keystoreException(4, "System error")
        // Robolectric ships the class; if a future one does not, the rest of the test still holds.
        if (invalidArgument != null && locked != null && busy != null) {
            assertTrue(WrongKeyForCopy.isKeystoreInvalidArgument(invalidArgument))
            assertFalse(WrongKeyForCopy.isKeystoreInvalidArgument(locked))
            assertTrue(WrongKeyForCopy.matches(IllegalBlockSizeException().apply { initCause(invalidArgument) }))
            assertTrue(WrongKeyForCopy.matches(BadPaddingException().apply { initCause(invalidArgument) }))
            assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply { initCause(locked) }))
            assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply { initCause(busy) }))
        }
        // Any other cause: a Keystore error, not a verdict on the copy.
        assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply { initCause(java.security.ProviderException("Keystore operation failed")) }))
        assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply { initCause(RuntimeException("binder died")) }))
        assertFalse(WrongKeyForCopy.matches(BadPaddingException().apply { initCause(IllegalStateException("?")) }))
        assertFalse(WrongKeyForCopy.isKeystoreInvalidArgument(RuntimeException("Invalid argument")))
    }

    @Test
    fun `other exception types and authentication failures never mean wrong key`() {
        assertFalse(WrongKeyForCopy.matches(java.security.ProviderException("Keystore operation failed")))
        assertFalse(WrongKeyForCopy.matches(java.security.InvalidKeyException("padding")))
        assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException("Key user not authenticated")))
        assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply {
            initCause(android.security.keystore.UserNotAuthenticatedException())
        }))
        assertFalse(WrongKeyForCopy.matches(IllegalBlockSizeException().apply {
            initCause(android.security.keystore.KeyPermanentlyInvalidatedException())
        }))
    }

    @Test
    fun `a Keystore failure after the prompt keeps the copy and the registration`() = runTest {
        val s = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        keys.ensureKey()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 2, emptyList())
        var forgotten = 0

        // What a transient failure looks like on a device: the type that used
        // to be read as "wrong key", with the real error as its cause.
        keys.unwrapError = IllegalBlockSizeException().apply { initCause(java.security.ProviderException("Keystore operation failed")) }
        val result = s.unlock("st", passes, onSealedForAnotherKey = { forgotten++ }, verify = { _, _, _ -> null })

        assertTrue(result is VaultFileUnlockResult.Failed)
        assertTrue("the copy is still there", s.exists("st"))
        assertEquals("and so is the registration", 0, forgotten)
        assertNotNull(keys.pair)

        // The Keystore recovers: the same copy opens.
        keys.unwrapError = null
        assertEquals(VaultFileUnlockResult.Unlocked("st", 2, content), s.unlock("st", passes, verify = { _, _, _ -> null }))
    }

    @Test
    fun `a copy really sealed for another key is still given up`() = runTest {
        val s = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        keys.ensureKey()
        val other = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, other.public), 2, emptyList())
        var forgotten = 0

        val result = s.unlock("st", passes, onSealedForAnotherKey = { forgotten++ }, verify = { _, _, _ -> null })

        assertEquals(VaultFileUnlockResult.Invalidated("st"), result)
        assertFalse(s.exists("st"))
        assertEquals(1, forgotten)
    }

    // ── What may give a copy up after the prompt (A1) ───────────────────

    private fun keystoreFailure(code: Int, message: String): Exception {
        val cause = keystoreException(code, message)
        org.junit.Assume.assumeTrue("Robolectric ships android.security.KeyStoreException", cause != null)
        return IllegalBlockSizeException().apply { initCause(cause) }
    }

    private fun serverCopy(): UserAuthVaultStorage {
        val s = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        keys.ensureKey()
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 2, emptyList())
        return s
    }

    private val noCheck: UnlockVerifier = { _, _, _ -> null }

    @Test
    fun `transient Keystore errors never give a server copy up, however often`() = runTest {
        val s = serverCopy()
        var forgotten = 0
        val transient = listOf(
            IllegalBlockSizeException().apply { initCause(java.security.ProviderException("Keystore operation failed")) },
            keystoreFailure(-28, "Invalid operation handle"),       // the operation was pruned
            keystoreFailure(-31, "Too many operations"),
            keystoreFailure(-1000, "Key user not authenticated"),    // anything about authentication
            keystoreFailure(4, "System error")
        )
        repeat(2) {
            for (error in transient) {
                keys.unwrapError = error
                assertTrue(s.unlock("st", passes, onSealedForAnotherKey = { forgotten++ }, verify = noCheck) is VaultFileUnlockResult.Failed)
            }
        }
        assertTrue("the copy is kept", s.exists("st"))
        assertEquals("and so is the registration", 0, forgotten)
        assertTrue("but the next fetch downloads it whole", s.needsFetch("st"))
        keys.unwrapError = null
        assertEquals(VaultFileUnlockResult.Unlocked("st", 2, content), s.unlock("st", passes, verify = noCheck))
        assertFalse(s.needsFetch("st"))
    }

    @Test
    fun `the emulator's UNKNOWN_ERROR for a wrong key gives a server copy up the second time in a row`() = runTest {
        val s = serverCopy()
        var forgotten = 0
        keys.unwrapError = keystoreFailure(-1000, "System error (internal Keystore code: -1000 message: n/a)")

        assertTrue(s.unlock("st", passes, onSealedForAnotherKey = { forgotten++ }, verify = noCheck) is VaultFileUnlockResult.Failed)
        assertTrue("kept after the first", s.exists("st"))
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes, onSealedForAnotherKey = { forgotten++ }, verify = noCheck))
        assertFalse(s.exists("st"))
        assertEquals(1, forgotten)
    }

    @Test
    fun `a success, a new copy or a clear starts the count again`() = runTest {
        val s = serverCopy()
        val unknown = keystoreFailure(-1000, "System error")
        fun failOnce() = kotlinx.coroutines.runBlocking {
            keys.unwrapError = unknown
            assertTrue(s.unlock("st", passes, verify = noCheck) is VaultFileUnlockResult.Failed)
            keys.unwrapError = null
        }

        failOnce()
        assertTrue(s.unlock("st", passes, verify = noCheck) is VaultFileUnlockResult.Unlocked)
        failOnce()
        assertTrue("one failure since the success: kept", s.exists("st"))

        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 3, emptyList())
        failOnce()
        assertTrue("one failure since the new copy: kept", s.exists("st"))

        s.clear("st")
        s.saveSealedByServer("st", SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 4, emptyList())
        failOnce()
        assertTrue(s.exists("st"))
    }

    @Test
    fun `a copy sealed on this device is never given up after the prompt, only marked for a fetch`() = runTest {
        val s = storage()
        s.save("st", content, 1)
        // Even what would mean "another key" for a server copy: this copy's key
        // id was checked against the current key before the prompt.
        for (error in listOf(BadPaddingException("Decryption error"), keystoreFailure(-1000, "System error"), keystoreFailure(-1000, "System error"))) {
            keys.unwrapError = error
            assertTrue(s.unlock("st", passes) is VaultFileUnlockResult.Failed)
        }
        assertTrue(s.exists("st"))
        assertTrue(s.needsFetch("st"))
        // A retired key still gives it up.
        keys.unwrapError = Exception("Keystore operation failed", android.security.keystore.KeyPermanentlyInvalidatedException())
        assertEquals(VaultFileUnlockResult.Invalidated("st"), s.unlock("st", passes))
        assertFalse(s.exists("st"))
        assertFalse(s.needsFetch("st"))
    }

    @Test
    fun `only the Keystore's UNKNOWN_ERROR is counted`() {
        val unknown = keystoreException(-1000, "System error")
        org.junit.Assume.assumeTrue(unknown != null)
        assertTrue(WrongKeyForCopy.isUnknownKeystoreError(IllegalBlockSizeException().apply { initCause(unknown) }))
        assertFalse(WrongKeyForCopy.isUnknownKeystoreError(IllegalBlockSizeException().apply { initCause(keystoreException(-28, "x")) }))
        assertFalse(WrongKeyForCopy.isUnknownKeystoreError(IllegalBlockSizeException().apply { initCause(keystoreException(-31, "x")) }))
        assertFalse("authentication is never a wrong key",
            WrongKeyForCopy.isUnknownKeystoreError(IllegalBlockSizeException("Key user not authenticated").apply { initCause(unknown) }))
        assertFalse(WrongKeyForCopy.isUnknownKeystoreError(java.security.ProviderException("internal Keystore code: -1000")))
    }
}
