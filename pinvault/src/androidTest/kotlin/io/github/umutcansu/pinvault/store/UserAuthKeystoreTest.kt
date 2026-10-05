package io.github.umutcansu.pinvault.store

import android.os.Build
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.umutcansu.pinvault.internal.UserAuthPrompt
import io.github.umutcansu.pinvault.keystore.KeystoreUserAuthKeys
import io.github.umutcansu.pinvault.keystore.UserAuthKeyKind
import io.github.umutcansu.pinvault.keystore.UserAuthKeys
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFileUnlockPrompt
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * [UserAuthVaultStorage] on the real Android Keystore, where the hardware
 * enforces the lock. Needs a device with a screen-lock PIN, passed in:
 *
 *     ./gradlew :pinvault:connectedDebugAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.screenLockPin=1234 \
 *         -Pandroid.testInstrumentationRunnerArguments.class=io.github.umutcansu.pinvault.store.UserAuthKeystoreTest
 *
 * Without the argument every test is skipped. The test types the PIN into
 * the system prompt itself (`input text`), so it runs unattended. Run it on
 * an emulator WITHOUT an enrolled fingerprint: on Android 7–10 a fingerprint
 * makes the key fingerprint-only, which a typed PIN cannot open (those tests
 * are skipped then). The attestation test needs no PIN prompt but shares
 * the PIN argument gate.
 */
@RunWith(AndroidJUnit4::class)
class UserAuthKeystoreTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val pin: String? = InstrumentationRegistry.getArguments().getString("screenLockPin")
    private val keys = KeystoreUserAuthKeys(instrumentation.targetContext) { DEVICE_ID }
    private val inner = MemStore()
    private val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED)
    /** An encryption(USER_AUTH) file: only the server's sealed copy counts. */
    private val serverSealed = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
    private val content = "account-statement".toByteArray()

    private class MemStore : VaultStorageProvider {
        val blobs = linkedMapOf<String, ByteArray>()
        val versions = linkedMapOf<String, Int>()
        override fun save(key: String, bytes: ByteArray, version: Int) { blobs[key] = bytes; versions[key] = version }
        override fun load(key: String): ByteArray? = blobs[key]
        override fun getVersion(key: String): Int = versions[key] ?: 0
        override fun exists(key: String): Boolean = blobs.containsKey(key)
        override fun clear(key: String) { blobs.remove(key); versions.remove(key) }
    }

    @Before
    fun needsScreenLock() {
        assumeTrue("pass -e screenLockPin <pin> on a device locked with that PIN", pin != null)
        assertTrue("the device has no screen lock", keys.isScreenLockSet())
        keys.delete()   // every test starts with a fresh device key
    }

    @After
    fun cleanUp() {
        keys.delete()
    }

    @Test
    fun keyKindMatchesTheDevice() {
        keys.ensureKey()
        val expected = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> UserAuthKeyKind.PER_USE
            strongFingerprint() -> UserAuthKeyKind.PER_USE_BIOMETRIC
            else -> UserAuthKeyKind.TIME_BOUND
        }
        assertEquals(expected, keys.kind())
    }

    @Test
    fun ensureKeyKeepsAUsableKey() {
        assertTrue("first call makes the key", keys.ensureKey())
        val first = keys.publicKey().encoded
        assertFalse("a usable key is never replaced", keys.ensureKey())
        assertArrayEquals(first, keys.publicKey().encoded)
        assertEquals(UserAuthKeys.State.USABLE, keys.state())
    }

    @Test
    fun hardwareRefusesTheKeyWithoutThePrompt() = runBlocking {
        storage.save(KEY, content, 1)
        assertTrue(storage.isLocked(KEY))
        assertNull(storage.load(KEY))
        // A time-bound key opens for a few seconds after any screen unlock;
        // wait that window out so only the hardware's refusal is left.
        if (keys.kind() == UserAuthKeyKind.TIME_BOUND) delay((KeystoreUserAuthKeys.LEGACY_WINDOW_SECONDS + 2) * 1000L)

        // A forged "prompt passed": our code is fooled, the Keystore is not.
        val result = storage.unlock(KEY, { _, cipher -> AuthOutcome.Succeeded(cipher) })

        assertTrue("expected Failed, was $result", result is VaultFileUnlockResult.Failed)
        assertTrue("a refused key is not a retired one: the copy stays", storage.exists(KEY))
        assertEquals("and so does the key", UserAuthKeys.State.USABLE, keys.state())
    }

    @Test
    fun screenLockPinOpensTheFile() = runBlocking {
        storage.save(KEY, content, 7)
        assumeTrue("a fingerprint-only key does not take a PIN", keys.kind() != UserAuthKeyKind.PER_USE_BIOMETRIC)

        val result = unlockWithPin { storage.unlock(KEY, showPrompt) }

        assertEquals(VaultFileUnlockResult.Unlocked(KEY, 7, content), result)
    }

    @Test
    fun serverSealedFileOpensOnlyAfterThePin() = runBlocking {
        keys.ensureKey()
        assumeTrue("a fingerprint-only key does not take a PIN", keys.kind() != UserAuthKeyKind.PER_USE_BIOMETRIC)
        // What the server sends for encryption = user_auth: the end_to_end
        // envelope, wrapped for the registered user-auth key.
        serverSealed.saveSealedByServer(KEY, serverEnvelope(content), 4, listOf(SignatureEntry("k1", "sig")))
        assertNull(serverSealed.load(KEY))

        var checked: Pair<String, Int>? = null
        val result = unlockWithPin {
            serverSealed.unlock(KEY, showPrompt, verify = { plain, version, _ -> checked = String(plain) to version; null })
        }

        assertEquals(VaultFileUnlockResult.Unlocked(KEY, 4, content), result)
        assertEquals("account-statement" to 4, checked)
    }

    @Test
    fun copySealedForAnotherKeyIsGivenUpAfterThePin() = runBlocking {
        keys.ensureKey()
        assumeTrue("a fingerprint-only key does not take a PIN", keys.kind() != UserAuthKeyKind.PER_USE_BIOMETRIC)
        // Stamped with this key, but wrapped for another one: after the PIN,
        // the Keystore's OAEP unwrap fails (BadPaddingException).
        val other = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        serverSealed.saveSealedByServer(KEY, serverEnvelope(content, other.public), 4, emptyList())
        var forgotten = false

        val attempt: suspend () -> VaultFileUnlockResult = {
            unlockWithPin {
                serverSealed.unlock(KEY, showPrompt, onSealedForAnotherKey = { forgotten = true }, verify = { _, _, _ -> null })
            }
        }
        var result = attempt()
        // A Keystore that names the wrong key (BadPadding, INVALID_ARGUMENT) gives
        // the copy up at once. One that only says UNKNOWN_ERROR (the emulator's
        // KeyMint: -1000) keeps it for one more approved attempt.
        if (result is VaultFileUnlockResult.Failed) {
            assertTrue("kept after the first unnamed failure", serverSealed.exists(KEY))
            result = attempt()
        }

        val chain = (result as? VaultFileUnlockResult.Failed)?.exception?.let { e ->
            generateSequence<Throwable>(e) { it.cause?.takeIf { c -> c !== it } }.take(8)
                .joinToString(" <- ") { "${it.javaClass.name}: ${it.message}" }
        }
        assertEquals("cause chain: $chain", VaultFileUnlockResult.Invalidated(KEY), result)
        assertFalse("the copy is deleted", serverSealed.exists(KEY))
        assertTrue("the registration is forgotten", forgotten)
        assertEquals("the key stays", UserAuthKeys.State.USABLE, keys.state())
    }

    /**
     * The key is generated with an attestation challenge bound to the device
     * id; the server checks the chain (USER_AUTH_ATTESTATION). Skipped where
     * the Keystore cannot attest (the key is then made without, and
     * registered without a chain).
     */
    @Test
    fun userAuthKeyCarriesAnAttestationChainForThisDevice() {
        keys.ensureKey()
        assertEquals(UserAuthKeys.State.USABLE, keys.state())
        val chain = keys.attestationChain()
        assumeTrue("this device's Keystore cannot attest keys", chain.isNotEmpty())

        val factory = java.security.cert.CertificateFactory.getInstance("X.509")
        val certs = chain.map { factory.generateCertificate(it.inputStream()) as java.security.cert.X509Certificate }
        assertTrue("leaf + at least one attestation certificate", certs.size >= 2)
        assertArrayEquals("the leaf is the user-auth key", keys.publicKey().encoded, certs[0].publicKey.encoded)
        for (i in 0 until certs.size - 1) certs[i].verify(certs[i + 1].publicKey)   // leaf first, each signed by the next

        val extension = certs[0].getExtensionValue(UserAuthKeys.ATTESTATION_EXTENSION_OID)
        assertNotNull("the leaf carries the key attestation extension", extension)
        val challenge = UserAuthKeys.attestationChallenge(DEVICE_ID)
        assertTrue("the extension carries the challenge for this device id", extension!!.containsSequence(challenge))
        assertFalse("and not another device's", extension.containsSequence(UserAuthKeys.attestationChallenge("another-device")))
    }

    @Test
    fun copySealedWithADeletedKeyIsGivenUp() = runBlocking {
        storage.save(KEY, content, 1)
        keys.delete()   // the key is truly gone

        assertEquals(VaultFileUnlockResult.Invalidated(KEY), storage.unlock(KEY, { _, c -> AuthOutcome.Succeeded(c) }))
        assertFalse(storage.exists(KEY))
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private lateinit var activity: FragmentActivity

    private val showPrompt: suspend (UserAuthKeyKind, Cipher?) -> AuthOutcome =
        { kind, cipher -> UserAuthPrompt.authenticate(activity, VaultFileUnlockPrompt("Open statement"), kind, cipher) }

    /** Runs [unlock] with a real prompt on screen and types the PIN into it. */
    private suspend fun unlockWithPin(
        unlock: suspend () -> VaultFileUnlockResult
    ): VaultFileUnlockResult = kotlinx.coroutines.coroutineScope {
        ActivityScenario.launch(FragmentActivity::class.java).use { scenario ->
            scenario.onActivity { activity = it }
            // Key events (the previous test's Enter, an adb unlock) leave touch
            // mode, and then the PIN screen focuses its Cancel button: the
            // typed PIN goes nowhere and Enter cancels. A tap on the empty
            // activity puts the device back in touch mode first.
            val metrics = instrumentation.targetContext.resources.displayMetrics
            shell("input tap ${metrics.widthPixels / 2} ${metrics.heightPixels / 2}")
            val unlocking = async { unlock() }
            delay(PROMPT_SETTLE_MS)
            shell("input text $pin")
            shell("input keyevent 66")
            unlocking.await()
        }
    }

    private fun strongFingerprint(): Boolean =
        BiometricManager.from(instrumentation.targetContext)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun ByteArray.containsSequence(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }

    private fun serverEnvelope(plain: ByteArray, wrapFor: java.security.PublicKey = keys.publicKey()): ByteArray {
        val random = SecureRandom()
        val aesKey = ByteArray(32).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, iv))
            doFinal(plain)
        }
        val wrapped = Cipher.getInstance(UserAuthKeys.RSA_TRANSFORMATION).run {
            init(Cipher.ENCRYPT_MODE, wrapFor, UserAuthKeys.OAEP)
            doFinal(aesKey)
        }
        return ByteBuffer.allocate(4 + wrapped.size + iv.size + ciphertext.size)
            .putInt(wrapped.size).put(wrapped).put(iv).put(ciphertext).array()
    }

    private fun shell(command: String) {
        instrumentation.uiAutomation.executeShellCommand(command).use { fd ->
            java.io.FileInputStream(fd.fileDescriptor).readBytes()
        }
    }

    private companion object {
        const val KEY = "userauth-instrumented"
        /** Stands in for the X-Device-Id the library sends. */
        const val DEVICE_ID = "android-test-device"
        const val PROMPT_SETTLE_MS = 3_000L
    }
}
