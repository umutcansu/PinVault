package io.github.umutcansu.pinvault.internal

import android.util.Base64
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.VaultFetchHttpException
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.ScreenLockRequiredException
import io.github.umutcansu.pinvault.model.UserAuth
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.model.VaultFileUnlockResult
import io.github.umutcansu.pinvault.store.AuthOutcome
import io.github.umutcansu.pinvault.store.MemVaultStore
import io.github.umutcansu.pinvault.store.SoftwareUserAuthKeys
import io.github.umutcansu.pinvault.store.UserAuthVaultStorage
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * [VaultFileRouter] with `encryption = USER_AUTH` files: the device's
 * user-auth key is registered before the download, the server's envelope is
 * stored sealed and never decrypted at fetch time, and unlock checks the
 * signature with the same trust the fetch would.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class UserAuthRouterTest {

    private val signer = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val signerB64 = Base64.encodeToString(signer.public.encoded, Base64.NO_WRAP)
    private val block = ConfigApiBlock(id = "default", configUrl = "https://example.test/", bootstrapPins = emptyList(), signaturePublicKey = signerB64)

    private val keys = SoftwareUserAuthKeys()
    private val inner = MemVaultStore()
    private val content = "account-statement".toByteArray()
    private val api = mockk<CertificateConfigApi>(relaxed = true)

    private fun sign(key: String, version: Int, bytes: ByteArray): String {
        val hex = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(signer.private)
            update("pinvault-vault-file:v1:$key:$version:$hex".toByteArray(Charsets.UTF_8))
            Base64.encodeToString(sign(), Base64.NO_WRAP)
        }
    }

    private fun file(policy: UserAuth = UserAuth.REQUIRED, key: String = "st") = VaultFileConfig.Builder(key)
        .endpoint("api/v1/vault/$key")
        .encryption(VaultFileEncryption.USER_AUTH)
        .userAuth(policy)
        .build()

    private val registrations = io.github.umutcansu.pinvault.store.UserAuthRegistrations.InMemory()

    private fun router(storage: UserAuthVaultStorage, files: List<VaultFileConfig> = listOf(file())): VaultFileRouter {
        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns block
        every { client.signatureTrust } returns SignatureTrust.forBlock(block, null)
        return VaultFileRouter(mapOf("default" to client), { storage }, null, { "device-1" }, keys, { files }, registrations)
    }

    /** A server that seals [content] for whichever user-auth key the device registered last. */
    private fun serverSealsForRegisteredKey(version: Int = 3, sign: Boolean = true, encryption: String = "user_auth") {
        val pem = slot<String>()
        coEvery { api.registerUserAuthPublicKey("device-1", capture(pem), any()) } returns Unit
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } answers {
            VaultFetchResponse(
                content = SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()),
                version = version,
                encryption = encryption,
                signature = if (sign) sign("st", version, content) else null
            )
        }
    }

    private val passes: suspend (io.github.umutcansu.pinvault.keystore.UserAuthKeyKind, javax.crypto.Cipher?) -> AuthOutcome =
        { _, c -> AuthOutcome.Succeeded(c) }

    @Test
    fun `user_auth file is stored sealed and opens only through unlock`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey()
        val router = router(storage)

        val result = router.fetchFile(file())

        assertEquals("the app gets no content from the fetch", VaultFileResult.Updated("st", 3, ByteArray(0)), result)
        coVerify(exactly = 1) { api.registerUserAuthPublicKey("device-1", any(), any()) }
        assertNull(storage.load("st"))
        assertTrue(storage.isLocked("st"))

        val unlocked = storage.unlock("st", passes, verify = router.unlockVerifier(file()))
        assertEquals(VaultFileUnlockResult.Unlocked("st", 3, content), unlocked)
    }

    @Test
    fun `unlock deletes a user_auth copy whose signature does not match`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey()
        val router = router(storage)
        router.fetchFile(file())

        // Signed for another file name: valid signature, wrong file.
        val wrongTrust = router.unlockVerifier(file(key = "other"))!!
        val result = storage.unlock("st", passes) { plain, version, sigs -> wrongTrust(plain, version, sigs) }

        assertTrue(result is VaultFileUnlockResult.Failed)
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `user_auth file without a signature is refused at fetch when a key is configured`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey(sign = false)

        val result = router(storage).fetchFile(file())

        assertTrue(result is VaultFileResult.Failed)
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `older user_auth version is refused at fetch`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey(version = 5)
        val router = router(storage)
        router.fetchFile(file())
        serverSealsForRegisteredKey(version = 4)

        val result = router.fetchFile(file())

        assertTrue((result as VaultFileResult.Failed).reason.contains("downgrade"))
        assertEquals(5, storage.getVersion("st"))
    }

    @Test
    fun `a plain answer for a user_auth file is refused`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey(encryption = "plain")

        val result = router(storage).fetchFile(file())

        assertTrue((result as VaultFileResult.Failed).reason.contains("encryption=plain"))
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `IF_SCREEN_LOCK user_auth file cannot be received without a screen lock`() = runTest {
        keys.screenLock = false
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.IF_SCREEN_LOCK, serverSealedOnly = true)
        serverSealsForRegisteredKey()

        val result = router(storage, listOf(file(UserAuth.IF_SCREEN_LOCK))).fetchFile(file(UserAuth.IF_SCREEN_LOCK))

        val failed = result as VaultFileResult.Failed
        assertTrue(failed.exception is ScreenLockRequiredException)
        assertTrue(failed.reason, failed.reason.contains("cannot be received"))
        coVerify(exactly = 0) { api.downloadVaultFileWithMeta(any(), any(), any(), any()) }
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `412 user_auth_key_required registers the key again and retries once`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey()
        var calls = 0
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } answers {
            calls++
            if (calls == 1) throw VaultFetchHttpException(412, """{"error":"user_auth_key_required"}""")
            VaultFetchResponse(SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()), 3, "user_auth",
                signature = sign("st", 3, content))
        }

        val result = router(storage).fetchFile(file())

        assertTrue("expected Updated, was $result", result is VaultFileResult.Updated)
        assertEquals(2, calls)
        coVerify(exactly = 2) { api.registerUserAuthPublicKey("device-1", any(), any()) }
    }

    @Test
    fun `a second 412 is not retried again`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey()
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } throws
            VaultFetchHttpException(412, """{"error":"user_auth_key_required"}""")

        val result = router(storage).fetchFile(file())

        assertTrue((result as VaultFileResult.Failed).reason.contains("HTTP 412"))
        coVerify(exactly = 2) { api.downloadVaultFileWithMeta(any(), any(), any(), any()) }
    }

    @Test
    fun `a new key is registered before the next fetch`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey(version = 1)
        val router = router(storage)
        router.fetchFile(file())
        router.fetchFile(file())
        coVerify(exactly = 1) { api.registerUserAuthPublicKey("device-1", any(), any()) }

        keys.retired = true   // a fingerprint was added; the key is gone
        serverSealsForRegisteredKey(version = 2)
        val result = router.fetchFile(file())

        assertTrue("expected Updated, was $result", result is VaultFileResult.Updated)
        assertEquals(2, keys.generated)
        coVerify(exactly = 2) { api.registerUserAuthPublicKey("device-1", any(), any()) }
        assertTrue(storage.unlock("st", passes, verify = router.unlockVerifier(file())) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `registration failure fails the fetch and downloads nothing`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        coEvery { api.registerUserAuthPublicKey(any(), any(), any()) } throws Exception("HTTP 409")

        val result = router(storage).fetchFile(file())

        assertTrue((result as VaultFileResult.Failed).reason.contains("could not register the user-auth key"))
        coVerify(exactly = 0) { api.downloadVaultFileWithMeta(any(), any(), any(), any()) }
    }

    @Test
    fun `locally sealed file hands out no content from the fetch`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED)
        val local = VaultFileConfig(key = "st", endpoint = "api/v1/vault/st", userAuth = UserAuth.REQUIRED)
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } returns
            VaultFetchResponse(content, 2, "plain", signature = sign("st", 2, content))

        val result = router(storage, listOf(local)).fetchFile(local)

        assertEquals(VaultFileResult.Updated("st", 2, ByteArray(0)), result)
        assertTrue(storage.isLocked("st"))
    }

    @Test
    fun `key proof covers user_auth files`() {
        val tokenFile = VaultFileConfig.Builder("st")
            .endpoint("api/v1/vault/st")
            .encryption(VaultFileEncryption.USER_AUTH)
            .userAuth(UserAuth.REQUIRED)
            .accessPolicy(VaultFileAccessPolicy.TOKEN)
            .accessToken { "tok-123" }
            .build()

        val proof = router(UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)).keyProof("default", listOf(tokenFile))

        assertEquals("st", proof?.vaultKey)
        assertEquals("tok-123", proof?.token)
    }

    // ── Review fixes: key stamps, races, attestation, refusals ──────────

    private fun strictStorage() = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun `a copy is stamped with the key registered with the server`() = runTest {
        val storage = strictStorage()
        serverSealsForRegisteredKey()

        router(storage).fetchFile(file())

        assertEquals(registrations.get("default"), hex(storage.sealedKeyId("st")!!))
        assertEquals(hex(io.github.umutcansu.pinvault.keystore.UserAuthKeys.keyId(keys.publicKey())), registrations.get("default"))
    }

    @Test
    fun `a copy sealed for a replaced key is downloaded again, not answered already current`() = runTest {
        val storage = strictStorage()
        serverSealsForRegisteredKey(version = 3)
        val router = router(storage)
        router.fetchFile(file())
        val oldStamp = hex(storage.sealedKeyId("st")!!)

        keys.retired = true   // Android retired the key; the next fetch makes and registers a new one
        val result = router.fetchFile(file())

        assertEquals("same version, but the old copy can never open", VaultFileResult.Updated("st", 3, ByteArray(0)), result)
        assertNotEquals(oldStamp, hex(storage.sealedKeyId("st")!!))
        assertTrue(storage.unlock("st", passes, verify = router.unlockVerifier(file())) is VaultFileUnlockResult.Unlocked)
    }

    @Test
    fun `init's registration and an early fetch do not race`() = runTest {
        val storage = strictStorage()
        serverSealsForRegisteredKey()
        coEvery { api.registerUserAuthPublicKey("device-1", any(), any()) } coAnswers { kotlinx.coroutines.delay(100) }
        val router = router(storage)

        kotlinx.coroutines.coroutineScope {
            launch { router.registerUserAuthKeyEverywhere("device-1") }
            launch { router.fetchFile(file()) }
        }

        assertEquals(1, keys.generated)
        coVerify(exactly = 1) { api.registerUserAuthPublicKey("device-1", any(), any()) }
    }

    @Test
    fun `a forgotten registration is made again before the next fetch`() = runTest {
        val storage = strictStorage()
        serverSealsForRegisteredKey()
        val router = router(storage)
        router.fetchFile(file())

        router.forgetUserAuthRegistration("default")
        router.fetchFile(file())

        coVerify(exactly = 2) { api.registerUserAuthPublicKey("device-1", any(), any()) }
    }

    @Test
    fun `the attestation chain goes along, Base64 and leaf first`() = runTest {
        keys.chain = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))
        serverSealsForRegisteredKey()

        router(strictStorage()).fetchFile(file())

        coVerify { api.registerUserAuthPublicKey("device-1", any(), listOf("AQID", "BAU=")) }
    }

    @Test
    fun `user_auth_key_exists fails the fetch and says an administrator must reset the key`() = runTest {
        coEvery { api.registerUserAuthPublicKey(any(), any(), any()) } throws
            io.github.umutcansu.pinvault.api.UserAuthKeyRefusedException.from(409, "user_auth_key_exists", null, sentChain = false)!!

        val result = router(strictStorage()).fetchFile(file()) as VaultFileResult.Failed

        assertTrue(result.reason, result.reason.contains("administrator must reset"))
        assertNull("not recorded as registered", registrations.get("default"))
        coVerify(exactly = 0) { api.downloadVaultFileWithMeta(any(), any(), any(), any()) }
    }

    @Test
    fun `a backend built against 2_1_1 has no registerUserAuthPublicKey`() = runTest {
        coEvery { api.registerUserAuthPublicKey(any(), any(), any()) } throws AbstractMethodError("registerUserAuthPublicKey")

        val result = router(strictStorage()).fetchFile(file()) as VaultFileResult.Failed

        assertTrue(result.reason, result.reason.contains("does not implement registerUserAuthPublicKey"))
    }

    @Test
    fun `no verifier for a file of an unknown Config API, a no-op one for an unsigned API`() = runTest {
        val router = router(strictStorage())
        assertNull(router.unlockVerifier(file().copy(configApiId = "gone")))

        val unsigned = ConfigApiBlock(id = "default", configUrl = "https://example.test/", bootstrapPins = emptyList())
        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns unsigned
        every { client.signatureTrust } returns null
        val unsignedRouter = VaultFileRouter(mapOf("default" to client), { strictStorage() }, null, { "device-1" }, keys, { listOf(file()) })
        assertNull(unsignedRouter.unlockVerifier(file())!!.invoke(content, 1, emptyList()))
    }

    @Test
    fun `the attestation challenge is SHA-256 over the prefixed device id`() {
        val expected = MessageDigest.getInstance("SHA-256").digest("pinvault-user-auth-key:v1:device-1".toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected, io.github.umutcansu.pinvault.keystore.UserAuthKeys.attestationChallenge("device-1"))
    }

    // ── A version nobody verified yet, and signatures that name the Config API ──

    @Test
    fun `a user_auth envelope with an absurd version is refused before it is stored`() = runTest {
        val storage = strictStorage()
        // The version comes from a header; the content it would be checked
        // against is only opened after the prompt.
        serverSealsForRegisteredKey(version = Int.MAX_VALUE)

        val result = router(storage).fetchFile(file()) as VaultFileResult.Failed

        assertTrue(result.reason, result.reason.contains("more than 1000000 above"))
        assertFalse("nothing stored: the real file is not blocked as 'older'", storage.exists("st"))
        assertEquals(0, storage.getVersion("st"))

        serverSealsForRegisteredKey(version = 3)
        assertEquals(VaultFileResult.Updated("st", 3, ByteArray(0)), router(storage).fetchFile(file()))
    }

    private fun signV2(scope: String, key: String, version: Int, bytes: ByteArray): String {
        val hex = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(signer.private)
            update("pinvault-vault-file:v2:$scope:$key:$version:$hex".toByteArray(Charsets.UTF_8))
            Base64.encodeToString(sign(), Base64.NO_WRAP)
        }
    }

    private fun scopedRouter(storage: UserAuthVaultStorage, scope: String): VaultFileRouter {
        val scoped = block.copy(serverScope = scope)
        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns scoped
        every { client.signatureTrust } returns SignatureTrust.forBlock(scoped, null)
        return VaultFileRouter(mapOf("default" to client), { storage }, null, { "device-1" }, keys, { listOf(file()) }, registrations)
    }

    private fun serverSealsWithSignatures(v1: String?, v2: String?) {
        coEvery { api.registerUserAuthPublicKey("device-1", any(), any()) } returns Unit
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } answers {
            VaultFetchResponse(
                content = SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()),
                version = 3, encryption = "user_auth", signature = v1, signatureV2 = v2
            )
        }
    }

    @Test
    fun `a scoped block keeps the v2 signature with a user_auth copy and checks it at unlock`() = runTest {
        val storage = strictStorage()
        val router = scopedRouter(storage, "prod-mtls")
        serverSealsWithSignatures(v1 = sign("st", 3, content), v2 = signV2("prod-mtls", "st", 3, content))

        assertEquals(VaultFileResult.Updated("st", 3, ByteArray(0)), router.fetchFile(file()))
        assertEquals(
            VaultFileUnlockResult.Unlocked("st", 3, content),
            storage.unlock("st", passes, verify = router.unlockVerifier(file()))
        )
    }

    @Test
    fun `a user_auth copy signed for another Config API fails at unlock and is deleted`() = runTest {
        val storage = strictStorage()
        val router = scopedRouter(storage, "prod-mtls")
        serverSealsWithSignatures(v1 = null, v2 = signV2("staging-mtls", "st", 3, content))

        // Stored sealed: nothing can be verified before the prompt.
        assertTrue(router.fetchFile(file()) is VaultFileResult.Updated)

        val result = storage.unlock("st", passes, verify = router.unlockVerifier(file()))
        assertTrue(result is VaultFileUnlockResult.Failed)
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `a scoped block refuses a user_auth file that has only a v1 signature`() = runTest {
        val storage = strictStorage()
        serverSealsWithSignatures(v1 = sign("st", 3, content), v2 = null)

        val result = scopedRouter(storage, "prod-mtls").fetchFile(file()) as VaultFileResult.Failed

        assertTrue(result.reason, result.reason.contains("X-Vault-Signature-V2"))
        assertFalse(storage.exists("st"))
    }

    @Test
    fun `a copy kept after an inconclusive unlock failure is downloaded whole and replaced`() = runTest {
        val storage = UserAuthVaultStorage(inner, keys, UserAuth.REQUIRED, serverSealedOnly = true)
        serverSealsForRegisteredKey()
        val router = router(storage)
        router.fetchFile(file())

        // A Keystore fault after the prompt: not "wrong key", so nothing is deleted…
        keys.unwrapError = java.security.ProviderException("Keystore operation failed")
        assertTrue(storage.unlock("st", passes, verify = router.unlockVerifier(file())) is VaultFileUnlockResult.Failed)
        assertTrue(storage.exists("st"))
        assertTrue(storage.needsFetch("st"))

        // …but the next fetch asks for the whole file, and the same version replaces the copy.
        val asked = mutableListOf<Int>()
        coEvery { api.downloadVaultFileWithMeta(any(), capture(asked), any(), any()) } answers {
            VaultFetchResponse(
                content = SoftwareUserAuthKeys.serverEnvelope(content, keys.publicKey()),
                version = 3, encryption = "user_auth", signature = sign("st", 3, content)
            )
        }
        assertEquals(VaultFileResult.Updated("st", 3, ByteArray(0)), router.fetchFile(file()))
        assertEquals(listOf(0), asked)
        assertFalse("a new copy: the mark is gone", storage.needsFetch("st"))

        keys.unwrapError = null
        assertEquals(VaultFileUnlockResult.Unlocked("st", 3, content), storage.unlock("st", passes, verify = router.unlockVerifier(file())))
    }
}
