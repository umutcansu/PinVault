package io.github.umutcansu.pinvault.internal

import android.util.Base64
import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Verifies that [VaultFileRouter] enforces vault file content signatures
 * **fail-closed**: a tampered or unsigned file is NEVER written to storage when
 * a verifying key is configured. This is the integrity guarantee that lets a
 * device safely distribute a trust anchor (truststore/CA) over the air — even a
 * compromised server cannot get a forged file persisted.
 *
 * The router is driven directly with a MockK [ConfigApiClient] (its real
 * constructor builds EncryptedSharedPreferences / Keystore machinery we don't
 * want in a unit test), so only `api` and `block` are stubbed.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileSignatureRouterTest {

    private val keyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    private val pubB64 = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun sign(key: String, version: Int, content: ByteArray, priv: PrivateKey): String {
        val canonical = "pinvault-vault-file:v1:$key:$version:${sha256Hex(content)}"
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(priv)
        s.update(canonical.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(s.sign(), Base64.NO_WRAP)
    }

    /** In-memory storage so we can assert exactly whether save() happened. */
    private class MemStore : VaultStorageProvider {
        val saved = linkedMapOf<String, ByteArray>()
        override fun save(key: String, bytes: ByteArray, version: Int) { saved[key] = bytes }
        override fun load(key: String): ByteArray? = saved[key]
        override fun getVersion(key: String): Int = if (saved.containsKey(key)) 1 else 0
        override fun exists(key: String): Boolean = saved.containsKey(key)
        override fun clear(key: String) { saved.remove(key) }
    }

    private fun routerFor(
        storage: MemStore,
        response: VaultFetchResponse,
        verifyingKey: String?
    ): VaultFileRouter = routerFor(
        storage, response,
        ConfigApiBlock(
            id = "default",
            configUrl = "https://example.test/",
            bootstrapPins = emptyList(),
            signaturePublicKey = verifyingKey
        )
    )

    private fun routerFor(
        storage: MemStore,
        response: VaultFetchResponse,
        block: ConfigApiBlock
    ): VaultFileRouter {
        val api = mockk<CertificateConfigApi>()
        coEvery { api.downloadVaultFileWithMeta(any(), any(), any(), any()) } returns response
        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns block
        every { client.signatureTrust } returns SignatureTrust.forBlock(block, null)
        return VaultFileRouter(
            clients = mapOf("default" to client),
            storageFor = { storage },
            deviceKeyProvider = null,
            deviceIdProvider = { "test-device" }
        )
    }

    private fun fileFor(key: String) =
        VaultFileConfig(key = key, endpoint = "api/v1/vault/$key", configApiId = "default")

    @Test
    fun `valid signature is accepted and stored`() = runTest {
        val content = "truststore-bytes".toByteArray()
        val storage = MemStore()
        val response = VaultFetchResponse(
            content = content, version = 1, encryption = "plain",
            signature = sign("ts", 1, content, keyPair.private)
        )
        val result = routerFor(storage, response, verifyingKey = pubB64).fetchFile(fileFor("ts"))

        assertTrue("valid signature must yield Updated", result is VaultFileResult.Updated)
        assertArrayEquals(content, storage.load("ts"))
    }

    @Test
    fun `tampered signature is rejected and NOT stored`() = runTest {
        val content = "real".toByteArray()
        val storage = MemStore()
        // Signature made over DIFFERENT content → canonical mismatch on verify.
        val response = VaultFetchResponse(
            content = content, version = 1, encryption = "plain",
            signature = sign("ts", 1, "ATTACKER".toByteArray(), keyPair.private)
        )
        val result = routerFor(storage, response, verifyingKey = pubB64).fetchFile(fileFor("ts"))

        assertTrue("bad signature must yield Failed", result is VaultFileResult.Failed)
        assertNull("tampered file must NOT be persisted", storage.load("ts"))
    }

    @Test
    fun `missing signature with key configured is rejected (fail-closed)`() = runTest {
        val content = "real".toByteArray()
        val storage = MemStore()
        val response = VaultFetchResponse(
            content = content, version = 1, encryption = "plain", signature = null
        )
        val result = routerFor(storage, response, verifyingKey = pubB64).fetchFile(fileFor("ts"))

        assertTrue("missing signature must yield Failed", result is VaultFileResult.Failed)
        assertNull("unsigned file must NOT be persisted when a key is set", storage.load("ts"))
    }

    @Test
    fun `no verifying key (allowUnsigned) bypasses verification`() = runTest {
        val content = "legacy".toByteArray()
        val storage = MemStore()
        val response = VaultFetchResponse(
            content = content, version = 1, encryption = "plain", signature = null
        )
        // verifyingKey null mirrors an allowUnsigned() Config API (no signaturePublicKey).
        val result = routerFor(storage, response, verifyingKey = null).fetchFile(fileFor("ts"))

        assertTrue("unsigned mode must still store", result is VaultFileResult.Updated)
        assertArrayEquals(content, storage.load("ts"))
    }

    // ── m-of-n and several trusted keys ─────────────────────────────────────

    private val secondKeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    private val secondB64 = Base64.encodeToString(secondKeyPair.public.encoded, Base64.NO_WRAP)

    private fun twoKeyBlock(required: Int) = ConfigApiBlock(
        id = "default",
        configUrl = "https://example.test/",
        bootstrapPins = emptyList(),
        signaturePublicKey = pubB64,
        signaturePublicKeys = listOf(pubB64, secondB64),
        requiredSignatures = required
    )

    @Test
    fun `either trusted key may sign when one signature is required`() = runTest {
        val content = "model-v2".toByteArray()
        val storage = MemStore()
        // Signed by the SECOND (backup) key only — the one-key check would fail.
        val response = VaultFetchResponse(
            content = content, version = 2, encryption = "plain",
            signature = sign("m", 2, content, secondKeyPair.private)
        )
        val result = routerFor(storage, response, twoKeyBlock(required = 1)).fetchFile(fileFor("m"))

        assertTrue("backup-key signature must be accepted, got $result", result is VaultFileResult.Updated)
    }

    @Test
    fun `m-of-n — one of two required signatures is rejected, both are accepted`() = runTest {
        val content = "model-v2".toByteArray()
        val one = listOf(SignatureEntry(signature = sign("m", 2, content, keyPair.private)))
        // The same signature twice still counts as ONE key.
        val duplicated = one + one
        val both = one + SignatureEntry(signature = sign("m", 2, content, secondKeyPair.private))

        for (entries in listOf(one, duplicated)) {
            val storage = MemStore()
            val result = routerFor(
                storage, VaultFetchResponse(content = content, version = 2, signatures = entries), twoKeyBlock(2)
            ).fetchFile(fileFor("m"))
            assertTrue("one distinct signer must be rejected, got $result", result is VaultFileResult.Failed)
            assertTrue(
                "reason must say how many signatures were valid: ${(result as VaultFileResult.Failed).reason}",
                result.reason.contains("1 of 2 required signatures valid")
            )
            assertNull(storage.load("m"))
        }

        val storage = MemStore()
        val result = routerFor(
            storage, VaultFetchResponse(content = content, version = 2, signatures = both), twoKeyBlock(2)
        ).fetchFile(fileFor("m"))
        assertTrue("two distinct signers must be accepted, got $result", result is VaultFileResult.Updated)
        assertArrayEquals(content, storage.load("m"))
    }
}
