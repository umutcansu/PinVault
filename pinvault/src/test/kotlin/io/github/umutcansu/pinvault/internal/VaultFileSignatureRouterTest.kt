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

    // ── end_to_end: one failure code whatever went wrong in the envelope (L-11) ──
    //
    // The signature covers the plaintext, so it cannot be checked before the
    // envelope is open; what the server learns from a failure must therefore
    // not say WHICH step failed (layout, RSA-OAEP, AES-GCM): that is the
    // shape of a padding oracle.

    private fun signedBlock() = ConfigApiBlock(
        id = "default", configUrl = "https://example.test/", bootstrapPins = emptyList(), signaturePublicKey = pubB64
    )

    private fun routerWith(
        storage: VaultStorageProvider,
        api: CertificateConfigApi,
        block: ConfigApiBlock = signedBlock(),
        keys: io.github.umutcansu.pinvault.keystore.DeviceKeyProvider? = null
    ): VaultFileRouter {
        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns block
        every { client.signatureTrust } returns SignatureTrust.forBlock(block, null)
        return VaultFileRouter(mapOf("default" to client), { storage }, keys, { "test-device" })
    }

    private fun answering(response: VaultFetchResponse): CertificateConfigApi = mockk<CertificateConfigApi>().also {
        coEvery { it.downloadVaultFileWithMeta(any(), any(), any(), any()) } returns response
    }

    private fun e2eFile(key: String) = VaultFileConfig(
        key = key, endpoint = "api/v1/vault/$key", configApiId = "default",
        encryption = io.github.umutcansu.pinvault.model.VaultFileEncryption.END_TO_END
    )

    /** The device's RSA public key, from the PEM the provider registers with the server. */
    private fun publicKeyOf(provider: io.github.umutcansu.pinvault.keystore.DeviceKeyProvider): java.security.PublicKey {
        provider.ensureKeyPair()
        val der = provider.getPublicKeyPem().lines().filter { !it.startsWith("-----") }.joinToString("")
        return java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.X509EncodedKeySpec(Base64.decode(der, Base64.DEFAULT)))
    }

    @Test
    fun `every way an end_to_end envelope can fail gives the same code and reason, without the exception text`() = runTest {
        val content = "model".toByteArray()
        val device = io.github.umutcansu.pinvault.keystore.DeviceKeyProvider.software("e2e-codes-${System.nanoTime()}")
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val good = io.github.umutcansu.pinvault.store.SoftwareUserAuthKeys.serverEnvelope(content, publicKeyOf(device))
        // The GCM tag fails / the RSA-OAEP unwrap fails / the layout fails.
        val tampered = good.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val wrongKey = io.github.umutcansu.pinvault.store.SoftwareUserAuthKeys.serverEnvelope(content, other.public)
        val malformed = ByteArray(8)
        val signature = sign("m", 1, content, keyPair.private)

        val failures = listOf("tampered" to tampered, "wrong key" to wrongKey, "malformed" to malformed).map { (what, envelope) ->
            val storage = MemStore()
            val response = VaultFetchResponse(content = envelope, version = 1, encryption = "end_to_end", signature = signature)
            val result = routerWith(storage, answering(response), keys = device).fetchFile(e2eFile("m"))
            assertTrue("$what: expected Failed, was $result", result is VaultFileResult.Failed)
            assertNull("$what: nothing stored", storage.load("m"))
            result as VaultFileResult.Failed
        }
        for (failed in failures) {
            assertEquals(VaultFileResult.Failed.CODE_DECRYPT_FAILED, failed.code)
            assertEquals("one text whatever the step", failures[0].reason, failed.reason)
            val message = failed.exception?.message
            if (!message.isNullOrBlank()) assertFalse("the exception's text stays out of the reason", failed.reason.contains(message))
        }

        val storage = MemStore()
        val response = VaultFetchResponse(content = good, version = 1, encryption = "end_to_end", signature = signature)
        assertTrue(routerWith(storage, answering(response), keys = device).fetchFile(e2eFile("m")) is VaultFileResult.Updated)
        assertArrayEquals(content, storage.load("m"))
    }

    @Test
    fun `an unsigned end_to_end answer is refused before the device key touches it`() = runTest {
        val device = io.github.umutcansu.pinvault.keystore.DeviceKeyProvider.software("e2e-unsigned-${System.nanoTime()}")
        val envelope = io.github.umutcansu.pinvault.store.SoftwareUserAuthKeys.serverEnvelope("model".toByteArray(), publicKeyOf(device))
        var keyUsed = false
        val watched = object : io.github.umutcansu.pinvault.keystore.DeviceKeyProvider by device {
            override fun getPrivateKey(): java.security.PrivateKey { keyUsed = true; return device.getPrivateKey() }
        }
        val response = VaultFetchResponse(content = envelope, version = 1, encryption = "end_to_end", signature = null)

        val result = routerWith(MemStore(), answering(response), keys = watched).fetchFile(e2eFile("m")) as VaultFileResult.Failed

        assertEquals(VaultFileResult.Failed.CODE_SIGNATURE_MISSING, result.code)
        assertFalse("no signature, no decryption", keyUsed)
    }

    @Test
    fun `failure codes name the class of a failure, never the server's text`() = runTest {
        val content = "real".toByteArray()

        val refused = mockk<CertificateConfigApi>()
        coEvery { refused.downloadVaultFileWithMeta(any(), any(), any(), any()) } throws
            io.github.umutcansu.pinvault.api.VaultFetchHttpException(401, """{"error":"invalid or revoked token"}""")
        val http = routerWith(MemStore(), refused).fetchFile(fileFor("ts")) as VaultFileResult.Failed
        assertEquals("http_401", http.code)
        assertTrue("the app still gets the detail", http.reason.contains("HTTP 401"))

        val forged = VaultFetchResponse(content = content, version = 1, signature = sign("ts", 1, "ATTACKER".toByteArray(), keyPair.private))
        assertEquals(
            VaultFileResult.Failed.CODE_SIGNATURE_INVALID,
            (routerWith(MemStore(), answering(forged)).fetchFile(fileFor("ts")) as VaultFileResult.Failed).code
        )

        val unsigned = VaultFetchResponse(content = content, version = 1, signature = null)
        assertEquals(
            VaultFileResult.Failed.CODE_SIGNATURE_MISSING,
            (routerWith(MemStore(), answering(unsigned)).fetchFile(fileFor("ts")) as VaultFileResult.Failed).code
        )

        val offline = mockk<CertificateConfigApi>()
        coEvery { offline.downloadVaultFileWithMeta(any(), any(), any(), any()) } throws java.net.UnknownHostException("config.example.test")
        assertEquals(
            VaultFileResult.Failed.CODE_NETWORK,
            (routerWith(MemStore(), offline).fetchFile(fileFor("ts")) as VaultFileResult.Failed).code
        )

        val unknownApi = routerWith(MemStore(), answering(unsigned)).fetchFile(fileFor("ts").copy(configApiId = "gone")) as VaultFileResult.Failed
        assertEquals(VaultFileResult.Failed.CODE_NOT_CONFIGURED, unknownApi.code)
    }
}
