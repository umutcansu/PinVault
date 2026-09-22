package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.model.ConfigApiBlock
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A blank `accessToken { … }` result must NOT become an empty `X-Vault-Token`
 * header.
 *
 * Found by E2E scenario C08: a host app whose token store is still empty
 * returns `""`, the router sent the header anyway, and the server answered
 * "Invalid or revoked token" — pointing operators at a revoked token that was
 * never issued, when the real answer is "no token was supplied". Both are 401;
 * only the reason differs, and the reason is what ends up in the server's
 * distribution history.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class VaultFileTokenHeaderTest {

    private class MemStore : VaultStorageProvider {
        val saved = linkedMapOf<String, ByteArray>()
        override fun save(key: String, bytes: ByteArray, version: Int) { saved[key] = bytes }
        override fun load(key: String): ByteArray? = saved[key]
        override fun getVersion(key: String): Int = 0
        override fun exists(key: String): Boolean = saved.containsKey(key)
        override fun clear(key: String) { saved.remove(key) }
    }

    /** Returns the `accessToken` argument the router passed to the API. */
    private suspend fun tokenSentFor(provider: (() -> String)?): String? {
        val api = mockk<CertificateConfigApi>()
        val tokenSlot = slot<String?>()
        coEvery {
            api.downloadVaultFileWithMeta(any(), any(), any(), captureNullable(tokenSlot))
        } returns VaultFetchResponse(
            content = "payload".toByteArray(), version = 1, encryption = "plain"
        )

        val client = mockk<ConfigApiClient>()
        every { client.api } returns api
        every { client.block } returns ConfigApiBlock(
            id = "default",
            configUrl = "https://example.test/",
            bootstrapPins = emptyList(),
            // No verifying key: this test is about the request, not integrity.
            signaturePublicKey = null
        )

        val router = VaultFileRouter(
            clients = mapOf("default" to client),
            storageFor = { MemStore() },
            deviceKeyProvider = null,
            deviceIdProvider = { "test-device" }
        )

        router.fetchFile(
            VaultFileConfig(
                key = "secret",
                endpoint = "api/v1/vault/secret",
                configApiId = "default",
                accessPolicy = VaultFileAccessPolicy.TOKEN,
                accessTokenProvider = provider
            )
        )
        return tokenSlot.captured
    }

    @Test
    fun `boş token başlık olarak gönderilmez`() = runTest {
        assertNull(
            "an empty accessToken must be dropped, not sent as `X-Vault-Token: `",
            tokenSentFor { "" }
        )
    }

    @Test
    fun `yalnızca boşluk içeren token başlık olarak gönderilmez`() = runTest {
        assertNull(
            "a whitespace-only accessToken is still 'no token'",
            tokenSentFor { "   " }
        )
    }

    @Test
    fun `gerçek token değişmeden gönderilir`() = runTest {
        assertEquals("real-token-value", tokenSentFor { "real-token-value" })
    }
}
