package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.api.CertificateConfigApi
import io.github.umutcansu.pinvault.api.DefaultCertificateConfigApi
import io.github.umutcansu.pinvault.api.DeviceKeyProof
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Over a TLS Config API the server keeps a device's first E2E key and
 * replaces it only for a request carrying the device's token for an
 * end_to_end file. The router picks that token per Config API.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DeviceKeyProofTest {

    private fun router(clients: Map<String, ConfigApiClient> = emptyMap()) = VaultFileRouter(
        clients = clients,
        storageFor = { mockk<VaultStorageProvider>(relaxed = true) },
        deviceKeyProvider = null,
        deviceIdProvider = { "android-07" }
    )

    private fun file(
        key: String,
        api: String = "default-tls",
        policy: VaultFileAccessPolicy = VaultFileAccessPolicy.TOKEN,
        encryption: VaultFileEncryption = VaultFileEncryption.END_TO_END,
        endpoint: String = "api/v1/vault/$key",
        token: (() -> String)? = { "tok-$key" }
    ) = VaultFileConfig(
        key = key, endpoint = endpoint, configApiId = api,
        accessPolicy = policy, accessTokenProvider = token, encryption = encryption
    )

    @Test
    fun `the token of an end_to_end file of the same Config API is the proof`() {
        val files = listOf(
            file("flags", encryption = VaultFileEncryption.PLAIN),
            file("other-api-model", api = "secure-mtls"),
            file("public-e2e", policy = VaultFileAccessPolicy.PUBLIC, token = null),
            file("model", endpoint = "api/v1/vault/ml-model-v2?channel=beta")
        )
        assertEquals(DeviceKeyProof("ml-model-v2", "tok-model"), router().keyProof("default-tls", files))
    }

    @Test
    fun `no proof without a usable token`() {
        val files = listOf(
            file("blank", token = { "  " }),
            file("throws", token = { error("token store locked") }),
            file("none", token = null)
        )
        assertNull(router().keyProof("default-tls", files))
        assertNull(router().keyProof("default-tls", emptyList()))
    }

    @Test
    fun `registration carries the proof to the default API and stays plain for custom ones`() = runTest {
        val defaultApi = mockk<DefaultCertificateConfigApi>(relaxed = true)
        val customApi = mockk<CertificateConfigApi>(relaxed = true)
        val tlsClient = mockk<ConfigApiClient> { every { api } returns defaultApi }
        val customClient = mockk<ConfigApiClient> { every { api } returns customApi }
        coEvery { defaultApi.registerDevicePublicKey(any(), any(), any()) } returns Unit

        router(mapOf("default-tls" to tlsClient, "custom" to customClient))
            .registerDevicePublicKey("android-07", "PEM", listOf(file("model")))

        coVerify { defaultApi.registerDevicePublicKey("android-07", "PEM", DeviceKeyProof("model", "tok-model")) }
        coVerify { customApi.registerDevicePublicKey("android-07", "PEM") }
    }
}
