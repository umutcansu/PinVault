package io.github.umutcansu.pinvault.internal

import io.github.umutcansu.pinvault.crypto.VaultFileDecryptor
import io.github.umutcansu.pinvault.keystore.DeviceKeyProvider
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.model.VaultFileAccessPolicy
import io.github.umutcansu.pinvault.model.VaultFileConfig
import io.github.umutcansu.pinvault.model.VaultFileEncryption
import io.github.umutcansu.pinvault.model.VaultFileResult
import io.github.umutcansu.pinvault.store.VaultStorageProvider
import timber.log.Timber

/**
 * Routes vault file fetches to the right [ConfigApiClient] and applies
 * per-file decryption on the way back.
 *
 * Responsibilities:
 *   1. Look up `file.configApiId` in the per-block client map.
 *   2. Resolve deviceId + access token based on [VaultFileConfig.accessPolicy].
 *   3. Call `downloadVaultFileWithMeta` on the bound client's API impl.
 *   4. For `encryption = END_TO_END`, decrypt the envelope via
 *      [VaultFileDecryptor] using [deviceKeyProvider]'s private key.
 *   5. Persist via the file's [VaultStorageProvider] and return a
 *      [VaultFileResult].
 *
 * Storage/reporting is the caller's concern — router returns the VaultFileResult
 * for the caller to handle (PinVault orchestrates notify/listener/report).
 */
internal class VaultFileRouter(
    private val clients: Map<String, ConfigApiClient>,
    private val storageFor: (String) -> VaultStorageProvider,
    private val deviceKeyProvider: DeviceKeyProvider?,
    private val deviceIdProvider: () -> String
) {

    /**
     * Perform the fetch. Does NOT send the distribution report — caller does
     * that once it has the final [VaultFileResult].
     */
    suspend fun fetchFile(file: VaultFileConfig): VaultFileResult {
        val client = clients[file.configApiId]
            ?: return VaultFileResult.Failed(
                file.key,
                "VaultFile '${file.key}' bound to unknown configApi '${file.configApiId}'"
            )

        return try {
            val storage = storageFor(file.key)
            val currentVersion = storage.getVersion(file.key)

            val deviceId = deviceIdProvider()
            val token = when (file.accessPolicy) {
                VaultFileAccessPolicy.TOKEN,
                VaultFileAccessPolicy.TOKEN_MTLS -> file.accessTokenProvider?.invoke()
                else -> null
            }
            Timber.d("Vault fetch [%s] via %s (token=%s)", file.key,
                file.accessPolicy.name.lowercase(),
                if (token != null) "***" + token.takeLast(4) else "none")

            val response: VaultFetchResponse = client.api.downloadVaultFileWithMeta(
                endpoint = file.endpoint,
                currentVersion = currentVersion,
                deviceId = deviceId.takeIf { it.isNotBlank() },
                accessToken = token
            )

            if (response.notModified) {
                return VaultFileResult.AlreadyCurrent(file.key, currentVersion)
            }

            // Decrypt if E2E
            val plain: ByteArray = when (
                VaultFileEncryption.entries.find { it.name.equals(response.encryption, ignoreCase = true) }
                    ?: file.encryption
            ) {
                VaultFileEncryption.END_TO_END -> {
                    val kp = deviceKeyProvider
                        ?: return VaultFileResult.Failed(
                            file.key,
                            "encryption=end_to_end requires DeviceKeyProvider; none configured"
                        )
                    kp.ensureKeyPair()
                    try {
                        VaultFileDecryptor.decrypt(response.content, kp.getPrivateKey())
                    } catch (e: Exception) {
                        Timber.e(e, "E2E decrypt failed: %s", file.key)
                        return VaultFileResult.Failed(file.key, "E2E decrypt failed: ${e.message}", e)
                    }
                }
                else -> response.content
            }

            // Persist. Dedupe against stored to emit AlreadyCurrent when server
            // didn't 304 but the bytes match (e.g. legacy backend without
            // version-header support).
            val storedBytes = storage.load(file.key)
            if (storedBytes != null && plain.contentEquals(storedBytes)) {
                VaultFileResult.AlreadyCurrent(file.key, currentVersion)
            } else {
                val newVersion = if (response.version > 0) response.version else (currentVersion + 1)
                storage.save(file.key, plain, newVersion)
                Timber.d(
                    "Vault file updated [%s]: %s v%d → v%d (%d bytes, encryption=%s)",
                    file.configApiId, file.key, currentVersion, newVersion, plain.size, response.encryption
                )
                VaultFileResult.Updated(file.key, newVersion, plain)
            }
        } catch (e: Exception) {
            // Beklenen HTTP 4xx senaryoları (dosya yok / geçersiz token / yetkisiz)
            // genuine bug değil — policy enforcement'ı doğrulayan testler bu yolu
            // kasten tetikliyor. Stack trace olmadan W seviyesinde logla, üst katman
            // VaultFileResult.Failed ile zaten sinyal alıyor. 5xx veya ağ hatası gibi
            // gerçek problemler E olarak kalsın.
            val msg = e.message ?: ""
            val isExpected4xx = Regex("HTTP 4\\d{2}").containsMatchIn(msg)
            if (isExpected4xx) {
                Timber.w("Vault fetch rejected [%s]: %s — %s", file.configApiId, file.key, msg.take(120))
            } else {
                Timber.e(e, "Vault fetch failed [%s]: %s", file.configApiId, file.key)
            }
            VaultFileResult.Failed(file.key, e.message ?: "Unknown error", e)
        }
    }

    /** Ask the bound client's API to report the outcome. */
    suspend fun report(file: VaultFileConfig, report: VaultDownloadReport) {
        val client = clients[file.configApiId] ?: return
        try {
            client.api.reportVaultDownload(report)
        } catch (e: Exception) {
            Timber.e(e, "Report send failed [%s]: %s", file.configApiId, file.key)
        }
    }

    /** Register this device's RSA public key with EVERY Config API (E2E support). */
    suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String) {
        for ((id, client) in clients) {
            try {
                client.api.registerDevicePublicKey(deviceId, publicKeyPem)
            } catch (e: Exception) {
                Timber.w(e, "Public-key registration failed on [%s]", id)
            }
        }
    }
}
