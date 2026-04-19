package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse

/**
 * Backend API interface for fetching SSL certificate configuration.
 *
 * Implement this to integrate PinVault with any backend (REST, gRPC, local files, etc.).
 * The default implementation [DefaultCertificateConfigApi] provides HTTP/Retrofit-based
 * communication. Override any method to customize behavior.
 *
 * Example custom implementation:
 * ```kotlin
 * class MyCertApi : CertificateConfigApi {
 *     override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
 *         return myBackend.getPins(currentVersion)
 *     }
 *     override suspend fun healthCheck(): Boolean = true
 *     // ... other methods
 * }
 * ```
 */
interface CertificateConfigApi {
    /**
     * Checks if the backend is reachable.
     * @return true if healthy, false otherwise.
     */
    suspend fun healthCheck(): Boolean

    /**
     * Fetches the latest certificate config from the backend.
     *
     * @param currentVersion The version currently held by the client (0 if first call).
     * @throws Exception on network or server errors.
     */
    suspend fun fetchConfig(currentVersion: Int): CertificateConfig

    /**
     * V2 scoped fetch: the backend returns only pins for the intersection of
     * [hosts] and the device's server-side ACL. Omit [hosts] to let the
     * server decide based purely on device ACL (or return everything when
     * [deviceId] is also null — legacy behavior).
     *
     * Default implementation drops the extra parameters and delegates to
     * [fetchConfig] so existing backend impls continue to work.
     */
    suspend fun fetchScopedConfig(
        currentVersion: Int,
        hosts: List<String>? = null,
        deviceId: String? = null
    ): CertificateConfig {
        return fetchConfig(currentVersion)
    }

    /**
     * Downloads a host-specific PKCS12 client certificate for mTLS.
     * Called when [io.github.umutcansu.pinvault.model.HostPin.mtls] is true
     * and [io.github.umutcansu.pinvault.model.HostPin.clientCertVersion] has changed.
     *
     * @param hostname The host whose client cert to download.
     * @return PKCS12 bytes for the host's client certificate.
     */
    suspend fun downloadHostClientCert(hostname: String): ByteArray

    /**
     * Downloads a vault file from the given endpoint path.
     *
     * Legacy method (V1). New code should use [downloadVaultFileWithMeta] to
     * receive encryption metadata needed for [VaultFetchResponse.encryption] =
     * "end_to_end" files.
     *
     * @param endpoint Relative path to the file endpoint (e.g. "api/v1/vault/ml-model").
     * @return Raw file bytes.
     */
    suspend fun downloadVaultFile(endpoint: String): ByteArray

    /**
     * V2 download with full metadata — returns content + version + encryption
     * mode. Required for per-file policy (token) and encryption (end_to_end)
     * support introduced in V2.
     *
     * Default implementation wraps [downloadVaultFile] for backward
     * compatibility: callers that haven't overridden this get plain bytes
     * with unknown version.
     *
     * @param endpoint Relative path to the file.
     * @param currentVersion Version currently held by client (for 304 support).
     * @param deviceId Device identifier sent as X-Device-Id header.
     * @param accessToken Per-file token sent as X-Vault-Token header (required
     *                    when the file's access_policy is "token" or "token_mtls").
     */
    suspend fun downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int = 0,
        deviceId: String? = null,
        accessToken: String? = null
    ): VaultFetchResponse {
        // Default: fall through to legacy downloadVaultFile. Returns plain
        // bytes with version=0 — good enough for tests and custom backends
        // that haven't implemented the new endpoint.
        val bytes = downloadVaultFile(endpoint)
        return VaultFetchResponse(content = bytes, version = 0, encryption = "plain")
    }

    /**
     * Registers the device's RSA public key with a Config API. The server
     * uses this key to wrap session keys for encryption = "end_to_end" files.
     *
     * Default implementation is a no-op — custom backends without E2E support
     * can ignore this call.
     *
     * @param deviceId Device identifier.
     * @param publicKeyPem PEM-encoded RSA public key
     *        ("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----").
     */
    suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String) {
        // Default: no-op.
    }

    /**
     * Enrolls a device to obtain a PKCS12 client certificate.
     * Called by [io.github.umutcansu.pinvault.PinVault.enroll] and
     * [io.github.umutcansu.pinvault.PinVault.autoEnroll].
     *
     * Implement token-based or device-based enrollment depending on your backend.
     *
     * @param token One-time enrollment token (null for auto-enrollment).
     * @param deviceId Device identifier for auto-enrollment (null for token-based).
     * @param deviceAlias Human-readable device name (optional).
     * @param deviceUid Unique device identifier (optional).
     * @return [EnrollmentResult] containing P12 bytes and optional hash.
     * @throws Exception on enrollment failure.
     */
    suspend fun enroll(
        token: String?,
        deviceId: String?,
        deviceAlias: String? = null,
        deviceUid: String? = null
    ): EnrollmentResult

    /**
     * Reports a vault file download to the server for analytics/tracking.
     * Fire-and-forget — failures are logged but don't affect vault file operations.
     *
     * @param report Download report with device and file metadata.
     */
    suspend fun reportVaultDownload(report: VaultDownloadReport) {
        // Default: no-op. Override to enable server-side tracking.
    }
}
