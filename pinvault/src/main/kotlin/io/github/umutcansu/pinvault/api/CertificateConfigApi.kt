package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.VaultDownloadReport

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
     * @param currentVersion The version currently held by the client (0 if first call).
     * @throws Exception on network or server errors.
     */
    suspend fun fetchConfig(currentVersion: Int): CertificateConfig

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
     * @param endpoint Relative path to the file endpoint (e.g. "api/v1/vault/ml-model").
     * @return Raw file bytes.
     */
    suspend fun downloadVaultFile(endpoint: String): ByteArray

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
