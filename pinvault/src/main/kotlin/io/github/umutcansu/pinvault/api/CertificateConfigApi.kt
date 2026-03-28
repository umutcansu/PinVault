package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.model.CertificateConfig

/**
 * Backend API interface for fetching SSL certificate configuration.
 *
 * Implement this in your app module with your actual Retrofit/network layer.
 * The initial call (bootstrap) should use a hardcoded pin set, since we don't
 * yet have a dynamic config.
 *
 * Example Retrofit implementation:
 * ```kotlin
 * class CertificateConfigApiImpl @Inject constructor(
 *     private val retrofitService: CertService
 * ) : CertificateConfigApi {
 *     override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
 *         return retrofitService.getCertConfig(currentVersion)
 *     }
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
     *                       Backend can use this to return 304-equivalent or delta.
     * @throws Exception on network or server errors.
     */
    suspend fun fetchConfig(currentVersion: Int): CertificateConfig
}
