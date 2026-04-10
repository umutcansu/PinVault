package io.github.umutcansu.pinvault.model

/**
 * Report sent to server after a vault file download attempt.
 * Passed to [io.github.umutcansu.pinvault.api.CertificateConfigApi.reportVaultDownload].
 */
data class VaultDownloadReport(
    val key: String,
    val version: Int,
    val status: String,
    val deviceManufacturer: String,
    val deviceModel: String,
    val enrollmentLabel: String,
    val deviceId: String,
    val deviceAlias: String
)
