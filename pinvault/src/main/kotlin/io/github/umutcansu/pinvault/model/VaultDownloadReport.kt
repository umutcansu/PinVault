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
    val deviceAlias: String,
    /**
     * status == "failed" ise başarısızlık nedeni (HTTP 401 / 404 / decrypt fail
     * / network error mesajı). Başarılı fetch'lerde null.
     */
    val failureReason: String? = null,
    /**
     * Fetch için kullanılan yetkilendirme: "public" (header'sız), "token",
     * "token_mtls", "api_key". Audit / debug için web UI + mobile log'larda
     * gösterilir. Başarısız fetch'te bile denenen method yazılır.
     */
    val authMethod: String? = null
)
