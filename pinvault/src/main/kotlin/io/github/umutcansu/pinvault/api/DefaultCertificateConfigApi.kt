package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.crypto.ConfigSignatureVerifier
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import com.google.gson.Gson
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Body
import retrofit2.http.Query
import retrofit2.http.QueryMap
import retrofit2.http.Url
import timber.log.Timber

/**
 * Default implementation of [CertificateConfigApi] using Retrofit/OkHttp.
 *
 * All endpoint paths are configurable. If [signaturePublicKey] is provided,
 * config responses must be signed envelopes with ECDSA-SHA256 verification.
 */
internal class DefaultCertificateConfigApi(
    private val configUrl: String,
    private val configEndpoint: String = "api/v1/certificate-config",
    private val healthEndpoint: String = "health",
    private val clientCertEndpoint: String = "api/v1/client-certs",
    private val enrollmentEndpoint: String = "api/v1/client-certs/enroll",
    private val vaultReportEndpoint: String = "api/v1/vault/report",
    private val signaturePublicKey: String? = null,
    bootstrapPins: List<HostPin>,
    private val sslManager: DynamicSSLManager
) : CertificateConfigApi {

    private val gson = Gson()

    private val bootstrapClient by lazy { sslManager.buildBootstrapClient(bootstrapPins) }

    private val service: DynamicConfigService by lazy {
        Retrofit.Builder()
            .baseUrl(configUrl)
            .client(bootstrapClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(DynamicConfigService::class.java)
    }

    override suspend fun healthCheck(): Boolean {
        return try {
            val response = service.healthCheck(healthEndpoint)
            val isHealthy = response["status"] == "ok"
            Timber.d("Health check: %s", if (isHealthy) "ok" else "unhealthy")
            isHealthy
        } catch (e: Exception) {
            Timber.e(e, "Health check failed")
            false
        }
    }

    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
        if (signaturePublicKey == null) {
            Timber.w("Config signature verification DISABLED — config integrity cannot be guaranteed. " +
                "Set signaturePublicKey in PinVaultConfig for production use.")
            return service.getConfig(configEndpoint, currentVersion)
        }

        val signed = service.getSignedConfig(configEndpoint, currentVersion)

        val valid = ConfigSignatureVerifier.verify(
            payload = signed.payload,
            signature = signed.signature,
            publicKeyBase64 = signaturePublicKey
        )

        if (!valid) {
            throw SecurityException(
                "Config signature verification failed — possible tampering detected. " +
                "Keeping previous safe config."
            )
        }

        return gson.fromJson(signed.payload, CertificateConfig::class.java)
    }

    override suspend fun downloadHostClientCert(hostname: String): ByteArray {
        val url = "$clientCertEndpoint/$hostname/download"
        Timber.d("Downloading host client cert: %s", url)
        val body = service.downloadBinary(url)
        return body.bytes()
    }

    override suspend fun downloadVaultFile(endpoint: String): ByteArray {
        Timber.d("Downloading vault file: %s", endpoint)
        val body = service.downloadBinary(endpoint)
        return body.bytes()
    }

    /**
     * V2 download with full HTTP metadata. Handles:
     *   - ?version=N query for 304 support
     *   - X-Device-Id header (required when access_policy is token/token_mtls)
     *   - X-Vault-Token header (when accessToken is provided)
     *   - X-Vault-Version / X-Vault-Encryption response headers
     *   - 304 Not Modified → notModified=true, empty content
     *   - 401/other failures → throws Exception
     *
     * OkHttp's synchronous `.execute()` is a blocking call; this method must
     * run off the main thread. We wrap in [Dispatchers.IO] so callers who
     * forget to dispatch don't hit [NetworkOnMainThreadException].
     */
    override suspend fun downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int,
        deviceId: String?,
        accessToken: String?
    ): VaultFetchResponse = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        Timber.d("Downloading vault file (meta): %s v=%d", endpoint, currentVersion)
        val url = if (endpoint.contains("?")) "$endpoint&version=$currentVersion"
                  else "$endpoint?version=$currentVersion"

        val requestBuilder = okhttp3.Request.Builder().url("${configUrl}$url").get()
        deviceId?.let { requestBuilder.header("X-Device-Id", it) }
        accessToken?.let { requestBuilder.header("X-Vault-Token", it) }

        val response = bootstrapClient.newCall(requestBuilder.build()).execute()
        response.use { resp ->
            val version = resp.header("X-Vault-Version")?.toIntOrNull() ?: currentVersion
            val encryption = resp.header("X-Vault-Encryption") ?: "plain"

            if (resp.code == 304) {
                return@withContext VaultFetchResponse(
                    content = ByteArray(0),
                    version = version,
                    encryption = encryption,
                    notModified = true
                )
            }

            if (!resp.isSuccessful) {
                throw Exception("Vault fetch failed: HTTP ${resp.code} — ${resp.body?.string()?.take(200)}")
            }

            val bytes = resp.body?.bytes() ?: ByteArray(0)
            VaultFetchResponse(
                content = bytes,
                version = version,
                encryption = encryption,
                notModified = false
            )
        }
    }

    /**
     * Scoped config fetch. Sends `?hosts=a,b,c` query param and/or X-Device-Id
     * header so the server can filter pins per the device's ACL.
     */
    override suspend fun fetchScopedConfig(
        currentVersion: Int,
        hosts: List<String>?,
        deviceId: String?
    ): CertificateConfig {
        val hostsParam = hosts?.takeIf { it.isNotEmpty() }?.joinToString(",")

        if (signaturePublicKey == null) {
            Timber.w("Config signature verification DISABLED (scoped fetch)")
            return if (hostsParam != null || deviceId != null) {
                service.getScopedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
            } else {
                service.getConfig(configEndpoint, currentVersion)
            }
        }

        val signed = if (hostsParam != null || deviceId != null) {
            service.getScopedSignedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
        } else {
            service.getSignedConfig(configEndpoint, currentVersion)
        }

        val valid = ConfigSignatureVerifier.verify(
            payload = signed.payload,
            signature = signed.signature,
            publicKeyBase64 = signaturePublicKey
        )
        if (!valid) {
            throw SecurityException("Config signature verification failed (scoped fetch).")
        }
        return gson.fromJson(signed.payload, CertificateConfig::class.java)
    }

    /** Register RSA public key for E2E vault file encryption. */
    override suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String) =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val json = org.json.JSONObject()
                .put("publicKeyPem", publicKeyPem)
                .put("algorithm", "RSA-OAEP-SHA256")
                .toString()
            val requestBody = json.toRequestBody("application/json".toMediaType())
            val request = okhttp3.Request.Builder()
                .url("${configUrl}api/v1/vault/devices/$deviceId/public-key")
                .post(requestBody)
                .build()
            bootstrapClient.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) {
                    throw Exception("Device public key registration failed: HTTP ${resp.code}")
                }
                Timber.d("Registered device public key: %s", deviceId)
            }
        }

    override suspend fun enroll(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?
    ): EnrollmentResult = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val json = org.json.JSONObject()
        token?.let { json.put("token", it) }
        deviceId?.let { json.put("deviceId", it) }
        deviceAlias?.let { json.put("deviceAlias", it) }
        deviceUid?.let { json.put("deviceUid", it) }

        val requestBody = json.toString().toRequestBody("application/json".toMediaType())
        val request = okhttp3.Request.Builder()
            .url("${configUrl}$enrollmentEndpoint")
            .post(requestBody)
            .build()

        val response = bootstrapClient.newCall(request).execute()
        if (!response.isSuccessful) {
            throw Exception("Enrollment failed — HTTP ${response.code}")
        }

        val p12Bytes = response.body?.bytes() ?: throw Exception("Empty enrollment response")
        val p12Hash = response.header("X-P12-SHA256")

        Timber.d("Enrollment successful — %d bytes", p12Bytes.size)
        EnrollmentResult(p12Bytes, p12Hash)
    }

    override suspend fun reportVaultDownload(report: VaultDownloadReport) =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val json = org.json.JSONObject()
                    .put("key", report.key)
                    .put("version", report.version)
                    .put("status", report.status)
                    .put("deviceManufacturer", report.deviceManufacturer)
                    .put("deviceModel", report.deviceModel)
                    .put("enrollmentLabel", report.enrollmentLabel)
                    .put("deviceId", report.deviceId)
                    .put("deviceAlias", report.deviceAlias)
                    .apply { report.failureReason?.let { put("failureReason", it) } }
                    .apply { report.authMethod?.let { put("authMethod", it) } }
                    .toString()

                val requestBody = json.toRequestBody("application/json".toMediaType())
                val request = okhttp3.Request.Builder()
                    .url("${configUrl}$vaultReportEndpoint")
                    .post(requestBody)
                    .build()

                val reportClient = bootstrapClient.newBuilder()
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()

                reportClient.newCall(request).execute().close()
                Timber.d("Vault report sent: %s → %s", report.key, report.status)
            } catch (e: Exception) {
                Timber.e(e, "Failed to report vault download: %s", report.key)
            }
        }
}

/** Uses @Url so endpoint paths are determined at runtime, not compile time. */
internal interface DynamicConfigService {
    @GET
    suspend fun healthCheck(@retrofit2.http.Url url: String): Map<String, String>

    @GET
    suspend fun getConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): CertificateConfig

    @GET
    suspend fun getSignedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): SignedConfigResponse

    /** V2 scoped config fetch. `hosts` is null when not filtering. */
    @GET
    suspend fun getScopedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int,
        @Query("hosts") hosts: String?,
        @Header("X-Device-Id") deviceId: String?
    ): CertificateConfig

    @GET
    suspend fun getScopedSignedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int,
        @Query("hosts") hosts: String?,
        @Header("X-Device-Id") deviceId: String?
    ): SignedConfigResponse

    @GET
    suspend fun downloadBinary(@Url url: String): ResponseBody
}
