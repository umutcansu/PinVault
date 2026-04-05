package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.crypto.ConfigSignatureVerifier
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import com.google.gson.Gson
import okhttp3.ResponseBody
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Query
import retrofit2.http.Url
import timber.log.Timber

/**
 * Default implementation of [CertificateConfigApi] using Retrofit.
 *
 * If [signaturePublicKey] is provided, the response must be a signed envelope
 * (`{payload, signature}`) and the signature is verified before parsing.
 * If null, the response is parsed directly as [CertificateConfig] (backward compatible).
 */
internal class DefaultCertificateConfigApi(
    configUrl: String,
    private val configEndpoint: String = "api/v1/certificate-config",
    private val healthEndpoint: String = "health",
    private val clientCertEndpoint: String = "api/v1/client-certs",
    private val signaturePublicKey: String? = null,
    bootstrapPins: List<HostPin>,
    sslManager: DynamicSSLManager
) : CertificateConfigApi {

    private val gson = Gson()

    private val service: DynamicConfigService by lazy {
        val bootstrapClient = sslManager.buildBootstrapClient(bootstrapPins)

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
            // İmza doğrulaması kapalı — direkt CertificateConfig parse et
            return service.getConfig(configEndpoint, currentVersion)
        }

        // İmzalı response al → doğrula → parse et
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
}

/** Uses @Url so endpoint paths are determined at runtime, not compile time. */
internal interface DynamicConfigService {
    @GET
    suspend fun healthCheck(@retrofit2.http.Url url: String): Map<String, String>

    /** İmza doğrulaması kapalıyken — direkt CertificateConfig */
    @GET
    suspend fun getConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): CertificateConfig

    /** İmza doğrulaması açıkken — SignedConfigResponse envelope */
    @GET
    suspend fun getSignedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): SignedConfigResponse

    /** Binary download (P12 client cert etc.) */
    @GET
    suspend fun downloadBinary(@Url url: String): ResponseBody
}
