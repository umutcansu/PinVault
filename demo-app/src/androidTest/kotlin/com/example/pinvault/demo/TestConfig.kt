package com.example.pinvault.demo

import android.os.Build
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Test ortam config'i — emülatör vs fiziksel cihaz otomatik algılama.
 * Emülatörde 10.0.2.2, fiziksel cihazda bilgisayarın LAN IP'si kullanılır.
 */
object TestConfig {
    private val isEmulator: Boolean = Build.FINGERPRINT.contains("generic")
            || Build.FINGERPRINT.contains("emulator")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK")
            || Build.MANUFACTURER.contains("Genymotion")
            || Build.PRODUCT.contains("sdk")
            || Build.PRODUCT.contains("emulator")

    /** Demo-server'ın çalıştığı bilgisayarın IP'si */
    val HOST_IP: String = if (isEmulator) "10.0.2.2" else "192.168.1.80"

    /** TLS Config API */
    val TLS_CONFIG_URL = "https://$HOST_IP:8091/"

    /** mTLS Config API */
    val MTLS_CONFIG_URL = "https://$HOST_IP:8092/"

    /** Management API */
    val MANAGEMENT_URL = "http://$HOST_IP:8090"

    /** Mock TLS Host — emülatörde :8443, fiziksel cihazda :8444 */
    val TLS_HOST_PORT = if (isEmulator) 8443 else 8444
    val TLS_HOST_URL = "https://$HOST_IP:$TLS_HOST_PORT/health"

    /** Remote mTLS Host IP */
    const val MTLS_HOST_IP = "192.168.1.217"

    /** mTLS Host URL */
    val MTLS_HOST_URL = "https://$MTLS_HOST_IP:9443/health"

    /** Host cert label (config'teki hostname ile eşleşmeli) */
    val MTLS_HOST_CERT_LABEL = "host_$MTLS_HOST_IP"

    /** Vault file test endpoint (management API üzerinden yükleme/indirme) */
    val VAULT_API_URL = "$MANAGEMENT_URL/api/v1/vault"

    /** Bootstrap pins — demo-server TLS cert */
    val BOOTSTRAP_PINS = listOf(
        io.github.umutcansu.pinvault.model.HostPin(HOST_IP, listOf(
            "ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=",
            "vXC1UZ8OFlga9Ltwsa2Hyg2lqZkLUE+DbdBPvT3ah3o="
        ))
    )

    /** Pin doğrulamasız plain HTTP client — sadece test altyapısı için */
    val plainClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build()
    }

    /** TLS doğrulamasız HTTPS client — sunucu erişilebilirlik kontrolü ve enrollment için */
    val trustAllClient: OkHttpClient by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustAll), java.security.SecureRandom())
        OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustAll)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Management API üzerinden mTLS Config API'nin restart olmasını bekler.
     * Enrollment sonrası sunucu yeni truststore ile mTLS connector'ı yeniden başlatır.
     * İki aşamalı: (1) management API rapor eder, (2) port erişilebilir olur.
     */
    fun waitForMtlsRestart(timeoutMs: Long = 15000) {
        val deadline = System.currentTimeMillis() + timeoutMs

        // Aşama 1: Management API mTLS running raporlayana kadar bekle
        while (System.currentTimeMillis() < deadline) {
            try {
                val resp = plainClient.newCall(
                    Request.Builder().url("$MANAGEMENT_URL/api/v1/config-apis").build()
                ).execute()
                val body = resp.body?.string() ?: ""
                if (body.contains("mtls") && body.contains("\"running\":true")) break
            } catch (_: Exception) {}
            Thread.sleep(500)
        }

        // Aşama 2: mTLS port'a TCP bağlantısı kurulana kadar bekle (Netty bind)
        while (System.currentTimeMillis() < deadline) {
            try {
                val resp = trustAllClient.newCall(
                    Request.Builder().url("${MTLS_CONFIG_URL}health").build()
                ).execute()
                resp.close()
                return
            } catch (_: javax.net.ssl.SSLHandshakeException) {
                // Client cert yok → handshake fail ama sunucu dinliyor = OK
                return
            } catch (_: Exception) {}
            Thread.sleep(500)
        }
    }

    /**
     * Belirtilen HTTPS URL'e bağlantı kurulabilene kadar bekler.
     * Sertifika doğrulaması yapmaz — sadece TCP+TLS handshake kontrolü.
     */
    fun waitForServerReachable(url: String, timeoutMs: Long = 5000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                val resp = trustAllClient.newCall(
                    Request.Builder().url(url).build()
                ).execute()
                resp.close()
                return
            } catch (_: Exception) {}
            Thread.sleep(500)
        }
    }
}
