package com.example.pinvault.server

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import com.example.pinvault.server.route.certificateConfigRoutes
import com.example.pinvault.server.route.hostRoutes
import com.example.pinvault.server.service.CertificateService
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.MockServerManager
import com.example.pinvault.server.store.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.*

/**
 * Remote mTLS E2E Test
 *
 * Gerçek mTLS host'a (192.168.1.217:9443) bağlantı testi.
 * client.p12 ile mTLS handshake yapılır.
 *
 * Önkoşul:
 * - 192.168.1.217:9443'te mTLS sunucu çalışıyor
 * - /Users/thell/Downloads/certs/client.p12 mevcut (password: changeit)
 * - /Users/thell/Downloads/certs/server.jks mevcut (server cert)
 *
 * NOT: Bu test sadece hedef sunucu erişilebilir olduğunda çalışır.
 *      CI'da `-Dremote.mtls.skip=true` ile atlanabilir.
 */
class RemoteMtlsE2ETest {

    companion object {
        private const val REMOTE_HOST = "192.168.1.217"
        private const val REMOTE_PORT = 9443
        private const val REMOTE_URL = "https://$REMOTE_HOST:$REMOTE_PORT"
        private const val CLIENT_P12_PATH = "/Users/thell/Downloads/certs/client.p12"
        private const val SERVER_JKS_PATH = "/Users/thell/Downloads/certs/server.jks"
        private const val PASSWORD = "changeit"
        // SPKI SHA-256 pin from server cert
        private const val SERVER_PIN = "I19FuAvWij0v4d6igzKgOb7hsHzQTWjzGKqygf0SMJE="
    }

    private fun shouldSkip(): Boolean {
        if (System.getProperty("remote.mtls.skip") == "true") return true
        if (!File(CLIENT_P12_PATH).exists()) return true
        // Quick connectivity check
        return try {
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress(REMOTE_HOST, REMOTE_PORT), 2000)
            }
            false
        } catch (_: Exception) {
            true
        }
    }

    private fun buildMtlsClient(): OkHttpClient {
        // Client keystore (for mTLS — presents client cert)
        val clientKs = KeyStore.getInstance("PKCS12")
        File(CLIENT_P12_PATH).inputStream().use { clientKs.load(it, PASSWORD.toCharArray()) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(clientKs, PASSWORD.toCharArray())

        // Trust store (trust the server cert)
        val serverKs = KeyStore.getInstance("JKS")
        File(SERVER_JKS_PATH).inputStream().use { serverKs.load(it, PASSWORD.toCharArray()) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(serverKs)

        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(kmf.keyManagers, tmf.trustManagers, null)

        val tm = tmf.trustManagers.first() as X509TrustManager

        return OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, tm)
            .hostnameVerifier { _, _ -> true } // self-signed, SAN may not match IP
            .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
            .build()
    }

    // ── Remote mTLS bağlantı testi ──────────────────────

    @Test
    fun `remote mTLS — client cert ile bağlantı başarılı`() {
        if (shouldSkip()) {
            println("SKIPPED: Remote mTLS host not reachable ($REMOTE_URL)")
            return
        }

        val client = buildMtlsClient()
        val request = Request.Builder().url("$REMOTE_URL/health").build()

        val response = client.newCall(request).execute()
        println("Remote mTLS response: ${response.code} — ${response.body?.string()?.take(200)}")
        assertTrue(response.isSuccessful, "Expected 2xx but got ${response.code}")
    }

    @Test
    fun `remote mTLS — client cert olmadan reddedilir`() {
        if (shouldSkip()) {
            println("SKIPPED: Remote mTLS host not reachable ($REMOTE_URL)")
            return
        }

        // Trust server but do NOT present client cert
        val serverKs = KeyStore.getInstance("JKS")
        File(SERVER_JKS_PATH).inputStream().use { serverKs.load(it, PASSWORD.toCharArray()) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(serverKs)

        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, tmf.trustManagers, null) // NO client key managers

        val tm = tmf.trustManagers.first() as X509TrustManager
        val noClientCertClient = OkHttpClient.Builder()
            .sslSocketFactory(sslCtx.socketFactory, tm)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
            .build()

        val request = Request.Builder().url("$REMOTE_URL/health").build()

        try {
            val response = noClientCertClient.newCall(request).execute()
            fail("Expected SSL exception but got ${response.code}")
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            // Expected — server requires client cert
            println("Correctly rejected: ${e.message}")
        } catch (e: javax.net.ssl.SSLException) {
            println("Correctly rejected (SSLException): ${e.message}")
        } catch (e: java.net.SocketException) {
            println("Correctly rejected (SocketException): ${e.message}")
        }
    }

    // ── Web + Android E2E akışı ─────────────────────────

    @Test
    fun `E2E — Web config'e mTLS host ekle, cert yükle, download doğrula`() {
        if (shouldSkip()) {
            println("SKIPPED: Remote mTLS host not reachable")
            return
        }

        // Bu test demo-server'ın management API'sini kullanır (localhost:8090)
        val mgmtClient = OkHttpClient.Builder()
            .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
            .build()

        // 1. Sunucu çalışıyor mu?
        val healthReq = Request.Builder().url("http://localhost:8090/health").build()
        val healthResp = try { mgmtClient.newCall(healthReq).execute() } catch (_: Exception) {
            println("SKIPPED: Demo-server not running at localhost:8090")
            return
        }
        if (!healthResp.isSuccessful) {
            println("SKIPPED: Demo-server unhealthy")
            return
        }

        // 2. Config'i oku
        val configReq = Request.Builder()
            .url("http://localhost:8090/api/v1/certificate-config?signed=false")
            .build()
        val configResp = mgmtClient.newCall(configReq).execute()
        val configJson = configResp.body?.string() ?: "{}"
        println("Current config: ${configJson.take(300)}")

        // 3. Client cert download kontrol
        val dlReq = Request.Builder()
            .url("http://localhost:8090/api/v1/client-certs/$REMOTE_HOST/download")
            .build()
        val dlResp = mgmtClient.newCall(dlReq).execute()
        println("Client cert download: ${dlResp.code} (${dlResp.body?.bytes()?.size ?: 0} bytes)")

        if (dlResp.isSuccessful) {
            // 4. İndirilen P12 ile mTLS bağlantı yap
            val p12Bytes = dlResp.body?.bytes()
            if (p12Bytes != null && p12Bytes.isNotEmpty()) {
                val ks = KeyStore.getInstance("PKCS12")
                ks.load(p12Bytes.inputStream(), PASSWORD.toCharArray())
                val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                kmf.init(ks, PASSWORD.toCharArray())

                val serverKs = KeyStore.getInstance("JKS")
                File(SERVER_JKS_PATH).inputStream().use { serverKs.load(it, PASSWORD.toCharArray()) }
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(serverKs)

                val sslCtx = SSLContext.getInstance("TLS")
                sslCtx.init(kmf.keyManagers, tmf.trustManagers, null)
                val tm = tmf.trustManagers.first() as X509TrustManager

                val downloadedCertClient = OkHttpClient.Builder()
                    .sslSocketFactory(sslCtx.socketFactory, tm)
                    .hostnameVerifier { _, _ -> true }
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()

                val mtlsReq = Request.Builder().url("$REMOTE_URL/health").build()
                val mtlsResp = downloadedCertClient.newCall(mtlsReq).execute()
                println("mTLS with downloaded cert: ${mtlsResp.code}")
                assertTrue(mtlsResp.isSuccessful, "Downloaded cert should work for mTLS")
            }
        } else {
            println("No client cert stored for $REMOTE_HOST — upload first via Web UI or curl")
        }
    }

    // ── Pin doğrulaması ─────────────────────────────────

    @Test
    fun `remote host — pin hash doğru`() {
        if (shouldSkip()) {
            println("SKIPPED: Remote mTLS host not reachable")
            return
        }

        // Server cert'in public key pin'ini doğrula
        val serverKs = KeyStore.getInstance("JKS")
        File(SERVER_JKS_PATH).inputStream().use { serverKs.load(it, PASSWORD.toCharArray()) }
        val cert = serverKs.getCertificate("server") as java.security.cert.X509Certificate
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
        val pin = java.util.Base64.getEncoder().encodeToString(digest)

        assertEquals(SERVER_PIN, pin)
        println("Server pin verified: $pin")
    }
}
