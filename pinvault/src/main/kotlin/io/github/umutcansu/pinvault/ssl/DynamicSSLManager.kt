package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import timber.log.Timber
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import android.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/**
 * Builds OkHttpClient instances with certificate pinning from a [CertificateConfig].
 *
 * ## Trust model
 * Pinning is implemented inside a custom [X509ExtendedTrustManager] rather than via
 * OkHttp's [okhttp3.CertificatePinner].  This avoids an Android/Conscrypt limitation
 * where [javax.net.ssl.SSLSession.getPeerCertificates] throws
 * [javax.net.ssl.SSLPeerUnverifiedException] when a non-system TrustManager is used,
 * leaving OkHttp's CertificatePinner with an empty peer-certificate chain.
 *
 * Instead, `checkServerTrusted()` is invoked by Conscrypt during the TLS handshake
 * with the actual certificate chain, making the pin hash check 100 % reliable.
 */
internal class DynamicSSLManager {

    /**
     * Applies certificate pinning to an existing [OkHttpClient.Builder].
     * Installs a custom [X509ExtendedTrustManager] that enforces public-key pinning.
     */
    fun applyTo(builder: OkHttpClient.Builder, config: CertificateConfig) {
        val tm = pinnedTrustManager(config.pins)
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, arrayOf(tm), null)
        builder.sslSocketFactory(sslCtx.socketFactory, tm)

        Timber.d(
            "Applied pinning via TrustManager — version: %d, %d hosts",
            config.version, config.pins.size
        )
    }

    /**
     * Creates an OkHttpClient pinned according to the given [config].
     * If [config] is null, returns a client with system-default trust (no pinning).
     */
    fun buildClient(
        config: CertificateConfig?,
        connectionSettings: HttpConnectionSettings = HttpConnectionSettings()
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .cache(null)
            .connectionPool(
                ConnectionPool(
                    connectionSettings.maxIdleConnections,
                    connectionSettings.keepAliveDuration,
                    connectionSettings.keepAliveDurationUnit
                )
            )

        applyTimeouts(builder, connectionSettings)

        if (config == null) {
            Timber.d("No config — building client with system defaults")
            return builder.build()
        }

        applyTo(builder, config)
        return builder.build()
    }

    /**
     * Builds a bootstrap OkHttpClient used for the initial config fetch.
     *
     * If [bootstrapPins] are provided, the client is pinned so even the
     * first config fetch is protected against MITM.
     * If the config endpoint is plain HTTP, pinning is skipped automatically
     * (TrustManager is only invoked for TLS connections).
     */
    fun buildBootstrapClient(bootstrapPins: List<HostPin>): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS)

        if (bootstrapPins.isNotEmpty()) {
            val config = CertificateConfig(version = 0, pins = bootstrapPins)
            applyTo(builder, config)
            Timber.d("Bootstrap client pinned — %d hosts", bootstrapPins.size)
        } else {
            Timber.d("Bootstrap client — no pins, using system defaults")
        }

        return builder.build()
    }

    private fun applyTimeouts(builder: OkHttpClient.Builder, settings: HttpConnectionSettings) {
        if (settings.connectTimeout > 0) builder.connectTimeout(settings.connectTimeout, TimeUnit.SECONDS)
        if (settings.readTimeout > 0)    builder.readTimeout(settings.readTimeout, TimeUnit.SECONDS)
        if (settings.writeTimeout > 0)   builder.writeTimeout(settings.writeTimeout, TimeUnit.SECONDS)
        if (settings.callTimeout > 0)    builder.callTimeout(settings.callTimeout, TimeUnit.SECONDS)
    }

    /**
     * Builds a set of accepted SHA-256 pin hashes from [pins].
     * Includes emulator alias: localhost/127.0.0.1 hashes are also valid for 10.0.2.2.
     */
    private fun buildAcceptedPins(pins: List<HostPin>): Set<String> =
        pins.flatMap { it.sha256 }.toSet()

    /**
     * Returns a [X509ExtendedTrustManager] that:
     * - Accepts self-signed certificates (no CA-chain validation).
     * - Verifies that the leaf certificate's public-key SHA-256 matches one of [pins].
     *
     * Security comes entirely from public-key pinning — this is equivalent to, and more
     * reliable than, OkHttp's [okhttp3.CertificatePinner] on Android.
     */
    private fun pinnedTrustManager(pins: List<HostPin>): X509TrustManager {
        val acceptedHashes = buildAcceptedPins(pins)

        return object : X509ExtendedTrustManager() {

            // ── Server auth (called by Conscrypt during handshake) ─────────────────

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String,
                socket: Socket
            ) = verifyPin(chain)

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String,
                engine: SSLEngine
            ) = verifyPin(chain)

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String
            ) = verifyPin(chain)

            // ── Client auth ───────────────────────────────────────────────────────

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

            // ── Pin verification ──────────────────────────────────────────────────

            private fun verifyPin(chain: Array<X509Certificate>) {
                if (chain.isEmpty()) throw CertificateException("No server certificate provided")

                val leaf = chain[0]

                // Pin listesi boşsa bağlantıyı reddet — boş pin = güvenlik yok
                if (acceptedHashes.isEmpty()) {
                    throw CertificateException(
                        "No pins configured — refusing connection. " +
                        "Call PinVault.init() before making HTTPS requests."
                    )
                }

                // Sertifika süre kontrolü
                try {
                    leaf.checkValidity()
                } catch (e: Exception) {
                    throw CertificateException("Server certificate is expired or not yet valid: ${e.message}")
                }

                // Pin doğrulama
                val certHash = sha256Base64(leaf.publicKey.encoded)
                if (certHash !in acceptedHashes) {
                    Timber.e("Pin mismatch! cert=$certHash, accepted=$acceptedHashes")
                    throw CertificateException(
                        "Certificate pinning failure!\n" +
                        "  Cert hash:    sha256/$certHash\n" +
                        "  Accepted pins: ${acceptedHashes.joinToString { "sha256/$it" }}"
                    )
                }

                Timber.d("Pin verified ✓ — sha256/%s", certHash.take(16))
            }
        }
    }

    private fun sha256Base64(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    companion object {
        private const val DEFAULT_TIMEOUT = 30L
    }
}
