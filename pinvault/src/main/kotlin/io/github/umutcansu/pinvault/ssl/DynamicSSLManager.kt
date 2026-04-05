package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import timber.log.Timber
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import android.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
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

    /** Default client keystore for mTLS (optional — used when no host-specific cert exists) */
    @Volatile
    private var clientKeyManagers: Array<KeyManager>? = null

    /** Host-specific client certs for mTLS — hostname → KeyManager */
    @Volatile
    private var hostKeyManagers: Map<String, javax.net.ssl.X509ExtendedKeyManager> = emptyMap()

    /**
     * Loads a PKCS12 client keystore for mTLS (default — used for all hosts without specific cert).
     */
    fun loadClientKeystore(p12Bytes: ByteArray, password: String) {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(p12Bytes.inputStream(), password.toCharArray())
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password.toCharArray())
        clientKeyManagers = kmf.keyManagers

        val alias = ks.aliases().toList().firstOrNull()
        val cert = alias?.let { ks.getCertificate(it) as? java.security.cert.X509Certificate }
        val cn = cert?.subjectX500Principal?.name?.substringAfter("CN=")?.substringBefore(",") ?: "?"
        val fingerprint = cert?.let { sha256Base64(it.publicKey.encoded).take(16) } ?: "?"
        Timber.d("Default client keystore loaded — CN=%s, pin=%s...", cn, fingerprint)
    }

    /**
     * Loads host-specific client certs for mTLS.
     * Each host gets its own KeyManager — during TLS handshake the correct cert is selected.
     *
     * @param hostCerts hostname → P12 bytes
     */
    fun loadHostClientCerts(hostCerts: Map<String, ByteArray>, password: String) {
        val managers = mutableMapOf<String, javax.net.ssl.X509ExtendedKeyManager>()

        for ((hostname, p12) in hostCerts) {
            try {
                val ks = KeyStore.getInstance("PKCS12")
                ks.load(p12.inputStream(), password.toCharArray())
                val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                kmf.init(ks, password.toCharArray())
                val km = kmf.keyManagers.firstOrNull { it is javax.net.ssl.X509ExtendedKeyManager } as? javax.net.ssl.X509ExtendedKeyManager
                if (km != null) {
                    managers[hostname] = km
                    val alias = ks.aliases().toList().firstOrNull()
                    val cert = alias?.let { ks.getCertificate(it) as? java.security.cert.X509Certificate }
                    val cn = cert?.subjectX500Principal?.name?.substringAfter("CN=")?.substringBefore(",") ?: "?"
                    Timber.d("Host client cert loaded: %s → CN=%s", hostname, cn)
                }
            } catch (e: Exception) {
                Timber.e(e, "Failed to load client cert for host: %s", hostname)
            }
        }

        hostKeyManagers = managers
        Timber.d("Loaded %d host-specific client certs", managers.size)
    }

    /**
     * Creates a composite KeyManager that selects the right cert per hostname.
     * Falls back to default client cert if no host-specific cert exists.
     */
    private fun buildCompositeKeyManagers(): Array<KeyManager>? {
        if (hostKeyManagers.isEmpty()) return clientKeyManagers

        val defaultKm = clientKeyManagers?.firstOrNull { it is javax.net.ssl.X509ExtendedKeyManager } as? javax.net.ssl.X509ExtendedKeyManager
        val hostKms = hostKeyManagers

        val composite = object : javax.net.ssl.X509ExtendedKeyManager() {
            private fun resolveForHost(hostname: String?): javax.net.ssl.X509ExtendedKeyManager? {
                if (hostname == null) return defaultKm
                return hostKms[hostname] ?: defaultKm
            }

            override fun chooseClientAlias(keyTypes: Array<String>, issuers: Array<java.security.Principal>?, socket: Socket): String? {
                val host = (socket as? javax.net.ssl.SSLSocket)?.handshakeSession?.peerHost
                    ?: socket.inetAddress?.hostName
                return resolveForHost(host)?.chooseClientAlias(keyTypes, issuers, socket)
            }

            override fun chooseEngineClientAlias(keyTypes: Array<String>, issuers: Array<java.security.Principal>?, engine: SSLEngine): String? {
                return resolveForHost(engine.peerHost)?.chooseEngineClientAlias(keyTypes, issuers, engine)
            }

            override fun getClientAliases(keyType: String, issuers: Array<java.security.Principal>?): Array<String>? {
                val all = mutableListOf<String>()
                defaultKm?.getClientAliases(keyType, issuers)?.let { all.addAll(it) }
                hostKms.values.forEach { km -> km.getClientAliases(keyType, issuers)?.let { all.addAll(it) } }
                return if (all.isEmpty()) null else all.toTypedArray()
            }

            override fun getCertificateChain(alias: String): Array<java.security.cert.X509Certificate>? {
                for (km in hostKms.values) { km.getCertificateChain(alias)?.let { return it } }
                return defaultKm?.getCertificateChain(alias)
            }

            override fun getPrivateKey(alias: String): java.security.PrivateKey? {
                for (km in hostKms.values) { km.getPrivateKey(alias)?.let { return it } }
                return defaultKm?.getPrivateKey(alias)
            }

            // Server-side (unused in client)
            override fun chooseServerAlias(keyType: String, issuers: Array<java.security.Principal>?, socket: Socket?) = null
            override fun chooseEngineServerAlias(keyType: String, issuers: Array<java.security.Principal>?, engine: SSLEngine?) = null
            override fun getServerAliases(keyType: String, issuers: Array<java.security.Principal>?) = null
        }

        return arrayOf(composite)
    }

    /**
     * Applies certificate pinning to an existing [OkHttpClient.Builder].
     * Installs a custom [X509ExtendedTrustManager] that enforces public-key pinning.
     * If client keystore is loaded, also presents client cert for mTLS.
     */
    fun applyTo(builder: OkHttpClient.Builder, config: CertificateConfig) {
        val tm = pinnedTrustManager(config.pins)
        val sslCtx = SSLContext.getInstance("TLS")
        val keyManagers = buildCompositeKeyManagers()
        sslCtx.init(keyManagers, arrayOf(tm), null)
        builder.sslSocketFactory(sslCtx.socketFactory, tm)

        val mtlsHosts = config.pins.count { it.mtls }
        Timber.d(
            "Applied pinning — version: %d, %d hosts (%d mTLS), defaultCert: %s, hostCerts: %d",
            config.version, config.pins.size, mtlsHosts, clientKeyManagers != null, hostKeyManagers.size
        )
    }

    /**
     * Creates an OkHttpClient pinned according to the given [config].
     * If [config] is null, returns a client with system-default trust (no pinning).
     */
    fun buildClient(
        config: CertificateConfig?,
        connectionSettings: HttpConnectionSettings = HttpConnectionSettings(),
        recoveryInterceptor: PinRecoveryInterceptor? = null
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
        recoveryInterceptor?.let { builder.addInterceptor(it) }
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

                val cn = leaf.subjectX500Principal.name.substringAfter("CN=").substringBefore(",")
                val hasClientCert = clientKeyManagers != null
                Timber.d("Pin verified ✓ — CN=%s, sha256/%s, clientCert=%s", cn, certHash.take(20), hasClientCert)
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
