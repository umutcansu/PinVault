package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.CertificateValidityException
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.HttpConnectionSettings
import okhttp3.ConnectionPool
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
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
 *
 * ## After the handshake
 * A trust manager is asked once per FULL handshake. A connection kept alive
 * (HTTP/2, keep-alive) or a TLS session resumed from the cache never asks it
 * again, so a pin removed or a config expired in the meantime would go
 * unnoticed. Two things close that:
 *  - every client built or configured here carries a network interceptor
 *    ([PinnedConnectionInterceptor]) that checks, on every request, the
 *    connection's certificates against the live config and the config's
 *    expiry;
 *  - every pin change ([onPinsChanged]) gives the socket factories a fresh
 *    SSLContext — no cached session to resume — and closes the pooled
 *    connections of the clients the library built itself.
 */
internal class DynamicSSLManager(
    /**
     * Optional listener fired on every pin verification (success or mismatch).
     * `null` keeps the library completely silent — the default. Wired up
     * from `PinVaultConfig.Builder.onConnectionEvent(...)` via PinVault.
     */
    @Volatile
    private var connectionListener: io.github.umutcansu.pinvault.api.PinVaultConnectionListener? = null
) {

    /**
     * Background executor used to dispatch [connectionListener] callbacks
     * off the TLS handshake thread. Single-threaded so listener
     * implementations can rely on serial in-order delivery; daemon thread
     * so it never blocks JVM shutdown.
     *
     * The work queue is bounded ([LISTENER_QUEUE_CAPACITY]) and overflowing
     * tasks are silently discarded — a misbehaving listener that blocks for
     * minutes (e.g. a synchronous HTTP POST against an unreachable telemetry
     * endpoint) must never accumulate handshake events into an OOM. Losing
     * a few telemetry events under that pathological condition is acceptable;
     * crashing the host app is not.
     */
    private val listenerDispatcher: java.util.concurrent.ExecutorService by lazy {
        java.util.concurrent.ThreadPoolExecutor(
            1, 1,
            0L, java.util.concurrent.TimeUnit.MILLISECONDS,
            java.util.concurrent.LinkedBlockingQueue(LISTENER_QUEUE_CAPACITY),
            { r -> Thread(r, "PinVault-Listener").apply { isDaemon = true } },
            java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
        )
    }

    /** Updates the listener at runtime (used after init when config arrives). */
    fun setConnectionListener(listener: io.github.umutcansu.pinvault.api.PinVaultConnectionListener?) {
        this.connectionListener = listener
    }

    /**
     * How long a config may still be used after its `expiresAt`
     * (`PinVaultConfig.Builder.expiredConfigGrace`). Zero: an expired config
     * pins nothing and every handshake through it is refused.
     */
    @Volatile
    internal var expiredConfigGraceMs: Long = 0L

    /**
     * Clock for the expiry check: the block's [TrustedClock] in production
     * (it does not go back when the device clock does), tests set their own.
     */
    @Volatile
    internal var clock: () -> Long = System::currentTimeMillis

    /** Host patterns whose chain must also pass the platform CAs (`requireCaTrust`), pattern → empty set. */
    @Volatile
    private var caTrustPatterns: Map<String, Set<String>> = emptyMap()

    /** The platform CA check; tests swap in one over their own trust store. */
    @Volatile
    internal var caCheck: ServerCaCheck = TrustManagerCaCheck.platform()

    /**
     * Hosts (same patterns as pins: exact, `*.example.com`, optional `:port`)
     * whose server chain must validate against the platform's trust store in
     * addition to matching a pin. Set from `PinVaultConfig.Builder.requireCaTrust`;
     * nothing the server sends changes it.
     */
    fun requireCaTrust(hostPatterns: List<String>) {
        caTrustPatterns = PinHostMatcher.build(hostPatterns.map { it to emptySet() })
    }

    /** Default client keystore for mTLS (optional — used when no host-specific cert exists) */
    @Volatile
    private var clientKeyManagers: Array<KeyManager>? = null

    /** Host-specific client certs for mTLS — hostname → KeyManager */
    @Volatile
    private var hostKeyManagers: Map<String, javax.net.ssl.X509ExtendedKeyManager> = emptyMap()

    /**
     * Bumped on every change of the client identity AND of the pins, so
     * [LiveSocketFactory] makes a fresh SSLContext for the next connection.
     */
    private val keyGeneration = java.util.concurrent.atomic.AtomicLong()

    /**
     * `host:port` of the listeners the default client identity belongs to:
     * the block's Config API, enrollment and renewal URLs. See
     * [setIdentityHosts].
     */
    @Volatile
    private var identityHosts: Map<String, Boolean> = emptyMap()

    /** Connection pools of the clients built by [buildDynamicClient], held weakly. */
    private val ownPools: MutableSet<ConnectionPool> =
        java.util.Collections.synchronizedSet(java.util.Collections.newSetFromMap(java.util.WeakHashMap()))

    /** The host each socket made by a [LiveSocketFactory] was opened for, as OkHttp named it. */
    private val socketHosts: MutableMap<Socket, String> =
        java.util.Collections.synchronizedMap(java.util.WeakHashMap())

    /**
     * Names the listeners the default client identity is for. It is offered
     * to those, to hosts whose pin entry says `mtls = true` and — through
     * their own certificate — to hosts with a host-specific client
     * certificate. Any other pinned host that asks for a client certificate
     * gets none: the certificate names the device (CN = device id), and a
     * host the device merely talks to has no business learning it.
     *
     * @param urls base URLs; anything that is not an http(s) URL is skipped.
     * @param onlyThese the app listed its mTLS hosts itself
     *   (`clientCertHosts`): then [urls] are the ONLY hosts the default
     *   identity goes to, and an `mtls = true` pin entry — which whoever
     *   signs the config writes — adds none. Without such a list, `mtls =
     *   true` entries still name further hosts, as before.
     */
    fun setIdentityHosts(urls: List<String?>, onlyThese: Boolean = false) {
        identityHosts = urls.mapNotNull { url ->
            url?.toHttpUrlOrNull()?.let { "${it.host.lowercase()}:${it.port}" to true }
        }.toMap()
        identityHostsOnly = onlyThese
        keyGeneration.incrementAndGet()
    }

    /** See [setIdentityHosts]: `mtls = true` pins name no further identity hosts. */
    @Volatile
    private var identityHostsOnly: Boolean = false

    /**
     * The pins changed (a new config, a rollback, a reset). From here on:
     *  - new connections come from a fresh SSLContext, so none of them can
     *    resume a TLS session that was verified against the old pins;
     *  - the pooled connections of the clients this manager built are closed.
     *
     * Clients the app built itself with [applyTo] keep their pool — it is the
     * app's — and are protected by [PinnedConnectionInterceptor] instead: the
     * next request on a connection whose certificate no longer matches fails
     * and closes it.
     */
    fun onPinsChanged() {
        keyGeneration.incrementAndGet()
        val pools = synchronized(ownPools) { ownPools.toList() }
        if (pools.isEmpty()) return
        // Off the caller's thread: closing sockets is network I/O.
        Thread({ pools.forEach { runCatching { it.evictAll() } } }, "PinVault-EvictPinned").apply { isDaemon = true }.start()
    }

    /**
     * Loads a PKCS12 client keystore for mTLS (default — used for all hosts without specific cert).
     */
    fun loadClientKeystore(p12Bytes: ByteArray, password: String) {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(p12Bytes.inputStream(), password.toCharArray())
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password.toCharArray())
        clientKeyManagers = kmf.keyManagers
        keyGeneration.incrementAndGet()

        // The subject names the device: say that a certificate is loaded, not whose.
        Timber.d("Default client keystore loaded — %d entr(ies)", ks.size())
    }

    /**
     * Loads a default client identity whose private key stays where it is —
     * an Android Keystore key with the certificate chain the server issued
     * over it. The CSR-enrolled counterpart of [loadClientKeystore]; the two
     * replace each other.
     */
    fun loadClientKey(privateKey: java.security.PrivateKey, chain: Array<X509Certificate>, alias: String = "pinvault-client") {
        val km = FixedClientKeyManager(alias, privateKey, chain)
        clientKeyManagers = arrayOf(km)
        keyGeneration.incrementAndGet()
        Timber.d("Default client key loaded — notAfter=%s", km.certificate.notAfter)
    }

    /** The leaf certificate the default client KeyManager presents, if one is loaded. */
    internal fun defaultClientCertificate(): X509Certificate? {
        val km = clientKeyManagers?.firstOrNull { it is javax.net.ssl.X509ExtendedKeyManager }
            as? javax.net.ssl.X509ExtendedKeyManager ?: return null
        val alias = listOf("EC", "RSA").firstNotNullOfOrNull { km.getClientAliases(it, null)?.firstOrNull() }
            ?: return null
        return km.getCertificateChain(alias)?.firstOrNull()
    }

    /**
     * Inverse of [loadClientKeystore]: drops the in-memory default client
     * KeyManager so subsequent handshakes present no client certificate.
     *
     * Needed by `PinVault.unenroll` — deleting the P12 from the encrypted
     * store is not enough on its own, because the KeyManager built at
     * enrollment time keeps the private key alive in this process. Without
     * this call mTLS kept working until the app was restarted, so an
     * "unenrolled" device still authenticated to mTLS hosts.
     *
     * Clients built by [applyTo] stop presenting it on their next connection
     * ([LiveSocketFactory]); connections they already opened keep the identity
     * they were made with until they close, so the caller still evicts
     * connection pools it owns (`clientProvider.swap` does for the library's).
     *
     * @param includeHostCerts also drop the per-host KeyManagers loaded by
     *        [loadHostClientCerts]. Those are re-downloaded on the next config
     *        sync, so dropping them keeps "unenrolled" consistent across every
     *        mTLS host rather than only the default cert.
     */
    fun clearClientKeystore(includeHostCerts: Boolean = true) {
        clientKeyManagers = null
        if (includeHostCerts) hostKeyManagers = emptyMap()
        keyGeneration.incrementAndGet()
        Timber.d("Client keystore cleared — no client cert will be presented (hostCerts=%b)", includeHostCerts)
    }

    /** True while a default or host-specific client KeyManager is loaded. */
    internal fun hasClientKeystore(): Boolean =
        clientKeyManagers != null || hostKeyManagers.isNotEmpty()

    /**
     * Loads host-specific client certs for mTLS.
     * Each host gets its own KeyManager — during TLS handshake the correct cert is selected.
     *
     * @param hostCerts hostname → P12 bytes
     */
    fun loadHostClientCerts(hostCerts: Map<String, ByteArray>, password: String) =
        loadHostClientIdentities(emptyMap(), hostCerts, password)

    /**
     * Loads host-specific client identities for mTLS, replacing the ones
     * loaded before. [hostKeys] are identities whose private key stays in the
     * Android Keystore (hostname → key and chain) — what a host's P12 becomes
     * once its key is imported; [hostCerts] (hostname → P12 bytes) are the
     * ones the platform refused to import. A host in both uses its key.
     */
    fun loadHostClientIdentities(
        hostKeys: Map<String, Pair<java.security.PrivateKey, Array<X509Certificate>>>,
        hostCerts: Map<String, ByteArray>,
        password: String
    ) {
        val managers = mutableMapOf<String, javax.net.ssl.X509ExtendedKeyManager>()

        for ((hostname, identity) in hostKeys) {
            try {
                managers[hostname.lowercase()] = FixedClientKeyManager("pinvault-host", identity.first, identity.second)
                Timber.d("Host client key loaded: %s", hostname)
            } catch (e: Exception) {
                Timber.e(e, "Failed to load client key for host: %s", hostname)
            }
        }

        for ((hostname, p12) in hostCerts) {
            if (hostname.lowercase() in managers) continue
            try {
                val ks = KeyStore.getInstance("PKCS12")
                ks.load(p12.inputStream(), password.toCharArray())
                val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                kmf.init(ks, password.toCharArray())
                val km = kmf.keyManagers.firstOrNull { it is javax.net.ssl.X509ExtendedKeyManager } as? javax.net.ssl.X509ExtendedKeyManager
                if (km != null) {
                    managers[hostname.lowercase()] = km
                    Timber.d("Host client cert loaded: %s", hostname)
                }
            } catch (e: Exception) {
                Timber.e(e, "Failed to load client cert for host: %s", hostname)
            }
        }

        hostKeyManagers = managers
        keyGeneration.incrementAndGet()
        Timber.d("Loaded %d host-specific client certs", managers.size)
    }

    /**
     * The KeyManager that decides, per connection, which client certificate
     * the peer gets — or none. Null when no identity is loaded at all.
     *
     *  1. A host with its own client certificate ([loadHostClientCerts]) gets
     *     that certificate. Entries follow the pin syntax (exact, `*.domain`,
     *     `host:port`).
     *  2. The default identity goes to the block's own listeners
     *     ([setIdentityHosts]) and — unless the app listed its hosts itself
     *     (`clientCertHosts`) — to hosts whose pin entry in the live config
     *     ([configProvider]) has `mtls = true`.
     *  3. Everyone else gets nothing, as does a connection whose host is
     *     unknown.
     *
     * It used to hand the default identity to every host that asked for a
     * client certificate.
     */
    internal fun buildCompositeKeyManagers(configProvider: () -> CertificateConfig? = { null }): Array<KeyManager>? {
        val defaultKm = clientKeyManagers?.firstOrNull { it is javax.net.ssl.X509ExtendedKeyManager } as? javax.net.ssl.X509ExtendedKeyManager
        val hostKms = hostKeyManagers
        if (defaultKm == null && hostKms.isEmpty()) return null

        val composite = object : javax.net.ssl.X509ExtendedKeyManager() {
            // Two key stores may use the same alias ("client", "1"), so the
            // alias handed to the TLS stack names its owner as well:
            // `d/<alias>` for the default identity, `h/<host entry>/<alias>`.
            private fun owner(alias: String?): Pair<javax.net.ssl.X509ExtendedKeyManager, String>? {
                if (alias == null) return null
                if (alias.startsWith(DEFAULT_ALIAS_PREFIX)) {
                    return defaultKm?.let { it to alias.removePrefix(DEFAULT_ALIAS_PREFIX) }
                }
                if (alias.startsWith(HOST_ALIAS_PREFIX)) {
                    val rest = alias.removePrefix(HOST_ALIAS_PREFIX)
                    val entry = hostKms.keys.firstOrNull { rest.startsWith("$it/") } ?: return null
                    return hostKms.getValue(entry) to rest.removePrefix("$entry/")
                }
                return null
            }

            /** (key manager, alias prefix) for [host]:[port], or null: this peer gets no certificate. */
            private fun resolve(host: String?, port: Int?): Pair<javax.net.ssl.X509ExtendedKeyManager, String>? {
                if (host.isNullOrEmpty()) return null
                val name = host.lowercase()
                hostKms.entries.firstOrNull { (entry, _) ->
                    PinHostMatcher.match(mapOf(entry to true), name, port) != null
                }?.let { (entry, km) -> return km to "$HOST_ALIAS_PREFIX$entry/" }
                if (defaultKm == null) return null
                val ownListener = port != null && identityHosts["$name:$port"] == true
                val mtlsHost = !ownListener && !identityHostsOnly && configProvider()?.pins
                    ?.let { pins -> PinHostMatcher.match(pins.associateBy { it.hostname.lowercase() }, name, port) }
                    ?.mtls == true
                return if (ownListener || mtlsHost) defaultKm to DEFAULT_ALIAS_PREFIX else null
            }

            override fun chooseClientAlias(keyTypes: Array<String>?, issuers: Array<java.security.Principal>?, socket: Socket?): String? {
                val (km, prefix) = resolve(hostnameFromSocket(socket).ifEmpty { null }, socket?.port) ?: return null
                return km.chooseClientAlias(keyTypes, issuers, socket)?.let { prefix + it }
            }

            override fun chooseEngineClientAlias(keyTypes: Array<String>?, issuers: Array<java.security.Principal>?, engine: SSLEngine?): String? {
                val (km, prefix) = resolve(engine?.peerHost, engine?.peerPort) ?: return null
                return km.chooseEngineClientAlias(keyTypes, issuers, engine)?.let { prefix + it }
            }

            override fun getClientAliases(keyType: String?, issuers: Array<java.security.Principal>?): Array<String>? {
                val all = mutableListOf<String>()
                defaultKm?.getClientAliases(keyType, issuers)?.forEach { all += DEFAULT_ALIAS_PREFIX + it }
                hostKms.forEach { (entry, km) ->
                    km.getClientAliases(keyType, issuers)?.forEach { all += "$HOST_ALIAS_PREFIX$entry/$it" }
                }
                return if (all.isEmpty()) null else all.toTypedArray()
            }

            override fun getCertificateChain(alias: String?): Array<java.security.cert.X509Certificate>? =
                owner(alias)?.let { (km, own) -> km.getCertificateChain(own) }

            override fun getPrivateKey(alias: String?): java.security.PrivateKey? =
                owner(alias)?.let { (km, own) -> km.getPrivateKey(own) }

            // Server-side (unused in client)
            override fun chooseServerAlias(keyType: String?, issuers: Array<java.security.Principal>?, socket: Socket?) = null
            override fun chooseEngineServerAlias(keyType: String?, issuers: Array<java.security.Principal>?, engine: SSLEngine?) = null
            override fun getServerAliases(keyType: String?, issuers: Array<java.security.Principal>?) = null
        }

        return arrayOf(composite)
    }

    /**
     * The socket factory every client built by [applyTo] holds. Its sockets
     * come from an SSLContext made for the client identity and the pins in
     * force now, and a new one is made whenever either changes (renewal,
     * recovery, re-enrollment, unenroll, host certificates; a new config).
     *
     * A context built once kept presenting the identity of the moment the
     * client was built. Swapping only the key manager would not be enough
     * either: a new connection resumes the context's cached TLS session and
     * the server sees the client certificate of that old session again — and
     * a resumed session is not shown to the trust manager, so it would also
     * outlive a pin that has been removed. A fresh context has no such
     * session.
     *
     * The factory object itself stays the same, so OkHttp keeps pooling
     * connections as before.
     */
    private inner class LiveSocketFactory(
        private val trustManager: X509TrustManager,
        private val configProvider: () -> CertificateConfig?
    ) : javax.net.ssl.SSLSocketFactory() {

        private inner class Built(val generation: Long, val factory: javax.net.ssl.SSLSocketFactory)

        @Volatile
        private var built: Built? = null

        private fun current(): javax.net.ssl.SSLSocketFactory {
            val generation = keyGeneration.get()
            built?.takeIf { it.generation == generation }?.let { return it.factory }
            // "TLS", not "TLSv1.2": the latter caps the connection at 1.2 on
            // every platform, and below TLS 1.3 the client certificate — whose
            // subject names the device — crosses the wire in the clear. The
            // floor the old string was there for is set per socket instead
            // (see harden): nothing below TLS 1.2 is ever enabled.
            val sslCtx = SSLContext.getInstance("TLS")
            sslCtx.init(buildCompositeKeyManagers(configProvider), arrayOf(trustManager), null)
            return sslCtx.socketFactory.also { built = Built(generation, it) }
        }

        /**
         * Leaves only TLS 1.2 and newer enabled, whatever the platform's
         * defaults are, and remembers the host the socket is for. OkHttp's
         * ConnectionSpec narrows the enabled protocols further but never adds
         * to them, so this is a floor no client configuration can lower.
         */
        private fun harden(socket: Socket, host: String?): Socket {
            if (socket is javax.net.ssl.SSLSocket) {
                val modern = socket.enabledProtocols.filter { it in MODERN_TLS }
                    .ifEmpty { socket.supportedProtocols.filter { it in MODERN_TLS } }
                if (modern.isEmpty()) {
                    runCatching { socket.close() }
                    throw javax.net.ssl.SSLException("This device supports neither TLS 1.2 nor TLS 1.3")
                }
                socket.enabledProtocols = modern.toTypedArray()
                if (!host.isNullOrEmpty()) socketHosts[socket] = host
            }
            return socket
        }

        override fun getDefaultCipherSuites(): Array<String> = current().defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = current().supportedCipherSuites
        override fun createSocket(): Socket = harden(current().createSocket(), null)
        override fun createSocket(socket: Socket, host: String, port: Int, autoClose: Boolean): Socket =
            harden(current().createSocket(socket, host, port, autoClose), host)
        override fun createSocket(host: String, port: Int): Socket = harden(current().createSocket(host, port), host)
        override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket =
            harden(current().createSocket(host, port, localHost, localPort), host)
        override fun createSocket(host: java.net.InetAddress, port: Int): Socket = harden(current().createSocket(host, port), null)
        override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket =
            harden(current().createSocket(address, port, localAddress, localPort), null)
    }

    /**
     * Applies certificate pinning to an existing [OkHttpClient.Builder].
     * Installs a custom [X509ExtendedTrustManager] that enforces public-key pinning,
     * and presents the client identity loaded when each connection is made
     * ([LiveSocketFactory]): the client follows renewal and re-enrollment
     * without being rebuilt. Connections it already opened keep the
     * certificate they were made with until they close.
     *
     * [configProvider] is invoked fresh on every TLS handshake. Pass a lambda
     * that re-reads the live config (e.g. `{ httpClientProvider.currentConfig }`)
     * for dynamic pin updates that follow [HttpClientProvider.swap] without
     * rebuilding the client; pass a constant lambda for a frozen snapshot.
     *
     * Also adds [PinnedConnectionInterceptor] as a network interceptor: the
     * handshake check is repeated, against the live config, on every request
     * — a connection opened before a pin was removed or before the config
     * expired does not get to carry another request.
     */
    fun applyTo(builder: OkHttpClient.Builder, configProvider: () -> CertificateConfig?) {
        val tm = pinnedTrustManager(configProvider)
        builder.sslSocketFactory(LiveSocketFactory(tm, configProvider), tm)
        builder.addNetworkInterceptor(
            PinnedConnectionInterceptor(configProvider, ::requireUsableConfig, ::matchPins) { chain, host, port ->
                // The handshake's auth type is not known here; "UNKNOWN" is the
                // value the JDK passes for TLS 1.3; the platform trust managers accept it.
                requireCaTrustFor(chain, "UNKNOWN", host, port)
            }
        )

        val initial = configProvider()
        val mtlsHosts = initial?.pins?.count { it.mtls } ?: 0
        Timber.d(
            "Applied dynamic pinning — initial v=%d, %d hosts (%d mTLS), defaultCert=%s, hostCerts=%d",
            initial?.version ?: -1, initial?.pins?.size ?: 0,
            mtlsHosts, clientKeyManagers != null, hostKeyManagers.size
        )
    }

    /**
     * Creates an OkHttpClient pinned according to the given [config] — a
     * frozen snapshot; later config swaps do not reach it (see
     * [buildDynamicClient] for the live variant).
     *
     * A `null` [config] does NOT fall back to system trust. Pinning is always
     * installed, and the trust manager refuses every TLS handshake while no
     * config is available (fail-closed). The previous behaviour returned an
     * unpinned client here, which let `PinVault.getClient()` callers skip
     * pinning entirely in the window between `init()` starting and the first
     * config arriving, and after `reset()`.
     */
    fun buildClient(
        config: CertificateConfig?,
        connectionSettings: HttpConnectionSettings = HttpConnectionSettings(),
        recoveryInterceptor: PinRecoveryInterceptor? = null
    ): OkHttpClient = buildDynamicClient({ config }, connectionSettings, recoveryInterceptor)

    /**
     * Creates an OkHttpClient whose pin set is re-read from [configProvider]
     * on every TLS handshake. While the provider returns `null` the client
     * refuses to connect; once a config is published it starts working
     * without being rebuilt. Used for [HttpClientProvider]'s "no config yet"
     * state and for `PinVault.getClient(settings)`.
     */
    fun buildDynamicClient(
        configProvider: () -> CertificateConfig?,
        connectionSettings: HttpConnectionSettings = HttpConnectionSettings(),
        recoveryInterceptor: PinRecoveryInterceptor? = null
    ): OkHttpClient {
        // Remembered (weakly) so that a pin change can close its connections.
        val pool = ConnectionPool(
            connectionSettings.maxIdleConnections,
            connectionSettings.keepAliveDuration,
            connectionSettings.keepAliveDurationUnit
        )
        ownPools += pool
        val builder = OkHttpClient.Builder()
            .cache(null)
            .connectionPool(pool)

        applyTimeouts(builder, connectionSettings)

        if (configProvider() == null) {
            Timber.d("No config yet — building fail-closed client (TLS refused until a config is applied)")
        }
        applyTo(builder, configProvider)
        // A pinned client never continues in the clear: a 30x from a pinned
        // host to an http:// URL is not followed (the bootstrap client has
        // refused that since 2.2.0; app builders passed to applyTo keep
        // their own setting).
        builder.followSslRedirects(false)
        recoveryInterceptor?.let { builder.addInterceptor(it) }
        return builder.build()
    }

    /**
     * Builds the bootstrap OkHttpClient: the client a Config API block talks
     * to its own backend with (config fetch, enrollment, renewal, vault
     * files), pinned to [bootstrapPins].
     *
     * It is pinned and HTTPS-only, always. Without bootstrap pins it used to
     * fall back to the system's certificate authorities, and a plain-HTTP URL
     * skipped TLS altogether; both are now refused unless the block asked for
     * it ([allowUnpinned], `ConfigApiBlock.Builder.allowUnpinnedConfigApi()`):
     * no pins → every TLS handshake is refused, `http://` → the request fails
     * before it is sent.
     */
    fun buildBootstrapClient(
        bootstrapPins: List<HostPin>,
        interceptor: okhttp3.Interceptor? = null,
        allowUnpinned: Boolean = false
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS)
        interceptor?.let { builder.addInterceptor(it) }

        if (bootstrapPins.isNotEmpty()) {
            val config = CertificateConfig(version = 0, pins = bootstrapPins)
            applyTo(builder) { config }
            Timber.d("Bootstrap client pinned — %d hosts", bootstrapPins.size)
        } else if (allowUnpinned) {
            Timber.w("Bootstrap client — no pins, using system defaults (allowUnpinnedConfigApi)")
        } else {
            // Fail closed: pinning over "no config" refuses every handshake.
            applyTo(builder) { null }
            Timber.e("Bootstrap client has no pins — every TLS handshake is refused (set bootstrapPins)")
        }
        if (!allowUnpinned) {
            // Not even by way of a redirect: neither to http:// nor to another
            // https:// host. The Config API's answers carry device headers
            // (X-Device-Id, X-Vault-Token) and enrollment bodies (a 307 keeps
            // the body); OkHttp strips only Authorization on a host change,
            // so a redirect to a sibling host under a wildcard or CA pin
            // would hand those over. The Config API never redirects.
            builder.followRedirects(false)
            builder.followSslRedirects(false)
            builder.addInterceptor(okhttp3.Interceptor { chain ->
                if (!chain.request().isHttps) {
                    throw java.io.IOException(
                        "Refusing a plain-HTTP request to the Config API (${chain.request().url.host}): " +
                            "use https://, or allowUnpinnedConfigApi() for tests"
                    )
                }
                chain.proceed(chain.request())
            })
        }

        return builder.build()
    }

    private fun applyTimeouts(builder: OkHttpClient.Builder, settings: HttpConnectionSettings) {
        if (settings.connectTimeout > 0) builder.connectTimeout(settings.connectTimeout, TimeUnit.SECONDS)
        if (settings.readTimeout > 0)    builder.readTimeout(settings.readTimeout, TimeUnit.SECONDS)
        if (settings.writeTimeout > 0)   builder.writeTimeout(settings.writeTimeout, TimeUnit.SECONDS)
        if (settings.callTimeout > 0)    builder.callTimeout(settings.callTimeout, TimeUnit.SECONDS)
    }

    private fun buildAcceptedPins(pins: List<HostPin>): Map<String, Set<String>> =
        PinHostMatcher.build(pins.map { it.hostname to it.sha256.toSet() })

    private fun matchPinsFor(
        pinMap: Map<String, Set<String>>,
        hostname: String,
        port: Int? = null
    ): Set<String>? = PinHostMatcher.match(pinMap, hostname, port)

    /**
     * Returns a [X509ExtendedTrustManager] that:
     * - Accepts self-signed certificates (no CA-chain validation).
     * - Verifies that the leaf certificate's public-key SHA-256 matches one of
     *   the pins returned by [configProvider] **at the time of the handshake**,
     *   or that the leaf chains to a served issuer certificate whose pin does
     *   ([ChainPinMatcher]).
     *
     * Pin lookup is dynamic: every TLS handshake re-invokes [configProvider]
     * and rebuilds the host → pin-set map. Callers that want snapshot semantics
     * pass a constant lambda; callers that want config swaps to take effect
     * without rebuilding the client pass a lambda over a live reference (e.g.
     * `HttpClientProvider.currentConfig`).
     *
     * Security comes from public-key pinning — this is equivalent to, and more
     * reliable than, OkHttp's [okhttp3.CertificatePinner] on Android — plus,
     * for the hosts named with [requireCaTrust], the platform's CA check. A
     * config past its `expiresAt` (plus [expiredConfigGraceMs]) is refused.
     */
    private fun pinnedTrustManager(configProvider: () -> CertificateConfig?): X509TrustManager {
        return object : X509ExtendedTrustManager() {

            // ── Server auth (called by Conscrypt during handshake) ─────────────────

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String,
                socket: Socket
            ) = verifyPin(chain, authType, hostnameFromSocket(socket), socket.port)

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String,
                engine: SSLEngine
            ) = verifyPin(chain, authType, engine.peerHost.orEmpty(), engine.peerPort)

            override fun checkServerTrusted(
                chain: Array<X509Certificate>,
                authType: String
            ) = verifyPin(chain, authType, "")

            // ── Client auth ───────────────────────────────────────────────────────

            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) = Unit
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

            // ── Pin verification ──────────────────────────────────────────────────

            private fun verifyPin(chain: Array<X509Certificate>, authType: String, hostname: String, port: Int? = null) {
                if (chain.isEmpty()) throw CertificateException("No server certificate provided")

                val leaf = chain[0]
                val config = requireUsableConfig(configProvider(), hostname)

                // Per-host pin lookup first: a hostname with no entry (and no
                // matching wildcard) must be refused — the alternative is
                // accepting any cert for unknown hosts, which is exactly the
                // cross-host pin-reuse attack H-01 closes.
                val acceptedForHost = pinsFor(config, hostname, port)

                // Sertifika süre kontrolü.
                //
                // Distinct exception type (not a bare CertificateException):
                // refetching the pin config cannot repair a certificate that is
                // outside its validity window, so PinRecoveryInterceptor must
                // not treat this as a pin mismatch. See
                // [CertificateValidityException].
                try {
                    leaf.checkValidity()
                } catch (e: Exception) {
                    throw CertificateValidityException(
                        "Server certificate is expired or not yet valid: ${e.message}", e
                    )
                }

                // Pin doğrulama: yaprak sertifika ya da yaprağın gerçekten
                // bağlandığı bir üst sertifika (bkz. ChainPinMatcher).
                val certHash = sha256Base64(leaf.publicKey.encoded)
                val matchedPin = matchPins(config, chain, hostname, port)

                requireCaTrustFor(chain, authType, hostname, port)

                val hasClientCert = clientKeyManagers != null
                val via = if (matchedPin == certHash) "" else " (issuer pin sha256/${matchedPin.take(12)}...)"
                // The host and the pin that matched; no certificate subject.
                Timber.d("Pin verified ✓ — host=%s, sha256/%s...%s, clientCert=%s",
                    hostname, certHash.take(12), via, hasClientCert)
                emitConnectionEvent(hostname, success = true, actualPin = certHash, expectedPins = acceptedForHost, pinVersion = config.version)
            }
        }
    }

    /**
     * `requireCaTrust`: the pins come from whoever signs the config, which on
     * its own makes that signer a private CA for every pinned host. For the
     * hosts the app named, the platform's CAs must accept the chain as well —
     * both checks, not either. Throws a
     * [io.github.umutcansu.pinvault.model.CaTrustException] (a
     * [CertificateException]); nothing for other hosts. Shared by the
     * handshake check and the per-request check ([PinnedConnectionInterceptor]).
     */
    internal fun requireCaTrustFor(chain: Array<X509Certificate>, authType: String, hostname: String, port: Int?) {
        val patterns = caTrustPatterns
        if (patterns.isEmpty() || PinHostMatcher.match(patterns, hostname, port) == null) return
        try {
            caCheck.check(chain, authType, hostname)
        } catch (e: Exception) {
            Timber.e("CA check failed for %s (requireCaTrust): %s", hostname, e.message)
            throw io.github.umutcansu.pinvault.model.CaTrustException(
                "Certificate for $hostname matches its pins but is not trusted by the platform's " +
                    "certificate authorities, which requireCaTrust asks for: ${e.message}", e
            )
        }
    }

    /**
     * [config] when it may be used right now, else a [CertificateException]:
     * no config (or one without pins), or a config past its `expiresAt` plus
     * [expiredConfigGraceMs]. Shared by the handshake check and the
     * per-request check ([PinnedConnectionInterceptor]).
     */
    internal fun requireUsableConfig(config: CertificateConfig?, hostname: String): CertificateConfig {
        if (config == null || config.pins.isEmpty()) {
            throw CertificateException(
                "No pins configured — refusing connection. " +
                "Call PinVault.init() before making HTTPS requests."
            )
        }

        // An expired config pins nothing: whoever keeps fresh configs
        // away from the device must not keep it on old pins for good.
        // A plain CertificateException on purpose — refetching the
        // config is exactly what repairs this, so the recovery
        // interceptor should try. Bootstrap and static configs carry
        // no expiresAt (0) and are never refused here.
        if (config.expiresAt > 0L && clock() > config.expiresAt + expiredConfigGraceMs) {
            throw CertificateException(
                "Pin config expired at ${config.expiresAt} (Unix ms) — refusing connection to '$hostname' " +
                    "until a fresh config is fetched",
                io.github.umutcansu.pinvault.model.ConfigExpiredException(config.expiresAt)
            )
        }
        return config
    }

    /** The pins [config] accepts for [hostname] (and [port]); [UnpinnedHostException] when it names none. */
    private fun pinsFor(config: CertificateConfig, hostname: String, port: Int?): Set<String> {
        val pinMap = buildAcceptedPins(config.pins)
        return matchPinsFor(pinMap, hostname, port)
            ?: throw io.github.umutcansu.pinvault.model.UnpinnedHostException(
                "No pin entry for hostname '$hostname'. " +
                "Configured hosts: ${pinMap.keys.joinToString()}"
            )
    }

    /**
     * The pin of [config] that [chain] satisfies for [hostname]: the leaf's
     * key, or an issuer the leaf really chains to ([ChainPinMatcher]). Throws
     * [CertificateException] (and reports the mismatch to the listener) when
     * there is none. The matcher of the handshake check and of the
     * per-request check — exact, wildcard and `host:port` entries alike.
     */
    internal fun matchPins(config: CertificateConfig, chain: Array<X509Certificate>, hostname: String, port: Int?): String {
        if (chain.isEmpty()) throw CertificateException("No server certificate provided")
        val acceptedForHost = pinsFor(config, hostname, port)
        val certHash = sha256Base64(chain[0].publicKey.encoded)
        val matchedPin = ChainPinMatcher.match(chain, acceptedForHost) { sha256Base64(it.publicKey.encoded) }
        if (matchedPin == null) {
            emitConnectionEvent(hostname, success = false, actualPin = certHash, expectedPins = acceptedForHost, pinVersion = config.version)
            Timber.e("Pin mismatch for %s — cert=%s..., expected %d pins",
                hostname, certHash.take(12), acceptedForHost.size)
            throw CertificateException(
                "Certificate pinning failure for $hostname!\n" +
                "  Cert hash: sha256/$certHash\n" +
                "  Accepted pins for this host: ${acceptedForHost.size}"
            )
        }
        // An issuer pin says "a certificate this CA issued": for a public CA
        // that is any site's certificate, so the leaf must also name the host.
        // A leaf pin names one key and needs no name check — the pin is the
        // identity (which is what lets self-signed and SAN-less certificates
        // work). The app's HostnameVerifier runs too, but an app that passes
        // its own builder to applyTo may have relaxed it; this check does
        // not depend on that.
        if (matchedPin != certHash && !ChainPinMatcher.leafNamesHost(chain[0], hostname)) {
            Timber.e("Issuer pin matched for %s but the certificate is not issued for that host", hostname)
            throw io.github.umutcansu.pinvault.model.HostnameMismatchException(
                "Certificate for $hostname chains to a pinned issuer but is not issued for $hostname " +
                    "(no matching subjectAltName); an issuer pin vouches for the CA, not for the name"
            )
        }
        return matchedPin
    }

    /**
     * The host a socket is being connected to, for the `Socket` overloads of
     * the trust manager and the key manager: the name OkHttp opened it with
     * (remembered by [LiveSocketFactory]), else the handshake session's peer
     * host. Nothing else — in particular no reverse DNS lookup of the remote
     * address, whose answer is whatever the network says it is. Unknown →
     * empty, and an empty host has no pin entry and gets no client
     * certificate (fail closed).
     */
    private fun hostnameFromSocket(socket: Socket?): String {
        if (socket == null) return ""
        socketHosts[socket]?.let { return it }
        return (socket as? javax.net.ssl.SSLSocket)?.handshakeSession?.peerHost.orEmpty()
    }

    /**
     * Builds and dispatches a [PinVaultConnectionEvent.Connection] off the
     * TLS handshake thread.
     */
    private fun emitConnectionEvent(
        hostname: String,
        success: Boolean,
        actualPin: String,
        expectedPins: Collection<String>,
        pinVersion: Int
    ) {
        if (connectionListener == null) return
        dispatchEvent(
            io.github.umutcansu.pinvault.api.PinVaultConnectionEvent.Connection(
                hostname = hostname,
                success = success,
                pinVersion = pinVersion,
                deviceManufacturer = android.os.Build.MANUFACTURER ?: "",
                deviceModel = android.os.Build.MODEL ?: "",
                actualPin = actualPin,
                expectedPins = expectedPins.toList()
            )
        )
    }

    /**
     * Internal hook used by [io.github.umutcansu.pinvault.PinVault] to push
     * non-handshake events (e.g. config-update results) onto the same
     * listener pipe. The TLS handshake path uses [emitConnectionEvent]
     * directly; everything else can call this.
     *
     * Listener exceptions are logged and swallowed — a misbehaving callback
     * can never break the underlying connection.
     */
    internal fun dispatchEvent(event: io.github.umutcansu.pinvault.api.PinVaultConnectionEvent) {
        val listener = connectionListener ?: return
        try {
            listenerDispatcher.execute {
                try {
                    listener.onEvent(event)
                } catch (t: Throwable) {
                    Timber.w(t, "PinVault connection listener threw — swallowing")
                }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            Timber.w(e, "PinVault listener dispatcher rejected event")
        }
    }

    private fun sha256Base64(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    companion object {
        private const val DEFAULT_TIMEOUT = 30L
        private const val LISTENER_QUEUE_CAPACITY = 256

        /** The only protocol versions a socket of this library ever enables. */
        private val MODERN_TLS = setOf("TLSv1.2", "TLSv1.3")

        private const val DEFAULT_ALIAS_PREFIX = "d/"
        private const val HOST_ALIAS_PREFIX = "h/"
    }
}
