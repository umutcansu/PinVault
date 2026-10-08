package io.github.umutcansu.pinvault.reactnative

import android.content.Context
import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import io.github.umutcansu.pinvault.PinVault
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Pins React Native's own networking (global `fetch` / `XMLHttpRequest`, and
 * `WebSocket`) with `PinVault.applyTo(builder)` — Android only.
 *
 * Two hooks, both verified against React Native 0.87's sources:
 *
 * - `NetworkingModule.setCustomClientBuilder`: RN calls it for **every**
 *   request on `client.newBuilder()`, so it takes effect whenever it is
 *   installed, also after `start()`. Each request gets the pinned socket
 *   factory and PinVault's interceptors (pin check of pooled connections,
 *   `PinVault-Token`, pin-mismatch recovery) of one client that
 *   `PinVault.applyTo` configured after `start()` — one per start, so pooled
 *   connections are reused.
 * - `OkHttpClientProvider.setOkHttpClientFactory`: the clients RN builds once
 *   and keeps (the networking module's base client, the WebSocket/dev-support
 *   singleton) get a forwarding socket factory: every TLS handshake uses the
 *   pinned factory of the current start, and fails before `start()`. RN asks
 *   the factory only when it creates such a client: a client created before
 *   the factory was installed stays unpinned. Install it in
 *   `MainApplication.onCreate` ([install]) to cover them all; `start()`
 *   installs it too, which covers clients RN creates later (the WebSocket
 *   client is created on the first WebSocket).
 *
 * Fail closed: until `start()` has run, an `https` request through RN's
 * networking is refused (`IOException: PinVault has not started`). Plain
 * `http` is not TLS and is left to the app's network security config (Metro
 * in debug builds uses it). Hosts without a pin entry are refused by
 * PinVault's trust manager like everywhere else. Not covered: images
 * (Fresco builds its client at app start) and native modules with their own
 * HTTP stack.
 */
object PinVaultNetworking {

    @Volatile private var installed = false
    internal val pinning = NetworkPinning { builder -> PinVault.applyTo(builder) }

    /** Call in `MainApplication.onCreate`, before React Native starts, to pin every RN client. */
    @JvmStatic
    @Synchronized
    fun install(context: Context) {
        if (installed) return
        val app = context.applicationContext
        OkHttpClientProvider.setOkHttpClientFactory(OkHttpClientFactory {
            pinning.configureLongLived(OkHttpClientProvider.createClientBuilder(app)).build()
        })
        NetworkingModule.setCustomClientBuilder { builder -> pinning.configurePerRequest(builder) }
        installed = true
    }

    @JvmStatic
    val isInstalled: Boolean get() = installed
}

/**
 * The mechanics of [PinVaultNetworking], with the `applyTo` call injected so
 * that JVM tests can run it without a device.
 */
internal class NetworkPinning(private val applier: (OkHttpClient.Builder) -> Unit) {

    /** A client `PinVault.applyTo` configured after the last `start()`; null = not started. */
    @Volatile private var template: OkHttpClient? = null

    val isActive: Boolean get() = template != null

    /** After `start()`: one pinned template per start (its socket factory keys the connection pool). */
    @Synchronized
    fun activate() {
        template = OkHttpClient.Builder().also(applier).build()
    }

    @Synchronized
    fun deactivate() {
        template = null
    }

    /** NetworkingModule's per-request builder. */
    fun configurePerRequest(builder: OkHttpClient.Builder) {
        val pinned = template
        if (pinned == null) {
            builder.addInterceptor(httpsGate)
            return
        }
        builder.sslSocketFactory(pinned.sslSocketFactory, requireNotNull(pinned.x509TrustManager))
        builder.hostnameVerifier(pinned.hostnameVerifier)
        builder.certificatePinner(pinned.certificatePinner)
        // A builder derived from a client this method already configured would
        // carry the interceptors twice; RN derives every request from its base client.
        pinned.interceptors.forEach { if (it !in builder.interceptors()) builder.addInterceptor(it) }
        pinned.networkInterceptors.forEach { if (it !in builder.networkInterceptors()) builder.addNetworkInterceptor(it) }
    }

    /** Clients RN builds once and keeps: TLS goes through the pinned factory of the current start. */
    fun configureLongLived(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        val forwarding = ForwardingSocketFactory { template?.sslSocketFactory }
        builder.sslSocketFactory(forwarding, ForwardingTrustManager { template?.x509TrustManager })
        builder.addInterceptor(httpsGate)
        return builder
    }

    /** Refuses `https` while PinVault has not started. */
    private val httpsGate = Interceptor { chain ->
        if (chain.request().isHttps && template == null) {
            throw IOException("PinVault has not started: https requests are refused until start() returns")
        }
        chain.proceed(chain.request())
    }
}

/** Hands every socket to the pinned factory of the current start; none before `start()`. */
internal class ForwardingSocketFactory(private val current: () -> SSLSocketFactory?) : SSLSocketFactory() {

    private fun delegate(): SSLSocketFactory =
        current() ?: throw SSLHandshakeException("PinVault has not started: TLS is refused until start() returns")

    override fun getDefaultCipherSuites(): Array<String> = current()?.defaultCipherSuites ?: emptyArray()
    override fun getSupportedCipherSuites(): Array<String> = current()?.supportedCipherSuites ?: emptyArray()
    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
        delegate().createSocket(s, host, port, autoClose)
    override fun createSocket(host: String?, port: Int): Socket = delegate().createSocket(host, port)
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        delegate().createSocket(host, port, localHost, localPort)
    override fun createSocket(host: InetAddress?, port: Int): Socket = delegate().createSocket(host, port)
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        delegate().createSocket(address, port, localAddress, localPort)
    override fun createSocket(): Socket = delegate().createSocket()
}

/**
 * OkHttp uses this trust manager only to clean certificate chains; the
 * handshake itself is checked inside the pinned socket factory.
 */
internal class ForwardingTrustManager(private val current: () -> X509TrustManager?) : X509TrustManager {
    private fun delegate(): X509TrustManager =
        current() ?: throw java.security.cert.CertificateException("PinVault has not started")

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        delegate().checkClientTrusted(chain, authType)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        delegate().checkServerTrusted(chain, authType)
    override fun getAcceptedIssuers(): Array<X509Certificate> = current()?.acceptedIssuers ?: emptyArray()
}
