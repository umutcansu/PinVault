package io.github.umutcansu.pinvault.reactnative

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.util.Log
import com.facebook.react.modules.network.CustomClientBuilder
import com.facebook.react.modules.network.NetworkingModule
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import com.facebook.react.modules.websocket.WebSocketModule
import io.github.umutcansu.pinvault.PinVault
import okhttp3.Cache
import okhttp3.CookieJar
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Pins React Native's own networking (global `fetch` / `XMLHttpRequest`,
 * `WebSocket`, and `<Image>` through Fresco) with `PinVault.applyTo(builder)` —
 * Android only.
 *
 * Installed **automatically before the app's code runs**: the plugin's manifest
 * declares [PinVaultNetworkingInitializer], a `ContentProvider`, and Android
 * creates content providers before `Application.onCreate` (the AndroidX
 * Startup pattern, without the dependency). [install] stays as an explicit
 * alternative for apps that remove the provider.
 *
 * Three hooks, verified against React Native 0.81 and 0.87's sources:
 *
 * - `NetworkingModule.setCustomClientBuilder`: RN calls it for **every**
 *   fetch / XHR request on `client.newBuilder()`. Each request gets the
 *   pinned socket factory and PinVault's interceptors (pin check of pooled
 *   connections, `PinVault-Token`, pin-mismatch recovery) of one client that
 *   `PinVault.applyTo` configured after `start()` — one per start, so pooled
 *   connections are reused — no disk HTTP cache and no cookie jar (unless
 *   `android.keepReactNativeHttpCache` / `keepReactNativeCookies`), and no
 *   `https` → `http` redirects.
 * - `OkHttpClientProvider.setOkHttpClientFactory`: the clients RN builds once
 *   and keeps (the networking base client, the WebSocket / dev-support
 *   singleton, Fresco's image client) get a forwarding socket factory: every
 *   TLS handshake uses the pinned factory of the current start. No disk
 *   cache, no `https` → `http` redirects.
 * - `WebSocketModule.setCustomClientBuilder`: RN calls it for every
 *   `WebSocket`. Up to 0.81 the module builds each socket's client from a
 *   bare `OkHttpClient.Builder()`, outside `OkHttpClientProvider`; from 0.87
 *   it derives it from the provider's client. Either way the socket gets the
 *   same forwarding factory, gate and network interceptors.
 *
 * Before `start()` — and after a start that failed — every `https` request
 * through RN's networking fails (`IOException: PinVault has not started`),
 * the same fail-closed rule as the library's own `getClient()` / `applyTo`,
 * which refuse before `init`. Plain `http` is not TLS and is left to the
 * app's network security config (Metro in debug builds uses it). Hosts
 * without a pin entry are refused by PinVault's trust manager like
 * everywhere else.
 *
 * Another library that calls `setOkHttpClientFactory` or either
 * `setCustomClientBuilder` after PinVault replaces these hooks: [status]
 * tells, `start()` and every plugin `fetch` check it and log a warning, and
 * `requirePinnedReactNativeNetworking: true` makes `start()` fail.
 */
object PinVaultNetworking {

    private const val TAG = "PinVault"

    @Volatile private var installed = false
    @Volatile private var app: Context? = null

    /** The hooks this object installed; compared by identity in [status]. */
    private val factory = OkHttpClientFactory {
        pinning.track(pinning.configureLongLived(OkHttpClientProvider.createClientBuilder()).build())
    }
    private val clientBuilder = CustomClientBuilder { builder -> pinning.configurePerRequest(builder) }
    private val webSocketBuilder = CustomClientBuilder { builder -> pinning.configureLongLived(builder) }

    internal val pinning = NetworkPinning(
        applier = { builder -> PinVault.applyTo(builder) },
        httpCache = { app?.let { ReactHttpCache.get(it) } },
        hooksPinned = { status().pinned },
    )

    /** True when [install] ran only from `start()`: React Native may have built clients before it. */
    @Volatile private var installedLate = false

    /**
     * Installs the hooks (once per process). The plugin's content provider
     * calls it before `Application.onCreate`; call it yourself in
     * `MainApplication.onCreate`, before `loadReactNative`, only when the app
     * removed that provider.
     */
    @JvmStatic
    @Synchronized
    fun install(context: Context) = install(context, late = false)

    /** [late]: called from `start()`, after React Native may already have built its clients. */
    @Synchronized
    internal fun install(context: Context, late: Boolean) {
        if (installed) return
        app = context.applicationContext
        OkHttpClientProvider.setOkHttpClientFactory(factory)
        NetworkingModule.setCustomClientBuilder(clientBuilder)
        WebSocketModule.setCustomClientBuilder(webSocketBuilder)
        installed = true
        installedLate = late
    }

    @JvmStatic
    val isInstalled: Boolean get() = installed

    /** Whether React Native's networking hooks are still the ones [install] set. */
    @JvmStatic
    fun status(): HookStatus = HookStatus.read(installed, factory, clientBuilder, webSocketBuilder, installedLate)

    private val warned = java.util.concurrent.atomic.AtomicReference<HookStatus?>(null)

    /** Logs a warning when the hooks are not PinVault's, once per distinct state. */
    internal fun warnIfNotPinned(where: String): HookStatus {
        val s = status()
        if (!s.pinned && warned.getAndSet(s) != s) Log.w(TAG, "$where: ${s.describe()}")
        if (s.pinned) warned.set(null)
        return s
    }
}

/**
 * What React Native's networking hooks are now. `null` = could not be read
 * (a React Native version whose internals moved): treated as not pinned.
 */
data class HookStatus(
    val installed: Boolean,
    /** `OkHttpClientProvider`'s factory is PinVault's. */
    val factoryIsPinVault: Boolean?,
    /** `NetworkingModule`'s custom client builder is PinVault's. */
    val clientBuilderIsPinVault: Boolean?,
    /** `WebSocketModule`'s custom client builder is PinVault's. */
    val webSocketBuilderIsPinVault: Boolean?,
    /** Installed only by `start()`: clients React Native built before (Fresco's, among them) keep the system's trust. */
    val installedLate: Boolean = false,
) {
    val pinned: Boolean get() = installed && !installedLate && factoryIsPinVault == true &&
        clientBuilderIsPinVault == true && webSocketBuilderIsPinVault == true

    fun describe(): String = when {
        pinned -> "React Native's networking is pinned by PinVault"
        installed && installedLate -> "React Native's networking hooks were installed only by start() (the plugin's content provider " +
            "was removed and PinVaultNetworking.install was not called before React Native started): clients it built " +
            "before, such as the image client, are NOT pinned"
        !installed -> "React Native's networking hooks are not installed (the plugin's content provider was removed " +
            "and PinVaultNetworking.install was not called, or android.pinGlobalNetworking is false): " +
            "RN fetch / XHR / WebSocket / images are NOT pinned"
        else -> buildList {
            if (factoryIsPinVault != true) add("OkHttpClientProvider's client factory " + if (factoryIsPinVault == null) "could not be read" else "was replaced by another library")
            if (clientBuilderIsPinVault != true) add("NetworkingModule's custom client builder " + if (clientBuilderIsPinVault == null) "could not be read" else "was replaced by another library")
            if (webSocketBuilderIsPinVault != true) add("WebSocketModule's custom client builder " + if (webSocketBuilderIsPinVault == null) "could not be read" else "was replaced by another library")
        }.joinToString("; ") + ": React Native's own networking may NOT be pinned"
    }

    internal companion object {
        fun read(installed: Boolean, ourFactory: Any, ourBuilder: Any, ourWebSocketBuilder: Any, installedLate: Boolean = false): HookStatus = HookStatus(
            installed,
            isOurs(OkHttpClientProvider::class.java, "factory", ourFactory),
            isOurs(NetworkingModule::class.java, "customClientBuilder", ourBuilder),
            isOurs(WebSocketModule::class.java, "customClientBuilder", ourWebSocketBuilder),
            installedLate,
        )

        /**
         * Whether RN's private static field [name] holds [ours]; null when it
         * cannot be read. The plugin's consumer R8 rules keep the fields' names.
         */
        private fun isOurs(owner: Class<*>, name: String, ours: Any): Boolean? = try {
            owner.getDeclaredField(name).apply { isAccessible = true }.get(null) === ours
        } catch (_: ReflectiveOperationException) {
            null
        } catch (_: RuntimeException) {
            null
        }
    }
}

/**
 * Installs [PinVaultNetworking] when the app process starts, before
 * `Application.onCreate`. Opt out in the app's manifest:
 *
 * ```xml
 * <provider android:name="io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer"
 *     android:authorities="${applicationId}.pinvault-networking" tools:node="remove" />
 * ```
 */
class PinVaultNetworkingInitializer : ContentProvider() {
    override fun onCreate(): Boolean {
        context?.let { PinVaultNetworking.install(it) }
        return true
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}

/** RN's own 10 MiB disk cache (`OkHttpClientProvider.createClientBuilder(context)`), only with `keepReactNativeHttpCache`. */
internal object ReactHttpCache {
    @Volatile private var cache: Cache? = null

    fun get(context: Context): Cache = cache ?: synchronized(this) {
        cache ?: Cache(File(context.cacheDir, "http-cache"), 10L * 1024 * 1024).also { cache = it }
    }
}

/**
 * The mechanics of [PinVaultNetworking], with the `applyTo` call injected so
 * that JVM tests can run it without a device.
 */
internal class NetworkPinning(
    private val applier: (OkHttpClient.Builder) -> Unit,
    private val httpCache: () -> Cache? = { null },
    /** Whether React Native's hooks are still PinVault's (``PinVaultNetworking.status``). */
    private val hooksPinned: () -> Boolean = { true },
) {

    /** The long-lived clients React Native built through the factory: their pools are emptied on every change. */
    private val longLived = java.util.Collections.synchronizedList(mutableListOf<java.lang.ref.WeakReference<OkHttpClient>>())

    /** Last answer of [hooksPinned] and when it was read (reflection: not on every request). */
    @Volatile private var hooksCheckedAt = 0L
    @Volatile private var hooksWerePinned = true

    fun track(client: OkHttpClient): OkHttpClient {
        longLived.add(java.lang.ref.WeakReference(client))
        return client
    }

    /** Closes the idle pooled connections of every long-lived client: the next request makes a fresh, pinned handshake. */
    private fun evictLongLived() {
        synchronized(longLived) {
            longLived.removeAll { it.get() == null }
            longLived.forEach { it.get()?.connectionPool?.evictAll() }
        }
    }

    /** A client `PinVault.applyTo` configured after the last `start()`; null = not started. */
    @Volatile private var template: OkHttpClient? = null
    @Volatile var options: NetworkingOptions = NetworkingOptions()

    val isActive: Boolean get() = template != null

    /** After `start()`: one pinned template per start (its socket factory keys the connection pool). */
    @Synchronized
    fun activate(options: NetworkingOptions = this.options) {
        this.options = options
        template = OkHttpClient.Builder().also(applier).build()
        evictLongLived()
    }

    @Synchronized
    fun deactivate() {
        template = null
        evictLongLived()
    }

    /** NetworkingModule's per-request builder (fetch / XHR). */
    fun configurePerRequest(builder: OkHttpClient.Builder) {
        // Never from https into plain http; not even before start (the gate below refuses https anyway).
        builder.followSslRedirects(false)
        val o = options
        builder.cache(if (o.keepHttpCache) httpCache() else null)
        // RN puts its persistent cookie jar (Android's CookieManager) on its base client;
        // NO_COOKIES = nothing is sent or stored. RN itself sets NO_COOKIES for withCredentials: false.
        if (!o.keepCookies) builder.cookieJar(CookieJar.NO_COOKIES)
        val pinned = template
        if (pinned == null) {
            if (httpsGate !in builder.interceptors()) builder.addInterceptor(httpsGate)
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

    /**
     * Clients RN builds once and keeps, and each WebSocket's client: TLS goes
     * through the pinned factory of the current start. Idempotent: from RN
     * 0.87 a WebSocket's builder derives from a client already configured here.
     */
    fun configureLongLived(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        val forwarding = ForwardingSocketFactory { template?.sslSocketFactory }
        builder.sslSocketFactory(forwarding, ForwardingTrustManager { template?.x509TrustManager })
        if (httpsGate !in builder.interceptors()) builder.addInterceptor(httpsGate)
        // The current start's network interceptors (the per-request pin check of a pooled
        // or coalesced connection, among them) run for these clients too.
        if (forwardingNetwork !in builder.networkInterceptors()) builder.addNetworkInterceptor(forwardingNetwork)
        builder.cache(null)
        builder.followSslRedirects(false)
        return builder
    }

    /**
     * Refuses `https` while PinVault has not started, and — with
     * `requirePinnedReactNativeNetworking` — once another library has replaced
     * React Native's hooks after start (checked at most every few seconds).
     */
    private val httpsGate = Interceptor { chain ->
        if (chain.request().isHttps) {
            if (template == null) throw IOException("PinVault has not started: https requests are refused until start() returns")
            if (options.requirePinned && !hooksStillPinned()) {
                throw IOException("requirePinnedReactNativeNetworking: React Native's networking hooks are no longer PinVault's")
            }
        }
        chain.proceed(chain.request())
    }

    private fun hooksStillPinned(): Boolean {
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - hooksCheckedAt > HOOK_CHECK_MS) {
            hooksWerePinned = hooksPinned()
            hooksCheckedAt = now
        }
        return hooksWerePinned
    }

    /** Runs the current start's network interceptors in order, then the request. */
    private val forwardingNetwork = Interceptor { chain ->
        val interceptors = template?.networkInterceptors ?: emptyList()
        ForwardingChain(chain, interceptors, 0).proceed(chain.request())
    }

    companion object {
        const val HOOK_CHECK_MS = 5_000L
    }
}

/** A chain that hands the request to `interceptors[index]`, …, and finally to the real chain. */
internal class ForwardingChain(
    private val base: Interceptor.Chain,
    private val interceptors: List<Interceptor>,
    private val index: Int,
) : Interceptor.Chain by base {
    override fun proceed(request: okhttp3.Request): okhttp3.Response =
        if (index >= interceptors.size) base.proceed(request)
        else interceptors[index].intercept(ForwardingChain(base, interceptors, index + 1).withRequest(request))

    private var current: okhttp3.Request = base.request()
    private fun withRequest(request: okhttp3.Request) = also { current = request }
    override fun request(): okhttp3.Request = current
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
