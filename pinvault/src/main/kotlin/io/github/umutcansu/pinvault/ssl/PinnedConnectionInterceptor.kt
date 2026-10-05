package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import okhttp3.Connection
import okhttp3.Interceptor
import okhttp3.Response
import timber.log.Timber
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.WeakHashMap
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket

/**
 * OkHttp NETWORK interceptor: the pin check of the handshake, repeated on
 * every request against the config that is live now.
 *
 * The pinning trust manager only runs during a full TLS handshake. A
 * connection that stays open (HTTP/2, keep-alive) — or a new one that resumes
 * a cached TLS session — carries requests without it ever being asked again.
 * So after a pin was rotated away, or after the config expired, whoever was
 * on the other end of such a connection kept being trusted: with a stolen key
 * of a host that has since been re-pinned, for as long as they kept the
 * connection alive. The same goes for an HTTP/2 connection OkHttp reuses for
 * a second host name: the trust manager saw the first name only.
 *
 * Before each request this interceptor takes the certificates the connection
 * was established with and checks them for
 * the request's host and port against the live config — same matcher as the
 * trust manager (exact, wildcard and `host:port` entries, issuer pins) — and
 * checks the config's expiry (plus grace). On failure the call fails the way
 * a failed handshake does, an [SSLHandshakeException] whose cause is the
 * trust manager's [CertificateException], so callers and the recovery
 * interceptor treat both alike; and the connection is closed, so it serves
 * nobody else. `requireCaTrust` is checked with the pins (once per
 * connection, config and host); the certificate's own validity is a
 * handshake-time check and is not repeated.
 *
 * This is what protects clients the app builds itself with `applyTo`: the
 * library cannot close their connection pools, but no request of theirs goes
 * out on a connection that fails this check.
 *
 * The pin match of a connection is remembered per config object and host, so
 * the steady state costs a map lookup and the expiry comparison.
 *
 * ## Where the certificates come from
 * From the connection's TLS session (`SSLSocket.session.peerCertificates`) —
 * the chain the peer presented, also for a resumed session. OkHttp's own
 * `handshake().peerCertificates` is not usable here: it is the chain after
 * OkHttp's certificate-chain cleaner, which builds a path to a trust anchor
 * of the trust manager, and the pinning trust manager has none (it accepts
 * self-signed certificates), so that list comes back empty. It is only the
 * fallback for a socket that is not an `SSLSocket`. No certificates at all
 * fails the check.
 */
internal class PinnedConnectionInterceptor(
    private val configProvider: () -> CertificateConfig?,
    /** The config when it may be used now (present, not expired), else a [CertificateException]. */
    private val requireUsable: (config: CertificateConfig?, hostname: String) -> CertificateConfig,
    /** The matching pin, or a [CertificateException]. */
    private val matchPins: (config: CertificateConfig, chain: Array<X509Certificate>, hostname: String, port: Int?) -> String,
    /**
     * `requireCaTrust` for the request's host: nothing, or a
     * [CertificateException]. Run with the pin check, so also for a second
     * host name an HTTP/2 connection is reused for — the handshake judged
     * the first name only.
     */
    private val checkCaTrust: (chain: Array<X509Certificate>, hostname: String, port: Int?) -> Unit = { _, _, _ -> }
) : Interceptor {

    /** What a connection was last verified for. */
    private class Verified(val config: CertificateConfig, val hostPort: String)

    private val verified = WeakHashMap<Connection, Verified>()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val connection = chain.connection()
        // No handshake = a cleartext connection: nothing was pinned, nothing to re-check.
        if (connection?.handshake() == null) return chain.proceed(request)

        val host = request.url.host
        val port = request.url.port
        try {
            val config = requireUsable(configProvider(), host)
            val hostPort = "$host:$port"
            val known = synchronized(verified) { verified[connection] }
            if (known == null || known.config !== config || known.hostPort != hostPort) {
                val peers = peerChain(connection)
                matchPins(config, peers, host, port)
                checkCaTrust(peers, host, port)
                synchronized(verified) { verified[connection] = Verified(config, hostPort) }
            }
        } catch (e: CertificateException) {
            Timber.w("Connection to %s no longer passes the pin check — closing it: %s", host, e.message)
            synchronized(verified) { verified.remove(connection) }
            // Closed, so the pool cannot hand it to the next request (for
            // HTTP/2 that ends the other streams on it too — intended).
            runCatching { connection.socket().close() }
            throw SSLHandshakeException(e.message).apply { initCause(e) }
        }
        return chain.proceed(request)
    }

    /** The certificates the peer presented on [connection], leaf first; empty when they cannot be had. */
    private fun peerChain(connection: Connection): Array<X509Certificate> {
        val fromSession = try {
            (connection.socket() as? SSLSocket)?.session?.peerCertificates?.toList()
        } catch (e: SSLPeerUnverifiedException) {
            null
        }
        val certificates = fromSession ?: connection.handshake()?.peerCertificates.orEmpty()
        return certificates.filterIsInstance<X509Certificate>().toTypedArray()
    }
}
