package com.example.pinvault.server.service

import com.example.pinvault.server.model.HostPin
import com.example.pinvault.server.model.PinConfig
import kotlinx.serialization.Serializable
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedTrustManager

/**
 * Refuses to publish a pin set the live host would fail.
 *
 * Before new or changed pins are stored, the host is contacted and the chain
 * it serves RIGHT NOW is checked the way a device checks it ([PinChain]): the
 * leaf's pin, or the pin of an issuer the leaf really chains to. A pin set
 * that fails would make every device refuse that host the moment it applies
 * the config — a typo, a pin for next year's certificate without the current
 * one, the wrong host's key, a CA the host's certificate does not come from.
 * The check is a safety net against mistakes, not against an attacker on the
 * server's network path.
 *
 * `PIN_LIVE_CHECK`:
 *  - `off` (default) — no check.
 *  - `warn` — the change is stored; the failure is logged, audited and notified.
 *  - `enforce` — the change is refused (HTTP 422), also when the host cannot
 *    be reached. `?liveCheckOverride=<reason>` stores it anyway when
 *    `PIN_LIVE_CHECK_ALLOW_OVERRIDE` is not `false`; the override and its
 *    reason are audited and notified.
 *
 * `LIVE_CHECK_HOST_MAP="name=host:port;…"` says where to probe a pinned name
 * that this server cannot reach directly — a split-horizon or test hostname,
 * or a wildcard entry (`*.example.com=www.example.com:443`). Otherwise the
 * pinned name itself is probed, on its `:port` or 443.
 *
 * Proper rotation passes without an override: publish {current, next} while
 * the host still serves `current`, switch the host's certificate, then publish
 * {next, backup}.
 */
class LiveCertificateGate(
    val mode: Mode,
    private val hostMap: Map<String, String> = emptyMap(),
    private val timeoutMs: Int = 5_000,
    val allowOverride: Boolean = true,
    private val probe: (connectHost: String, port: Int, sni: String?, timeoutMs: Int) -> List<X509Certificate> = ::tlsProbe
) {
    enum class Mode { OFF, WARN, ENFORCE }

    @Serializable
    data class HostCheck(
        val hostname: String,
        /** host:port that was contacted; null when the name could not be probed at all. */
        val probed: String?,
        val reachable: Boolean,
        /** SPKI pins of every certificate in the served chain, leaf first. */
        val livePins: List<String>,
        val matched: Boolean,
        val error: String? = null
    )

    @Serializable
    data class Result(val mode: String, val passed: Boolean, val checks: List<HostCheck>) {
        fun failures() = checks.filter { !it.matched }
        fun describe(): String = failures().joinToString("; ") { c ->
            if (!c.reachable) "${c.hostname}: not reachable (${c.error ?: "no certificate"})"
            else "${c.hostname}: the certificate it serves now (${c.livePins.firstOrNull()?.take(12)}…) is not in the new pins"
        }
    }

    val enabled: Boolean get() = mode != Mode.OFF

    /** Checks the hosts whose pin set is new or changed between [before] and [after]. */
    fun check(before: PinConfig?, after: PinConfig): Result {
        val old = before?.pins.orEmpty().associateBy { it.hostname }
        val touched = after.pins.filter { pin -> old[pin.hostname]?.sha256?.toSet() != pin.sha256.toSet() }
        return checkPins(touched)
    }

    /** Checks every entry of [pins] (the dry-run endpoint uses this directly). */
    fun checkPins(pins: List<HostPin>): Result {
        val checks = pins.map(::checkHost)
        return Result(mode.name.lowercase(), checks.all { it.matched }, checks)
    }

    private fun <T> withDeadline(block: () -> T): T {
        val future = probePool.submit<T> { block() }
        return try {
            future.get(timeoutMs * 2L, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (e: java.util.concurrent.TimeoutException) {
            future.cancel(true)
            throw java.io.IOException("no complete TLS handshake within ${timeoutMs * 2}ms")
        } catch (e: java.util.concurrent.ExecutionException) {
            throw e.cause ?: e
        }
    }

    private fun checkHost(pin: HostPin): HostCheck {
        val target = hostMap[pin.hostname] ?: pin.hostname
        if (target.startsWith("*.")) {
            return HostCheck(pin.hostname, null, false, emptyList(), false,
                "wildcard entry — map it to a real host with LIVE_CHECK_HOST_MAP")
        }
        val (host, port) = splitHostPort(target)
        val sni = when {
            pin.hostname.startsWith("*.") -> host
            else -> splitHostPort(pin.hostname).first
        }.takeUnless(::isIpLiteral)
        return try {
            val chain = withDeadline { probe(host, port, sni, timeoutMs) }
            HostCheck(pin.hostname, "$host:$port", true, chain.map { spkiPin(it) }, PinChain.satisfies(chain, pin.sha256))
        } catch (e: Exception) {
            HostCheck(pin.hostname, "$host:$port", false, emptyList(), false, e.message ?: e.javaClass.simpleName)
        }
    }

    companion object {
        fun fromEnv(env: Map<String, String> = System.getenv()) = LiveCertificateGate(
            mode = when (env["PIN_LIVE_CHECK"]?.trim()?.lowercase()) {
                "warn" -> Mode.WARN
                "enforce" -> Mode.ENFORCE
                else -> Mode.OFF
            },
            hostMap = env["LIVE_CHECK_HOST_MAP"].orEmpty().split(';', ',')
                .map { it.trim() }.filter { '=' in it }
                .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() },
            timeoutMs = env["LIVE_CHECK_TIMEOUT_MS"]?.toIntOrNull() ?: 5_000,
            allowOverride = env["PIN_LIVE_CHECK_ALLOW_OVERRIDE"] != "false"
        )

        fun spkiPin(cert: X509Certificate): String =
            Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))

        /** "host", "host:port", "[v6]", "[v6]:port" or a bare IPv6 literal → host and port (443 default). */
        internal fun splitHostPort(value: String): Pair<String, Int> {
            Regex("^\\[([^\\]]+)](?::(\\d+))?$").matchEntire(value)?.let { m ->
                return m.groupValues[1] to (m.groupValues[2].toIntOrNull() ?: 443)
            }
            if (value.count { it == ':' } > 1) return value to 443 // bare IPv6
            val port = value.substringAfterLast(':', "").toIntOrNull()
            return if (port != null) value.substringBeforeLast(':') to port else value to 443
        }

        private fun isIpLiteral(host: String) = host.all { it.isDigit() || it == '.' } || ':' in host

        /**
         * Probes on their own threads with a hard deadline: socket timeouts
         * apply per read, so a host that drips bytes could otherwise hold a
         * request (and an event-loop thread) for as long as it likes.
         */
        private val probePool = java.util.concurrent.Executors.newCachedThreadPool { r ->
            Thread(r, "live-check-probe").apply { isDaemon = true }
        }

        /**
         * Connects, runs a TLS handshake and returns the chain the server
         * presented. Certificates are captured before any trust decision, so
         * a self-signed host or an mTLS host that then demands a client
         * certificate still yields its chain.
         */
        fun tlsProbe(host: String, port: Int, sni: String?, timeoutMs: Int): List<X509Certificate> {
            var captured: Array<X509Certificate>? = null
            val capture = object : X509ExtendedTrustManager() {
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?) { captured = chain }
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?, socket: Socket?) { captured = chain }
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?, engine: SSLEngine?) { captured = chain }
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = Unit
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, socket: Socket?) = Unit
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) = Unit
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(capture), null) }
            val plain = Socket()
            plain.connect(InetSocketAddress(host, port), timeoutMs)
            plain.soTimeout = timeoutMs
            val ssl = context.socketFactory.createSocket(plain, sni ?: host, port, true) as SSLSocket
            try {
                if (sni != null) ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
                try {
                    ssl.startHandshake()
                } catch (e: SSLException) {
                    if (captured == null) throw e
                }
            } finally {
                ssl.close()
            }
            return captured?.toList() ?: error("the server sent no certificate")
        }
    }
}
