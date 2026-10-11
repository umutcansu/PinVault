package com.example.pinvault.server.plugin

import com.example.pinvault.server.service.ServerEnv
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.mutableOriginConnectionPoint

/**
 * The client's address behind a reverse proxy (`TRUSTED_PROXIES`).
 *
 * Everything that counts or records a client by address (rate limits, refusal
 * cut-offs, the audit log, the request log) reads `call.request.origin`.
 * Without a proxy that is the socket's peer. Behind Cloudflare, a tunnel or a
 * load balancer the peer is the proxy, so every device shared one address and
 * one set of per-address limits.
 *
 * A forwarding header is believed only when the socket's peer is listed in
 * `TRUSTED_PROXIES` (IP literals or CIDRs); from anyone else it is ignored, so
 * a device talking to the server directly cannot pick its own address.
 * `CLIENT_IP_HEADER` names the header: `X-Forwarded-For` (default) is read
 * from the right, skipping the trusted proxies, and the first other hop is the
 * client; a single-address header (`CF-Connecting-IP`, `X-Real-IP`, …) is
 * taken as it is. A value that is not an IP literal is ignored (the peer
 * stays the client). Loopback decisions (anonymous admin, approval replay)
 * keep reading the socket — see [ApiKeyAuth].
 *
 * Install it on every listener, right after [EncodedPathGuard] and before
 * anything that reads the client's address.
 */
object TrustedProxies {
    const val ENV = "TRUSTED_PROXIES"
    const val HEADER_ENV = "CLIENT_IP_HEADER"
    private const val FORWARDED_FOR = "X-Forwarded-For"
    private val HEADER_NAME = Regex("^[A-Za-z0-9-]{1,64}$")

    /** `TRUSTED_PROXIES`; empty = no proxy is trusted. */
    @Volatile
    var rules: List<String> = parse(ServerEnv.get(ENV))

    /** `CLIENT_IP_HEADER`, default `X-Forwarded-For`. */
    @Volatile
    var header: String = ServerEnv.get(HEADER_ENV)?.trim()?.takeIf { it.isNotEmpty() } ?: FORWARDED_FOR

    fun parse(value: String?): List<String> =
        value.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

    /** Startup check: a typo must not silently trust nobody (or the wrong range). */
    fun validate() {
        val bad = rules.filterNot { PeerRules.valid(it) }
        require(bad.isEmpty()) { "$ENV: ${bad.joinToString()} is not an IP address or CIDR (e.g. 127.0.0.1 or 172.16.0.0/12)" }
        require(HEADER_NAME.matches(header)) { "$HEADER_ENV: '$header' is not a header name" }
    }

    /** Whether [peer] (a socket address) is one of the trusted proxies. */
    fun isProxy(peer: String): Boolean = rules.isNotEmpty() && PeerRules.matchesAny(peer, rules)

    /**
     * The client's address for a request whose socket peer is [peer] and whose
     * [header] values (in order) are [values].
     */
    fun clientAddress(peer: String, values: List<String>): String {
        if (!isProxy(peer)) return peer
        val hops = values.flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }
        if (hops.isEmpty()) return peer
        if (!header.equals(FORWARDED_FOR, ignoreCase = true)) return PeerRules.normalize(hops.last()) ?: peer
        var client = peer
        for (hop in hops.asReversed()) {
            client = PeerRules.normalize(hop) ?: return peer
            if (!PeerRules.matchesAny(client, rules)) return client
        }
        // Every hop is a proxy of ours: the leftmost one is as far as anyone vouches.
        return client
    }
}

val ClientAddress = createApplicationPlugin(name = "ClientAddress") {
    onCall { call ->
        if (TrustedProxies.rules.isEmpty()) return@onCall
        val peer = call.request.local.remoteAddress
        val client = TrustedProxies.clientAddress(peer, call.request.headers.getAll(TrustedProxies.header).orEmpty())
        if (client == peer) return@onCall
        call.mutableOriginConnectionPoint.remoteAddress = client
        call.mutableOriginConnectionPoint.remoteHost = client
    }
}
