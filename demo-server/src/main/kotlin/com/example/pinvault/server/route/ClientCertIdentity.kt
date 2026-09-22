package com.example.pinvault.server.route

import io.ktor.server.application.ApplicationCall
import io.ktor.util.AttributeKey
import javax.net.ssl.SSLPeerUnverifiedException
import javax.security.auth.x500.X500Principal

/**
 * Reads the identity of the mTLS client certificate the peer presented on this
 * call.
 *
 * ## Why this file exists (audit L-1)
 * Both [vaultRoutes] and [certificateConfigRoutes] used to look the principal
 * up in a `TLSPeerPrincipal` call attribute that nothing ever populated, so the
 * lookup always returned null. That made the `token_mtls` vault policy
 * permanently unusable (every request 401'd even with a valid client cert) and
 * the Config API's cert-based deviceId fallback inert.
 *
 * Ktor's Netty engine does not surface the TLS session on the call, but the
 * call *does* expose the Netty [io.netty.channel.ChannelHandlerContext] it was
 * created from. The verified peer chain is available from the channel's
 * `SslHandler`, which is exactly what this reads.
 *
 * ## Trust
 * `SSLSession.getPeerCertificates()` only returns a chain after the JSSE
 * handshake completed *and* the peer was authenticated against the connector's
 * trust store. It throws [SSLPeerUnverifiedException] otherwise. The Config API
 * connectors only enable client auth when a trust store is configured (mTLS
 * mode), so a chain here means "this cert was issued by our CA and the peer
 * proved possession of the private key". We never parse an unverified cert.
 */

/** Attribute a custom engine (or a test) can use to inject the peer principal. */
private val TLS_PEER_PRINCIPAL = AttributeKey<X500Principal>("TLSPeerPrincipal")

/** Prefix [com.example.pinvault.server.service.CertificateService] puts on every client CN. */
const val CLIENT_CN_PREFIX = "PinVault Client: "

/**
 * The full CN of the verified client certificate, e.g.
 * `PinVault Client: my-device`. Null when the connection is plain TLS, when the
 * peer presented no certificate, or when the handshake was not client-authenticated.
 */
fun ApplicationCall.clientCertCn(): String? {
    val principal = attributes.getOrNull(TLS_PEER_PRINCIPAL) ?: nettyPeerPrincipal() ?: return null
    return cnOf(principal.name)
}

/**
 * The client id embedded in the certificate CN — the CN with the
 * [CLIENT_CN_PREFIX] stripped. This is the value that was passed to
 * `POST /api/v1/client-certs/enroll` (a device's ANDROID_ID under
 * `ENROLLMENT_MODE=open`, or the admin-chosen client id under token
 * enrollment).
 */
fun ApplicationCall.clientCertId(): String? =
    clientCertCn()?.removePrefix(CLIENT_CN_PREFIX)?.trim()?.takeIf { it.isNotEmpty() }

/**
 * Pulls the verified peer principal off the Netty channel this call arrived on.
 *
 * Defensive throughout: a non-Netty engine (the Ktor test host), a plain-HTTP
 * channel, or an unauthenticated handshake all yield null rather than an error,
 * so callers fail closed.
 */
private fun ApplicationCall.nettyPeerPrincipal(): X500Principal? {
    val engineCall = unwrapEngineCall()
    val nettyCall = engineCall as? io.ktor.server.netty.NettyApplicationCall
    if (nettyCall == null) {
        identityLog.debug("no Netty call behind {} — TLS identity unavailable", engineCall::class.java.name)
        return null
    }
    return try {
        val sslHandler = findSslHandler(nettyCall.context.channel())
        if (sslHandler == null) {
            identityLog.debug("no SslHandler on this channel or its parents: {}",
                nettyCall.context.pipeline().names())
            return null
        }
        val peer = sslHandler.engine().session.peerCertificates.firstOrNull()
        (peer as? java.security.cert.X509Certificate)?.subjectX500Principal
    } catch (_: SSLPeerUnverifiedException) {
        // Normal on a TLS-only connector, or when the client sent no cert.
        identityLog.debug("TLS session has no verified peer certificate")
        null
    } catch (e: Throwable) {
        identityLog.debug("client certificate lookup failed: {}", e.toString())
        null
    }
}

/**
 * Finds the TLS handler for a request's channel, walking up to the parent
 * connection when necessary.
 *
 * HTTP/2 is the reason for the walk: once ALPN negotiates h2 — which both curl
 * and OkHttp do against these listeners — each request runs on its own *stream*
 * channel whose pipeline holds only `NettyHttp2Handler` and the Ktor call
 * handler. The `SslHandler`, and with it the authenticated session, lives on
 * the parent connection channel. Looking only at the request channel is why the
 * first attempt at this fix saw no TLS at all on an h2 connection while HTTP/1.1
 * would have worked.
 */
private fun findSslHandler(channel: io.netty.channel.Channel?): io.netty.handler.ssl.SslHandler? {
    var current = channel
    repeat(MAX_CHANNEL_PARENT_DEPTH) {
        if (current == null) return null
        current.pipeline().get(io.netty.handler.ssl.SslHandler::class.java)?.let { return it }
        current = current.parent()
    }
    return null
}

/** h2 stream → connection is one hop; a couple of spares cost nothing. */
private const val MAX_CHANNEL_PARENT_DEPTH = 4

private val identityLog = org.slf4j.LoggerFactory.getLogger("ClientCertIdentity")

/**
 * Unwraps the engine call a route handler's [ApplicationCall] delegates to.
 *
 * Inside a `routing { get { … } }` block Ktor 3 hands the handler a
 * `RoutingCall`, which wraps a `RoutingPipelineCall`, which wraps the real
 * engine call. Casting the handler's `call` straight to `NettyApplicationCall`
 * therefore always fails — the reason the first cut of this fix still answered
 * "mTLS client certificate required" for a correctly authenticated client.
 *
 * The loop is bounded so an unexpected self-referential wrapper cannot hang a
 * request.
 */
private fun ApplicationCall.unwrapEngineCall(): ApplicationCall {
    var current: ApplicationCall = this
    repeat(MAX_CALL_UNWRAP_DEPTH) {
        val next: ApplicationCall = when (current) {
            is io.ktor.server.routing.RoutingCall -> (current as io.ktor.server.routing.RoutingCall).pipelineCall
            is io.ktor.server.routing.RoutingPipelineCall -> (current as io.ktor.server.routing.RoutingPipelineCall).engineCall
            else -> return current
        }
        if (next === current) return current
        current = next
    }
    return current
}

/** Wrapper chain is RoutingCall → RoutingPipelineCall → engine call; 8 is ample. */
private const val MAX_CALL_UNWRAP_DEPTH = 8

/**
 * Extracts the CN from a DN. Full RFC 2253 parsing would need
 * `javax.naming.ldap.LdapName`; the CNs this server issues contain no escaped
 * commas, so the simple form is sufficient and keeps the demo dependency-free.
 */
private fun cnOf(dn: String): String? =
    Regex("CN=([^,]+)").find(dn)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
