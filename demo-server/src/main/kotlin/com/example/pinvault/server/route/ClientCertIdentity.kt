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

/** Attribute a test can use to inject the whole peer certificate (renewal needs its key and dates). */
val TLS_PEER_CERTIFICATE = AttributeKey<java.security.cert.X509Certificate>("TLSPeerCertificate")

/** Prefix [com.example.pinvault.server.service.CertificateService] puts on every client CN. */
const val CLIENT_CN_PREFIX = "PinVault Client: "

/**
 * The full CN of the verified client certificate, e.g.
 * `PinVault Client: my-device`. Null when the connection is plain TLS, when the
 * peer presented no certificate, or when the handshake was not client-authenticated.
 */
fun ApplicationCall.clientCertCn(): String? {
    val dn = attributes.getOrNull(TLS_PEER_PRINCIPAL)?.name
        ?: clientCertificate()?.subjectX500Principal?.name
        ?: return null
    return cnOf(dn)
}

/**
 * The verified client certificate itself, for callers that need more than its
 * name — the renewal endpoint compares its key with the CSR's. Null under the
 * same conditions as [clientCertCn].
 */
fun ApplicationCall.clientCertificate(): java.security.cert.X509Certificate? =
    attributes.getOrNull(TLS_PEER_CERTIFICATE) ?: nettyPeerCertificate()

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
private fun ApplicationCall.nettyPeerCertificate(): java.security.cert.X509Certificate? {
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
        sslHandler.engine().session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
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

/**
 * Whether the verified client certificate of [certClientId] belongs to the
 * device [deviceId] (a `X-Device-Id` header, or the device in a URL).
 *
 * Two accepted bindings, in order:
 *
 *  1. **Direct** — `certClientId == deviceId`. This is the auto-enrollment
 *     case (`ENROLLMENT_MODE=open`), where the device enrolls with its own
 *     ANDROID_ID, so the issued CN is literally `PinVault Client: <ANDROID_ID>`.
 *
 *  2. **Recorded at enrollment** — the `client_certs` row for `certClientId`
 *     has `device_uid == deviceId`. Token-based enrollment uses an
 *     admin-chosen client id that will never equal an ANDROID_ID, but the
 *     library sends its `deviceUid` in the enrollment body and the server
 *     stores it, so the certificate is still bound to one device (and a
 *     device id belongs to one active identity at a time).
 *
 * A revoked certificate is rejected even if the ids line up. Anything else
 * fails closed. Used by the `token_mtls` vault policy, E2E key registration
 * and [com.example.pinvault.server.plugin.DeviceIdBinding].
 */
fun certificateBoundTo(
    certClientId: String,
    deviceId: String,
    clientCertStore: com.example.pinvault.server.store.ClientCertStore?
): Boolean {
    val record = clientCertStore?.get(certClientId)
    if (record != null && record.revoked) {
        identityLog.warn("request with a revoked certificate: clientId={}", certClientId)
        return false
    }
    if (certClientId == deviceId) return true
    return record?.deviceUid != null && record.deviceUid == deviceId
}

/**
 * Whether [certificate], whose CN names [clientId], is the certificate on
 * record for that id — checked on every mTLS request by
 * [com.example.pinvault.server.plugin.RevocationGate].
 *
 *  1. An identity enrolled over a device-held key (`client_identities`): the
 *     certificate's key must be that key. The handshake proved the peer holds
 *     its private half, so any certificate over it — the current serial, or
 *     the one before a renewal on a connection still open — is that device.
 *  2. Otherwise the `client_certs` row of the id (a server-made P12): the
 *     certificate must be exactly the stored one (SHA-256 of its DER).
 *  3. No row under the id: an uploaded certificate, trusted under its row
 *     id while its subject may say something else — exactly that certificate.
 *
 * Anything else is a leaf some other trusted key signed with this id in it.
 * Per-certificate trust anchors (self-signed P12s from before P12s came from
 * the client CA, uploaded certificates) can sign such leaves, and JSSE does
 * not look at an anchor's CA flag — this is what keeps one device from
 * presenting itself as another.
 */
fun presentedLeafOnRecord(
    clientId: String,
    certificate: java.security.cert.X509Certificate,
    clientCertStore: com.example.pinvault.server.store.ClientCertStore?,
    identityStore: com.example.pinvault.server.store.ClientIdentityStore?
): Boolean {
    identityStore?.get(clientId)?.let { identity ->
        return sha256Base64(certificate.publicKey.encoded) == identity.spkiSha256
    }
    val fingerprint = sha256Base64(certificate.encoded)
    clientCertStore?.get(clientId)?.let { record -> return record.fingerprint == fingerprint }
    return clientCertStore?.idByFingerprint(fingerprint) != null
}

private fun sha256Base64(bytes: ByteArray): String =
    java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))

/**
 * What a client id or a device id may look like. Both are printed in the
 * dashboard and a client id becomes part of a certificate subject, so nothing
 * that could open markup or a new name part (`<`, `"`, `,`, `=`, `+`, spaces).
 */
private val IDENTIFIER = Regex("^[A-Za-z0-9._:-]{1,64}$")

fun isValidIdentifier(value: String): Boolean = IDENTIFIER.matches(value)

/**
 * Whether [value] is a name the server keeps for itself (the client CA's
 * truststore alias and its other keystore aliases, ignoring case). Such a
 * client id would let revoke, forget or upload act on the CA's entry.
 */
fun isReservedClientId(value: String): Boolean =
    com.example.pinvault.server.service.CertificateService.isReservedAlias(value)

/** The answer when a client id is one of [isReservedClientId]. */
internal const val RESERVED_CLIENT_ID =
    """{"error":"reserved_client_id","message":"This name is used by the server itself (e.g. client-ca) and cannot be a client id."}"""

/**
 * [certificateBoundTo], and more: the device id is not just what the
 * enrolling party said. Required for everything that opens a device's keys
 * or files — replacing its E2E or user-auth key over a certificate, its
 * `token_mtls` files, its host client certificates under a host ACL.
 *
 * A device id sent at enrollment is a bare claim: a holder of any token or
 * code who knows a victim's ANDROID_ID could enroll naming it and, through
 * [certificateBoundTo], act for that device. Proven means one of:
 *
 *  1. the client id IS the device id (open mode, or a token an admin minted
 *     with the device id as its client id);
 *  2. the `client_certs` row says `device_uid_proven` (V20): a passing
 *     Android Key Attestation with the app binding (its challenge is the
 *     device id), or a token an administrator bound to the device id.
 *
 * `identity_devices` rows do not count: they are a vault token of the device
 * used over the certificate (a bearer secret that may be the very thing that
 * leaked) or the device's public key sent again (public). They decide what
 * revocation cuts off, not what a certificate may open.
 */
fun certificateProvenFor(
    certClientId: String,
    deviceId: String,
    clientCertStore: com.example.pinvault.server.store.ClientCertStore?
): Boolean {
    val record = clientCertStore?.get(certClientId)
    if (record != null && record.revoked) return false
    if (certClientId == deviceId) return true
    return record?.deviceUid == deviceId && record.deviceUidProven
}
