package com.example.pinvault.server.plugin

import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * Refuses, on a connection without TLS, the device endpoints that carry a
 * credential or key material.
 *
 * The management server listens on plain HTTP (and, with
 * `MANAGEMENT_HTTPS_PORT`, on TLS too) and serves a copy of the enrollment
 * endpoint: a device enrolling there over HTTP sent its enrollment token and
 * got back a private key and the password that opens it, all readable by
 * anyone on the same network. Those requests are now answered `403
 * tls_required` before the body is read — unless the connection comes from
 * this machine (loopback: local tooling, tests, a TLS-terminating proxy on
 * the same host). Devices enroll on a Config API port or the management TLS
 * port, both of which serve the certificate they pin.
 *
 * Scheme and peer address are the socket's own (`request.local`), never a
 * forwarded header.
 */
class CleartextGuardConfig {
    /** Which requests need TLS; default: every device endpoint that takes a token or returns a key ([carriesDeviceSecrets]). */
    var appliesTo: (path: String, method: HttpMethod) -> Boolean = { path, method -> carriesDeviceSecrets(path, method) }

    /** Whether a peer address is this machine. */
    var isLoopback: (remoteAddress: String) -> Boolean = ::isLoopbackAddress
}

val CleartextGuard = createApplicationPlugin(name = "CleartextGuard", ::CleartextGuardConfig) {
    val appliesTo = pluginConfig.appliesTo
    val isLoopback = pluginConfig.isLoopback

    onCall { call ->
        if (call.response.isCommitted) return@onCall
        val local = call.request.local
        if (local.scheme == "https") return@onCall
        if (!appliesTo(call.request.path(), call.request.httpMethod)) return@onCall
        if (isLoopback(local.remoteAddress)) return@onCall
        cleartextLog.warn("Refused {} {} over cleartext HTTP from {}",
            call.request.httpMethod.value, call.request.path(), local.remoteAddress)
        call.respondText(
            """{"error":"tls_required","message":"This endpoint is served over TLS only. Use a Config API port or the management TLS port."}""",
            ContentType.Application.Json, HttpStatusCode.Forbidden
        )
    }
}

private val HOST_CERT_DOWNLOAD = Regex("/api/v1/client-certs/[^/]+/download")
private val DEVICE_KEY = Regex("/api/v1/vault/devices/[^/]+/public-key")
private val VAULT_FILE = Regex("/api/v1/vault/([A-Za-z0-9._-]{1,64})")

/**
 * The device endpoints that take a token (enrollment, vault tokens) or answer
 * with key material (a P12, a certificate, a vault file).
 */
internal fun carriesDeviceSecrets(path: String, method: HttpMethod): Boolean = when (method) {
    HttpMethod.Post -> path == "/api/v1/client-certs/enroll" || path == "/api/v1/client-certs/renew" || DEVICE_KEY.matches(path)
    HttpMethod.Get -> HOST_CERT_DOWNLOAD.matches(path) ||
        VAULT_FILE.matchEntire(path)?.groupValues?.get(1)?.let { it !in RESERVED_VAULT_SEGMENTS } == true
    else -> false
}

private val cleartextLog = org.slf4j.LoggerFactory.getLogger("CleartextGuard")

private val IP_LITERAL = Regex("^[0-9A-Fa-f:.]+(%[0-9A-Za-z._-]+)?$")

/**
 * Whether [address] is a loopback address. A real socket reports an IP
 * literal, which is parsed and never resolved; the Ktor test host reports
 * `localhost`. Anything else is not loopback.
 */
internal fun isLoopbackAddress(address: String): Boolean =
    address == "localhost" || (IP_LITERAL.matches(address) && try {
        java.net.InetAddress.getByName(address).isLoopbackAddress
    } catch (_: Exception) {
        false
    })
