package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.clientCertId
import com.example.pinvault.server.route.isValidIdentifier
import com.example.pinvault.server.service.AuthFailureRecorder
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * On an mTLS listener, refuses a request whose `X-Device-Id` names a device
 * the presented client certificate does not belong to.
 *
 * The header picks the per-device host ACL a config fetch is filtered with,
 * and the device a `token` vault download is checked against. It used to be
 * taken at its word, so an enrolled device could send another device's id and
 * read that device's pin list, or download with a token taken from it. The
 * certificate is the device's identity on these listeners; the header may
 * only repeat it ([isBound], normally
 * [com.example.pinvault.server.route.certificateBoundTo]). The library always
 * sends the ANDROID_ID it enrolled with, so a device's own requests pass.
 *
 * Requests without the header or without a certificate are left alone: the
 * routes decide what those may see. On a TLS listener there is no
 * certificate, the header is self-reported, and the ACL is advisory.
 */
class DeviceIdBindingConfig {
    /** Whether the certificate of client id `certClientId` belongs to device `deviceId`. */
    var isBound: (certClientId: String, deviceId: String) -> Boolean = { certClientId, deviceId -> certClientId == deviceId }

    /** Records refusals without flooding the audit log; null = not recorded. */
    var refusals: AuthFailureRecorder? = null
}

val DeviceIdBinding = createApplicationPlugin(name = "DeviceIdBinding", ::DeviceIdBindingConfig) {
    val isBound = pluginConfig.isBound
    val refusals = pluginConfig.refusals

    onCall { call ->
        val deviceId = call.request.header("X-Device-Id")?.trim()?.takeIf { it.isNotEmpty() } ?: return@onCall
        val certClientId = call.clientCertId() ?: return@onCall
        if (isBound(certClientId, deviceId)) return@onCall
        refusals?.report(call.request.origin.remoteAddress, call.request.httpMethod.value, call.request.path(),
            actor = certClientId,
            // The header is the caller's text; only a well-formed id goes into the log.
            reason = if (isValidIdentifier(deviceId)) "certificate not bound to device $deviceId" else "malformed X-Device-Id")
        call.respondText(
            """{"error":"device_identity_mismatch","message":"X-Device-Id does not belong to the client certificate of this connection."}""",
            ContentType.Application.Json, HttpStatusCode.Forbidden
        )
    }
}
