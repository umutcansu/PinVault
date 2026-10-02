package com.example.pinvault.server.plugin

import com.example.pinvault.server.route.clientCertId
import com.example.pinvault.server.route.clientCertificate
import com.example.pinvault.server.service.AuthFailureRecorder
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.createApplicationPlugin
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText

/**
 * Refuses every request on an mTLS listener whose client certificate belongs
 * to a revoked identity.
 *
 * The listeners trust the client CA, so the handshake accepts any certificate
 * the CA issued until it expires. Revocation used to be checked only when a
 * device renewed, which left a revoked device up to `CLIENT_CERT_TTL_DAYS` of
 * config and file access. The answer is the one a refused renewal gives
 * (`403 reenroll_required`), so the library reports it the same way.
 *
 * A forgotten identity has no row left to be revoked in, and its client id may
 * enroll again: its certificates are refused by their key instead.
 */
class RevocationGateConfig {
    /** Whether the identity named by a certificate's client id was revoked. */
    var isRevoked: (clientId: String) -> Boolean = { false }

    /** Whether the certificate's key was retired when its identity was forgotten. */
    var isRetiredKey: (certificate: java.security.cert.X509Certificate) -> Boolean = { false }

    /** Records refusals without flooding the audit log; null = not recorded. */
    var refusals: AuthFailureRecorder? = null
}

val RevocationGate = createApplicationPlugin(name = "RevocationGate", ::RevocationGateConfig) {
    val isRevoked = pluginConfig.isRevoked
    val isRetiredKey = pluginConfig.isRetiredKey
    val refusals = pluginConfig.refusals

    onCall { call ->
        val clientId = call.clientCertId() ?: return@onCall
        val reason = when {
            isRevoked(clientId) -> "revoked"
            call.clientCertificate()?.let(isRetiredKey) == true -> "key retired (identity forgotten)"
            else -> return@onCall
        }
        refusals?.report(call.request.origin.remoteAddress, call.request.httpMethod.value, call.request.path(),
            actor = clientId, reason = reason)
        call.respondText(
            """{"error":"reenroll_required","message":"This identity was revoked. Enroll again."}""",
            ContentType.Application.Json, HttpStatusCode.Forbidden
        )
    }
}
